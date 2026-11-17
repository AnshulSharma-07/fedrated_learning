import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { FederatedEnvelope } from './types';

function resolveKeyDir(): string {
  const dir = process.env.FL_IDS_KEY_DIR || path.resolve(process.cwd(), '.local_keys');
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  return dir;
}

function getJwtSecret(): string {
  return process.env.FL_IDS_JWT_SECRET || 'fl-ids-local-dev-jwt-secret-change-in-prod-2026';
}

function getMasterAesKey(): Buffer {
  const raw = process.env.FL_IDS_PAYLOAD_MASTER_KEY || 'fl-ids-local-dev-aes-master-key-change-prod';
  return crypto.createHash('sha256').update(raw, 'utf8').digest();
}

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `scrypt:${salt}:${derived}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  const parts = storedHash.split(':');
  if (parts.length !== 3 || parts[0] !== 'scrypt') {
    return false;
  }
  const [, salt, expectedHex] = parts;
  const derived = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(expectedHex, 'hex');
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}

export interface JwtPayload {
  sub: string;
  email: string;
  name: string;
  role: 'admin' | 'analyst' | 'viewer';
  iat: number;
  exp: number;
}

function base64UrlEncode(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url');
}

function base64UrlDecode(input: string): string {
  return Buffer.from(input, 'base64url').toString('utf8');
}

export function signJwt(payload: Omit<JwtPayload, 'iat' | 'exp'>, ttlSeconds = 86400): string {
  const now = Math.floor(Date.now() / 1000);
  const fullPayload: JwtPayload = {
    ...payload,
    iat: now,
    exp: now + ttlSeconds,
  };
  const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = base64UrlEncode(JSON.stringify(fullPayload));
  const data = `${header}.${body}`;
  const sig = crypto
    .createHmac('sha256', getJwtSecret())
    .update(data)
    .digest('base64url');
  return `${data}.${sig}`;
}

export function verifyJwt(token: string): JwtPayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [header, body, sig] = parts;
    const expectedSig = crypto
      .createHmac('sha256', getJwtSecret())
      .update(`${header}.${body}`)
      .digest('base64url');
    const a = Buffer.from(sig);
    const b = Buffer.from(expectedSig);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return null;
    }
    const parsed = JSON.parse(base64UrlDecode(body)) as JwtPayload;
    if (parsed.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function canonicalizeJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalizeJson).join(',')}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalizeJson(obj[k])}`).join(',')}}`;
}

export function sha256Hex(data: string | Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

export interface GeneratedClientKeyPair {
  keyId: string;
  publicKeyPem: string;
  fingerprint: string;
  privateKeyPath: string;
}

export function generateAndStoreEd25519KeyPair(clientId: string, persistPrivateKey = true): GeneratedClientKeyPair & { privateKeyPem: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const fingerprint = sha256Hex(publicKey).slice(0, 32);
  const keyId = `ed25519-${fingerprint.slice(0, 12)}`;
  let privateKeyPath = '';
  if (persistPrivateKey) {
    const keyDir = resolveKeyDir();
    privateKeyPath = path.join(keyDir, `${clientId.replace(/[^a-zA-Z0-9_-]/g, '_')}.key.pem`);
    fs.writeFileSync(privateKeyPath, privateKey, { mode: 0o600 });
  }
  return {
    keyId,
    publicKeyPem: publicKey,
    privateKeyPem: privateKey,
    fingerprint,
    privateKeyPath,
  };
}

export function loadClientPrivateKey(clientId: string): string | null {
  const keyDir = resolveKeyDir();
  const privateKeyPath = path.join(keyDir, `${clientId.replace(/[^a-zA-Z0-9_-]/g, '_')}.key.pem`);
  if (!fs.existsSync(privateKeyPath)) return null;
  return fs.readFileSync(privateKeyPath, 'utf8');
}

export function buildSignedEncryptedEnvelope(params: {
  clientId: string;
  round: number;
  modelVersion: string;
  sampleCount: number;
  payload: unknown;
  privateKeyPem: string;
  sharedAesKey?: Buffer;
  forcedNonce?: string;
}): FederatedEnvelope {
  const canonicalPayload = canonicalizeJson(params.payload);
  const payloadSha256 = sha256Hex(canonicalPayload);
  const nonce = params.forcedNonce || crypto.randomBytes(12).toString('hex');
  const timestamp = new Date().toISOString();

  // AES-256-GCM authenticated encryption with unique 96-bit IV per message
  const aesKey = params.sharedAesKey || getMasterAesKey();
  const iv = crypto.randomBytes(12);
  const aad = Buffer.from(
    canonicalizeJson({
      clientId: params.clientId,
      modelVersion: params.modelVersion,
      nonce,
      round: params.round,
    }),
    'utf8',
  );
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  cipher.setAAD(aad);
  const encrypted = Buffer.concat([cipher.update(canonicalPayload, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Sign canonical metadata binding client, round, version, sample count, nonce, and payload hash
  const metadataToSign = canonicalizeJson({
    clientId: params.clientId,
    modelVersion: params.modelVersion,
    nonce,
    payloadSha256,
    round: params.round,
    sampleCount: params.sampleCount,
    timestamp,
  });
  const signature = crypto.sign(null, Buffer.from(metadataToSign, 'utf8'), params.privateKeyPem);

  return {
    clientId: params.clientId,
    round: params.round,
    modelVersion: params.modelVersion,
    sampleCount: params.sampleCount,
    nonce,
    timestamp,
    payloadSha256,
    signatureBase64: signature.toString('base64'),
    ivBase64: iv.toString('base64'),
    authTagBase64: authTag.toString('base64'),
    ciphertextBase64: encrypted.toString('base64'),
  };
}

export interface EnvelopeVerificationResult<T = unknown> {
  ok: boolean;
  reason?: string;
  code?: 'REPLAY_DETECTED' | 'SIGNATURE_INVALID' | 'DECRYPTION_FAILED' | 'INTEGRITY_MISMATCH' | 'UNAUTHORIZED_CLIENT';
  signatureVerified: boolean;
  decryptionVerified: boolean;
  integrityVerified: boolean;
  payload?: T;
}

export class ReplayGuard {
  private seenNonces = new Set<string>();

  constructor(initialNonces: string[] = []) {
    for (const n of initialNonces) {
      this.seenNonces.add(n);
    }
  }

  has(clientId: string, nonce: string): boolean {
    return this.seenNonces.has(`${clientId}:${nonce}`);
  }

  mark(clientId: string, nonce: string): void {
    this.seenNonces.add(`${clientId}:${nonce}`);
  }
}

export function verifyAndDecryptEnvelope<T = unknown>(params: {
  envelope: FederatedEnvelope;
  publicKeyPem: string | null;
  clientActive: boolean;
  keyRevoked: boolean;
  replayGuard: ReplayGuard;
  sharedAesKey?: Buffer;
}): EnvelopeVerificationResult<T> {
  const { envelope, publicKeyPem, clientActive, keyRevoked, replayGuard } = params;

  if (!clientActive || keyRevoked || !publicKeyPem) {
    return {
      ok: false,
      code: 'UNAUTHORIZED_CLIENT',
      reason: !publicKeyPem
        ? 'Client public key is not registered'
        : keyRevoked
          ? 'Client Ed25519 key has been revoked'
          : 'Client is inactive or deauthorized',
      signatureVerified: false,
      decryptionVerified: false,
      integrityVerified: false,
    };
  }

  if (replayGuard.has(envelope.clientId, envelope.nonce)) {
    return {
      ok: false,
      code: 'REPLAY_DETECTED',
      reason: `Replay detected: nonce ${envelope.nonce} was already processed for ${envelope.clientId}`,
      signatureVerified: false,
      decryptionVerified: false,
      integrityVerified: false,
    };
  }

  const metadataToVerify = canonicalizeJson({
    clientId: envelope.clientId,
    modelVersion: envelope.modelVersion,
    nonce: envelope.nonce,
    payloadSha256: envelope.payloadSha256,
    round: envelope.round,
    sampleCount: envelope.sampleCount,
    timestamp: envelope.timestamp,
  });

  let signatureVerified = false;
  try {
    signatureVerified = crypto.verify(
      null,
      Buffer.from(metadataToVerify, 'utf8'),
      publicKeyPem,
      Buffer.from(envelope.signatureBase64, 'base64'),
    );
  } catch {
    signatureVerified = false;
  }

  if (!signatureVerified) {
    return {
      ok: false,
      code: 'SIGNATURE_INVALID',
      reason: 'Ed25519 digital signature verification failed',
      signatureVerified: false,
      decryptionVerified: false,
      integrityVerified: false,
    };
  }

  // Decrypt AES-256-GCM payload and verify GCM auth tag + AAD
  let plaintext = '';
  try {
    const aesKey = params.sharedAesKey || getMasterAesKey();
    const iv = Buffer.from(envelope.ivBase64, 'base64');
    const authTag = Buffer.from(envelope.authTagBase64, 'base64');
    const ciphertext = Buffer.from(envelope.ciphertextBase64, 'base64');
    const aad = Buffer.from(
      canonicalizeJson({
        clientId: envelope.clientId,
        modelVersion: envelope.modelVersion,
        nonce: envelope.nonce,
        round: envelope.round,
      }),
      'utf8',
    );
    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(authTag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  } catch {
    return {
      ok: false,
      code: 'DECRYPTION_FAILED',
      reason: 'AES-256-GCM decryption or authentication tag verification failed',
      signatureVerified: true,
      decryptionVerified: false,
      integrityVerified: false,
    };
  }

  // Verify SHA-256 canonical digest
  const computedHash = sha256Hex(plaintext);
  if (computedHash !== envelope.payloadSha256) {
    return {
      ok: false,
      code: 'INTEGRITY_MISMATCH',
      reason: `SHA-256 payload mismatch: expected ${envelope.payloadSha256.slice(0, 12)}, got ${computedHash.slice(0, 12)}`,
      signatureVerified: true,
      decryptionVerified: true,
      integrityVerified: false,
    };
  }

  replayGuard.mark(envelope.clientId, envelope.nonce);
  const parsed = JSON.parse(plaintext) as T;
  return {
    ok: true,
    signatureVerified: true,
    decryptionVerified: true,
    integrityVerified: true,
    payload: parsed,
  };
}
