import type { FederatedEnvelope } from '../engine/types';

function getSubtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle;
  if (!s) {
    throw new Error('Web Crypto API (crypto.subtle) is required in this browser context');
  }
  return s;
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function toArrayBuffer(view: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(view.byteLength);
  copy.set(view);
  return copy.buffer;
}

export function canonicalizeJsonWeb(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalizeJsonWeb).join(',')}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalizeJsonWeb(obj[k])}`).join(',')}}`;
}

export async function sha256HexWeb(input: string | Uint8Array): Promise<string> {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  const digest = await getSubtle().digest('SHA-256', toArrayBuffer(bytes));
  return toHex(new Uint8Array(digest));
}

export interface WebClientKeyMaterial {
  keyId: string;
  algorithm: 'Ed25519' | 'ECDSA-P256';
  publicKeyPem: string;
  fingerprint: string;
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

function spkiToPem(spkiBytes: ArrayBuffer): string {
  const b64 = toBase64(new Uint8Array(spkiBytes));
  const lines = b64.match(/.{1,64}/g)?.join('\n') || b64;
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`;
}

export async function generateWebSigningKeyPair(): Promise<WebClientKeyMaterial> {
  const subtle = getSubtle();
  let algorithm: 'Ed25519' | 'ECDSA-P256' = 'Ed25519';
  let kp: CryptoKeyPair;

  try {
    kp = (await subtle.generateKey('Ed25519', true, ['sign', 'verify'])) as CryptoKeyPair;
  } catch {
    // Graceful fallback for older browsers without WebCrypto Ed25519
    algorithm = 'ECDSA-P256';
    kp = (await subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
  }

  const spki = await subtle.exportKey('spki', kp.publicKey);
  const publicKeyPem = spkiToPem(spki);
  const fingerprint = (await sha256HexWeb(publicKeyPem)).slice(0, 32);
  const keyId = `${algorithm.toLowerCase()}-${fingerprint.slice(0, 12)}`;

  return {
    keyId,
    algorithm,
    publicKeyPem,
    fingerprint,
    publicKey: kp.publicKey,
    privateKey: kp.privateKey,
  };
}

let cachedAesKey: CryptoKey | null = null;
async function getSessionAesKey(): Promise<CryptoKey> {
  if (cachedAesKey) return cachedAesKey;
  const subtle = getSubtle();
  // Derive deterministic 256-bit AES-GCM key for browser-local envelope verification
  const rawSeed = new TextEncoder().encode('fl-ids-browser-aes-256-gcm-session-key-2026');
  const digest = await subtle.digest('SHA-256', toArrayBuffer(rawSeed));
  cachedAesKey = await subtle.importKey('raw', digest, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ]);
  return cachedAesKey;
}

export class WebReplayGuard {
  private seenNonces = new Set<string>();

  has(clientId: string, nonce: string): boolean {
    return this.seenNonces.has(`${clientId}:${nonce}`);
  }

  mark(clientId: string, nonce: string): void {
    this.seenNonces.add(`${clientId}:${nonce}`);
  }
}

export async function buildSignedEncryptedEnvelopeWeb(params: {
  clientId: string;
  round: number;
  modelVersion: string;
  sampleCount: number;
  payload: unknown;
  keyMaterial: WebClientKeyMaterial;
  forcedNonce?: string;
}): Promise<FederatedEnvelope> {
  const subtle = getSubtle();
  const canonicalPayload = canonicalizeJsonWeb(params.payload);
  const payloadSha256 = await sha256HexWeb(canonicalPayload);
  const nonceBytes = new Uint8Array(12);
  globalThis.crypto.getRandomValues(nonceBytes);
  const nonce = params.forcedNonce || toHex(nonceBytes);
  const timestamp = new Date().toISOString();

  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(iv);
  const aadBytes = new TextEncoder().encode(
    canonicalizeJsonWeb({
      clientId: params.clientId,
      modelVersion: params.modelVersion,
      nonce,
      round: params.round,
    }),
  );

  const aesKey = await getSessionAesKey();
  const ctAndTagBuffer = await subtle.encrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv), additionalData: toArrayBuffer(aadBytes), tagLength: 128 },
    aesKey,
    toArrayBuffer(new TextEncoder().encode(canonicalPayload)),
  );
  const ctAndTag = new Uint8Array(ctAndTagBuffer);
  const ciphertext = ctAndTag.slice(0, ctAndTag.length - 16);
  const authTag = ctAndTag.slice(ctAndTag.length - 16);

  const metadataBytes = new TextEncoder().encode(
    canonicalizeJsonWeb({
      clientId: params.clientId,
      modelVersion: params.modelVersion,
      nonce,
      payloadSha256,
      round: params.round,
      sampleCount: params.sampleCount,
      timestamp,
    }),
  );

  const signAlg =
    params.keyMaterial.algorithm === 'Ed25519'
      ? 'Ed25519'
      : ({ name: 'ECDSA', hash: 'SHA-256' } as const);
  const sigBuffer = await subtle.sign(
    signAlg,
    params.keyMaterial.privateKey,
    toArrayBuffer(metadataBytes),
  );

  return {
    clientId: params.clientId,
    round: params.round,
    modelVersion: params.modelVersion,
    sampleCount: params.sampleCount,
    nonce,
    timestamp,
    payloadSha256,
    signatureBase64: toBase64(new Uint8Array(sigBuffer)),
    ivBase64: toBase64(iv),
    authTagBase64: toBase64(authTag),
    ciphertextBase64: toBase64(ciphertext),
  };
}

export async function verifyAndDecryptEnvelopeWeb<T = unknown>(params: {
  envelope: FederatedEnvelope;
  keyMaterial: WebClientKeyMaterial | null;
  clientActive: boolean;
  keyRevoked: boolean;
  replayGuard: WebReplayGuard;
}): Promise<{
  ok: boolean;
  code?: 'UNAUTHORIZED_CLIENT' | 'REPLAY_DETECTED' | 'SIGNATURE_INVALID' | 'DECRYPTION_FAILED' | 'INTEGRITY_MISMATCH';
  reason?: string;
  signatureVerified: boolean;
  decryptionVerified: boolean;
  integrityVerified: boolean;
  payload?: T;
}> {
  const { envelope, keyMaterial, clientActive, keyRevoked, replayGuard } = params;

  if (!clientActive || keyRevoked || !keyMaterial) {
    return {
      ok: false,
      code: 'UNAUTHORIZED_CLIENT',
      reason: !keyMaterial
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

  const subtle = getSubtle();
  const metadataBytes = new TextEncoder().encode(
    canonicalizeJsonWeb({
      clientId: envelope.clientId,
      modelVersion: envelope.modelVersion,
      nonce: envelope.nonce,
      payloadSha256: envelope.payloadSha256,
      round: envelope.round,
      sampleCount: envelope.sampleCount,
      timestamp: envelope.timestamp,
    }),
  );

  let signatureVerified = false;
  try {
    const verifyAlg =
      keyMaterial.algorithm === 'Ed25519'
        ? 'Ed25519'
        : ({ name: 'ECDSA', hash: 'SHA-256' } as const);
    signatureVerified = await subtle.verify(
      verifyAlg,
      keyMaterial.publicKey,
      toArrayBuffer(fromBase64(envelope.signatureBase64)),
      toArrayBuffer(metadataBytes),
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

  let plaintext = '';
  try {
    const aesKey = await getSessionAesKey();
    const iv = fromBase64(envelope.ivBase64);
    const authTag = fromBase64(envelope.authTagBase64);
    const ciphertext = fromBase64(envelope.ciphertextBase64);
    const combined = new Uint8Array(ciphertext.length + authTag.length);
    combined.set(ciphertext, 0);
    combined.set(authTag, ciphertext.length);

    const aadBytes = new TextEncoder().encode(
      canonicalizeJsonWeb({
        clientId: envelope.clientId,
        modelVersion: envelope.modelVersion,
        nonce: envelope.nonce,
        round: envelope.round,
      }),
    );

    const ptBuf = await subtle.decrypt(
      { name: 'AES-GCM', iv: toArrayBuffer(iv), additionalData: toArrayBuffer(aadBytes), tagLength: 128 },
      aesKey,
      toArrayBuffer(combined),
    );
    plaintext = new TextDecoder().decode(ptBuf);
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

  const computedHash = await sha256HexWeb(plaintext);
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
  return {
    ok: true,
    signatureVerified: true,
    decryptionVerified: true,
    integrityVerified: true,
    payload: JSON.parse(plaintext) as T,
  };
}
