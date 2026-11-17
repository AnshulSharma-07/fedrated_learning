// server.ts
import "dotenv/config";
import express from "express";
import fs3 from "node:fs";
import path3 from "node:path";
import crypto2 from "node:crypto";

// src/engine/crypto.ts
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
function resolveKeyDir() {
  const dir = process.env.FL_IDS_KEY_DIR || path.resolve(process.cwd(), ".local_keys");
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 448 });
  }
  return dir;
}
function getJwtSecret() {
  return process.env.FL_IDS_JWT_SECRET || "fl-ids-local-dev-jwt-secret-change-in-prod-2026";
}
function getMasterAesKey() {
  const raw = process.env.FL_IDS_PAYLOAD_MASTER_KEY || "fl-ids-local-dev-aes-master-key-change-prod";
  return crypto.createHash("sha256").update(raw, "utf8").digest();
}
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derived = crypto.scryptSync(password, salt, 64).toString("hex");
  return `scrypt:${salt}:${derived}`;
}
function verifyPassword(password, storedHash) {
  const parts = storedHash.split(":");
  if (parts.length !== 3 || parts[0] !== "scrypt") {
    return false;
  }
  const [, salt, expectedHex] = parts;
  const derived = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(expectedHex, "hex");
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}
function base64UrlEncode(input) {
  return Buffer.from(input).toString("base64url");
}
function base64UrlDecode(input) {
  return Buffer.from(input, "base64url").toString("utf8");
}
function signJwt(payload, ttlSeconds = 86400) {
  const now = Math.floor(Date.now() / 1e3);
  const fullPayload = {
    ...payload,
    iat: now,
    exp: now + ttlSeconds
  };
  const header = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = base64UrlEncode(JSON.stringify(fullPayload));
  const data = `${header}.${body}`;
  const sig = crypto.createHmac("sha256", getJwtSecret()).update(data).digest("base64url");
  return `${data}.${sig}`;
}
function verifyJwt(token) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [header, body, sig] = parts;
    const expectedSig = crypto.createHmac("sha256", getJwtSecret()).update(`${header}.${body}`).digest("base64url");
    const a = Buffer.from(sig);
    const b = Buffer.from(expectedSig);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return null;
    }
    const parsed = JSON.parse(base64UrlDecode(body));
    if (parsed.exp < Math.floor(Date.now() / 1e3)) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}
function canonicalizeJson(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalizeJson).join(",")}]`;
  }
  const obj = value;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalizeJson(obj[k])}`).join(",")}}`;
}
function sha256Hex(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}
function generateAndStoreEd25519KeyPair(clientId, persistPrivateKey = true) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });
  const fingerprint = sha256Hex(publicKey).slice(0, 32);
  const keyId = `ed25519-${fingerprint.slice(0, 12)}`;
  let privateKeyPath = "";
  if (persistPrivateKey) {
    const keyDir = resolveKeyDir();
    privateKeyPath = path.join(keyDir, `${clientId.replace(/[^a-zA-Z0-9_-]/g, "_")}.key.pem`);
    fs.writeFileSync(privateKeyPath, privateKey, { mode: 384 });
  }
  return {
    keyId,
    publicKeyPem: publicKey,
    privateKeyPem: privateKey,
    fingerprint,
    privateKeyPath
  };
}
function loadClientPrivateKey(clientId) {
  const keyDir = resolveKeyDir();
  const privateKeyPath = path.join(keyDir, `${clientId.replace(/[^a-zA-Z0-9_-]/g, "_")}.key.pem`);
  if (!fs.existsSync(privateKeyPath)) return null;
  return fs.readFileSync(privateKeyPath, "utf8");
}
function buildSignedEncryptedEnvelope(params) {
  const canonicalPayload = canonicalizeJson(params.payload);
  const payloadSha256 = sha256Hex(canonicalPayload);
  const nonce = params.forcedNonce || crypto.randomBytes(12).toString("hex");
  const timestamp = (/* @__PURE__ */ new Date()).toISOString();
  const aesKey = params.sharedAesKey || getMasterAesKey();
  const iv = crypto.randomBytes(12);
  const aad = Buffer.from(
    canonicalizeJson({
      clientId: params.clientId,
      modelVersion: params.modelVersion,
      nonce,
      round: params.round
    }),
    "utf8"
  );
  const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
  cipher.setAAD(aad);
  const encrypted = Buffer.concat([cipher.update(canonicalPayload, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const metadataToSign = canonicalizeJson({
    clientId: params.clientId,
    modelVersion: params.modelVersion,
    nonce,
    payloadSha256,
    round: params.round,
    sampleCount: params.sampleCount,
    timestamp
  });
  const signature = crypto.sign(null, Buffer.from(metadataToSign, "utf8"), params.privateKeyPem);
  return {
    clientId: params.clientId,
    round: params.round,
    modelVersion: params.modelVersion,
    sampleCount: params.sampleCount,
    nonce,
    timestamp,
    payloadSha256,
    signatureBase64: signature.toString("base64"),
    ivBase64: iv.toString("base64"),
    authTagBase64: authTag.toString("base64"),
    ciphertextBase64: encrypted.toString("base64")
  };
}
var ReplayGuard = class {
  constructor(initialNonces = []) {
    this.seenNonces = /* @__PURE__ */ new Set();
    for (const n of initialNonces) {
      this.seenNonces.add(n);
    }
  }
  has(clientId, nonce) {
    return this.seenNonces.has(`${clientId}:${nonce}`);
  }
  mark(clientId, nonce) {
    this.seenNonces.add(`${clientId}:${nonce}`);
  }
};
function verifyAndDecryptEnvelope(params) {
  const { envelope, publicKeyPem, clientActive, keyRevoked, replayGuard: replayGuard2 } = params;
  if (!clientActive || keyRevoked || !publicKeyPem) {
    return {
      ok: false,
      code: "UNAUTHORIZED_CLIENT",
      reason: !publicKeyPem ? "Client public key is not registered" : keyRevoked ? "Client Ed25519 key has been revoked" : "Client is inactive or deauthorized",
      signatureVerified: false,
      decryptionVerified: false,
      integrityVerified: false
    };
  }
  if (replayGuard2.has(envelope.clientId, envelope.nonce)) {
    return {
      ok: false,
      code: "REPLAY_DETECTED",
      reason: `Replay detected: nonce ${envelope.nonce} was already processed for ${envelope.clientId}`,
      signatureVerified: false,
      decryptionVerified: false,
      integrityVerified: false
    };
  }
  const metadataToVerify = canonicalizeJson({
    clientId: envelope.clientId,
    modelVersion: envelope.modelVersion,
    nonce: envelope.nonce,
    payloadSha256: envelope.payloadSha256,
    round: envelope.round,
    sampleCount: envelope.sampleCount,
    timestamp: envelope.timestamp
  });
  let signatureVerified = false;
  try {
    signatureVerified = crypto.verify(
      null,
      Buffer.from(metadataToVerify, "utf8"),
      publicKeyPem,
      Buffer.from(envelope.signatureBase64, "base64")
    );
  } catch {
    signatureVerified = false;
  }
  if (!signatureVerified) {
    return {
      ok: false,
      code: "SIGNATURE_INVALID",
      reason: "Ed25519 digital signature verification failed",
      signatureVerified: false,
      decryptionVerified: false,
      integrityVerified: false
    };
  }
  let plaintext = "";
  try {
    const aesKey = params.sharedAesKey || getMasterAesKey();
    const iv = Buffer.from(envelope.ivBase64, "base64");
    const authTag = Buffer.from(envelope.authTagBase64, "base64");
    const ciphertext = Buffer.from(envelope.ciphertextBase64, "base64");
    const aad = Buffer.from(
      canonicalizeJson({
        clientId: envelope.clientId,
        modelVersion: envelope.modelVersion,
        nonce: envelope.nonce,
        round: envelope.round
      }),
      "utf8"
    );
    const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(authTag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  } catch {
    return {
      ok: false,
      code: "DECRYPTION_FAILED",
      reason: "AES-256-GCM decryption or authentication tag verification failed",
      signatureVerified: true,
      decryptionVerified: false,
      integrityVerified: false
    };
  }
  const computedHash = sha256Hex(plaintext);
  if (computedHash !== envelope.payloadSha256) {
    return {
      ok: false,
      code: "INTEGRITY_MISMATCH",
      reason: `SHA-256 payload mismatch: expected ${envelope.payloadSha256.slice(0, 12)}, got ${computedHash.slice(0, 12)}`,
      signatureVerified: true,
      decryptionVerified: true,
      integrityVerified: false
    };
  }
  replayGuard2.mark(envelope.clientId, envelope.nonce);
  const parsed = JSON.parse(plaintext);
  return {
    ok: true,
    signatureVerified: true,
    decryptionVerified: true,
    integrityVerified: true,
    payload: parsed
  };
}

// src/engine/dataset.ts
var CORE_FEATURES = [
  "flow_duration",
  "total_fwd_packets",
  "total_bwd_packets",
  "fwd_packet_length_mean",
  "bwd_packet_length_mean",
  "flow_bytes_per_sec",
  "flow_packets_per_sec",
  "syn_flag_count",
  "ack_flag_count",
  "rst_flag_count",
  "psh_flag_count",
  "iat_mean",
  "init_win_bytes_fwd",
  "subflow_fwd_bytes"
];
var ATTACK_CATEGORIES = [
  "Benign",
  "DoS/DDoS",
  "PortScan",
  "BruteForce",
  "Botnet",
  "WebAttack"
];
var LEAKAGE_COLUMN_PATTERNS = [
  "flow id",
  "flow_id",
  "source ip",
  "src ip",
  "source_ip",
  "src_ip",
  "srcip",
  "destination ip",
  "dst ip",
  "destination_ip",
  "dst_ip",
  "dstip",
  "timestamp",
  "source port",
  "src port",
  "src_port",
  "sport",
  "id"
];
var COLUMN_ALIASES = {
  "flow duration": "flow_duration",
  "dur": "flow_duration",
  "total fwd packets": "total_fwd_packets",
  "tot fwd pkts": "total_fwd_packets",
  "spkts": "total_fwd_packets",
  "total backward packets": "total_bwd_packets",
  "tot bwd pkts": "total_bwd_packets",
  "dpkts": "total_bwd_packets",
  "fwd packet length mean": "fwd_packet_length_mean",
  "fwd pkt len mean": "fwd_packet_length_mean",
  "smean": "fwd_packet_length_mean",
  "bwd packet length mean": "bwd_packet_length_mean",
  "bwd pkt len mean": "bwd_packet_length_mean",
  "dmean": "bwd_packet_length_mean",
  "flow bytes/s": "flow_bytes_per_sec",
  "flow byts/s": "flow_bytes_per_sec",
  "rate": "flow_bytes_per_sec",
  "flow packets/s": "flow_packets_per_sec",
  "flow pkts/s": "flow_packets_per_sec",
  "syn flag count": "syn_flag_count",
  "syn flag cnt": "syn_flag_count",
  "ack flag count": "ack_flag_count",
  "ack flag cnt": "ack_flag_count",
  "rst flag count": "rst_flag_count",
  "rst flag cnt": "rst_flag_count",
  "psh flag count": "psh_flag_count",
  "psh flag cnt": "psh_flag_count",
  "flow iat mean": "iat_mean",
  "iat_mean": "iat_mean",
  "sinpkt": "iat_mean",
  "init_win_bytes_forward": "init_win_bytes_fwd",
  "init fwd win byts": "init_win_bytes_fwd",
  "swin": "init_win_bytes_fwd",
  "subflow fwd bytes": "subflow_fwd_bytes",
  "sbytes": "subflow_fwd_bytes",
  "label": "label",
  "attack_cat": "label",
  "class": "label"
};
function createSeededRng(seed) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = a + 1831565813 | 0;
    let t = Math.imul(a ^ a >>> 15, 1 | a);
    t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
    return ((t ^ t >>> 14) >>> 0) / 4294967296;
  };
}
function gaussian(rng, mean, std) {
  const u1 = Math.max(1e-7, rng());
  const u2 = rng();
  const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
  return mean + z * std;
}
function normalizeAttackLabel(raw) {
  if (!raw) return "Benign";
  const s = raw.trim().toLowerCase();
  if (s === "benign" || s === "normal" || s === "0") return "Benign";
  if (s.includes("dos") || s.includes("ddos") || s.includes("hulk") || s.includes("goldeneye") || s.includes("slowloris")) {
    return "DoS/DDoS";
  }
  if (s.includes("port") || s.includes("scan") || s.includes("recon")) return "PortScan";
  if (s.includes("brute") || s.includes("patator") || s.includes("ssh") || s.includes("ftp")) return "BruteForce";
  if (s.includes("bot") || s.includes("backdoor") || s.includes("c2")) return "Botnet";
  if (s.includes("web") || s.includes("xss") || s.includes("sql")) return "WebAttack";
  if (s === "1" || s === "malicious" || s === "attack") return "DoS/DDoS";
  return "Botnet";
}
function generateSyntheticCicIdsDataset(totalRows = 1200, seed = 42) {
  const rng = createSeededRng(seed);
  const categoryWeights = [
    { category: "Benign", share: 0.62 },
    { category: "DoS/DDoS", share: 0.14 },
    { category: "PortScan", share: 0.09 },
    { category: "BruteForce", share: 0.06 },
    { category: "Botnet", share: 0.05 },
    { category: "WebAttack", share: 0.04 }
  ];
  const records = [];
  const baseTime = Date.UTC(2026, 10, 17, 8, 0, 0);
  for (let i = 0; i < totalRows; i++) {
    const pick = rng();
    let acc = 0;
    let category = "Benign";
    for (const item of categoryWeights) {
      acc += item.share;
      if (pick <= acc) {
        category = item.category;
        break;
      }
    }
    const pos = (v, min = 0) => Math.max(min, Math.round(v * 100) / 100);
    let rec;
    if (category === "Benign") {
      const dur = pos(gaussian(rng, 245e3, 12e4), 1200);
      const fwd = Math.max(1, Math.round(gaussian(rng, 9, 4)));
      const bwd = Math.max(1, Math.round(gaussian(rng, 8, 4)));
      const fLen = pos(gaussian(rng, 165, 55), 40);
      const bLen = pos(gaussian(rng, 420, 140), 40);
      rec = {
        flow_duration: dur,
        total_fwd_packets: fwd,
        total_bwd_packets: bwd,
        fwd_packet_length_mean: fLen,
        bwd_packet_length_mean: bLen,
        flow_bytes_per_sec: pos((fwd * fLen + bwd * bLen) / (dur / 1e6) + gaussian(rng, 0, 180), 120),
        flow_packets_per_sec: pos((fwd + bwd) / (dur / 1e6) + gaussian(rng, 0, 4), 2),
        syn_flag_count: rng() < 0.85 ? 1 : 0,
        ack_flag_count: Math.max(1, Math.round(gaussian(rng, 7, 2))),
        rst_flag_count: rng() < 0.06 ? 1 : 0,
        psh_flag_count: Math.max(0, Math.round(gaussian(rng, 2, 1))),
        iat_mean: pos(dur / Math.max(1, fwd + bwd) + gaussian(rng, 2500, 1200), 400),
        init_win_bytes_fwd: rng() < 0.7 ? 29200 : 8192,
        subflow_fwd_bytes: pos(fwd * fLen + gaussian(rng, 20, 15), 40),
        label: "Benign"
      };
    } else if (category === "DoS/DDoS") {
      const dur = pos(gaussian(rng, 18500, 9500), 250);
      const fwd = Math.max(12, Math.round(gaussian(rng, 68, 22)));
      const bwd = Math.max(0, Math.round(gaussian(rng, 2, 2)));
      const fLen = pos(gaussian(rng, 48, 18), 20);
      const bLen = pos(gaussian(rng, 12, 14), 0);
      rec = {
        flow_duration: dur,
        total_fwd_packets: fwd,
        total_bwd_packets: bwd,
        fwd_packet_length_mean: fLen,
        bwd_packet_length_mean: bLen,
        flow_bytes_per_sec: pos(gaussian(rng, 185e3, 48e3), 25e3),
        flow_packets_per_sec: pos(gaussian(rng, 3900, 950), 600),
        syn_flag_count: Math.max(1, Math.round(gaussian(rng, 6, 2))),
        ack_flag_count: Math.max(0, Math.round(gaussian(rng, 1, 1))),
        rst_flag_count: Math.max(0, Math.round(gaussian(rng, 2, 1))),
        psh_flag_count: 0,
        iat_mean: pos(gaussian(rng, 290, 120), 20),
        init_win_bytes_fwd: 512,
        subflow_fwd_bytes: pos(fwd * fLen, 200),
        label: "DoS/DDoS"
      };
    } else if (category === "PortScan") {
      const dur = pos(gaussian(rng, 1850, 850), 80);
      const fwd = Math.max(1, Math.round(gaussian(rng, 2, 1)));
      const bwd = Math.max(0, Math.round(gaussian(rng, 1, 1)));
      const fLen = pos(gaussian(rng, 42, 8), 20);
      rec = {
        flow_duration: dur,
        total_fwd_packets: fwd,
        total_bwd_packets: bwd,
        fwd_packet_length_mean: fLen,
        bwd_packet_length_mean: pos(gaussian(rng, 28, 12), 0),
        flow_bytes_per_sec: pos(gaussian(rng, 44e3, 14e3), 4e3),
        flow_packets_per_sec: pos(gaussian(rng, 1350, 380), 250),
        syn_flag_count: 1,
        ack_flag_count: 0,
        rst_flag_count: Math.max(1, Math.round(gaussian(rng, 1.4, 0.5))),
        psh_flag_count: 0,
        iat_mean: pos(gaussian(rng, 620, 220), 40),
        init_win_bytes_fwd: 1024,
        subflow_fwd_bytes: pos(fwd * fLen, 28),
        label: "PortScan"
      };
    } else if (category === "BruteForce") {
      const dur = pos(gaussian(rng, 42e4, 95e3), 6e4);
      const fwd = Math.max(10, Math.round(gaussian(rng, 24, 6)));
      const bwd = Math.max(8, Math.round(gaussian(rng, 22, 6)));
      const fLen = pos(gaussian(rng, 118, 22), 60);
      const bLen = pos(gaussian(rng, 145, 28), 60);
      rec = {
        flow_duration: dur,
        total_fwd_packets: fwd,
        total_bwd_packets: bwd,
        fwd_packet_length_mean: fLen,
        bwd_packet_length_mean: bLen,
        flow_bytes_per_sec: pos(gaussian(rng, 14500, 4200), 2e3),
        flow_packets_per_sec: pos(gaussian(rng, 115, 32), 20),
        syn_flag_count: 1,
        ack_flag_count: Math.max(10, Math.round(gaussian(rng, 20, 5))),
        rst_flag_count: rng() < 0.65 ? 1 : 0,
        psh_flag_count: Math.max(6, Math.round(gaussian(rng, 12, 3))),
        iat_mean: pos(gaussian(rng, 9500, 2800), 1200),
        init_win_bytes_fwd: 29200,
        subflow_fwd_bytes: pos(fwd * fLen, 800),
        label: "BruteForce"
      };
    } else if (category === "Botnet") {
      const dur = pos(gaussian(rng, 92e4, 24e4), 15e4);
      const fwd = Math.max(5, Math.round(gaussian(rng, 14, 4)));
      const bwd = Math.max(5, Math.round(gaussian(rng, 14, 4)));
      const fLen = pos(gaussian(rng, 78, 16), 36);
      const bLen = pos(gaussian(rng, 92, 18), 36);
      rec = {
        flow_duration: dur,
        total_fwd_packets: fwd,
        total_bwd_packets: bwd,
        fwd_packet_length_mean: fLen,
        bwd_packet_length_mean: bLen,
        flow_bytes_per_sec: pos(gaussian(rng, 2600, 900), 300),
        flow_packets_per_sec: pos(gaussian(rng, 32, 10), 6),
        syn_flag_count: 1,
        ack_flag_count: Math.max(6, Math.round(gaussian(rng, 13, 3))),
        rst_flag_count: 0,
        psh_flag_count: Math.max(5, Math.round(gaussian(rng, 9, 2))),
        iat_mean: pos(gaussian(rng, 36e3, 8500), 5e3),
        init_win_bytes_fwd: 65535,
        subflow_fwd_bytes: pos(fwd * fLen, 300),
        label: "Botnet"
      };
    } else {
      const dur = pos(gaussian(rng, 31e4, 85e3), 35e3);
      const fwd = Math.max(8, Math.round(gaussian(rng, 18, 5)));
      const bwd = Math.max(6, Math.round(gaussian(rng, 14, 4)));
      const fLen = pos(gaussian(rng, 520, 110), 220);
      const bLen = pos(gaussian(rng, 680, 140), 180);
      rec = {
        flow_duration: dur,
        total_fwd_packets: fwd,
        total_bwd_packets: bwd,
        fwd_packet_length_mean: fLen,
        bwd_packet_length_mean: bLen,
        flow_bytes_per_sec: pos(gaussian(rng, 62e3, 18e3), 12e3),
        flow_packets_per_sec: pos(gaussian(rng, 110, 35), 25),
        syn_flag_count: 1,
        ack_flag_count: Math.max(8, Math.round(gaussian(rng, 16, 4))),
        rst_flag_count: 0,
        psh_flag_count: Math.max(4, Math.round(gaussian(rng, 7, 2))),
        iat_mean: pos(gaussian(rng, 9800, 3100), 1500),
        init_win_bytes_fwd: 64240,
        subflow_fwd_bytes: pos(fwd * fLen, 2200),
        label: "WebAttack"
      };
    }
    rec.timestamp = new Date(baseTime + i * 1200).toISOString();
    records.push(rec);
  }
  return records;
}
function parseCsvLine(line) {
  const result = [];
  let cur = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === "," && !inQuotes) {
      result.push(cur.trim());
      cur = "";
    } else {
      cur += ch;
    }
  }
  result.push(cur.trim());
  return result;
}
function parseAndCleanCsv(csvText, columnMapping, isSynthetic = false) {
  const lines = csvText.replace(/\r\n/g, "\n").split("\n").map((l) => l.trim()).filter((l) => l.length > 0);
  if (lines.length < 2) {
    throw new Error("CSV must include a header row and at least one data row");
  }
  const rawHeaders = parseCsvLine(lines[0]);
  const removedLeakageColumns = [];
  const headerToCanonical = rawHeaders.map((h) => {
    const norm = h.trim().toLowerCase();
    if (columnMapping && columnMapping[h]) {
      return columnMapping[h];
    }
    if (LEAKAGE_COLUMN_PATTERNS.includes(norm)) {
      removedLeakageColumns.push(h.trim());
      return null;
    }
    if (CORE_FEATURES.includes(norm)) {
      return norm;
    }
    if (COLUMN_ALIASES[norm]) {
      return COLUMN_ALIASES[norm];
    }
    return null;
  });
  const seenRows = /* @__PURE__ */ new Set();
  let droppedMissing = 0;
  let droppedInfinite = 0;
  let droppedDuplicates = 0;
  const records = [];
  const classDistribution = {};
  for (let i = 1; i < lines.length; i++) {
    const cells = parseCsvLine(lines[i]);
    if (cells.length !== rawHeaders.length) {
      droppedMissing++;
      continue;
    }
    const rowObj = {};
    let hasMissing = false;
    let hasInf = false;
    for (let c = 0; c < rawHeaders.length; c++) {
      const target = headerToCanonical[c];
      if (!target) continue;
      const val = cells[c];
      if (target === "label") {
        rowObj.label = val;
        continue;
      }
      if (val === "" || val.toLowerCase() === "nan" || val.toLowerCase() === "null") {
        hasMissing = true;
        break;
      }
      const num = Number(val);
      if (Number.isNaN(num)) {
        hasMissing = true;
        break;
      }
      if (!Number.isFinite(num)) {
        hasInf = true;
        break;
      }
      rowObj[target] = num;
    }
    if (hasMissing) {
      droppedMissing++;
      continue;
    }
    if (hasInf) {
      droppedInfinite++;
      continue;
    }
    const record = {
      flow_duration: Number(rowObj.flow_duration ?? 0),
      total_fwd_packets: Number(rowObj.total_fwd_packets ?? 0),
      total_bwd_packets: Number(rowObj.total_bwd_packets ?? 0),
      fwd_packet_length_mean: Number(rowObj.fwd_packet_length_mean ?? 0),
      bwd_packet_length_mean: Number(rowObj.bwd_packet_length_mean ?? 0),
      flow_bytes_per_sec: Number(rowObj.flow_bytes_per_sec ?? 0),
      flow_packets_per_sec: Number(rowObj.flow_packets_per_sec ?? 0),
      syn_flag_count: Number(rowObj.syn_flag_count ?? 0),
      ack_flag_count: Number(rowObj.ack_flag_count ?? 0),
      rst_flag_count: Number(rowObj.rst_flag_count ?? 0),
      psh_flag_count: Number(rowObj.psh_flag_count ?? 0),
      iat_mean: Number(rowObj.iat_mean ?? 0),
      init_win_bytes_fwd: Number(rowObj.init_win_bytes_fwd ?? 0),
      subflow_fwd_bytes: Number(rowObj.subflow_fwd_bytes ?? 0),
      label: rowObj.label !== void 0 ? normalizeAttackLabel(String(rowObj.label)) : void 0
    };
    const sig = CORE_FEATURES.map((f) => record[f]).join("|") + "|" + (record.label ?? "");
    if (seenRows.has(sig)) {
      droppedDuplicates++;
      continue;
    }
    seenRows.add(sig);
    const lbl = record.label ?? "Unlabeled";
    classDistribution[lbl] = (classDistribution[lbl] || 0) + 1;
    records.push(record);
  }
  return {
    records,
    report: {
      rawRows: lines.length - 1,
      cleanRows: records.length,
      droppedMissing,
      droppedInfinite,
      droppedDuplicates,
      removedLeakageColumns,
      classDistribution,
      featureColumns: [...CORE_FEATURES],
      isSynthetic
    }
  };
}
function recordsToCsv(records) {
  const headers = [...CORE_FEATURES, "label"];
  const rows = records.map(
    (r) => [...CORE_FEATURES.map((f) => String(r[f])), r.label ?? "Benign"].join(",")
  );
  return [headers.join(","), ...rows].join("\n");
}
function extractFeatureVector(record) {
  return CORE_FEATURES.map((f) => Number(record[f] ?? 0));
}
function fitScaler(XTrain) {
  const d = CORE_FEATURES.length;
  const n = Math.max(1, XTrain.length);
  const means = new Array(d).fill(0);
  const stds = new Array(d).fill(0);
  for (const row of XTrain) {
    for (let j = 0; j < d; j++) means[j] += row[j];
  }
  for (let j = 0; j < d; j++) means[j] /= n;
  for (const row of XTrain) {
    for (let j = 0; j < d; j++) {
      const diff = row[j] - means[j];
      stds[j] += diff * diff;
    }
  }
  for (let j = 0; j < d; j++) {
    stds[j] = Math.sqrt(stds[j] / n);
    if (stds[j] < 1e-6) stds[j] = 1;
  }
  return { featureNames: [...CORE_FEATURES], means, stds };
}
function transformWithScaler(X, scaler) {
  return X.map((row) => row.map((v, j) => (v - scaler.means[j]) / scaler.stds[j]));
}
function prepareStratifiedSplit(records, mode, seed = 42) {
  const labeled = records.filter((r) => r.label !== void 0);
  if (labeled.length < 30) {
    throw new Error("At least 30 labeled records are required for stratified splitting");
  }
  const classes = mode === "binary" ? ["Benign", "Malicious"] : ATTACK_CATEGORIES.filter((cat) => labeled.some((r) => r.label === cat));
  const classToIndex = /* @__PURE__ */ new Map();
  classes.forEach((c, idx) => classToIndex.set(c, idx));
  const buckets = /* @__PURE__ */ new Map();
  for (const rec of labeled) {
    const labelStr = mode === "binary" ? rec.label === "Benign" ? "Benign" : "Malicious" : rec.label;
    const idx = classToIndex.get(labelStr);
    if (idx === void 0) continue;
    if (!buckets.has(idx)) buckets.set(idx, []);
    buckets.get(idx).push(rec);
  }
  const rng = createSeededRng(seed);
  const trainRecs = [];
  const valRecs = [];
  const testRecs = [];
  for (const [clsIdx, list] of buckets.entries()) {
    const shuffled = [...list];
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    const nTrain = Math.max(1, Math.floor(shuffled.length * 0.7));
    const nVal = Math.max(1, Math.floor(shuffled.length * 0.15));
    for (let i = 0; i < shuffled.length; i++) {
      const item = { x: extractFeatureVector(shuffled[i]), y: clsIdx };
      if (i < nTrain) trainRecs.push(item);
      else if (i < nTrain + nVal) valRecs.push(item);
      else testRecs.push(item);
    }
  }
  const shufflePairs = (arr) => {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
  };
  shufflePairs(trainRecs);
  shufflePairs(valRecs);
  shufflePairs(testRecs);
  const rawXTrain = trainRecs.map((r) => r.x);
  const scaler = fitScaler(rawXTrain);
  const yTrain = trainRecs.map((r) => r.y);
  const counts = {};
  for (const y of yTrain) counts[y] = (counts[y] || 0) + 1;
  const maxCount = Math.max(...Object.values(counts));
  const minCount = Math.max(1, Math.min(...Object.values(counts)));
  const classWeights = {};
  for (let c = 0; c < classes.length; c++) {
    const cnt = Math.max(1, counts[c] || 1);
    classWeights[c] = Math.min(4, yTrain.length / (classes.length * cnt));
  }
  return {
    XTrain: transformWithScaler(rawXTrain, scaler),
    yTrain,
    XVal: transformWithScaler(valRecs.map((r) => r.x), scaler),
    yVal: valRecs.map((r) => r.y),
    XTest: transformWithScaler(testRecs.map((r) => r.x), scaler),
    yTest: testRecs.map((r) => r.y),
    classes,
    scaler,
    classWeights,
    imbalanceRatio: Number((maxCount / minCount).toFixed(2))
  };
}
function partitionNonIid(XTrain, yTrain, classes, clientIds, alpha = 0.5, seed = 42) {
  const rng = createSeededRng(seed);
  const numClients = clientIds.length;
  const partitions = clientIds.map((clientId) => ({
    clientId,
    X: [],
    y: [],
    classCounts: {}
  }));
  const byClass = classes.map(() => []);
  for (let i = 0; i < yTrain.length; i++) {
    byClass[yTrain[i]].push(i);
  }
  const sampleGamma = (shape) => {
    const s = Math.max(0.15, shape);
    let sum = 0;
    const k = Math.max(1, Math.round(s * 2));
    for (let i = 0; i < k; i++) {
      sum -= Math.log(Math.max(1e-7, rng()));
    }
    return sum * (s / k);
  };
  for (let c = 0; c < classes.length; c++) {
    const indices = [...byClass[c]];
    for (let i = indices.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      [indices[i], indices[j]] = [indices[j], indices[i]];
    }
    const rawProps = clientIds.map((_, idx) => {
      const affinityBoost = (c + idx) % numClients === 0 ? 2.5 : 1;
      return Math.pow(sampleGamma(alpha), 1 / Math.max(0.2, alpha)) * affinityBoost;
    });
    const propSum = rawProps.reduce((a, b) => a + b, 0) || 1;
    const normalized = rawProps.map((p) => p / propSum);
    let cursor = 0;
    for (let k = 0; k < numClients; k++) {
      const count = k === numClients - 1 ? indices.length - cursor : Math.max(1, Math.floor(indices.length * normalized[k]));
      const slice = indices.slice(cursor, Math.min(indices.length, cursor + count));
      cursor += slice.length;
      const clsName = classes[c];
      for (const idx of slice) {
        partitions[k].X.push(XTrain[idx]);
        partitions[k].y.push(yTrain[idx]);
        partitions[k].classCounts[clsName] = (partitions[k].classCounts[clsName] || 0) + 1;
      }
    }
  }
  return partitions;
}

// src/engine/db.ts
import fs2 from "node:fs";
import path2 from "node:path";
import { DatabaseSync } from "node:sqlite";

// src/engine/ml.ts
function softmax(logits) {
  const max = Math.max(...logits);
  const exps = logits.map((v) => Math.exp(Math.min(50, v - max)));
  const sum = exps.reduce((a, b) => a + b, 0) || 1;
  return exps.map((e) => e / sum);
}
function computeRocAucBinary(yTrue, yScore) {
  const positives = yTrue.filter((y) => y === 1).length;
  const negatives = yTrue.length - positives;
  if (positives === 0 || negatives === 0) return null;
  const pairs = yTrue.map((y, i) => ({ y, s: yScore[i] })).sort((a, b) => b.s - a.s);
  let tp = 0;
  let fp = 0;
  let prevTp = 0;
  let prevFp = 0;
  let auc = 0;
  for (let i = 0; i < pairs.length; i++) {
    if (pairs[i].y === 1) tp++;
    else fp++;
    if (i === pairs.length - 1 || pairs[i + 1].s !== pairs[i].s) {
      auc += (fp - prevFp) * (tp + prevTp) / 2;
      prevTp = tp;
      prevFp = fp;
    }
  }
  return Number((auc / (positives * negatives)).toFixed(4));
}
function evaluatePredictions(params) {
  const { yTrue, probs, classes } = params;
  const k = classes.length;
  const matrix = Array.from({ length: k }, () => new Array(k).fill(0));
  const yPred = probs.map((p) => {
    let best = 0;
    for (let i = 1; i < p.length; i++) {
      if (p[i] > p[best]) best = i;
    }
    return best;
  });
  let correct = 0;
  for (let i = 0; i < yTrue.length; i++) {
    const t = yTrue[i];
    const p = yPred[i];
    if (t >= 0 && t < k && p >= 0 && p < k) {
      matrix[t][p]++;
      if (t === p) correct++;
    }
  }
  const perClass = [];
  let totalSupport = 0;
  let weightedPrecision = 0;
  let weightedRecall = 0;
  let weightedF1 = 0;
  for (let c = 0; c < k; c++) {
    const tp = matrix[c][c];
    let fp = 0;
    let fn = 0;
    let support = 0;
    for (let r = 0; r < k; r++) {
      support += matrix[c][r];
      if (r !== c) {
        fp += matrix[r][c];
        fn += matrix[c][r];
      }
    }
    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    const f1Score = precision + recall > 0 ? 2 * precision * recall / (precision + recall) : 0;
    perClass.push({
      label: classes[c],
      precision: Number(precision.toFixed(4)),
      recall: Number(recall.toFixed(4)),
      f1Score: Number(f1Score.toFixed(4)),
      support
    });
    totalSupport += support;
    weightedPrecision += precision * support;
    weightedRecall += recall * support;
    weightedF1 += f1Score * support;
  }
  const benignIdx = Math.max(0, classes.findIndex((c) => c.toLowerCase() === "benign"));
  let tn = 0;
  let fpTotal = 0;
  for (let r = 0; r < k; r++) {
    if (r === benignIdx) {
      tn += matrix[benignIdx][benignIdx];
      for (let c = 0; c < k; c++) {
        if (c !== benignIdx) fpTotal += matrix[benignIdx][c];
      }
    }
  }
  const falsePositiveRate = fpTotal + tn > 0 ? fpTotal / (fpTotal + tn) : 0;
  const binaryTrue = yTrue.map((y) => y === benignIdx ? 0 : 1);
  const attackScores = probs.map((p) => 1 - (p[benignIdx] ?? 0));
  const rocAuc = computeRocAucBinary(binaryTrue, attackScores);
  const accuracy = yTrue.length > 0 ? correct / yTrue.length : 0;
  return {
    accuracy: Number(accuracy.toFixed(4)),
    precision: Number((totalSupport > 0 ? weightedPrecision / totalSupport : 0).toFixed(4)),
    recall: Number((totalSupport > 0 ? weightedRecall / totalSupport : 0).toFixed(4)),
    f1Score: Number((totalSupport > 0 ? weightedF1 / totalSupport : 0).toFixed(4)),
    falsePositiveRate: Number(falsePositiveRate.toFixed(4)),
    rocAuc,
    loss: params.loss !== void 0 ? Number(params.loss.toFixed(4)) : void 0,
    confusionMatrix: { labels: classes, matrix },
    perClass,
    sampleCount: yTrue.length,
    trainingTimeMs: params.trainingTimeMs ?? 0,
    communicationBytes: params.communicationBytes ?? 0
  };
}
function trainLogisticRegression(params) {
  const { XTrain, yTrain, classes, mode, scaler, classWeights, epochs = 140, lr = 0.15, l2 = 1e-3 } = params;
  const n = XTrain.length;
  const d = XTrain[0].length;
  const k = classes.length;
  const weights = Array.from({ length: k }, () => new Array(d).fill(0));
  const biases = new Array(k).fill(0);
  for (let epoch = 0; epoch < epochs; epoch++) {
    const gradW = Array.from({ length: k }, () => new Array(d).fill(0));
    const gradB = new Array(k).fill(0);
    let weightSum = 0;
    for (let i = 0; i < n; i++) {
      const x = XTrain[i];
      const y = yTrain[i];
      const cw = classWeights[y] ?? 1;
      weightSum += cw;
      const logits = new Array(k);
      for (let c = 0; c < k; c++) {
        let z = biases[c];
        for (let j = 0; j < d; j++) z += weights[c][j] * x[j];
        logits[c] = z;
      }
      const p = softmax(logits);
      for (let c = 0; c < k; c++) {
        const err = (p[c] - (c === y ? 1 : 0)) * cw;
        gradB[c] += err;
        for (let j = 0; j < d; j++) {
          gradW[c][j] += err * x[j];
        }
      }
    }
    const norm = Math.max(1, weightSum);
    for (let c = 0; c < k; c++) {
      biases[c] -= lr * (gradB[c] / norm);
      for (let j = 0; j < d; j++) {
        weights[c][j] -= lr * (gradW[c][j] / norm + l2 * weights[c][j]);
      }
    }
  }
  return { kind: "logistic_regression", weights, biases, classes, mode, scaler };
}
function predictLogisticRegressionProbs(model, XScaled) {
  const k = model.classes.length;
  return XScaled.map((x) => {
    const logits = new Array(k);
    for (let c = 0; c < k; c++) {
      let z = model.biases[c];
      for (let j = 0; j < x.length; j++) z += model.weights[c][j] * x[j];
      logits[c] = z;
    }
    return softmax(logits);
  });
}
function giniFromCounts(counts, total) {
  if (total === 0) return 0;
  let sumSq = 0;
  for (let i = 0; i < counts.length; i++) {
    const p = counts[i] / total;
    sumSq += p * p;
  }
  return 1 - sumSq;
}
function buildCartTree(X, y, indices, numClasses, depth, maxDepth, minSamplesSplit, mtry, rng, importances) {
  const counts = new Array(numClasses).fill(0);
  for (const idx of indices) counts[y[idx]]++;
  const n = indices.length;
  const probs = counts.map((c) => c / Math.max(1, n));
  const parentGini = giniFromCounts(counts, n);
  if (depth >= maxDepth || n < minSamplesSplit || parentGini < 1e-6) {
    return { classProbs: probs };
  }
  const d = X[0].length;
  const featIndices = Array.from({ length: d }, (_, i) => i);
  for (let i = featIndices.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [featIndices[i], featIndices[j]] = [featIndices[j], featIndices[i]];
  }
  const candidateFeatures = featIndices.slice(0, mtry);
  let bestGain = 0;
  let bestFeature = -1;
  let bestThreshold = 0;
  for (const feat of candidateFeatures) {
    const sorted = [...indices].sort((a, b) => X[a][feat] - X[b][feat]);
    const step = Math.max(1, Math.floor(sorted.length / 16));
    const leftCounts = new Array(numClasses).fill(0);
    let leftTotal = 0;
    let prevPos = 0;
    for (let pos = 0; pos < sorted.length - 1; pos++) {
      const idx = sorted[pos];
      leftCounts[y[idx]]++;
      leftTotal++;
      if (pos - prevPos < step && pos < sorted.length - 2 || X[sorted[pos]][feat] === X[sorted[pos + 1]][feat]) {
        continue;
      }
      prevPos = pos;
      const rightTotal = n - leftTotal;
      if (leftTotal === 0 || rightTotal === 0) continue;
      const rightCounts = counts.map((c, ci) => c - leftCounts[ci]);
      const gLeft = giniFromCounts(leftCounts, leftTotal);
      const gRight = giniFromCounts(rightCounts, rightTotal);
      const weightedGini = leftTotal / n * gLeft + rightTotal / n * gRight;
      const gain = parentGini - weightedGini;
      if (gain > bestGain) {
        bestGain = gain;
        bestFeature = feat;
        bestThreshold = (X[sorted[pos]][feat] + X[sorted[pos + 1]][feat]) / 2;
      }
    }
  }
  if (bestFeature === -1 || bestGain <= 1e-6) {
    return { classProbs: probs };
  }
  importances[bestFeature] += n * bestGain;
  const leftIdx = [];
  const rightIdx = [];
  for (const idx of indices) {
    if (X[idx][bestFeature] <= bestThreshold) leftIdx.push(idx);
    else rightIdx.push(idx);
  }
  if (leftIdx.length === 0 || rightIdx.length === 0) {
    return { classProbs: probs };
  }
  return {
    featureIndex: bestFeature,
    threshold: bestThreshold,
    left: buildCartTree(X, y, leftIdx, numClasses, depth + 1, maxDepth, minSamplesSplit, mtry, rng, importances),
    right: buildCartTree(X, y, rightIdx, numClasses, depth + 1, maxDepth, minSamplesSplit, mtry, rng, importances)
  };
}
function predictTreeProbs(node, x) {
  if (node.classProbs) return node.classProbs;
  if (x[node.featureIndex] <= node.threshold) {
    return predictTreeProbs(node.left, x);
  }
  return predictTreeProbs(node.right, x);
}
function trainRandomForest(params) {
  const { XTrain, yTrain, classes, mode, scaler, numTrees = 18, maxDepth = 7, seed = 42 } = params;
  const n = XTrain.length;
  const d = XTrain[0].length;
  const mtry = Math.max(2, Math.floor(Math.sqrt(d)));
  const rng = createSeededRng(seed);
  const importances = new Array(d).fill(0);
  const trees = [];
  for (let t = 0; t < numTrees; t++) {
    const bootIdx = [];
    for (let i = 0; i < n; i++) {
      bootIdx.push(Math.floor(rng() * n));
    }
    trees.push(buildCartTree(XTrain, yTrain, bootIdx, classes.length, 0, maxDepth, 6, mtry, rng, importances));
  }
  const impSum = importances.reduce((a, b) => a + b, 0) || 1;
  const featureImportances = {};
  CORE_FEATURES.forEach((feat, idx) => {
    featureImportances[feat] = Number((importances[idx] / impSum).toFixed(4));
  });
  return { kind: "random_forest", trees, classes, mode, scaler, featureImportances };
}
function predictRandomForestProbs(model, XScaled) {
  const k = model.classes.length;
  const nTrees = model.trees.length;
  return XScaled.map((x) => {
    const avg = new Array(k).fill(0);
    for (const tree of model.trees) {
      const p = predictTreeProbs(tree, x);
      for (let c = 0; c < k; c++) avg[c] += p[c];
    }
    return avg.map((v) => v / nTrees);
  });
}
function initializeMLPWeights(inputDim, classes, mode, scaler, seed = 42) {
  const rng = createSeededRng(seed);
  const architecture = [inputDim, 32, 16, classes.length];
  const weights = [];
  const biases = [];
  for (let l = 0; l < architecture.length - 1; l++) {
    const inDim = architecture[l];
    const outDim = architecture[l + 1];
    const scale = Math.sqrt(2 / inDim);
    const layerW = [];
    for (let o = 0; o < outDim; o++) {
      const row = [];
      for (let i = 0; i < inDim; i++) {
        const u1 = Math.max(1e-7, rng());
        const u2 = rng();
        const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
        row.push(z * scale);
      }
      layerW.push(row);
    }
    weights.push(layerW);
    biases.push(new Array(outDim).fill(0));
  }
  return { architecture, weights, biases, classes, mode, scaler };
}
function cloneMLPWeights(model) {
  return {
    architecture: [...model.architecture],
    weights: model.weights.map((layer) => layer.map((row) => [...row])),
    biases: model.biases.map((b) => [...b]),
    classes: [...model.classes],
    mode: model.mode,
    scaler: {
      featureNames: [...model.scaler.featureNames],
      means: [...model.scaler.means],
      stds: [...model.scaler.stds]
    }
  };
}
function forwardSingle(model, x) {
  const activations = [x];
  const preActs = [];
  let cur = x;
  const numLayers = model.weights.length;
  for (let l = 0; l < numLayers; l++) {
    const W = model.weights[l];
    const b = model.biases[l];
    const out = new Array(W.length);
    for (let o = 0; o < W.length; o++) {
      let sum = b[o];
      const row = W[o];
      for (let i = 0; i < cur.length; i++) sum += row[i] * cur[i];
      out[o] = sum;
    }
    preActs.push(out);
    if (l < numLayers - 1) {
      cur = out.map((v) => v > 0 ? v : 0);
    } else {
      cur = softmax(out);
    }
    activations.push(cur);
  }
  return { activations, preActs };
}
function predictMLPProbs(model, XScaled) {
  return XScaled.map((x) => {
    const { activations } = forwardSingle(model, x);
    return activations[activations.length - 1];
  });
}
function computeCrossEntropyLoss(probs, yTrue, classWeights) {
  let loss = 0;
  let wSum = 0;
  for (let i = 0; i < yTrue.length; i++) {
    const y = yTrue[i];
    const w = classWeights ? classWeights[y] ?? 1 : 1;
    const p = Math.max(1e-7, probs[i][y] ?? 1e-7);
    loss -= w * Math.log(p);
    wSum += w;
  }
  return wSum > 0 ? loss / wSum : 0;
}
function trainMLPEpochs(params) {
  const {
    initialModel,
    XTrain,
    yTrain,
    classWeights,
    epochs,
    lr,
    batchSize = 32,
    l2 = 1e-4,
    dpClipNorm = null,
    dpNoiseMultiplier = null,
    seed = 42
  } = params;
  const model = cloneMLPWeights(initialModel);
  const rng = createSeededRng(seed);
  const n = XTrain.length;
  const numLayers = model.weights.length;
  const gaussianNoise = (std) => {
    const u1 = Math.max(1e-7, rng());
    const u2 = rng();
    return std * Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
  };
  for (let epoch = 0; epoch < epochs; epoch++) {
    const indices = Array.from({ length: n }, (_, i) => i);
    for (let i = indices.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      [indices[i], indices[j]] = [indices[j], indices[i]];
    }
    for (let start = 0; start < n; start += batchSize) {
      const end = Math.min(n, start + batchSize);
      const batchCount = end - start;
      const gradW = model.weights.map((W) => W.map((row) => new Array(row.length).fill(0)));
      const gradB = model.biases.map((b) => new Array(b.length).fill(0));
      for (let bIdx = start; bIdx < end; bIdx++) {
        const sampleIdx = indices[bIdx];
        const x = XTrain[sampleIdx];
        const y = yTrain[sampleIdx];
        const cw = classWeights ? classWeights[y] ?? 1 : 1;
        const { activations, preActs } = forwardSingle(model, x);
        const probs2 = activations[numLayers];
        let delta = probs2.map((p, c) => (p - (c === y ? 1 : 0)) * cw);
        const sampleGradW = model.weights.map((W) => W.map((row) => new Array(row.length).fill(0)));
        const sampleGradB = model.biases.map((b) => new Array(b.length).fill(0));
        for (let l = numLayers - 1; l >= 0; l--) {
          const prevAct = activations[l];
          for (let o = 0; o < delta.length; o++) {
            sampleGradB[l][o] = delta[o];
            for (let i = 0; i < prevAct.length; i++) {
              sampleGradW[l][o][i] = delta[o] * prevAct[i];
            }
          }
          if (l > 0) {
            const nextDelta = new Array(prevAct.length).fill(0);
            const W = model.weights[l];
            for (let i = 0; i < prevAct.length; i++) {
              let sum = 0;
              for (let o = 0; o < delta.length; o++) sum += W[o][i] * delta[o];
              nextDelta[i] = preActs[l - 1][i] > 0 ? sum : 0;
            }
            delta = nextDelta;
          }
        }
        let clipFactor = 1;
        if (dpClipNorm && dpClipNorm > 0) {
          let normSq = 0;
          for (let l = 0; l < numLayers; l++) {
            for (let o = 0; o < sampleGradB[l].length; o++) {
              normSq += sampleGradB[l][o] * sampleGradB[l][o];
              for (let i = 0; i < sampleGradW[l][o].length; i++) {
                normSq += sampleGradW[l][o][i] * sampleGradW[l][o][i];
              }
            }
          }
          const norm = Math.sqrt(normSq);
          if (norm > dpClipNorm) clipFactor = dpClipNorm / norm;
        }
        for (let l = 0; l < numLayers; l++) {
          for (let o = 0; o < gradB[l].length; o++) {
            gradB[l][o] += sampleGradB[l][o] * clipFactor;
            for (let i = 0; i < gradW[l][o].length; i++) {
              gradW[l][o][i] += sampleGradW[l][o][i] * clipFactor;
            }
          }
        }
      }
      const noiseStd = dpClipNorm && dpNoiseMultiplier && dpClipNorm > 0 && dpNoiseMultiplier > 0 ? dpClipNorm * dpNoiseMultiplier / batchCount : 0;
      for (let l = 0; l < numLayers; l++) {
        for (let o = 0; o < model.biases[l].length; o++) {
          const gB = gradB[l][o] / batchCount + (noiseStd > 0 ? gaussianNoise(noiseStd) : 0);
          model.biases[l][o] -= lr * gB;
          for (let i = 0; i < model.weights[l][o].length; i++) {
            const gW = gradW[l][o][i] / batchCount + l2 * model.weights[l][o][i] + (noiseStd > 0 ? gaussianNoise(noiseStd) : 0);
            model.weights[l][o][i] -= lr * gW;
          }
        }
      }
    }
  }
  const probs = predictMLPProbs(model, XTrain);
  const finalLoss = computeCrossEntropyLoss(probs, yTrain, classWeights);
  return { model, finalLoss: Number(finalLoss.toFixed(4)) };
}

// src/engine/federated.ts
function validateWeightPayload(payload, expected) {
  if (!payload || !Array.isArray(payload.weights) || !Array.isArray(payload.biases)) {
    return { valid: false, reason: "Malformed weight update structure" };
  }
  if (payload.weights.length !== expected.weights.length || payload.biases.length !== expected.biases.length) {
    return {
      valid: false,
      reason: `Layer count mismatch: expected ${expected.weights.length}, got ${payload.weights.length}`
    };
  }
  let sqNorm = 0;
  for (let l = 0; l < expected.weights.length; l++) {
    if (payload.weights[l].length !== expected.weights[l].length) {
      return { valid: false, reason: `Layer ${l} output dimension mismatch` };
    }
    if (payload.biases[l].length !== expected.biases[l].length) {
      return { valid: false, reason: `Layer ${l} bias dimension mismatch` };
    }
    for (let o = 0; o < expected.weights[l].length; o++) {
      const bVal = payload.biases[l][o];
      if (typeof bVal !== "number" || !Number.isFinite(bVal)) {
        return { valid: false, reason: `Non-finite bias detected in layer ${l}` };
      }
      sqNorm += bVal * bVal;
      if (payload.weights[l][o].length !== expected.weights[l][o].length) {
        return { valid: false, reason: `Layer ${l} row ${o} input dimension mismatch` };
      }
      for (let i = 0; i < expected.weights[l][o].length; i++) {
        const wVal = payload.weights[l][o][i];
        if (typeof wVal !== "number" || !Number.isFinite(wVal)) {
          return { valid: false, reason: `Non-finite weight (NaN/Inf) detected in layer ${l}` };
        }
        sqNorm += wVal * wVal;
      }
    }
  }
  if (Math.sqrt(sqNorm) > 5e3) {
    return { valid: false, reason: "Weight norm exceeds safe bound (potential gradient explosion/poisoning)" };
  }
  return { valid: true };
}
function fedAvgAggregate(baseModel, updates) {
  if (updates.length === 0) {
    throw new Error("Cannot aggregate zero valid client updates");
  }
  const totalSamples = updates.reduce((sum, u) => sum + u.sampleCount, 0);
  if (totalSamples <= 0) {
    throw new Error("Total sample count across valid updates must be positive");
  }
  const nextModel = cloneMLPWeights(baseModel);
  for (let l = 0; l < nextModel.weights.length; l++) {
    for (let o = 0; o < nextModel.weights[l].length; o++) {
      let bAcc = 0;
      for (const u of updates) {
        bAcc += u.sampleCount / totalSamples * u.biases[l][o];
      }
      nextModel.biases[l][o] = bAcc;
      for (let i = 0; i < nextModel.weights[l][o].length; i++) {
        let wAcc = 0;
        for (const u of updates) {
          wAcc += u.sampleCount / totalSamples * u.weights[l][o][i];
        }
        nextModel.weights[l][o][i] = wAcc;
      }
    }
  }
  return nextModel;
}
function processIncomingClientEnvelope(params) {
  const { envelope, client, expectedModel, expectedModelVersion, expectedRound, replayGuard: replayGuard2 } = params;
  if (!client) {
    return {
      accepted: false,
      code: "UNAUTHORIZED_CLIENT",
      reason: `Client '${envelope.clientId}' is not registered with coordinator`,
      signatureVerified: false,
      decryptionVerified: false,
      integrityVerified: false
    };
  }
  if (envelope.modelVersion !== expectedModelVersion) {
    return {
      accepted: false,
      code: "VERSION_MISMATCH",
      reason: `Model version mismatch: expected ${expectedModelVersion}, got ${envelope.modelVersion}`,
      signatureVerified: false,
      decryptionVerified: false,
      integrityVerified: false
    };
  }
  if (envelope.round !== expectedRound) {
    return {
      accepted: false,
      code: "ROUND_MISMATCH",
      reason: `Round mismatch: expected round ${expectedRound}, got ${envelope.round}`,
      signatureVerified: false,
      decryptionVerified: false,
      integrityVerified: false
    };
  }
  const cryptoRes = verifyAndDecryptEnvelope({
    envelope,
    publicKeyPem: client.publicKeyPem,
    clientActive: client.active,
    keyRevoked: client.keyRevoked,
    replayGuard: replayGuard2
  });
  if (!cryptoRes.ok || !cryptoRes.payload) {
    return {
      accepted: false,
      code: cryptoRes.code,
      reason: cryptoRes.reason,
      signatureVerified: cryptoRes.signatureVerified,
      decryptionVerified: cryptoRes.decryptionVerified,
      integrityVerified: cryptoRes.integrityVerified
    };
  }
  const shapeCheck = validateWeightPayload(cryptoRes.payload, expectedModel);
  if (!shapeCheck.valid) {
    return {
      accepted: false,
      code: "INVALID_TENSOR",
      reason: shapeCheck.reason,
      signatureVerified: true,
      decryptionVerified: true,
      integrityVerified: true
    };
  }
  if (envelope.sampleCount <= 0 || envelope.sampleCount > 1e6) {
    return {
      accepted: false,
      code: "INVALID_SAMPLE_COUNT",
      reason: `Invalid sample count ${envelope.sampleCount}`,
      signatureVerified: true,
      decryptionVerified: true,
      integrityVerified: true
    };
  }
  return {
    accepted: true,
    payload: cryptoRes.payload,
    signatureVerified: true,
    decryptionVerified: true,
    integrityVerified: true
  };
}
function executeFederatedRound(params) {
  const start = Date.now();
  const {
    round,
    globalModel,
    modelVersion,
    nextModelVersion,
    clients,
    partitions,
    XTest,
    yTest,
    classWeights,
    localEpochs,
    learningRate,
    dpClipNorm = null,
    dpNoiseMultiplier = null,
    replayGuard: replayGuard2,
    seed = 42,
    onSecurityRejection
  } = params;
  const clientOutcomes = [];
  const validUpdates = [];
  let totalCommunicationBytes = 0;
  const globalPayloadBytes = Buffer.byteLength(
    JSON.stringify({ weights: globalModel.weights, biases: globalModel.biases }),
    "utf8"
  );
  for (let idx = 0; idx < clients.length; idx++) {
    const client = clients[idx];
    const partition = partitions.get(client.id);
    if (!client.active || !partition || partition.X.length === 0) {
      continue;
    }
    const privateKeyPem = loadClientPrivateKey(client.id);
    if (!privateKeyPem) {
      const rejected = {
        clientId: client.id,
        clientName: client.name,
        status: "rejected",
        reason: "Missing local Ed25519 private key for client signing",
        sampleCount: partition.X.length,
        localLoss: 0,
        localAccuracy: 0,
        localF1: 0,
        payloadBytes: 0,
        signatureVerified: false,
        integrityVerified: false,
        decryptionVerified: false
      };
      clientOutcomes.push(rejected);
      onSecurityRejection?.(rejected, "UNAUTHORIZED_CLIENT");
      continue;
    }
    const { model: localModel, finalLoss } = trainMLPEpochs({
      initialModel: globalModel,
      XTrain: partition.X,
      yTrain: partition.y,
      classWeights,
      epochs: localEpochs,
      lr: learningRate,
      dpClipNorm,
      dpNoiseMultiplier,
      seed: seed + round * 100 + idx
    });
    const localProbs = predictMLPProbs(localModel, partition.X);
    const localMetrics = evaluatePredictions({
      yTrue: partition.y,
      probs: localProbs,
      classes: globalModel.classes,
      loss: finalLoss
    });
    const updatePayload = {
      weights: localModel.weights,
      biases: localModel.biases,
      localLoss: finalLoss,
      localAccuracy: localMetrics.accuracy,
      localF1: localMetrics.f1Score
    };
    const envelope = buildSignedEncryptedEnvelope({
      clientId: client.id,
      round,
      modelVersion,
      sampleCount: partition.X.length,
      payload: updatePayload,
      privateKeyPem
    });
    const envelopeBytes = Buffer.byteLength(JSON.stringify(envelope), "utf8");
    totalCommunicationBytes += globalPayloadBytes + envelopeBytes;
    const verification = processIncomingClientEnvelope({
      envelope,
      client,
      expectedModel: globalModel,
      expectedModelVersion: modelVersion,
      expectedRound: round,
      replayGuard: replayGuard2
    });
    if (!verification.accepted || !verification.payload) {
      const rejected = {
        clientId: client.id,
        clientName: client.name,
        status: "rejected",
        reason: verification.reason,
        sampleCount: partition.X.length,
        localLoss: finalLoss,
        localAccuracy: localMetrics.accuracy,
        localF1: localMetrics.f1Score,
        payloadBytes: envelopeBytes,
        signatureVerified: verification.signatureVerified,
        integrityVerified: verification.integrityVerified,
        decryptionVerified: verification.decryptionVerified
      };
      clientOutcomes.push(rejected);
      onSecurityRejection?.(rejected, verification.code || "REJECTED");
      continue;
    }
    validUpdates.push({
      sampleCount: partition.X.length,
      weights: verification.payload.weights,
      biases: verification.payload.biases
    });
    clientOutcomes.push({
      clientId: client.id,
      clientName: client.name,
      status: "accepted",
      sampleCount: partition.X.length,
      localLoss: finalLoss,
      localAccuracy: localMetrics.accuracy,
      localF1: localMetrics.f1Score,
      payloadBytes: envelopeBytes,
      signatureVerified: true,
      integrityVerified: true,
      decryptionVerified: true
    });
  }
  const updatedModel = validUpdates.length > 0 ? fedAvgAggregate(globalModel, validUpdates) : cloneMLPWeights(globalModel);
  const testProbs = predictMLPProbs(updatedModel, XTest);
  const testLoss = computeCrossEntropyLoss(testProbs, yTest, classWeights);
  const durationMs = Math.max(1, Date.now() - start);
  const metrics = evaluatePredictions({
    yTrue: yTest,
    probs: testProbs,
    classes: updatedModel.classes,
    loss: testLoss,
    trainingTimeMs: durationMs,
    communicationBytes: totalCommunicationBytes
  });
  const dpEpsilonEstimate = dpClipNorm && dpNoiseMultiplier && dpNoiseMultiplier > 0 ? Number((round * localEpochs * 1.2 / Math.max(0.1, dpNoiseMultiplier)).toFixed(2)) : null;
  return {
    updatedModel,
    roundResult: {
      round,
      modelVersion: nextModelVersion,
      globalLoss: Number(testLoss.toFixed(4)),
      globalAccuracy: metrics.accuracy,
      globalPrecision: metrics.precision,
      globalRecall: metrics.recall,
      globalF1: metrics.f1Score,
      globalFpr: metrics.falsePositiveRate,
      globalRocAuc: metrics.rocAuc,
      participatingClients: clientOutcomes.length,
      acceptedClients: validUpdates.length,
      rejectedClients: clientOutcomes.length - validUpdates.length,
      communicationBytes: totalCommunicationBytes,
      durationMs,
      dpEpsilonEstimate,
      clientOutcomes,
      metrics
    }
  };
}

// src/engine/db.ts
var dbInstance = null;
function getDb() {
  if (dbInstance) return dbInstance;
  const dataDir = path2.resolve(process.cwd(), "data");
  if (!fs2.existsSync(dataDir)) {
    fs2.mkdirSync(dataDir, { recursive: true });
  }
  const dbPath = path2.join(dataDir, "fl_ids.db");
  dbInstance = new DatabaseSync(dbPath);
  dbInstance.exec("PRAGMA journal_mode = WAL;");
  dbInstance.exec("PRAGMA foreign_keys = ON;");
  initializeSchema(dbInstance);
  seedInitialDataIfEmpty(dbInstance);
  return dbInstance;
}
function initializeSchema(db2) {
  db2.exec(`
    CREATE TABLE IF NOT EXISTS roles (
      id TEXT PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      permissions_json TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role_id TEXT NOT NULL REFERENCES roles(id),
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS datasets (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      source_type TEXT NOT NULL,
      is_synthetic INTEGER NOT NULL DEFAULT 0,
      raw_rows INTEGER NOT NULL,
      clean_rows INTEGER NOT NULL,
      dropped_missing INTEGER NOT NULL,
      dropped_infinite INTEGER NOT NULL,
      dropped_duplicates INTEGER NOT NULL,
      removed_leakage_json TEXT NOT NULL,
      class_distribution_json TEXT NOT NULL,
      feature_columns_json TEXT NOT NULL,
      csv_path TEXT NOT NULL,
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS models (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      architecture TEXT NOT NULL,
      training_paradigm TEXT NOT NULL,
      classification_mode TEXT NOT NULL,
      version TEXT NOT NULL,
      dataset_id TEXT REFERENCES datasets(id),
      accuracy REAL NOT NULL,
      precision_score REAL NOT NULL,
      recall_score REAL NOT NULL,
      f1_score REAL NOT NULL,
      false_positive_rate REAL NOT NULL,
      roc_auc REAL,
      training_time_ms INTEGER NOT NULL,
      communication_bytes INTEGER NOT NULL DEFAULT 0,
      metrics_json TEXT NOT NULL,
      artifact_json TEXT NOT NULL,
      is_active INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS federated_clients (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      organization TEXT NOT NULL,
      subnet_cidr TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1,
      last_seen_at TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS public_keys (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL REFERENCES federated_clients(id),
      key_id TEXT NOT NULL,
      algorithm TEXT NOT NULL DEFAULT 'Ed25519',
      public_key_pem TEXT NOT NULL,
      fingerprint TEXT NOT NULL,
      revoked INTEGER NOT NULL DEFAULT 0,
      revoked_reason TEXT,
      created_at TEXT NOT NULL,
      rotated_at TEXT
    );

    CREATE TABLE IF NOT EXISTS federated_rounds (
      id TEXT PRIMARY KEY,
      job_id TEXT NOT NULL,
      round_number INTEGER NOT NULL,
      model_version TEXT NOT NULL,
      classification_mode TEXT NOT NULL,
      global_loss REAL NOT NULL,
      global_accuracy REAL NOT NULL,
      global_precision REAL NOT NULL,
      global_recall REAL NOT NULL,
      global_f1 REAL NOT NULL,
      global_fpr REAL NOT NULL,
      global_roc_auc REAL,
      participating_clients INTEGER NOT NULL,
      accepted_clients INTEGER NOT NULL,
      rejected_clients INTEGER NOT NULL,
      communication_bytes INTEGER NOT NULL,
      duration_ms INTEGER NOT NULL,
      dp_epsilon_estimate REAL,
      metrics_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS client_metrics (
      id TEXT PRIMARY KEY,
      round_id TEXT NOT NULL REFERENCES federated_rounds(id),
      client_id TEXT NOT NULL REFERENCES federated_clients(id),
      status TEXT NOT NULL,
      rejection_reason TEXT,
      sample_count INTEGER NOT NULL,
      local_loss REAL NOT NULL,
      local_accuracy REAL NOT NULL,
      local_f1 REAL NOT NULL,
      payload_bytes INTEGER NOT NULL,
      signature_verified INTEGER NOT NULL,
      integrity_verified INTEGER NOT NULL,
      decryption_verified INTEGER NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS security_events (
      id TEXT PRIMARY KEY,
      event_type TEXT NOT NULL,
      severity TEXT NOT NULL,
      client_id TEXT,
      description TEXT NOT NULL,
      signature_status TEXT NOT NULL,
      integrity_status TEXT NOT NULL,
      encryption_status TEXT NOT NULL,
      blocked INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS predictions (
      id TEXT PRIMARY KEY,
      batch_id TEXT NOT NULL,
      model_id TEXT NOT NULL,
      client_sensor TEXT NOT NULL,
      ingestion_mode TEXT NOT NULL,
      predicted_label TEXT NOT NULL,
      true_label TEXT,
      is_malicious INTEGER NOT NULL,
      confidence REAL NOT NULL,
      severity TEXT NOT NULL,
      flow_duration REAL NOT NULL,
      flow_bytes_per_sec REAL NOT NULL,
      syn_flag_count INTEGER NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS alerts (
      id TEXT PRIMARY KEY,
      prediction_id TEXT,
      client_sensor TEXT NOT NULL,
      attack_category TEXT NOT NULL,
      severity TEXT NOT NULL,
      confidence REAL NOT NULL,
      status TEXT NOT NULL DEFAULT 'open',
      summary TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      actor_email TEXT NOT NULL,
      actor_role TEXT NOT NULL,
      action TEXT NOT NULL,
      resource TEXT NOT NULL,
      outcome TEXT NOT NULL,
      details TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);
}
function seedInitialDataIfEmpty(db2) {
  const roleCount = db2.prepare("SELECT COUNT(*) as cnt FROM roles").get();
  if (roleCount.cnt === 0) {
    const insertRole = db2.prepare("INSERT INTO roles (id, name, permissions_json) VALUES (?, ?, ?)");
    insertRole.run(
      "role-admin",
      "admin",
      JSON.stringify(["read", "upload_dataset", "train_models", "run_federated", "manage_keys", "run_inference", "manage_alerts"])
    );
    insertRole.run(
      "role-analyst",
      "analyst",
      JSON.stringify(["read", "upload_dataset", "run_inference", "manage_alerts"])
    );
    insertRole.run("role-viewer", "viewer", JSON.stringify(["read"]));
  }
  const userCount = db2.prepare("SELECT COUNT(*) as cnt FROM users").get();
  if (userCount.cnt === 0) {
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const insertUser = db2.prepare(
      "INSERT INTO users (id, email, name, password_hash, role_id, created_at) VALUES (?, ?, ?, ?, ?, ?)"
    );
    insertUser.run("user-admin", "admin@fl-ids.local", "Security Admin", hashPassword("Admin@FLIDS2026!"), "role-admin", now);
    insertUser.run("user-analyst", "analyst@fl-ids.local", "SOC Analyst", hashPassword("Analyst@FLIDS2026!"), "role-analyst", now);
  }
  const clientCount = db2.prepare("SELECT COUNT(*) as cnt FROM federated_clients").get();
  if (clientCount.cnt === 0) {
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const clients = [
      { id: "client-hospital", name: "Hospital-East", org: "Regional Health Network", cidr: "10.14.0.0/16" },
      { id: "client-fintech", name: "FinTech-Core", org: "Payment Clearing Hub", cidr: "10.22.0.0/16" },
      { id: "client-campus", name: "Campus-Net", org: "University Research Backbone", cidr: "10.31.0.0/16" },
      { id: "client-cloud", name: "Cloud-Edge", org: "Edge Compute Cluster", cidr: "10.45.0.0/16" },
      { id: "client-telecom", name: "Telecom-West", org: "Metro ISP Gateway", cidr: "10.58.0.0/16" }
    ];
    const insertClient = db2.prepare(
      "INSERT INTO federated_clients (id, name, organization, subnet_cidr, active, last_seen_at, created_at) VALUES (?, ?, ?, ?, 1, ?, ?)"
    );
    const insertKey = db2.prepare(
      "INSERT INTO public_keys (id, client_id, key_id, algorithm, public_key_pem, fingerprint, revoked, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?)"
    );
    for (const c of clients) {
      insertClient.run(c.id, c.name, c.org, c.cidr, now, now);
      const kp = generateAndStoreEd25519KeyPair(c.id, true);
      insertKey.run(`pk-${c.id}`, c.id, kp.keyId, "Ed25519", kp.publicKeyPem, kp.fingerprint, now);
    }
  }
  const dsCount = db2.prepare("SELECT COUNT(*) as cnt FROM datasets").get();
  if (dsCount.cnt === 0) {
    const sampleDir = path2.resolve(process.cwd(), "data", "sample");
    if (!fs2.existsSync(sampleDir)) fs2.mkdirSync(sampleDir, { recursive: true });
    const syntheticRecords = generateSyntheticCicIdsDataset(1080, 42);
    const csvPath = path2.join(sampleDir, "synthetic_cicids2017_sample.csv");
    fs2.writeFileSync(csvPath, recordsToCsv(syntheticRecords), "utf8");
    const dist = {};
    for (const r of syntheticRecords) {
      const lbl = r.label || "Benign";
      dist[lbl] = (dist[lbl] || 0) + 1;
    }
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const datasetId = "ds-synthetic-cicids2017";
    db2.prepare(
      `INSERT INTO datasets (
        id, name, source_type, is_synthetic, raw_rows, clean_rows,
        dropped_missing, dropped_infinite, dropped_duplicates,
        removed_leakage_json, class_distribution_json, feature_columns_json,
        csv_path, created_by, created_at
      ) VALUES (?, ?, ?, 1, ?, ?, 0, 0, 0, ?, ?, ?, ?, ?, ?)`
    ).run(
      datasetId,
      "CIC-IDS2017 Synthetic Benchmark (1,080 flows)",
      "cicids2017_synthetic",
      syntheticRecords.length,
      syntheticRecords.length,
      JSON.stringify(["Flow ID", "Source IP", "Destination IP", "Timestamp", "Src Port"]),
      JSON.stringify(dist),
      JSON.stringify([
        "flow_duration",
        "total_fwd_packets",
        "total_bwd_packets",
        "fwd_packet_length_mean",
        "bwd_packet_length_mean",
        "flow_bytes_per_sec",
        "flow_packets_per_sec",
        "syn_flag_count",
        "ack_flag_count",
        "rst_flag_count",
        "psh_flag_count",
        "iat_mean",
        "init_win_bytes_fwd",
        "subflow_fwd_bytes"
      ]),
      csvPath,
      "system-seed",
      now
    );
    runInitialRealTrainingAndSeedPredictions(db2, datasetId, syntheticRecords);
  }
}
function runInitialRealTrainingAndSeedPredictions(db2, datasetId, records) {
  const now = (/* @__PURE__ */ new Date()).toISOString();
  const split = prepareStratifiedSplit(records, "multiclass", 42);
  const rfStart = Date.now();
  const rfModel = trainRandomForest({
    XTrain: split.XTrain,
    yTrain: split.yTrain,
    classes: split.classes,
    mode: "multiclass",
    scaler: split.scaler,
    numTrees: 18,
    maxDepth: 7,
    seed: 42
  });
  const rfTime = Math.max(1, Date.now() - rfStart);
  const rfProbs = predictRandomForestProbs(rfModel, split.XTest);
  const rfMetrics = evaluatePredictions({
    yTrue: split.yTest,
    probs: rfProbs,
    classes: split.classes,
    trainingTimeMs: rfTime,
    communicationBytes: 0
  });
  db2.prepare(
    `INSERT INTO models (
      id, name, architecture, training_paradigm, classification_mode, version, dataset_id,
      accuracy, precision_score, recall_score, f1_score, false_positive_rate, roc_auc,
      training_time_ms, communication_bytes, metrics_json, artifact_json, is_active, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`
  ).run(
    "model-rf-v1",
    "Random Forest Baseline",
    "random_forest",
    "centralized",
    "multiclass",
    "v1.0.0",
    datasetId,
    rfMetrics.accuracy,
    rfMetrics.precision,
    rfMetrics.recall,
    rfMetrics.f1Score,
    rfMetrics.falsePositiveRate,
    rfMetrics.rocAuc,
    rfTime,
    0,
    JSON.stringify({ ...rfMetrics, featureImportances: rfModel.featureImportances, imbalanceRatio: split.imbalanceRatio }),
    JSON.stringify(rfModel),
    now
  );
  const lrStart = Date.now();
  const lrModel = trainLogisticRegression({
    XTrain: split.XTrain,
    yTrain: split.yTrain,
    classes: split.classes,
    mode: "multiclass",
    scaler: split.scaler,
    classWeights: split.classWeights,
    epochs: 140,
    lr: 0.18
  });
  const lrTime = Math.max(1, Date.now() - lrStart);
  const lrProbs = predictLogisticRegressionProbs(lrModel, split.XTest);
  const lrMetrics = evaluatePredictions({
    yTrue: split.yTest,
    probs: lrProbs,
    classes: split.classes,
    trainingTimeMs: lrTime,
    communicationBytes: 0
  });
  db2.prepare(
    `INSERT INTO models (
      id, name, architecture, training_paradigm, classification_mode, version, dataset_id,
      accuracy, precision_score, recall_score, f1_score, false_positive_rate, roc_auc,
      training_time_ms, communication_bytes, metrics_json, artifact_json, is_active, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`
  ).run(
    "model-lr-v1",
    "Logistic Regression Baseline",
    "logistic_regression",
    "centralized",
    "multiclass",
    "v1.0.0",
    datasetId,
    lrMetrics.accuracy,
    lrMetrics.precision,
    lrMetrics.recall,
    lrMetrics.f1Score,
    lrMetrics.falsePositiveRate,
    lrMetrics.rocAuc,
    lrTime,
    0,
    JSON.stringify({ ...lrMetrics, imbalanceRatio: split.imbalanceRatio }),
    JSON.stringify(lrModel),
    now
  );
  const cMlpStart = Date.now();
  const initCMlp = initializeMLPWeights(split.XTrain[0].length, split.classes, "multiclass", split.scaler, 42);
  const { model: cMlpModel, finalLoss: cMlpLoss } = trainMLPEpochs({
    initialModel: initCMlp,
    XTrain: split.XTrain,
    yTrain: split.yTrain,
    classWeights: split.classWeights,
    epochs: 28,
    lr: 0.06,
    seed: 42
  });
  const cMlpTime = Math.max(1, Date.now() - cMlpStart);
  const cMlpProbs = predictMLPProbs(cMlpModel, split.XTest);
  const cMlpMetrics = evaluatePredictions({
    yTrue: split.yTest,
    probs: cMlpProbs,
    classes: split.classes,
    loss: cMlpLoss,
    trainingTimeMs: cMlpTime,
    communicationBytes: 0
  });
  db2.prepare(
    `INSERT INTO models (
      id, name, architecture, training_paradigm, classification_mode, version, dataset_id,
      accuracy, precision_score, recall_score, f1_score, false_positive_rate, roc_auc,
      training_time_ms, communication_bytes, metrics_json, artifact_json, is_active, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`
  ).run(
    "model-cmlp-v1",
    "Centralized PyTorch-style MLP",
    "centralized_mlp",
    "centralized",
    "multiclass",
    "v1.0.0",
    datasetId,
    cMlpMetrics.accuracy,
    cMlpMetrics.precision,
    cMlpMetrics.recall,
    cMlpMetrics.f1Score,
    cMlpMetrics.falsePositiveRate,
    cMlpMetrics.rocAuc,
    cMlpTime,
    0,
    JSON.stringify({ ...cMlpMetrics, imbalanceRatio: split.imbalanceRatio }),
    JSON.stringify({ kind: "mlp", ...cMlpModel }),
    now
  );
  const clientRows = db2.prepare(
    `SELECT fc.id, fc.name, fc.organization, fc.active, pk.public_key_pem, pk.revoked
       FROM federated_clients fc
       LEFT JOIN public_keys pk ON pk.client_id = fc.id AND pk.revoked = 0`
  ).all();
  const clientDescriptors = clientRows.map((c) => ({
    id: c.id,
    name: c.name,
    organization: c.organization,
    active: c.active === 1,
    publicKeyPem: c.public_key_pem,
    keyRevoked: c.revoked === 1
  }));
  const partitionsArr = partitionNonIid(
    split.XTrain,
    split.yTrain,
    split.classes,
    clientDescriptors.map((c) => c.id),
    0.65,
    42
  );
  const partitions = new Map(partitionsArr.map((p) => [p.clientId, p]));
  const replayGuard2 = new ReplayGuard();
  let currentGlobal = initializeMLPWeights(split.XTrain[0].length, split.classes, "multiclass", split.scaler, 42);
  let totalFlTime = 0;
  let totalCommBytes = 0;
  let lastRoundResult = null;
  const jobId = "fl-job-seed-001";
  for (let r = 1; r <= 5; r++) {
    const prevVer = `v1.0.${r - 1}`;
    const nextVer = `v1.0.${r}`;
    const { updatedModel, roundResult } = executeFederatedRound({
      round: r,
      globalModel: currentGlobal,
      modelVersion: prevVer,
      nextModelVersion: nextVer,
      clients: clientDescriptors,
      partitions,
      XTest: split.XTest,
      yTest: split.yTest,
      classWeights: split.classWeights,
      localEpochs: 5,
      learningRate: 0.06,
      replayGuard: replayGuard2,
      seed: 42
    });
    currentGlobal = updatedModel;
    totalFlTime += roundResult.durationMs;
    totalCommBytes += roundResult.communicationBytes;
    lastRoundResult = roundResult;
    const roundId = `round-seed-${r}`;
    db2.prepare(
      `INSERT INTO federated_rounds (
        id, job_id, round_number, model_version, classification_mode,
        global_loss, global_accuracy, global_precision, global_recall, global_f1, global_fpr, global_roc_auc,
        participating_clients, accepted_clients, rejected_clients, communication_bytes, duration_ms,
        dp_epsilon_estimate, metrics_json, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      roundId,
      jobId,
      r,
      nextVer,
      "multiclass",
      roundResult.globalLoss,
      roundResult.globalAccuracy,
      roundResult.globalPrecision,
      roundResult.globalRecall,
      roundResult.globalF1,
      roundResult.globalFpr,
      roundResult.globalRocAuc,
      roundResult.participatingClients,
      roundResult.acceptedClients,
      roundResult.rejectedClients,
      roundResult.communicationBytes,
      roundResult.durationMs,
      roundResult.dpEpsilonEstimate,
      JSON.stringify(roundResult.metrics),
      now
    );
    const insertClientMetric = db2.prepare(
      `INSERT INTO client_metrics (
        id, round_id, client_id, status, rejection_reason, sample_count,
        local_loss, local_accuracy, local_f1, payload_bytes,
        signature_verified, integrity_verified, decryption_verified, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
    for (const outcome of roundResult.clientOutcomes) {
      insertClientMetric.run(
        `cm-${roundId}-${outcome.clientId}`,
        roundId,
        outcome.clientId,
        outcome.status,
        outcome.reason ?? null,
        outcome.sampleCount,
        outcome.localLoss,
        outcome.localAccuracy,
        outcome.localF1,
        outcome.payloadBytes,
        outcome.signatureVerified ? 1 : 0,
        outcome.integrityVerified ? 1 : 0,
        outcome.decryptionVerified ? 1 : 0,
        now
      );
    }
  }
  if (lastRoundResult) {
    const flProbs = predictMLPProbs(currentGlobal, split.XTest);
    const flLoss = computeCrossEntropyLoss(flProbs, split.yTest, split.classWeights);
    const flMetrics = evaluatePredictions({
      yTrue: split.yTest,
      probs: flProbs,
      classes: split.classes,
      loss: flLoss,
      trainingTimeMs: totalFlTime,
      communicationBytes: totalCommBytes
    });
    const flModelId = "model-flmlp-v1";
    db2.prepare(
      `INSERT INTO models (
        id, name, architecture, training_paradigm, classification_mode, version, dataset_id,
        accuracy, precision_score, recall_score, f1_score, false_positive_rate, roc_auc,
        training_time_ms, communication_bytes, metrics_json, artifact_json, is_active, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`
    ).run(
      flModelId,
      "Federated FedAvg MLP",
      "federated_mlp",
      "federated",
      "multiclass",
      "v1.0.5",
      datasetId,
      flMetrics.accuracy,
      flMetrics.precision,
      flMetrics.recall,
      flMetrics.f1Score,
      flMetrics.falsePositiveRate,
      flMetrics.rocAuc,
      totalFlTime,
      totalCommBytes,
      JSON.stringify({ ...flMetrics, imbalanceRatio: split.imbalanceRatio }),
      JSON.stringify({ kind: "mlp", ...currentGlobal }),
      now
    );
    const sampleBatch = records.slice(0, 60);
    const scaledBatch = sampleBatch.map(
      (r) => currentGlobal.scaler.featureNames.map((fn, j) => {
        const val = Number(r[fn] ?? 0);
        return (val - currentGlobal.scaler.means[j]) / currentGlobal.scaler.stds[j];
      })
    );
    const batchProbs = predictMLPProbs(currentGlobal, scaledBatch);
    const sensorNames = ["Hospital-East", "FinTech-Core", "Campus-Net", "Cloud-Edge", "Telecom-West"];
    const insertPred = db2.prepare(
      `INSERT INTO predictions (
        id, batch_id, model_id, client_sensor, ingestion_mode,
        predicted_label, true_label, is_malicious, confidence, severity,
        flow_duration, flow_bytes_per_sec, syn_flag_count, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
    const insertAlert = db2.prepare(
      `INSERT INTO alerts (
        id, prediction_id, client_sensor, attack_category, severity, confidence, status, summary, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
    sampleBatch.forEach((rec, i) => {
      const p = batchProbs[i];
      let bestIdx = 0;
      for (let c = 1; c < p.length; c++) {
        if (p[c] > p[bestIdx]) bestIdx = c;
      }
      const predLabel = currentGlobal.classes[bestIdx];
      const confidence = Number(p[bestIdx].toFixed(4));
      const isMalicious = predLabel !== "Benign";
      const severity = !isMalicious ? "low" : predLabel === "DoS/DDoS" || predLabel === "Botnet" ? confidence >= 0.85 ? "critical" : "high" : confidence >= 0.85 ? "high" : "medium";
      const sensor = sensorNames[i % sensorNames.length];
      const ts = rec.timestamp || now;
      const predId = `pred-seed-${i + 1}`;
      insertPred.run(
        predId,
        "batch-seed-001",
        flModelId,
        sensor,
        "offline_csv_benchmark",
        predLabel,
        rec.label ?? null,
        isMalicious ? 1 : 0,
        confidence,
        severity,
        rec.flow_duration,
        rec.flow_bytes_per_sec,
        rec.syn_flag_count,
        ts
      );
      if (isMalicious) {
        insertAlert.run(
          `alert-seed-${i + 1}`,
          predId,
          sensor,
          predLabel,
          severity,
          confidence,
          "open",
          `${predLabel} detected on ${sensor} (${(confidence * 100).toFixed(1)}% confidence)`,
          ts
        );
      }
    });
    db2.prepare(
      `INSERT INTO security_events (
        id, event_type, severity, client_id, description,
        signature_status, integrity_status, encryption_status, blocked, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`
    ).run(
      "sec-seed-1",
      "FEDAVG_ROUND_VERIFIED",
      "low",
      "client-hospital",
      "Initial 5-round federated training completed with 25/25 Ed25519 + AES-256-GCM verified client updates",
      "verified",
      "verified",
      "aes-256-gcm",
      now
    );
    db2.prepare(
      `INSERT INTO audit_logs (
        id, actor_email, actor_role, action, resource, outcome, details, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      "audit-seed-1",
      "system@fl-ids.local",
      "admin",
      "BOOTSTRAP_PIPELINE",
      "models/model-flmlp-v1",
      "success",
      "Trained baseline centralized models (RF, LR, MLP) and 5-round Federated MLP on synthetic CIC-IDS2017 split",
      now
    );
  }
}

// server.ts
var PORT = Number(process.env.PORT || 3e3);
var app = express();
app.use(express.json({ limit: "25mb" }));
var rateBuckets = /* @__PURE__ */ new Map();
function rateLimiter(maxRequests = 180, windowMs = 6e4) {
  return (req, res, next) => {
    if (!req.path.startsWith("/api")) return next();
    const ip = req.ip || "local";
    const now = Date.now();
    const history = (rateBuckets.get(ip) || []).filter((t) => now - t < windowMs);
    if (history.length >= maxRequests) {
      return res.status(429).json({ error: "Rate limit exceeded. Retry shortly." });
    }
    history.push(now);
    rateBuckets.set(ip, history);
    next();
  };
}
app.use(rateLimiter());
var db = getDb();
var replayGuard = new ReplayGuard();
var federatedJob = {
  jobId: "fl-job-seed-001",
  status: "completed",
  totalRounds: 5,
  currentRound: 5,
  classificationMode: "multiclass",
  dpEnabled: false,
  message: "Initial 5-round federated run completed",
  startedAt: (/* @__PURE__ */ new Date()).toISOString(),
  completedAt: (/* @__PURE__ */ new Date()).toISOString()
};
var trainingJobs = /* @__PURE__ */ new Map();
function writeAuditLog(actor, action, resource, outcome, details) {
  db.prepare(
    `INSERT INTO audit_logs (id, actor_email, actor_role, action, resource, outcome, details, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    `audit-${crypto2.randomUUID().slice(0, 8)}`,
    actor.email,
    actor.role,
    action,
    resource,
    outcome,
    details,
    (/* @__PURE__ */ new Date()).toISOString()
  );
}
function writeSecurityEvent(params) {
  db.prepare(
    `INSERT INTO security_events (
      id, event_type, severity, client_id, description,
      signature_status, integrity_status, encryption_status, blocked, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    `sec-${crypto2.randomUUID().slice(0, 8)}`,
    params.eventType,
    params.severity,
    params.clientId ?? null,
    params.description,
    params.signatureStatus,
    params.integrityStatus,
    params.encryptionStatus,
    params.blocked ? 1 : 0,
    (/* @__PURE__ */ new Date()).toISOString()
  );
}
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Authentication required" });
  }
  const token = header.slice(7).trim();
  const payload = verifyJwt(token);
  if (!payload) {
    return res.status(401).json({ error: "Invalid or expired authentication token" });
  }
  req.user = payload;
  next();
}
function requireRole(...allowed) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: "Authentication required" });
    }
    if (!allowed.includes(req.user.role)) {
      writeAuditLog(
        { email: req.user.email, role: req.user.role },
        "ACCESS_DENIED",
        req.originalUrl,
        "denied",
        `Role '${req.user.role}' lacks permission (${allowed.join(", ")})`
      );
      return res.status(403).json({ error: `Insufficient permissions. Required role: ${allowed.join(" or ")}` });
    }
    next();
  };
}
function loadDatasetRecords(datasetId) {
  const row = db.prepare("SELECT id, name, csv_path, is_synthetic FROM datasets WHERE id = ?").get(datasetId);
  if (!row) {
    throw new Error(`Dataset '${datasetId}' not found`);
  }
  const csvText = fs3.readFileSync(row.csv_path, "utf8");
  const { records } = parseAndCleanCsv(csvText, void 0, row.is_synthetic === 1);
  return { records, name: row.name, isSynthetic: row.is_synthetic === 1 };
}
function computeSeverity(label, confidence) {
  if (label === "Benign") return "low";
  if ((label === "DoS/DDoS" || label === "Botnet") && confidence >= 0.85) return "critical";
  if (label === "DoS/DDoS" || label === "Botnet" || confidence >= 0.85) return "high";
  return "medium";
}
function runModelInference(modelRow, records) {
  const artifact = JSON.parse(modelRow.artifact_json);
  const scaled = records.map(
    (rec) => artifact.scaler.featureNames.map((fn, idx) => {
      const val = Number(rec[fn] ?? 0);
      return (val - artifact.scaler.means[idx]) / artifact.scaler.stds[idx];
    })
  );
  let probs;
  if (artifact.kind === "random_forest") {
    probs = predictRandomForestProbs(artifact, scaled);
  } else if (artifact.kind === "logistic_regression") {
    probs = predictLogisticRegressionProbs(artifact, scaled);
  } else {
    probs = predictMLPProbs(artifact, scaled);
  }
  return probs.map((p) => {
    let best = 0;
    for (let i = 1; i < p.length; i++) {
      if (p[i] > p[best]) best = i;
    }
    const label = artifact.classes[best];
    const confidence = Number(p[best].toFixed(4));
    const isMalicious = label !== "Benign";
    return {
      predictedLabel: label,
      confidence,
      isMalicious,
      severity: computeSeverity(label, confidence)
    };
  });
}
app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password || typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "Email and password are required" });
  }
  const user = db.prepare(
    `SELECT u.id, u.email, u.name, u.password_hash, r.name as role_name, r.permissions_json
       FROM users u JOIN roles r ON u.role_id = r.id WHERE u.email = ?`
  ).get(email.trim().toLowerCase());
  if (!user || !verifyPassword(password, user.password_hash)) {
    writeAuditLog(
      { email: email.trim(), role: "unknown" },
      "LOGIN_FAILED",
      "auth/login",
      "denied",
      "Invalid email or password"
    );
    return res.status(401).json({ error: "Invalid credentials" });
  }
  const token = signJwt({
    sub: user.id,
    email: user.email,
    name: user.name,
    role: user.role_name
  });
  writeAuditLog(
    { email: user.email, role: user.role_name },
    "LOGIN_SUCCESS",
    "auth/login",
    "success",
    "Authenticated via scrypt + HS256 JWT"
  );
  return res.json({
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role_name,
      permissions: JSON.parse(user.permissions_json)
    }
  });
});
app.get("/api/auth/me", requireAuth, (req, res) => {
  return res.json({ user: req.user });
});
app.get("/api/overview", requireAuth, (_req, res) => {
  const predStats = db.prepare(
    `SELECT COUNT(*) as total,
              SUM(CASE WHEN is_malicious = 1 THEN 1 ELSE 0 END) as malicious,
              SUM(CASE WHEN is_malicious = 0 THEN 1 ELSE 0 END) as benign
       FROM predictions`
  ).get();
  const activeClients = db.prepare("SELECT COUNT(*) as cnt FROM federated_clients WHERE active = 1").get();
  const latestRound = db.prepare(
    `SELECT round_number, model_version, global_accuracy, global_f1, global_loss, global_fpr,
              accepted_clients, rejected_clients, communication_bytes, created_at
       FROM federated_rounds ORDER BY created_at DESC, round_number DESC LIMIT 1`
  ).get();
  const activeModel = db.prepare(
    `SELECT id, name, architecture, version, accuracy, precision_score, recall_score, f1_score, false_positive_rate, roc_auc
       FROM models WHERE is_active = 1 ORDER BY created_at DESC LIMIT 1`
  ).get();
  const recentAlerts = db.prepare("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 8").all();
  const modelsSummary = db.prepare(
    `SELECT id, name, architecture, training_paradigm, classification_mode, version, accuracy, precision_score, recall_score, f1_score, false_positive_rate
       FROM models ORDER BY created_at DESC LIMIT 6`
  ).all();
  return res.json({
    totalRecordsAnalyzed: predStats.total || 0,
    maliciousRecords: predStats.malicious || 0,
    benignRecords: predStats.benign || 0,
    activeFederatedClients: activeClients.cnt || 0,
    globalModelVersion: latestRound?.model_version || activeModel?.version || "v1.0.0",
    latestRoundNumber: latestRound?.round_number || 0,
    activeModel,
    latestRound,
    recentAlerts,
    modelsSummary
  });
});
app.get("/api/datasets", requireAuth, (_req, res) => {
  const rows = db.prepare("SELECT * FROM datasets ORDER BY created_at DESC").all();
  return res.json({
    datasets: rows.map((r) => ({
      ...r,
      isSynthetic: r.is_synthetic === 1,
      removedLeakageColumns: JSON.parse(String(r.removed_leakage_json)),
      classDistribution: JSON.parse(String(r.class_distribution_json)),
      featureColumns: JSON.parse(String(r.feature_columns_json))
    }))
  });
});
app.get("/api/datasets/:id/preview", requireAuth, (req, res) => {
  try {
    const { records, name, isSynthetic } = loadDatasetRecords(String(req.params.id));
    return res.json({
      id: req.params.id,
      name,
      isSynthetic,
      totalRows: records.length,
      preview: records.slice(0, 25),
      featureColumns: CORE_FEATURES
    });
  } catch (err) {
    return res.status(404).json({ error: err.message });
  }
});
app.post("/api/datasets/upload", requireAuth, requireRole("admin", "analyst"), (req, res) => {
  try {
    const { name, csvText, columnMapping, sourceType } = req.body;
    if (!csvText || typeof csvText !== "string") {
      return res.status(400).json({ error: "csvText is required" });
    }
    const { records, report } = parseAndCleanCsv(csvText, columnMapping, false);
    if (records.length === 0) {
      return res.status(400).json({ error: "No valid flow records remained after cleaning NaN/Inf/duplicates" });
    }
    const id = `ds-${crypto2.randomUUID().slice(0, 8)}`;
    const uploadDir = path3.resolve(process.cwd(), "data", "uploads");
    if (!fs3.existsSync(uploadDir)) fs3.mkdirSync(uploadDir, { recursive: true });
    const csvPath = path3.join(uploadDir, `${id}.csv`);
    fs3.writeFileSync(csvPath, recordsToCsv(records), "utf8");
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const datasetName = (name || "Uploaded Network Flows").trim();
    db.prepare(
      `INSERT INTO datasets (
        id, name, source_type, is_synthetic, raw_rows, clean_rows,
        dropped_missing, dropped_infinite, dropped_duplicates,
        removed_leakage_json, class_distribution_json, feature_columns_json,
        csv_path, created_by, created_at
      ) VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      id,
      datasetName,
      sourceType || "custom_csv",
      report.rawRows,
      report.cleanRows,
      report.droppedMissing,
      report.droppedInfinite,
      report.droppedDuplicates,
      JSON.stringify(report.removedLeakageColumns),
      JSON.stringify(report.classDistribution),
      JSON.stringify(report.featureColumns),
      csvPath,
      req.user.email,
      now
    );
    writeAuditLog(
      { email: req.user.email, role: req.user.role },
      "UPLOAD_DATASET",
      `datasets/${id}`,
      "success",
      `Uploaded '${datasetName}' (${report.cleanRows}/${report.rawRows} clean rows)`
    );
    return res.status(201).json({ id, name: datasetName, report, preview: records.slice(0, 15) });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});
app.get("/api/models", requireAuth, (_req, res) => {
  const rows = db.prepare(
    `SELECT id, name, architecture, training_paradigm, classification_mode, version, dataset_id,
              accuracy, precision_score, recall_score, f1_score, false_positive_rate, roc_auc,
              training_time_ms, communication_bytes, metrics_json, is_active, created_at
       FROM models ORDER BY created_at DESC`
  ).all();
  return res.json({
    models: rows.map((r) => ({
      ...r,
      isActive: r.is_active === 1,
      metrics: JSON.parse(String(r.metrics_json))
    }))
  });
});
app.post("/api/models/train", requireAuth, requireRole("admin"), (req, res) => {
  const {
    datasetId = "ds-synthetic-cicids2017",
    architecture = "random_forest",
    classificationMode = "multiclass",
    seed = 42
  } = req.body;
  if (!["random_forest", "logistic_regression", "centralized_mlp"].includes(architecture)) {
    return res.status(400).json({ error: "Unsupported centralized architecture" });
  }
  const jobId = `train-${crypto2.randomUUID().slice(0, 8)}`;
  const job = {
    jobId,
    status: "running",
    architecture,
    modelId: null,
    message: `Training ${architecture} (${classificationMode}) on ${datasetId}...`,
    startedAt: (/* @__PURE__ */ new Date()).toISOString(),
    completedAt: null
  };
  trainingJobs.set(jobId, job);
  setTimeout(() => {
    try {
      const { records } = loadDatasetRecords(datasetId);
      const split = prepareStratifiedSplit(records, classificationMode, seed);
      const start = Date.now();
      let artifact;
      let probs;
      let loss;
      let extra = { imbalanceRatio: split.imbalanceRatio };
      if (architecture === "random_forest") {
        const rf = trainRandomForest({
          XTrain: split.XTrain,
          yTrain: split.yTrain,
          classes: split.classes,
          mode: classificationMode,
          scaler: split.scaler,
          numTrees: 18,
          maxDepth: 7,
          seed
        });
        artifact = rf;
        probs = predictRandomForestProbs(rf, split.XTest);
        extra = { ...extra, featureImportances: rf.featureImportances };
      } else if (architecture === "logistic_regression") {
        const lr = trainLogisticRegression({
          XTrain: split.XTrain,
          yTrain: split.yTrain,
          classes: split.classes,
          mode: classificationMode,
          scaler: split.scaler,
          classWeights: split.classWeights,
          epochs: 140,
          lr: 0.18
        });
        artifact = lr;
        probs = predictLogisticRegressionProbs(lr, split.XTest);
      } else {
        const init = initializeMLPWeights(split.XTrain[0].length, split.classes, classificationMode, split.scaler, seed);
        const trained = trainMLPEpochs({
          initialModel: init,
          XTrain: split.XTrain,
          yTrain: split.yTrain,
          classWeights: split.classWeights,
          epochs: 28,
          lr: 0.06,
          seed
        });
        artifact = { kind: "mlp", ...trained.model };
        loss = trained.finalLoss;
        probs = predictMLPProbs(trained.model, split.XTest);
      }
      const elapsed = Math.max(1, Date.now() - start);
      const metrics = evaluatePredictions({
        yTrue: split.yTest,
        probs,
        classes: split.classes,
        loss,
        trainingTimeMs: elapsed,
        communicationBytes: 0
      });
      const modelId = `model-${architecture}-${crypto2.randomUUID().slice(0, 6)}`;
      const labelMap = {
        random_forest: "Random Forest Baseline",
        logistic_regression: "Logistic Regression Baseline",
        centralized_mlp: "Centralized PyTorch-style MLP"
      };
      const version = `v1.${Math.floor(Date.now() / 1e3) % 1e3}.0`;
      db.prepare(
        `INSERT INTO models (
          id, name, architecture, training_paradigm, classification_mode, version, dataset_id,
          accuracy, precision_score, recall_score, f1_score, false_positive_rate, roc_auc,
          training_time_ms, communication_bytes, metrics_json, artifact_json, is_active, created_at
        ) VALUES (?, ?, ?, 'centralized', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 0, ?)`
      ).run(
        modelId,
        labelMap[architecture],
        architecture,
        classificationMode,
        version,
        datasetId,
        metrics.accuracy,
        metrics.precision,
        metrics.recall,
        metrics.f1Score,
        metrics.falsePositiveRate,
        metrics.rocAuc,
        elapsed,
        JSON.stringify({ ...metrics, ...extra }),
        JSON.stringify(artifact),
        (/* @__PURE__ */ new Date()).toISOString()
      );
      writeAuditLog(
        { email: req.user.email, role: req.user.role },
        "TRAIN_CENTRALIZED_MODEL",
        `models/${modelId}`,
        "success",
        `Trained ${architecture} (${classificationMode}) -> Accuracy ${(metrics.accuracy * 100).toFixed(1)}%`
      );
      job.status = "completed";
      job.modelId = modelId;
      job.message = `Completed ${labelMap[architecture]} (Accuracy ${(metrics.accuracy * 100).toFixed(1)}%)`;
      job.completedAt = (/* @__PURE__ */ new Date()).toISOString();
    } catch (err) {
      job.status = "failed";
      job.message = err.message;
      job.completedAt = (/* @__PURE__ */ new Date()).toISOString();
    }
  }, 20);
  return res.status(202).json({ job });
});
app.get("/api/models/jobs/:jobId", requireAuth, (req, res) => {
  const job = trainingJobs.get(String(req.params.jobId));
  if (!job) return res.status(404).json({ error: "Training job not found" });
  return res.json({ job });
});
app.get("/api/federated/status", requireAuth, (_req, res) => {
  return res.json({ job: federatedJob });
});
app.get("/api/federated/clients", requireAuth, (_req, res) => {
  const clients = db.prepare(
    `SELECT fc.*, pk.key_id, pk.fingerprint, pk.revoked, pk.created_at as key_created_at, pk.rotated_at
       FROM federated_clients fc
       LEFT JOIN public_keys pk ON pk.client_id = fc.id
       ORDER BY fc.created_at ASC`
  ).all();
  const latestClientStats = db.prepare(
    `SELECT cm.client_id, cm.status, cm.sample_count, cm.local_loss, cm.local_accuracy, cm.local_f1, cm.payload_bytes, cm.rejection_reason
       FROM client_metrics cm
       WHERE cm.round_id = (SELECT id FROM federated_rounds ORDER BY created_at DESC, round_number DESC LIMIT 1)`
  ).all();
  const statByClient = new Map(latestClientStats.map((s) => [String(s.client_id), s]));
  return res.json({
    clients: clients.map((c) => ({
      ...c,
      active: c.active === 1,
      revoked: c.revoked === 1,
      latestMetrics: statByClient.get(String(c.id)) || null
    }))
  });
});
app.post("/api/federated/clients/register", requireAuth, requireRole("admin"), (req, res) => {
  const { name, organization, subnetCidr } = req.body;
  if (!name || !organization) {
    return res.status(400).json({ error: "Client name and organization are required" });
  }
  const clientId = `client-${name.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 18)}-${crypto2.randomUUID().slice(0, 4)}`;
  const now = (/* @__PURE__ */ new Date()).toISOString();
  const kp = generateAndStoreEd25519KeyPair(clientId, true);
  db.prepare(
    `INSERT INTO federated_clients (id, name, organization, subnet_cidr, active, last_seen_at, created_at)
     VALUES (?, ?, ?, ?, 1, ?, ?)`
  ).run(clientId, name.trim(), organization.trim(), (subnetCidr || "10.90.0.0/16").trim(), now, now);
  db.prepare(
    `INSERT INTO public_keys (id, client_id, key_id, algorithm, public_key_pem, fingerprint, revoked, created_at)
     VALUES (?, ?, ?, 'Ed25519', ?, ?, 0, ?)`
  ).run(`pk-${clientId}`, clientId, kp.keyId, kp.publicKeyPem, kp.fingerprint, now);
  writeAuditLog(
    { email: req.user.email, role: req.user.role },
    "REGISTER_FL_CLIENT",
    `federated_clients/${clientId}`,
    "success",
    `Registered client '${name.trim()}' and provisioned Ed25519 key ${kp.keyId}`
  );
  return res.status(201).json({
    client: { id: clientId, name: name.trim(), organization: organization.trim(), keyId: kp.keyId, fingerprint: kp.fingerprint }
  });
});
app.post("/api/federated/clients/:id/toggle", requireAuth, requireRole("admin"), (req, res) => {
  const clientId = String(req.params.id);
  const existing = db.prepare("SELECT id, name, active FROM federated_clients WHERE id = ?").get(clientId);
  if (!existing) {
    return res.status(404).json({ error: "Federated client not found" });
  }
  const nextActive = existing.active === 1 ? 0 : 1;
  db.prepare("UPDATE federated_clients SET active = ? WHERE id = ?").run(nextActive, clientId);
  writeAuditLog(
    { email: req.user.email, role: req.user.role },
    nextActive === 1 ? "ENABLE_FL_CLIENT" : "PAUSE_FL_CLIENT",
    `federated_clients/${clientId}`,
    "success",
    `${existing.name} participation set to ${nextActive === 1 ? "active" : "paused"}`
  );
  return res.json({ id: clientId, active: nextActive === 1 });
});
app.get("/api/federated/rounds", requireAuth, (_req, res) => {
  const rounds = db.prepare("SELECT * FROM federated_rounds ORDER BY created_at ASC, round_number ASC LIMIT 60").all();
  const clientMetrics = db.prepare(
    `SELECT cm.*, fc.name as client_name, fc.organization
       FROM client_metrics cm
       JOIN federated_clients fc ON fc.id = cm.client_id
       ORDER BY cm.created_at ASC`
  ).all();
  const byRound = /* @__PURE__ */ new Map();
  for (const cm of clientMetrics) {
    const rid = String(cm.round_id);
    if (!byRound.has(rid)) byRound.set(rid, []);
    byRound.get(rid).push({
      ...cm,
      signatureVerified: cm.signature_verified === 1,
      integrityVerified: cm.integrity_verified === 1,
      decryptionVerified: cm.decryption_verified === 1
    });
  }
  return res.json({
    rounds: rounds.map((r) => ({
      ...r,
      metrics: JSON.parse(String(r.metrics_json)),
      clientOutcomes: byRound.get(String(r.id)) || []
    }))
  });
});
app.post("/api/federated/start", requireAuth, requireRole("admin"), (req, res) => {
  if (federatedJob.status === "running") {
    return res.status(409).json({ error: "A federated training job is already running" });
  }
  const {
    datasetId = "ds-synthetic-cicids2017",
    rounds = 5,
    localEpochs = 4,
    learningRate = 0.06,
    nonIidAlpha = 0.65,
    classificationMode = "multiclass",
    dpEnabled = false,
    dpClipNorm = 1.5,
    dpNoiseMultiplier = 0.08,
    seed = 42
  } = req.body;
  const clampedRounds = Math.min(12, Math.max(1, Number(rounds)));
  const clampedEpochs = Math.min(10, Math.max(1, Number(localEpochs)));
  const jobId = `fl-job-${crypto2.randomUUID().slice(0, 8)}`;
  federatedJob = {
    jobId,
    status: "running",
    totalRounds: clampedRounds,
    currentRound: 0,
    classificationMode,
    dpEnabled: Boolean(dpEnabled),
    message: `Initializing global MLP and dispatching to active clients...`,
    startedAt: (/* @__PURE__ */ new Date()).toISOString(),
    completedAt: null
  };
  const actor = { email: req.user.email, role: req.user.role };
  (async () => {
    try {
      const { records } = loadDatasetRecords(datasetId);
      const split = prepareStratifiedSplit(records, classificationMode, seed);
      const clientRows = db.prepare(
        `SELECT fc.id, fc.name, fc.organization, fc.active, pk.public_key_pem, pk.revoked
           FROM federated_clients fc
           LEFT JOIN public_keys pk ON pk.client_id = fc.id`
      ).all();
      const activeClients = clientRows.filter((c) => c.active === 1).map((c) => ({
        id: c.id,
        name: c.name,
        organization: c.organization,
        active: true,
        publicKeyPem: c.public_key_pem,
        keyRevoked: c.revoked === 1
      }));
      if (activeClients.length < 2) {
        throw new Error("At least 2 active federated clients are required for FedAvg");
      }
      const partitionsArr = partitionNonIid(
        split.XTrain,
        split.yTrain,
        split.classes,
        activeClients.map((c) => c.id),
        nonIidAlpha,
        seed
      );
      const partitions = new Map(partitionsArr.map((p) => [p.clientId, p]));
      let globalModel = initializeMLPWeights(split.XTrain[0].length, split.classes, classificationMode, split.scaler, seed);
      const versionBase = Math.floor(Date.now() / 1e3) % 1e3;
      let totalDurationMs = 0;
      let totalCommBytes = 0;
      let lastRoundResult = null;
      for (let r = 1; r <= clampedRounds; r++) {
        await new Promise((resolve) => setTimeout(resolve, 60));
        const prevVer = `v2.${versionBase}.${r - 1}`;
        const nextVer = `v2.${versionBase}.${r}`;
        const { updatedModel, roundResult } = executeFederatedRound({
          round: r,
          globalModel,
          modelVersion: prevVer,
          nextModelVersion: nextVer,
          clients: activeClients,
          partitions,
          XTest: split.XTest,
          yTest: split.yTest,
          classWeights: split.classWeights,
          localEpochs: clampedEpochs,
          learningRate,
          dpClipNorm: dpEnabled ? dpClipNorm : null,
          dpNoiseMultiplier: dpEnabled ? dpNoiseMultiplier : null,
          replayGuard,
          seed,
          onSecurityRejection: (outcome, code) => {
            writeSecurityEvent({
              eventType: code,
              severity: "high",
              clientId: outcome.clientId,
              description: `Round ${r} update from ${outcome.clientName} rejected: ${outcome.reason}`,
              signatureStatus: outcome.signatureVerified ? "verified" : "failed",
              integrityStatus: outcome.integrityVerified ? "verified" : "failed",
              encryptionStatus: outcome.decryptionVerified ? "aes-256-gcm" : "failed",
              blocked: true
            });
          }
        });
        globalModel = updatedModel;
        totalDurationMs += roundResult.durationMs;
        totalCommBytes += roundResult.communicationBytes;
        lastRoundResult = roundResult;
        const now = (/* @__PURE__ */ new Date()).toISOString();
        const roundId = `round-${jobId}-${r}`;
        db.prepare(
          `INSERT INTO federated_rounds (
            id, job_id, round_number, model_version, classification_mode,
            global_loss, global_accuracy, global_precision, global_recall, global_f1, global_fpr, global_roc_auc,
            participating_clients, accepted_clients, rejected_clients, communication_bytes, duration_ms,
            dp_epsilon_estimate, metrics_json, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(
          roundId,
          jobId,
          r,
          nextVer,
          classificationMode,
          roundResult.globalLoss,
          roundResult.globalAccuracy,
          roundResult.globalPrecision,
          roundResult.globalRecall,
          roundResult.globalF1,
          roundResult.globalFpr,
          roundResult.globalRocAuc,
          roundResult.participatingClients,
          roundResult.acceptedClients,
          roundResult.rejectedClients,
          roundResult.communicationBytes,
          roundResult.durationMs,
          roundResult.dpEpsilonEstimate,
          JSON.stringify(roundResult.metrics),
          now
        );
        const insertClientMetric = db.prepare(
          `INSERT INTO client_metrics (
            id, round_id, client_id, status, rejection_reason, sample_count,
            local_loss, local_accuracy, local_f1, payload_bytes,
            signature_verified, integrity_verified, decryption_verified, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        );
        for (const outcome of roundResult.clientOutcomes) {
          insertClientMetric.run(
            `cm-${roundId}-${outcome.clientId}`,
            roundId,
            outcome.clientId,
            outcome.status,
            outcome.reason ?? null,
            outcome.sampleCount,
            outcome.localLoss,
            outcome.localAccuracy,
            outcome.localF1,
            outcome.payloadBytes,
            outcome.signatureVerified ? 1 : 0,
            outcome.integrityVerified ? 1 : 0,
            outcome.decryptionVerified ? 1 : 0,
            now
          );
          db.prepare("UPDATE federated_clients SET last_seen_at = ? WHERE id = ?").run(now, outcome.clientId);
        }
        federatedJob.currentRound = r;
        federatedJob.message = `Round ${r}/${clampedRounds} aggregated (${roundResult.acceptedClients} accepted, accuracy ${(roundResult.globalAccuracy * 100).toFixed(1)}%)`;
      }
      if (lastRoundResult) {
        const modelId = `model-flmlp-${jobId}`;
        db.prepare("UPDATE models SET is_active = 0 WHERE training_paradigm = ?").run("federated");
        db.prepare(
          `INSERT INTO models (
            id, name, architecture, training_paradigm, classification_mode, version, dataset_id,
            accuracy, precision_score, recall_score, f1_score, false_positive_rate, roc_auc,
            training_time_ms, communication_bytes, metrics_json, artifact_json, is_active, created_at
          ) VALUES (?, ?, 'federated_mlp', 'federated', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`
        ).run(
          modelId,
          dpEnabled ? "Federated FedAvg MLP (DP-SGD)" : "Federated FedAvg MLP",
          classificationMode,
          lastRoundResult.modelVersion,
          datasetId,
          lastRoundResult.globalAccuracy,
          lastRoundResult.globalPrecision,
          lastRoundResult.globalRecall,
          lastRoundResult.globalF1,
          lastRoundResult.globalFpr,
          lastRoundResult.globalRocAuc,
          totalDurationMs,
          totalCommBytes,
          JSON.stringify({ ...lastRoundResult.metrics, dpEnabled, dpEpsilonEstimate: lastRoundResult.dpEpsilonEstimate }),
          JSON.stringify({ kind: "mlp", ...globalModel }),
          (/* @__PURE__ */ new Date()).toISOString()
        );
        writeAuditLog(
          actor,
          "RUN_FEDERATED_TRAINING",
          `models/${modelId}`,
          "success",
          `Completed ${clampedRounds} rounds (${classificationMode}, DP=${dpEnabled}) -> Accuracy ${(lastRoundResult.globalAccuracy * 100).toFixed(1)}%`
        );
      }
      federatedJob.status = "completed";
      federatedJob.completedAt = (/* @__PURE__ */ new Date()).toISOString();
    } catch (err) {
      federatedJob.status = "failed";
      federatedJob.message = err.message;
      federatedJob.completedAt = (/* @__PURE__ */ new Date()).toISOString();
    }
  })();
  return res.status(202).json({ job: federatedJob });
});
app.get("/api/security/keys", requireAuth, (_req, res) => {
  const keys = db.prepare(
    `SELECT pk.id, pk.client_id, fc.name as client_name, fc.organization, fc.active as client_active,
              pk.key_id, pk.algorithm, pk.public_key_pem, pk.fingerprint, pk.revoked, pk.revoked_reason,
              pk.created_at, pk.rotated_at
       FROM public_keys pk
       JOIN federated_clients fc ON fc.id = pk.client_id
       ORDER BY pk.created_at ASC`
  ).all();
  return res.json({
    keys: keys.map((k) => ({
      ...k,
      clientActive: k.client_active === 1,
      revoked: k.revoked === 1
    }))
  });
});
app.post("/api/security/keys/:clientId/rotate", requireAuth, requireRole("admin"), (req, res) => {
  const clientId = String(req.params.clientId);
  const client = db.prepare("SELECT id, name FROM federated_clients WHERE id = ?").get(clientId);
  if (!client) return res.status(404).json({ error: "Client not found" });
  const kp = generateAndStoreEd25519KeyPair(clientId, true);
  const now = (/* @__PURE__ */ new Date()).toISOString();
  db.prepare(
    `UPDATE public_keys SET key_id = ?, public_key_pem = ?, fingerprint = ?, revoked = 0, revoked_reason = NULL, rotated_at = ?
     WHERE client_id = ?`
  ).run(kp.keyId, kp.publicKeyPem, kp.fingerprint, now, clientId);
  writeSecurityEvent({
    eventType: "KEY_ROTATED",
    severity: "low",
    clientId,
    description: `Rotated Ed25519 key pair for ${client.name} (new keyId ${kp.keyId})`,
    signatureStatus: "verified",
    integrityStatus: "verified",
    encryptionStatus: "aes-256-gcm",
    blocked: false
  });
  writeAuditLog(
    { email: req.user.email, role: req.user.role },
    "ROTATE_CLIENT_KEY",
    `public_keys/${clientId}`,
    "success",
    `Provisioned new Ed25519 key ${kp.keyId} (fingerprint ${kp.fingerprint.slice(0, 12)})`
  );
  return res.json({ clientId, keyId: kp.keyId, fingerprint: kp.fingerprint, rotatedAt: now });
});
app.post("/api/security/keys/:clientId/revoke", requireAuth, requireRole("admin"), (req, res) => {
  const clientId = String(req.params.clientId);
  const { reason = "Compromised key / administrative revocation" } = req.body;
  const client = db.prepare("SELECT id, name FROM federated_clients WHERE id = ?").get(clientId);
  if (!client) return res.status(404).json({ error: "Client not found" });
  db.prepare("UPDATE public_keys SET revoked = 1, revoked_reason = ? WHERE client_id = ?").run(reason, clientId);
  writeSecurityEvent({
    eventType: "KEY_REVOKED",
    severity: "high",
    clientId,
    description: `Revoked Ed25519 public key for ${client.name}: ${reason}`,
    signatureStatus: "revoked",
    integrityStatus: "n/a",
    encryptionStatus: "n/a",
    blocked: true
  });
  writeAuditLog(
    { email: req.user.email, role: req.user.role },
    "REVOKE_CLIENT_KEY",
    `public_keys/${clientId}`,
    "success",
    reason
  );
  return res.json({ clientId, revoked: true });
});
app.post("/api/security/simulate-attack", requireAuth, requireRole("admin", "analyst"), (req, res) => {
  const {
    attackType,
    clientId = "client-hospital"
  } = req.body;
  if (!attackType) {
    return res.status(400).json({ error: "attackType is required" });
  }
  const activeModelRow = db.prepare("SELECT version, artifact_json FROM models WHERE training_paradigm = 'federated' ORDER BY created_at DESC LIMIT 1").get();
  if (!activeModelRow) {
    return res.status(400).json({ error: "No federated model found" });
  }
  const baseModel = JSON.parse(activeModelRow.artifact_json);
  const clientRow = db.prepare(
    `SELECT fc.id, fc.name, fc.organization, fc.active, pk.public_key_pem, pk.revoked
       FROM federated_clients fc LEFT JOIN public_keys pk ON pk.client_id = fc.id WHERE fc.id = ?`
  ).get(clientId);
  const privateKeyPem = loadClientPrivateKey(clientId);
  if (!clientRow || !privateKeyPem) {
    return res.status(404).json({ error: "Target client or local key missing" });
  }
  const cleanPayload = {
    weights: baseModel.weights,
    biases: baseModel.biases,
    localLoss: 0.21,
    localAccuracy: 0.93,
    localF1: 0.92
  };
  const descriptor = {
    id: clientRow.id,
    name: clientRow.name,
    organization: clientRow.organization,
    active: clientRow.active === 1,
    publicKeyPem: clientRow.public_key_pem,
    keyRevoked: clientRow.revoked === 1
  };
  let verificationResult;
  let eventType = "";
  if (attackType === "tamper_payload") {
    const env = buildSignedEncryptedEnvelope({
      clientId,
      round: 99,
      modelVersion: activeModelRow.version,
      sampleCount: 140,
      payload: cleanPayload,
      privateKeyPem
    });
    const tamperedBytes = Buffer.from(env.ciphertextBase64, "base64");
    tamperedBytes[0] = tamperedBytes[0] ^ 255;
    env.ciphertextBase64 = tamperedBytes.toString("base64");
    verificationResult = processIncomingClientEnvelope({
      envelope: env,
      client: descriptor,
      expectedModel: baseModel,
      expectedModelVersion: activeModelRow.version,
      expectedRound: 99,
      replayGuard
    });
    eventType = "PAYLOAD_TAMPER_REJECTED";
  } else if (attackType === "replay_nonce") {
    const fixedNonce = crypto2.randomBytes(12).toString("hex");
    const env1 = buildSignedEncryptedEnvelope({
      clientId,
      round: 99,
      modelVersion: activeModelRow.version,
      sampleCount: 140,
      payload: cleanPayload,
      privateKeyPem,
      forcedNonce: fixedNonce
    });
    processIncomingClientEnvelope({
      envelope: env1,
      client: descriptor,
      expectedModel: baseModel,
      expectedModelVersion: activeModelRow.version,
      expectedRound: 99,
      replayGuard
    });
    verificationResult = processIncomingClientEnvelope({
      envelope: env1,
      client: descriptor,
      expectedModel: baseModel,
      expectedModelVersion: activeModelRow.version,
      expectedRound: 99,
      replayGuard
    });
    eventType = "REPLAY_ATTACK_REJECTED";
  } else if (attackType === "unauthorized_client") {
    const rogueKp = generateAndStoreEd25519KeyPair("rogue-unregistered", false);
    const env = buildSignedEncryptedEnvelope({
      clientId: "rogue-node-99",
      round: 99,
      modelVersion: activeModelRow.version,
      sampleCount: 140,
      payload: cleanPayload,
      privateKeyPem: rogueKp.privateKeyPem
    });
    verificationResult = processIncomingClientEnvelope({
      envelope: env,
      client: void 0,
      expectedModel: baseModel,
      expectedModelVersion: activeModelRow.version,
      expectedRound: 99,
      replayGuard
    });
    eventType = "UNAUTHORIZED_CLIENT_REJECTED";
  } else {
    const poisonedWeights = baseModel.weights.map((l) => l.map((r) => [...r]));
    poisonedWeights[0][0][0] = 999999;
    const env = buildSignedEncryptedEnvelope({
      clientId,
      round: 99,
      modelVersion: activeModelRow.version,
      sampleCount: 140,
      payload: { ...cleanPayload, weights: poisonedWeights },
      privateKeyPem
    });
    verificationResult = processIncomingClientEnvelope({
      envelope: env,
      client: descriptor,
      expectedModel: baseModel,
      expectedModelVersion: activeModelRow.version,
      expectedRound: 99,
      replayGuard
    });
    eventType = "POISONED_UPDATE_REJECTED";
  }
  writeSecurityEvent({
    eventType,
    severity: "critical",
    clientId: attackType === "unauthorized_client" ? "rogue-node-99" : clientId,
    description: verificationResult.reason || "Adversarial update blocked by coordinator",
    signatureStatus: verificationResult.signatureVerified ? "verified" : "failed",
    integrityStatus: verificationResult.integrityVerified ? "verified" : "failed",
    encryptionStatus: verificationResult.decryptionVerified ? "aes-256-gcm" : "failed",
    blocked: !verificationResult.accepted
  });
  writeAuditLog(
    { email: req.user.email, role: req.user.role },
    "SECURITY_VERIFICATION_TEST",
    `security/simulate-attack/${attackType}`,
    "success",
    `Verified coordinator blocked ${attackType}: ${verificationResult.reason}`
  );
  return res.json({
    attackType,
    blocked: !verificationResult.accepted,
    code: verificationResult.code,
    reason: verificationResult.reason,
    signatureVerified: verificationResult.signatureVerified,
    decryptionVerified: verificationResult.decryptionVerified,
    integrityVerified: verificationResult.integrityVerified
  });
});
app.get("/api/security/events", requireAuth, (_req, res) => {
  const events = db.prepare("SELECT * FROM security_events ORDER BY created_at DESC LIMIT 80").all();
  return res.json({ events });
});
app.get("/api/security/audit-logs", requireAuth, (_req, res) => {
  const logs = db.prepare("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 100").all();
  return res.json({ logs });
});
app.post("/api/inference/predict", requireAuth, requireRole("admin", "analyst"), (req, res) => {
  const { record, modelId, clientSensor = "Lab-Sensor-01" } = req.body;
  if (!record) return res.status(400).json({ error: "Flow record is required" });
  const modelRow = modelId ? db.prepare("SELECT id, name, architecture, artifact_json FROM models WHERE id = ?").get(modelId) : db.prepare("SELECT id, name, architecture, artifact_json FROM models WHERE is_active = 1 ORDER BY created_at DESC LIMIT 1").get();
  if (!modelRow) return res.status(404).json({ error: "No trained model available" });
  const [result] = runModelInference(modelRow, [record]);
  const predId = `pred-${crypto2.randomUUID().slice(0, 8)}`;
  const now = (/* @__PURE__ */ new Date()).toISOString();
  db.prepare(
    `INSERT INTO predictions (
      id, batch_id, model_id, client_sensor, ingestion_mode,
      predicted_label, true_label, is_malicious, confidence, severity,
      flow_duration, flow_bytes_per_sec, syn_flag_count, created_at
    ) VALUES (?, ?, ?, ?, 'single_api', ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    predId,
    `single-${predId}`,
    modelRow.id,
    clientSensor,
    result.predictedLabel,
    record.label ?? null,
    result.isMalicious ? 1 : 0,
    result.confidence,
    result.severity,
    record.flow_duration,
    record.flow_bytes_per_sec,
    record.syn_flag_count,
    now
  );
  if (result.isMalicious) {
    db.prepare(
      `INSERT INTO alerts (id, prediction_id, client_sensor, attack_category, severity, confidence, status, summary, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?)`
    ).run(
      `alert-${crypto2.randomUUID().slice(0, 8)}`,
      predId,
      clientSensor,
      result.predictedLabel,
      result.severity,
      result.confidence,
      `${result.predictedLabel} flow flagged on ${clientSensor} (${(result.confidence * 100).toFixed(1)}% confidence)`,
      now
    );
  }
  return res.json({ id: predId, modelName: modelRow.name, ...result });
});
app.post("/api/inference/batch", requireAuth, requireRole("admin", "analyst"), (req, res) => {
  try {
    const {
      csvText,
      useSyntheticSample = false,
      modelId,
      classificationMode = "multiclass",
      clientSensor = "Offline-CSV-Upload"
    } = req.body;
    let records = [];
    if (useSyntheticSample) {
      records = generateSyntheticCicIdsDataset(180, Math.floor(Date.now() % 1e4));
    } else if (csvText && typeof csvText === "string") {
      const parsed = parseAndCleanCsv(csvText);
      records = parsed.records;
    } else {
      return res.status(400).json({ error: "Provide csvText or set useSyntheticSample=true" });
    }
    if (records.length === 0) {
      return res.status(400).json({ error: "No valid records to classify" });
    }
    let modelRow = modelId ? db.prepare("SELECT id, name, architecture, classification_mode, artifact_json FROM models WHERE id = ?").get(modelId) : db.prepare(
      "SELECT id, name, architecture, classification_mode, artifact_json FROM models WHERE classification_mode = ? ORDER BY is_active DESC, created_at DESC LIMIT 1"
    ).get(classificationMode);
    if (!modelRow) {
      modelRow = db.prepare("SELECT id, name, architecture, classification_mode, artifact_json FROM models ORDER BY is_active DESC, created_at DESC LIMIT 1").get();
    }
    if (!modelRow) return res.status(404).json({ error: "No trained models available" });
    const artifact = JSON.parse(modelRow.artifact_json);
    const scaled = records.map(
      (rec) => artifact.scaler.featureNames.map((fn, idx) => {
        const val = Number(rec[fn] ?? 0);
        return (val - artifact.scaler.means[idx]) / artifact.scaler.stds[idx];
      })
    );
    const probs = artifact.kind === "random_forest" ? predictRandomForestProbs(artifact, scaled) : artifact.kind === "logistic_regression" ? predictLogisticRegressionProbs(artifact, scaled) : predictMLPProbs(artifact, scaled);
    const batchId = `batch-${crypto2.randomUUID().slice(0, 8)}`;
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const insertPred = db.prepare(
      `INSERT INTO predictions (
        id, batch_id, model_id, client_sensor, ingestion_mode,
        predicted_label, true_label, is_malicious, confidence, severity,
        flow_duration, flow_bytes_per_sec, syn_flag_count, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
    const insertAlert = db.prepare(
      `INSERT INTO alerts (
        id, prediction_id, client_sensor, attack_category, severity, confidence, status, summary, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?)`
    );
    const labeledIndices = [];
    const yTrue = [];
    const labeledProbs = [];
    const classes = classificationMode === "binary" && artifact.classes.length > 2 ? ["Benign", "Malicious"] : artifact.classes;
    const rowsOut = records.map((rec, i) => {
      const p = probs[i];
      let best = 0;
      for (let c = 1; c < p.length; c++) {
        if (p[c] > p[best]) best = c;
      }
      const rawPredLabel = artifact.classes[best];
      const predLabel = classificationMode === "binary" ? rawPredLabel === "Benign" ? "Benign" : "Malicious" : rawPredLabel;
      const confidence = classificationMode === "binary" && artifact.classes.length > 2 ? Number((rawPredLabel === "Benign" ? p[0] : 1 - p[0]).toFixed(4)) : Number(p[best].toFixed(4));
      const isMalicious = predLabel !== "Benign";
      const severity = computeSeverity(rawPredLabel, confidence);
      const predId = `pred-${batchId}-${i}`;
      if (rec.label) {
        const mappedTrue = classificationMode === "binary" ? rec.label === "Benign" ? "Benign" : "Malicious" : rec.label;
        const idx = classes.indexOf(mappedTrue);
        if (idx !== -1) {
          labeledIndices.push(i);
          yTrue.push(idx);
          if (classificationMode === "binary" && artifact.classes.length > 2) {
            const benignIdx = Math.max(0, artifact.classes.indexOf("Benign"));
            const pBenign = p[benignIdx] ?? 0;
            labeledProbs.push([pBenign, 1 - pBenign]);
          } else {
            labeledProbs.push(p);
          }
        }
      }
      if (i < 120) {
        insertPred.run(
          predId,
          batchId,
          modelRow.id,
          clientSensor,
          useSyntheticSample ? "synthetic_batch_csv" : "uploaded_csv",
          predLabel,
          rec.label ?? null,
          isMalicious ? 1 : 0,
          confidence,
          severity,
          rec.flow_duration,
          rec.flow_bytes_per_sec,
          rec.syn_flag_count,
          now
        );
        if (isMalicious && i < 60) {
          insertAlert.run(
            `alert-${predId}`,
            predId,
            clientSensor,
            rawPredLabel,
            severity,
            confidence,
            `${rawPredLabel} detected in CSV batch (${(confidence * 100).toFixed(1)}% confidence)`,
            now
          );
        }
      }
      return {
        id: predId,
        predictedLabel: predLabel,
        rawCategory: rawPredLabel,
        trueLabel: rec.label ?? null,
        isMalicious,
        confidence,
        severity,
        flowDuration: rec.flow_duration,
        flowBytesPerSec: rec.flow_bytes_per_sec,
        synFlagCount: rec.syn_flag_count,
        totalFwdPackets: rec.total_fwd_packets
      };
    });
    const evaluation = yTrue.length > 0 ? evaluatePredictions({
      yTrue,
      probs: labeledProbs,
      classes
    }) : null;
    writeAuditLog(
      { email: req.user.email, role: req.user.role },
      "RUN_BATCH_INFERENCE",
      `inference/${batchId}`,
      "success",
      `Classified ${records.length} flows using ${modelRow.name} (${classificationMode})`
    );
    return res.json({
      batchId,
      modelUsed: { id: modelRow.id, name: modelRow.name, architecture: modelRow.architecture },
      totalRecords: rowsOut.length,
      maliciousCount: rowsOut.filter((r) => r.isMalicious).length,
      benignCount: rowsOut.filter((r) => !r.isMalicious).length,
      predictions: rowsOut,
      evaluation
    });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});
app.post("/api/monitoring/stream-tick", requireAuth, requireRole("admin", "analyst"), (req, res) => {
  const { count = 8 } = req.body;
  const n = Math.min(24, Math.max(1, Number(count)));
  const modelRow = db.prepare("SELECT id, name, architecture, artifact_json FROM models WHERE is_active = 1 ORDER BY created_at DESC LIMIT 1").get();
  if (!modelRow) return res.status(404).json({ error: "No active model found" });
  const sensors = ["Hospital-East", "FinTech-Core", "Campus-Net", "Cloud-Edge", "Telecom-West"];
  const flows = generateSyntheticCicIdsDataset(n, Math.floor(Date.now() % 1e5));
  const preds = runModelInference(modelRow, flows);
  const now = (/* @__PURE__ */ new Date()).toISOString();
  const insertPred = db.prepare(
    `INSERT INTO predictions (
      id, batch_id, model_id, client_sensor, ingestion_mode,
      predicted_label, true_label, is_malicious, confidence, severity,
      flow_duration, flow_bytes_per_sec, syn_flag_count, created_at
    ) VALUES (?, ?, ?, ?, 'simulated_flow_adapter', ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );
  const insertAlert = db.prepare(
    `INSERT INTO alerts (
      id, prediction_id, client_sensor, attack_category, severity, confidence, status, summary, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?)`
  );
  const created = flows.map((flow, i) => {
    const p = preds[i];
    const sensor = sensors[(i + Math.floor(Date.now() / 1e3)) % sensors.length];
    const predId = `pred-live-${crypto2.randomUUID().slice(0, 8)}`;
    insertPred.run(
      predId,
      "live-flow-adapter",
      modelRow.id,
      sensor,
      p.predictedLabel,
      flow.label ?? null,
      p.isMalicious ? 1 : 0,
      p.confidence,
      p.severity,
      flow.flow_duration,
      flow.flow_bytes_per_sec,
      flow.syn_flag_count,
      now
    );
    if (p.isMalicious) {
      insertAlert.run(
        `alert-${predId}`,
        predId,
        sensor,
        p.predictedLabel,
        p.severity,
        p.confidence,
        `${p.predictedLabel} flagged by flow adapter on ${sensor} (${(p.confidence * 100).toFixed(1)}%)`,
        now
      );
    }
    return { id: predId, sensor, ...p, createdAt: now };
  });
  return res.json({ ingested: created.length, records: created });
});
app.get("/api/alerts", requireAuth, (req, res) => {
  const severity = req.query.severity ? String(req.query.severity) : null;
  const status = req.query.status ? String(req.query.status) : null;
  const query = "SELECT * FROM alerts ORDER BY created_at DESC LIMIT 150";
  let rows = db.prepare(query).all();
  if (severity && severity !== "all") {
    rows = rows.filter((r) => r.severity === severity);
  }
  if (status && status !== "all") {
    rows = rows.filter((r) => r.status === status);
  }
  return res.json({ alerts: rows });
});
app.post("/api/alerts/:id/ack", requireAuth, requireRole("admin", "analyst"), (req, res) => {
  const id = String(req.params.id);
  const existing = db.prepare("SELECT id, status FROM alerts WHERE id = ?").get(id);
  if (!existing) return res.status(404).json({ error: "Alert not found" });
  const nextStatus = existing.status === "acknowledged" ? "open" : "acknowledged";
  db.prepare("UPDATE alerts SET status = ? WHERE id = ?").run(nextStatus, id);
  writeAuditLog(
    { email: req.user.email, role: req.user.role },
    "UPDATE_ALERT_STATUS",
    `alerts/${id}`,
    "success",
    `Set alert status to ${nextStatus}`
  );
  return res.json({ id, status: nextStatus });
});
app.get("/api/metrics", requireAuth, (_req, res) => {
  const models = db.prepare(
    `SELECT id, name, architecture, training_paradigm, classification_mode, version,
              accuracy, precision_score, recall_score, f1_score, false_positive_rate, roc_auc,
              training_time_ms, communication_bytes, metrics_json, is_active, created_at
       FROM models ORDER BY created_at DESC`
  ).all();
  const attackDist = db.prepare(
    `SELECT predicted_label as category, COUNT(*) as count
       FROM predictions GROUP BY predicted_label ORDER BY count DESC`
  ).all();
  const sensorActivity = db.prepare(
    `SELECT client_sensor as sensor,
              COUNT(*) as total,
              SUM(CASE WHEN is_malicious = 1 THEN 1 ELSE 0 END) as malicious,
              SUM(CASE WHEN is_malicious = 0 THEN 1 ELSE 0 END) as benign
       FROM predictions GROUP BY client_sensor ORDER BY total DESC`
  ).all();
  const severityDist = db.prepare(
    `SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity`
  ).all();
  const timeline = db.prepare(
    `SELECT substr(created_at, 1, 16) as bucket,
              SUM(CASE WHEN is_malicious = 1 THEN 1 ELSE 0 END) as malicious,
              SUM(CASE WHEN is_malicious = 0 THEN 1 ELSE 0 END) as benign
       FROM predictions
       GROUP BY substr(created_at, 1, 16)
       ORDER BY bucket ASC
       LIMIT 24`
  ).all();
  return res.json({
    models: models.map((m) => ({
      ...m,
      isActive: m.is_active === 1,
      metrics: JSON.parse(String(m.metrics_json))
    })),
    attackDistribution: attackDist,
    sensorActivity,
    severityDistribution: severityDist,
    timeline
  });
});
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const { createServer: createViteServer } = await import("vite");
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa"
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path3.resolve(process.cwd(), "dist");
    app.use(express.static(distDir));
    app.get("*", (_req, res) => {
      res.sendFile(path3.join(distDir, "index.html"));
    });
  }
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`FL-IDS server listening on http://0.0.0.0:${PORT}`);
  });
}
startServer();
