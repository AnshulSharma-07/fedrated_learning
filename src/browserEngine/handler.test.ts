import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildSignedEncryptedEnvelopeWeb,
  generateWebSigningKeyPair,
  verifyAndDecryptEnvelopeWeb,
  WebReplayGuard,
} from './webCrypto';
import { handleBrowserApiRequest } from './handler';

test('WebCrypto Ed25519 + AES-256-GCM + SHA-256 verifies valid envelopes and rejects tampering and replay', async () => {
  const keyMat = await generateWebSigningKeyPair();
  const guard = new WebReplayGuard();

  const env = await buildSignedEncryptedEnvelopeWeb({
    clientId: 'web-client-1',
    round: 1,
    modelVersion: 'v1.0.0',
    sampleCount: 100,
    payload: { weights: [[[0.5, -0.25]]], biases: [[0.1]] },
    keyMaterial: keyMat,
  });

  const okRes = await verifyAndDecryptEnvelopeWeb<{ weights: number[][][] }>({
    envelope: env,
    keyMaterial: keyMat,
    clientActive: true,
    keyRevoked: false,
    replayGuard: guard,
  });
  assert.equal(okRes.ok, true);
  assert.equal(okRes.payload?.weights[0][0][0], 0.5);

  const replayRes = await verifyAndDecryptEnvelopeWeb({
    envelope: env,
    keyMaterial: keyMat,
    clientActive: true,
    keyRevoked: false,
    replayGuard: guard,
  });
  assert.equal(replayRes.ok, false);
  assert.equal(replayRes.code, 'REPLAY_DETECTED');

  const freshEnv = await buildSignedEncryptedEnvelopeWeb({
    clientId: 'web-client-1',
    round: 2,
    modelVersion: 'v1.0.0',
    sampleCount: 100,
    payload: { weights: [[[0.5, -0.25]]], biases: [[0.1]] },
    keyMaterial: keyMat,
  });
  freshEnv.ciphertextBase64 = 'AAAA' + freshEnv.ciphertextBase64.slice(4);
  const tamperRes = await verifyAndDecryptEnvelopeWeb({
    envelope: freshEnv,
    keyMaterial: keyMat,
    clientActive: true,
    keyRevoked: false,
    replayGuard: guard,
  });
  assert.equal(tamperRes.ok, false);
  assert.equal(tamperRes.code, 'DECRYPTION_FAILED');
});

test('Browser static engine executes full auth, overview, batch inference, FedAvg, and crypto attack simulation', async () => {
  const login = await handleBrowserApiRequest<{ token: string; user: { role: string } }>('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email: 'admin@fl-ids.local', password: 'Admin@FLIDS2026!' }),
  });
  assert.equal(login.user.role, 'admin');
  const authHeaders = { Authorization: `Bearer ${login.token}` };

  const overview = await handleBrowserApiRequest<{
    activeFederatedClients: number;
    globalModelVersion: string;
    modelsSummary: Array<{ accuracy: number }>;
  }>('/api/overview', { headers: authHeaders });
  assert.equal(overview.activeFederatedClients, 5);
  assert.ok(overview.modelsSummary.length >= 4);

  const batch = await handleBrowserApiRequest<{
    totalRecords: number;
    evaluation: { accuracy: number } | null;
  }>('/api/inference/batch', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ useSyntheticSample: true, classificationMode: 'multiclass' }),
  });
  assert.equal(batch.totalRecords, 180);
  assert.ok(batch.evaluation && batch.evaluation.accuracy > 0.75);

  const sim = await handleBrowserApiRequest<{ blocked: boolean; code: string }>('/api/security/simulate-attack', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ attackType: 'tamper_payload' }),
  });
  assert.equal(sim.blocked, true);
  assert.equal(sim.code, 'DECRYPTION_FAILED');

  const fl = await handleBrowserApiRequest<{ job: { status: string; currentRound: number } }>('/api/federated/start', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ rounds: 2, localEpochs: 2, classificationMode: 'binary', dpEnabled: true }),
  });
  assert.equal(fl.job.status, 'completed');
  assert.equal(fl.job.currentRound, 2);
});
