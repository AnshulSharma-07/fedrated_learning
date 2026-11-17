import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  buildSignedEncryptedEnvelope,
  generateAndStoreEd25519KeyPair,
  hashPassword,
  ReplayGuard,
  signJwt,
  verifyAndDecryptEnvelope,
  verifyJwt,
  verifyPassword,
} from './crypto';
import {
  generateSyntheticCicIdsDataset,
  parseAndCleanCsv,
  partitionNonIid,
  prepareStratifiedSplit,
} from './dataset';
import {
  evaluatePredictions,
  initializeMLPWeights,
  predictLogisticRegressionProbs,
  predictMLPProbs,
  predictRandomForestProbs,
  trainLogisticRegression,
  trainMLPEpochs,
  trainRandomForest,
} from './ml';
import {
  fedAvgAggregate,
  processIncomingClientEnvelope,
  validateWeightPayload,
} from './federated';

test('dataset cleaner removes missing, infinite, duplicates, and identifier leakage columns', () => {
  const csv = [
    'Flow ID,Source IP,Destination IP,Timestamp,Flow Duration,Total Fwd Packets,Total Backward Packets,Fwd Packet Length Mean,Bwd Packet Length Mean,Flow Bytes/s,Flow Packets/s,SYN Flag Count,ACK Flag Count,RST Flag Count,PSH Flag Count,Flow IAT Mean,Init_Win_bytes_forward,Subflow Fwd Bytes,Label',
    '1,10.0.0.1,10.0.0.2,2026-01-01,12000,8,6,150,300,24000,1100,1,6,0,2,1200,29200,1200,Benign',
    '2,10.0.0.1,10.0.0.2,2026-01-01,12000,8,6,150,300,24000,1100,1,6,0,2,1200,29200,1200,Benign',
    '3,10.0.0.5,10.0.0.9,2026-01-01,NaN,8,6,150,300,24000,1100,1,6,0,2,1200,29200,1200,DoS Hulk',
    '4,10.0.0.8,10.0.0.9,2026-01-01,5000,20,1,40,10,Infinity,4000,5,0,1,0,250,512,800,DDoS',
    '5,10.0.0.8,10.0.0.9,2026-01-01,5000,20,1,40,10,180000,4000,5,0,1,0,250,512,800,DDoS',
  ].join('\n');

  const { records, report } = parseAndCleanCsv(csv);
  assert.equal(report.rawRows, 5);
  assert.equal(report.cleanRows, 2);
  assert.equal(report.droppedDuplicates, 1);
  assert.equal(report.droppedMissing, 1);
  assert.equal(report.droppedInfinite, 1);
  assert.ok(report.removedLeakageColumns.includes('Flow ID'));
  assert.ok(report.removedLeakageColumns.includes('Source IP'));
  assert.equal(records[0].label, 'Benign');
  assert.equal(records[1].label, 'DoS/DDoS');
});

test('stratified split prevents leakage and non-IID partitioning isolates client samples', () => {
  const data = generateSyntheticCicIdsDataset(360, 7);
  const split = prepareStratifiedSplit(data, 'multiclass', 7);
  assert.ok(split.XTrain.length > 200);
  assert.ok(split.XTest.length > 30);
  assert.equal(split.scaler.means.length, 14);

  const partitions = partitionNonIid(
    split.XTrain,
    split.yTrain,
    split.classes,
    ['c1', 'c2', 'c3'],
    0.5,
    7,
  );
  const totalPartitioned = partitions.reduce((s, p) => s + p.X.length, 0);
  assert.equal(totalPartitioned, split.XTrain.length);
  for (const p of partitions) {
    assert.ok(p.X.length > 0);
  }
});

test('classical ML baselines and MLP achieve real non-trivial accuracy on synthetic CIC-IDS2017', () => {
  const data = generateSyntheticCicIdsDataset(420, 12);
  const split = prepareStratifiedSplit(data, 'binary', 12);

  const rf = trainRandomForest({
    XTrain: split.XTrain,
    yTrain: split.yTrain,
    classes: split.classes,
    mode: 'binary',
    scaler: split.scaler,
    numTrees: 12,
    maxDepth: 6,
    seed: 12,
  });
  const rfMetrics = evaluatePredictions({
    yTrue: split.yTest,
    probs: predictRandomForestProbs(rf, split.XTest),
    classes: split.classes,
  });
  assert.ok(rfMetrics.accuracy > 0.85, `Expected RF accuracy > 0.85, got ${rfMetrics.accuracy}`);
  assert.ok(rfMetrics.rocAuc !== null && rfMetrics.rocAuc > 0.85);

  const lr = trainLogisticRegression({
    XTrain: split.XTrain,
    yTrain: split.yTrain,
    classes: split.classes,
    mode: 'binary',
    scaler: split.scaler,
    classWeights: split.classWeights,
  });
  const lrMetrics = evaluatePredictions({
    yTrue: split.yTest,
    probs: predictLogisticRegressionProbs(lr, split.XTest),
    classes: split.classes,
  });
  assert.ok(lrMetrics.accuracy > 0.80, `Expected LR accuracy > 0.80, got ${lrMetrics.accuracy}`);

  const initMlp = initializeMLPWeights(14, split.classes, 'binary', split.scaler, 12);
  const { model: mlp } = trainMLPEpochs({
    initialModel: initMlp,
    XTrain: split.XTrain,
    yTrain: split.yTrain,
    classWeights: split.classWeights,
    epochs: 18,
    lr: 0.06,
    seed: 12,
  });
  const mlpMetrics = evaluatePredictions({
    yTrue: split.yTest,
    probs: predictMLPProbs(mlp, split.XTest),
    classes: split.classes,
  });
  assert.ok(mlpMetrics.accuracy > 0.85, `Expected MLP accuracy > 0.85, got ${mlpMetrics.accuracy}`);
});

test('FedAvg computes exact sample-weighted average of client weights', () => {
  const data = generateSyntheticCicIdsDataset(100, 3);
  const split = prepareStratifiedSplit(data, 'binary', 3);
  const base = initializeMLPWeights(14, split.classes, 'binary', split.scaler, 3);

  const w1 = base.weights.map((l) => l.map((r) => r.map(() => 1.0)));
  const b1 = base.biases.map((b) => b.map(() => 1.0));
  const w2 = base.weights.map((l) => l.map((r) => r.map(() => 3.0)));
  const b2 = base.biases.map((b) => b.map(() => 3.0));

  // Client 1 has 100 samples (value 1.0), Client 2 has 300 samples (value 3.0) -> weighted avg = 2.5
  const agg = fedAvgAggregate(base, [
    { sampleCount: 100, weights: w1, biases: b1 },
    { sampleCount: 300, weights: w2, biases: b2 },
  ]);
  assert.ok(Math.abs(agg.weights[0][0][0] - 2.5) < 1e-9);
  assert.ok(Math.abs(agg.biases[0][0] - 2.5) < 1e-9);
});

test('Cryptography layer verifies Ed25519, AES-256-GCM, SHA-256 and rejects tampering, replay, invalid tag, unauthorized client, and NaN tensors', () => {
  const data = generateSyntheticCicIdsDataset(100, 5);
  const split = prepareStratifiedSplit(data, 'binary', 5);
  const base = initializeMLPWeights(14, split.classes, 'binary', split.scaler, 5);
  const kp = generateAndStoreEd25519KeyPair('test-client-1', false);

  const payload = {
    weights: base.weights,
    biases: base.biases,
    localLoss: 0.25,
    localAccuracy: 0.92,
    localF1: 0.91,
  };

  const validEnv = buildSignedEncryptedEnvelope({
    clientId: 'test-client-1',
    round: 1,
    modelVersion: 'v1.0.0',
    sampleCount: 120,
    payload,
    privateKeyPem: kp.privateKeyPem,
  });

  const clientDesc = {
    id: 'test-client-1',
    name: 'Test Client',
    organization: 'Lab',
    active: true,
    publicKeyPem: kp.publicKeyPem,
    keyRevoked: false,
  };

  // 1. Valid envelope succeeds
  const replayGuard = new ReplayGuard();
  const okRes = processIncomingClientEnvelope({
    envelope: validEnv,
    client: clientDesc,
    expectedModel: base,
    expectedModelVersion: 'v1.0.0',
    expectedRound: 1,
    replayGuard,
  });
  assert.equal(okRes.accepted, true);

  // 2. Replay attack fails
  const replayRes = processIncomingClientEnvelope({
    envelope: validEnv,
    client: clientDesc,
    expectedModel: base,
    expectedModelVersion: 'v1.0.0',
    expectedRound: 1,
    replayGuard,
  });
  assert.equal(replayRes.accepted, false);
  assert.equal(replayRes.code, 'REPLAY_DETECTED');

  // 3. Payload tampering / invalid signature fails
  const tamperedHashEnv = { ...validEnv, nonce: crypto.randomBytes(12).toString('hex'), payloadSha256: '0'.repeat(64) };
  const sigFail = verifyAndDecryptEnvelope({
    envelope: tamperedHashEnv,
    publicKeyPem: kp.publicKeyPem,
    clientActive: true,
    keyRevoked: false,
    replayGuard: new ReplayGuard(),
  });
  assert.equal(sigFail.ok, false);
  assert.equal(sigFail.code, 'SIGNATURE_INVALID');

  // 4. Invalid AES-256-GCM auth tag fails (re-signed with valid signature but corrupted ciphertext/tag)
  const freshEnv = buildSignedEncryptedEnvelope({
    clientId: 'test-client-1',
    round: 1,
    modelVersion: 'v1.0.0',
    sampleCount: 120,
    payload,
    privateKeyPem: kp.privateKeyPem,
  });
  const badTagEnv = { ...freshEnv, authTagBase64: Buffer.alloc(16, 0xaa).toString('base64') };
  const tagFail = verifyAndDecryptEnvelope({
    envelope: badTagEnv,
    publicKeyPem: kp.publicKeyPem,
    clientActive: true,
    keyRevoked: false,
    replayGuard: new ReplayGuard(),
  });
  assert.equal(tagFail.ok, false);
  assert.equal(tagFail.code, 'DECRYPTION_FAILED');

  // 5. Unauthorized / revoked client fails
  const revokedFail = verifyAndDecryptEnvelope({
    envelope: freshEnv,
    publicKeyPem: kp.publicKeyPem,
    clientActive: true,
    keyRevoked: true,
    replayGuard: new ReplayGuard(),
  });
  assert.equal(revokedFail.ok, false);
  assert.equal(revokedFail.code, 'UNAUTHORIZED_CLIENT');

  // 6. Invalid NaN / dimension update fails validation
  const badWeights = base.weights.map((l) => l.map((r) => [...r]));
  badWeights[0][0][0] = Number.NaN;
  const nanCheck = validateWeightPayload({ ...payload, weights: badWeights }, base);
  assert.equal(nanCheck.valid, false);
});

test('Password hashing and JWT authentication verify and reject invalid credentials', () => {
  const hash = hashPassword('StrongPass123!');
  assert.equal(verifyPassword('StrongPass123!', hash), true);
  assert.equal(verifyPassword('WrongPass', hash), false);

  const token = signJwt({ sub: 'u1', email: 'a@b.com', name: 'Admin', role: 'admin' });
  const decoded = verifyJwt(token);
  assert.ok(decoded !== null);
  assert.equal(decoded?.role, 'admin');
  assert.equal(verifyJwt(`${token}tampered`), null);
});
