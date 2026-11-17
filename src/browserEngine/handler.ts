import {
  CORE_FEATURES,
  generateSyntheticCicIdsDataset,
  parseAndCleanCsv,
  partitionNonIid,
  prepareStratifiedSplit,
  recordsToCsv,
} from '../engine/dataset';
import {
  cloneMLPWeights,
  computeCrossEntropyLoss,
  evaluatePredictions,
  initializeMLPWeights,
  predictLogisticRegressionProbs,
  predictMLPProbs,
  predictRandomForestProbs,
  trainLogisticRegression,
  trainMLPEpochs,
  trainRandomForest,
} from '../engine/ml';
import type {
  ClassificationMode,
  EvaluationMetrics,
  FlowRecord,
  LogisticRegressionModel,
  MLPWeights,
  RandomForestModel,
  UserRole,
} from '../engine/types';
import {
  buildSignedEncryptedEnvelopeWeb,
  generateWebSigningKeyPair,
  verifyAndDecryptEnvelopeWeb,
  WebReplayGuard,
  type WebClientKeyMaterial,
} from './webCrypto';

interface StoredModel {
  id: string;
  name: string;
  architecture: string;
  training_paradigm: string;
  classification_mode: string;
  version: string;
  dataset_id: string;
  accuracy: number;
  precision_score: number;
  recall_score: number;
  f1_score: number;
  false_positive_rate: number;
  roc_auc: number | null;
  training_time_ms: number;
  communication_bytes: number;
  metrics: EvaluationMetrics & { featureImportances?: Record<string, number>; imbalanceRatio?: number };
  artifact: ({ kind: 'mlp' } & MLPWeights) | LogisticRegressionModel | RandomForestModel;
  isActive: boolean;
  created_at: string;
}

interface StoredDataset {
  id: string;
  name: string;
  source_type: string;
  isSynthetic: boolean;
  raw_rows: number;
  clean_rows: number;
  dropped_missing: number;
  dropped_infinite: number;
  dropped_duplicates: number;
  removedLeakageColumns: string[];
  classDistribution: Record<string, number>;
  featureColumns: string[];
  csvText: string;
  created_at: string;
}

interface StoredClient {
  id: string;
  name: string;
  organization: string;
  subnet_cidr: string;
  active: boolean;
  last_seen_at: string;
  created_at: string;
}

interface StoredKeyRecord {
  id: string;
  client_id: string;
  key_id: string;
  algorithm: string;
  public_key_pem: string;
  fingerprint: string;
  revoked: boolean;
  revoked_reason: string | null;
  created_at: string;
  rotated_at: string | null;
}

interface StoredRound {
  id: string;
  job_id: string;
  round_number: number;
  model_version: string;
  classification_mode: string;
  global_loss: number;
  global_accuracy: number;
  global_precision: number;
  global_recall: number;
  global_f1: number;
  global_fpr: number;
  global_roc_auc: number | null;
  participating_clients: number;
  accepted_clients: number;
  rejected_clients: number;
  communication_bytes: number;
  duration_ms: number;
  dp_epsilon_estimate: number | null;
  created_at: string;
  clientOutcomes: Array<{
    id: string;
    client_id: string;
    client_name: string;
    organization: string;
    status: string;
    rejection_reason: string | null;
    sample_count: number;
    local_loss: number;
    local_accuracy: number;
    local_f1: number;
    payload_bytes: number;
    signatureVerified: boolean;
    integrityVerified: boolean;
    decryptionVerified: boolean;
  }>;
}

interface StoredPrediction {
  id: string;
  batch_id: string;
  model_id: string;
  client_sensor: string;
  ingestion_mode: string;
  predicted_label: string;
  true_label: string | null;
  is_malicious: boolean;
  confidence: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  flow_duration: number;
  flow_bytes_per_sec: number;
  syn_flag_count: number;
  created_at: string;
}

interface StoredAlert {
  id: string;
  prediction_id: string | null;
  client_sensor: string;
  attack_category: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  status: 'open' | 'acknowledged';
  summary: string;
  created_at: string;
}

interface StoredSecurityEvent {
  id: string;
  event_type: string;
  severity: string;
  client_id: string | null;
  description: string;
  signature_status: string;
  integrity_status: string;
  encryption_status: string;
  blocked: number;
  created_at: string;
}

interface StoredAuditLog {
  id: string;
  actor_email: string;
  actor_role: string;
  action: string;
  resource: string;
  outcome: string;
  details: string;
  created_at: string;
}

interface BrowserState {
  initialized: boolean;
  datasets: StoredDataset[];
  models: StoredModel[];
  clients: StoredClient[];
  publicKeys: StoredKeyRecord[];
  rounds: StoredRound[];
  predictions: StoredPrediction[];
  alerts: StoredAlert[];
  securityEvents: StoredSecurityEvent[];
  auditLogs: StoredAuditLog[];
  federatedJob: {
    jobId: string;
    status: 'idle' | 'running' | 'completed' | 'failed';
    totalRounds: number;
    currentRound: number;
    classificationMode: ClassificationMode;
    dpEnabled: boolean;
    message: string;
  };
  trainingJobs: Record<
    string,
    { jobId: string; status: 'running' | 'completed' | 'failed'; modelId: string | null; message: string }
  >;
}

const STORAGE_KEY = 'fl_ids_static_state_v1';

const DEMO_USERS: Record<
  string,
  { id: string; email: string; name: string; password: string; role: UserRole; permissions: string[] }
> = {
  'admin@fl-ids.local': {
    id: 'user-admin',
    email: 'admin@fl-ids.local',
    name: 'Security Admin',
    password: 'Admin@FLIDS2026!',
    role: 'admin',
    permissions: ['read', 'upload_dataset', 'train_models', 'run_federated', 'manage_keys', 'run_inference', 'manage_alerts'],
  },
  'analyst@fl-ids.local': {
    id: 'user-analyst',
    email: 'analyst@fl-ids.local',
    name: 'SOC Analyst',
    password: 'Analyst@FLIDS2026!',
    role: 'analyst',
    permissions: ['read', 'upload_dataset', 'run_inference', 'manage_alerts'],
  },
};

const state: BrowserState = {
  initialized: false,
  datasets: [],
  models: [],
  clients: [],
  publicKeys: [],
  rounds: [],
  predictions: [],
  alerts: [],
  securityEvents: [],
  auditLogs: [],
  federatedJob: {
    jobId: 'fl-job-seed-001',
    status: 'completed',
    totalRounds: 5,
    currentRound: 5,
    classificationMode: 'multiclass',
    dpEnabled: false,
    message: 'Initial 5-round federated run completed',
  },
  trainingJobs: {},
};

const clientCryptoKeys = new Map<string, WebClientKeyMaterial>();
const replayGuard = new WebReplayGuard();
let initPromise: Promise<void> | null = null;

function randomId(prefix: string): string {
  const bytes = new Uint8Array(4);
  globalThis.crypto.getRandomValues(bytes);
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `${prefix}-${hex}`;
}

function saveStateToStorage(): void {
  try {
    if (typeof localStorage === 'undefined') return;
    // Persist lightweight state snapshot; re-runs seamlessly if quota is tight
    const compact = {
      ...state,
      predictions: state.predictions.slice(0, 120),
      alerts: state.alerts.slice(0, 100),
      rounds: state.rounds.slice(-15),
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(compact));
  } catch {
    // Ignore storage quota errors cleanly
  }
}

function computeSeverity(label: string, confidence: number): 'low' | 'medium' | 'high' | 'critical' {
  if (label === 'Benign') return 'low';
  if ((label === 'DoS/DDoS' || label === 'Botnet') && confidence >= 0.85) return 'critical';
  if (label === 'DoS/DDoS' || label === 'Botnet' || confidence >= 0.85) return 'high';
  return 'medium';
}

function validateWeightPayloadWeb(
  payload: { weights: number[][][]; biases: number[][] },
  expected: MLPWeights,
): { valid: boolean; reason?: string } {
  if (!payload || !Array.isArray(payload.weights) || !Array.isArray(payload.biases)) {
    return { valid: false, reason: 'Malformed weight update structure' };
  }
  if (payload.weights.length !== expected.weights.length || payload.biases.length !== expected.biases.length) {
    return { valid: false, reason: 'Layer count mismatch' };
  }
  let sqNorm = 0;
  for (let l = 0; l < expected.weights.length; l++) {
    for (let o = 0; o < expected.weights[l].length; o++) {
      const bVal = payload.biases[l][o];
      if (typeof bVal !== 'number' || !Number.isFinite(bVal)) {
        return { valid: false, reason: `Non-finite bias in layer ${l}` };
      }
      sqNorm += bVal * bVal;
      for (let i = 0; i < expected.weights[l][o].length; i++) {
        const wVal = payload.weights[l][o][i];
        if (typeof wVal !== 'number' || !Number.isFinite(wVal)) {
          return { valid: false, reason: `Non-finite weight (NaN/Inf) in layer ${l}` };
        }
        sqNorm += wVal * wVal;
      }
    }
  }
  if (Math.sqrt(sqNorm) > 5000) {
    return { valid: false, reason: 'Weight norm exceeds safe bound (potential poisoning spike)' };
  }
  return { valid: true };
}

function fedAvgAggregateWeb(
  baseModel: MLPWeights,
  updates: Array<{ sampleCount: number; weights: number[][][]; biases: number[][] }>,
): MLPWeights {
  const totalSamples = updates.reduce((s, u) => s + u.sampleCount, 0);
  const next = cloneMLPWeights(baseModel);
  for (let l = 0; l < next.weights.length; l++) {
    for (let o = 0; o < next.weights[l].length; o++) {
      let bAcc = 0;
      for (const u of updates) bAcc += (u.sampleCount / totalSamples) * u.biases[l][o];
      next.biases[l][o] = bAcc;
      for (let i = 0; i < next.weights[l][o].length; i++) {
        let wAcc = 0;
        for (const u of updates) wAcc += (u.sampleCount / totalSamples) * u.weights[l][o][i];
        next.weights[l][o][i] = wAcc;
      }
    }
  }
  return next;
}

async function ensureClientCryptoKeys(): Promise<void> {
  for (const client of state.clients) {
    if (!clientCryptoKeys.has(client.id)) {
      const kp = await generateWebSigningKeyPair();
      clientCryptoKeys.set(client.id, kp);
      const existingKey = state.publicKeys.find((k) => k.client_id === client.id);
      if (existingKey) {
        existingKey.key_id = kp.keyId;
        existingKey.algorithm = kp.algorithm;
        existingKey.public_key_pem = kp.publicKeyPem;
        existingKey.fingerprint = kp.fingerprint;
      } else {
        state.publicKeys.push({
          id: `pk-${client.id}`,
          client_id: client.id,
          key_id: kp.keyId,
          algorithm: kp.algorithm,
          public_key_pem: kp.publicKeyPem,
          fingerprint: kp.fingerprint,
          revoked: false,
          revoked_reason: null,
          created_at: client.created_at,
          rotated_at: null,
        });
      }
    }
  }
}

async function runFederatedRoundsBrowser(params: {
  jobId: string;
  records: FlowRecord[];
  rounds: number;
  localEpochs: number;
  learningRate: number;
  nonIidAlpha: number;
  classificationMode: ClassificationMode;
  dpEnabled: boolean;
  dpClipNorm: number;
  dpNoiseMultiplier: number;
  seed: number;
  datasetId: string;
  versionPrefix: string;
  actor?: { email: string; role: string };
}): Promise<void> {
  await ensureClientCryptoKeys();
  const split = prepareStratifiedSplit(params.records, params.classificationMode, params.seed);
  const activeClients = state.clients.filter((c) => c.active);
  if (activeClients.length < 2) {
    throw new Error('At least 2 active federated clients are required for FedAvg');
  }

  const partitionsArr = partitionNonIid(
    split.XTrain,
    split.yTrain,
    split.classes,
    activeClients.map((c) => c.id),
    params.nonIidAlpha,
    params.seed,
  );
  const partitions = new Map(partitionsArr.map((p) => [p.clientId, p]));
  let globalModel = initializeMLPWeights(
    split.XTrain[0].length,
    split.classes,
    params.classificationMode,
    split.scaler,
    params.seed,
  );

  let totalTime = 0;
  let totalCommBytes = 0;
  let lastMetrics: EvaluationMetrics | null = null;
  let lastVersion = `${params.versionPrefix}.0`;

  for (let r = 1; r <= params.rounds; r++) {
    const start = Date.now();
    const prevVer = `${params.versionPrefix}.${r - 1}`;
    const nextVer = `${params.versionPrefix}.${r}`;
    lastVersion = nextVer;

    const globalPayloadBytes = new TextEncoder().encode(
      JSON.stringify({ weights: globalModel.weights, biases: globalModel.biases }),
    ).length;

    const outcomes: StoredRound['clientOutcomes'] = [];
    const validUpdates: Array<{ sampleCount: number; weights: number[][][]; biases: number[][] }> = [];
    let roundBytes = 0;

    for (let idx = 0; idx < activeClients.length; idx++) {
      const client = activeClients[idx];
      const part = partitions.get(client.id);
      if (!part || part.X.length === 0) continue;

      const { model: localModel, finalLoss } = trainMLPEpochs({
        initialModel: globalModel,
        XTrain: part.X,
        yTrain: part.y,
        classWeights: split.classWeights,
        epochs: params.localEpochs,
        lr: params.learningRate,
        dpClipNorm: params.dpEnabled ? params.dpClipNorm : null,
        dpNoiseMultiplier: params.dpEnabled ? params.dpNoiseMultiplier : null,
        seed: params.seed + r * 100 + idx,
      });

      const localProbs = predictMLPProbs(localModel, part.X);
      const localMetrics = evaluatePredictions({
        yTrue: part.y,
        probs: localProbs,
        classes: globalModel.classes,
        loss: finalLoss,
      });

      const keyMat = clientCryptoKeys.get(client.id) || null;
      const keyRec = state.publicKeys.find((k) => k.client_id === client.id);
      if (!keyMat) continue;

      const payload = {
        weights: localModel.weights,
        biases: localModel.biases,
        localLoss: finalLoss,
        localAccuracy: localMetrics.accuracy,
        localF1: localMetrics.f1Score,
      };

      const envelope = await buildSignedEncryptedEnvelopeWeb({
        clientId: client.id,
        round: r,
        modelVersion: prevVer,
        sampleCount: part.X.length,
        payload,
        keyMaterial: keyMat,
      });

      const envBytes = new TextEncoder().encode(JSON.stringify(envelope)).length;
      roundBytes += globalPayloadBytes + envBytes;

      const verRes = await verifyAndDecryptEnvelopeWeb<typeof payload>({
        envelope,
        keyMaterial: keyMat,
        clientActive: client.active,
        keyRevoked: Boolean(keyRec?.revoked),
        replayGuard,
      });

      if (!verRes.ok || !verRes.payload) {
        outcomes.push({
          id: randomId('cm'),
          client_id: client.id,
          client_name: client.name,
          organization: client.organization,
          status: 'rejected',
          rejection_reason: verRes.reason || 'Cryptographic check failed',
          sample_count: part.X.length,
          local_loss: finalLoss,
          local_accuracy: localMetrics.accuracy,
          local_f1: localMetrics.f1Score,
          payload_bytes: envBytes,
          signatureVerified: verRes.signatureVerified,
          integrityVerified: verRes.integrityVerified,
          decryptionVerified: verRes.decryptionVerified,
        });
        state.securityEvents.unshift({
          id: randomId('sec'),
          event_type: verRes.code || 'REJECTED',
          severity: 'high',
          client_id: client.id,
          description: `Round ${r} update from ${client.name} rejected: ${verRes.reason}`,
          signature_status: verRes.signatureVerified ? 'verified' : 'failed',
          integrity_status: verRes.integrityVerified ? 'verified' : 'failed',
          encryption_status: verRes.decryptionVerified ? 'aes-256-gcm' : 'failed',
          blocked: 1,
          created_at: new Date().toISOString(),
        });
        continue;
      }

      const shapeCheck = validateWeightPayloadWeb(verRes.payload, globalModel);
      if (!shapeCheck.valid) {
        outcomes.push({
          id: randomId('cm'),
          client_id: client.id,
          client_name: client.name,
          organization: client.organization,
          status: 'rejected',
          rejection_reason: shapeCheck.reason || 'Invalid tensor',
          sample_count: part.X.length,
          local_loss: finalLoss,
          local_accuracy: localMetrics.accuracy,
          local_f1: localMetrics.f1Score,
          payload_bytes: envBytes,
          signatureVerified: true,
          integrityVerified: true,
          decryptionVerified: true,
        });
        continue;
      }

      validUpdates.push({
        sampleCount: part.X.length,
        weights: verRes.payload.weights,
        biases: verRes.payload.biases,
      });
      outcomes.push({
        id: randomId('cm'),
        client_id: client.id,
        client_name: client.name,
        organization: client.organization,
        status: 'accepted',
        rejection_reason: null,
        sample_count: part.X.length,
        local_loss: finalLoss,
        local_accuracy: localMetrics.accuracy,
        local_f1: localMetrics.f1Score,
        payload_bytes: envBytes,
        signatureVerified: true,
        integrityVerified: true,
        decryptionVerified: true,
      });
      client.last_seen_at = new Date().toISOString();
    }

    if (validUpdates.length > 0) {
      globalModel = fedAvgAggregateWeb(globalModel, validUpdates);
    }

    const testProbs = predictMLPProbs(globalModel, split.XTest);
    const testLoss = computeCrossEntropyLoss(testProbs, split.yTest, split.classWeights);
    const durationMs = Math.max(1, Date.now() - start);
    const metrics = evaluatePredictions({
      yTrue: split.yTest,
      probs: testProbs,
      classes: globalModel.classes,
      loss: testLoss,
      trainingTimeMs: durationMs,
      communicationBytes: roundBytes,
    });

    totalTime += durationMs;
    totalCommBytes += roundBytes;
    lastMetrics = metrics;

    const dpEps =
      params.dpEnabled && params.dpNoiseMultiplier > 0
        ? Number(((r * params.localEpochs * 1.2) / Math.max(0.1, params.dpNoiseMultiplier)).toFixed(2))
        : null;

    state.rounds.push({
      id: `round-${params.jobId}-${r}`,
      job_id: params.jobId,
      round_number: r,
      model_version: nextVer,
      classification_mode: params.classificationMode,
      global_loss: Number(testLoss.toFixed(4)),
      global_accuracy: metrics.accuracy,
      global_precision: metrics.precision,
      global_recall: metrics.recall,
      global_f1: metrics.f1Score,
      global_fpr: metrics.falsePositiveRate,
      global_roc_auc: metrics.rocAuc,
      participating_clients: outcomes.length,
      accepted_clients: validUpdates.length,
      rejected_clients: outcomes.length - validUpdates.length,
      communication_bytes: roundBytes,
      duration_ms: durationMs,
      dp_epsilon_estimate: dpEps,
      created_at: new Date().toISOString(),
      clientOutcomes: outcomes,
    });

    state.federatedJob.currentRound = r;
    state.federatedJob.message = `Round ${r}/${params.rounds} aggregated (${validUpdates.length} accepted, accuracy ${(metrics.accuracy * 100).toFixed(1)}%)`;
  }

  if (lastMetrics) {
    for (const m of state.models) {
      if (m.training_paradigm === 'federated') m.isActive = false;
    }
    const modelId = `model-flmlp-${params.jobId}`;
    state.models.unshift({
      id: modelId,
      name: params.dpEnabled ? 'Federated FedAvg MLP (DP-SGD)' : 'Federated FedAvg MLP',
      architecture: 'federated_mlp',
      training_paradigm: 'federated',
      classification_mode: params.classificationMode,
      version: lastVersion,
      dataset_id: params.datasetId,
      accuracy: lastMetrics.accuracy,
      precision_score: lastMetrics.precision,
      recall_score: lastMetrics.recall,
      f1_score: lastMetrics.f1Score,
      false_positive_rate: lastMetrics.falsePositiveRate,
      roc_auc: lastMetrics.rocAuc,
      training_time_ms: totalTime,
      communication_bytes: totalCommBytes,
      metrics: { ...lastMetrics, imbalanceRatio: split.imbalanceRatio },
      artifact: { kind: 'mlp', ...globalModel },
      isActive: true,
      created_at: new Date().toISOString(),
    });
    if (params.actor) {
      state.auditLogs.unshift({
        id: randomId('audit'),
        actor_email: params.actor.email,
        actor_role: params.actor.role,
        action: 'RUN_FEDERATED_TRAINING',
        resource: `models/${modelId}`,
        outcome: 'success',
        details: `Completed ${params.rounds} rounds (${params.classificationMode}, DP=${params.dpEnabled}) -> Accuracy ${(lastMetrics.accuracy * 100).toFixed(1)}%`,
        created_at: new Date().toISOString(),
      });
    }
  }
}

export async function ensureBrowserEngineInitialized(): Promise<void> {
  if (state.initialized) return;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    try {
      if (typeof localStorage !== 'undefined') {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (raw) {
          const parsed = JSON.parse(raw) as BrowserState;
          if (parsed && parsed.initialized && parsed.models?.length > 0) {
            Object.assign(state, parsed);
            await ensureClientCryptoKeys();
            return;
          }
        }
      }
    } catch {
      // Proceed to fresh deterministic seed
    }

    const now = new Date().toISOString();
    state.clients = [
      { id: 'client-hospital', name: 'Hospital-East', organization: 'Regional Health Network', subnet_cidr: '10.14.0.0/16', active: true, last_seen_at: now, created_at: now },
      { id: 'client-fintech', name: 'FinTech-Core', organization: 'Payment Clearing Hub', subnet_cidr: '10.22.0.0/16', active: true, last_seen_at: now, created_at: now },
      { id: 'client-campus', name: 'Campus-Net', organization: 'University Research Backbone', subnet_cidr: '10.31.0.0/16', active: true, last_seen_at: now, created_at: now },
      { id: 'client-cloud', name: 'Cloud-Edge', organization: 'Edge Compute Cluster', subnet_cidr: '10.45.0.0/16', active: true, last_seen_at: now, created_at: now },
      { id: 'client-telecom', name: 'Telecom-West', organization: 'Metro ISP Gateway', subnet_cidr: '10.58.0.0/16', active: true, last_seen_at: now, created_at: now },
    ];
    await ensureClientCryptoKeys();

    const records = generateSyntheticCicIdsDataset(1080, 42);
    const dist: Record<string, number> = {};
    for (const r of records) {
      const lbl = r.label || 'Benign';
      dist[lbl] = (dist[lbl] || 0) + 1;
    }

    const dsId = 'ds-synthetic-cicids2017';
    state.datasets = [
      {
        id: dsId,
        name: 'CIC-IDS2017 Synthetic Benchmark (1,080 flows)',
        source_type: 'cicids2017_synthetic',
        isSynthetic: true,
        raw_rows: records.length,
        clean_rows: records.length,
        dropped_missing: 0,
        dropped_infinite: 0,
        dropped_duplicates: 0,
        removedLeakageColumns: ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'Src Port'],
        classDistribution: dist,
        featureColumns: [...CORE_FEATURES],
        csvText: recordsToCsv(records),
        created_at: now,
      },
    ];

    const split = prepareStratifiedSplit(records, 'multiclass', 42);

    // 1. Random Forest
    const rfStart = Date.now();
    const rf = trainRandomForest({
      XTrain: split.XTrain,
      yTrain: split.yTrain,
      classes: split.classes,
      mode: 'multiclass',
      scaler: split.scaler,
      numTrees: 18,
      maxDepth: 7,
      seed: 42,
    });
    const rfTime = Math.max(1, Date.now() - rfStart);
    const rfMetrics = evaluatePredictions({
      yTrue: split.yTest,
      probs: predictRandomForestProbs(rf, split.XTest),
      classes: split.classes,
      trainingTimeMs: rfTime,
      communicationBytes: 0,
    });

    // 2. Logistic Regression
    const lrStart = Date.now();
    const lr = trainLogisticRegression({
      XTrain: split.XTrain,
      yTrain: split.yTrain,
      classes: split.classes,
      mode: 'multiclass',
      scaler: split.scaler,
      classWeights: split.classWeights,
      epochs: 140,
      lr: 0.18,
    });
    const lrTime = Math.max(1, Date.now() - lrStart);
    const lrMetrics = evaluatePredictions({
      yTrue: split.yTest,
      probs: predictLogisticRegressionProbs(lr, split.XTest),
      classes: split.classes,
      trainingTimeMs: lrTime,
      communicationBytes: 0,
    });

    // 3. Centralized MLP
    const cStart = Date.now();
    const initC = initializeMLPWeights(split.XTrain[0].length, split.classes, 'multiclass', split.scaler, 42);
    const { model: cMlp, finalLoss: cLoss } = trainMLPEpochs({
      initialModel: initC,
      XTrain: split.XTrain,
      yTrain: split.yTrain,
      classWeights: split.classWeights,
      epochs: 28,
      lr: 0.06,
      seed: 42,
    });
    const cTime = Math.max(1, Date.now() - cStart);
    const cMetrics = evaluatePredictions({
      yTrue: split.yTest,
      probs: predictMLPProbs(cMlp, split.XTest),
      classes: split.classes,
      loss: cLoss,
      trainingTimeMs: cTime,
      communicationBytes: 0,
    });

    state.models = [
      {
        id: 'model-cmlp-v1',
        name: 'Centralized PyTorch-style MLP',
        architecture: 'centralized_mlp',
        training_paradigm: 'centralized',
        classification_mode: 'multiclass',
        version: 'v1.0.0',
        dataset_id: dsId,
        accuracy: cMetrics.accuracy,
        precision_score: cMetrics.precision,
        recall_score: cMetrics.recall,
        f1_score: cMetrics.f1Score,
        false_positive_rate: cMetrics.falsePositiveRate,
        roc_auc: cMetrics.rocAuc,
        training_time_ms: cTime,
        communication_bytes: 0,
        metrics: { ...cMetrics, imbalanceRatio: split.imbalanceRatio },
        artifact: { kind: 'mlp', ...cMlp },
        isActive: false,
        created_at: now,
      },
      {
        id: 'model-lr-v1',
        name: 'Logistic Regression Baseline',
        architecture: 'logistic_regression',
        training_paradigm: 'centralized',
        classification_mode: 'multiclass',
        version: 'v1.0.0',
        dataset_id: dsId,
        accuracy: lrMetrics.accuracy,
        precision_score: lrMetrics.precision,
        recall_score: lrMetrics.recall,
        f1_score: lrMetrics.f1Score,
        false_positive_rate: lrMetrics.falsePositiveRate,
        roc_auc: lrMetrics.rocAuc,
        training_time_ms: lrTime,
        communication_bytes: 0,
        metrics: { ...lrMetrics, imbalanceRatio: split.imbalanceRatio },
        artifact: lr,
        isActive: false,
        created_at: now,
      },
      {
        id: 'model-rf-v1',
        name: 'Random Forest Baseline',
        architecture: 'random_forest',
        training_paradigm: 'centralized',
        classification_mode: 'multiclass',
        version: 'v1.0.0',
        dataset_id: dsId,
        accuracy: rfMetrics.accuracy,
        precision_score: rfMetrics.precision,
        recall_score: rfMetrics.recall,
        f1_score: rfMetrics.f1Score,
        false_positive_rate: rfMetrics.falsePositiveRate,
        roc_auc: rfMetrics.rocAuc,
        training_time_ms: rfTime,
        communication_bytes: 0,
        metrics: { ...rfMetrics, featureImportances: rf.featureImportances, imbalanceRatio: split.imbalanceRatio },
        artifact: rf,
        isActive: false,
        created_at: now,
      },
    ];

    // 4. 5-Round FedAvg MLP with WebCrypto verification
    await runFederatedRoundsBrowser({
      jobId: 'fl-job-seed-001',
      records,
      rounds: 5,
      localEpochs: 5,
      learningRate: 0.06,
      nonIidAlpha: 0.65,
      classificationMode: 'multiclass',
      dpEnabled: false,
      dpClipNorm: 1.5,
      dpNoiseMultiplier: 0.08,
      seed: 42,
      datasetId: dsId,
      versionPrefix: 'v1.0',
    });

    // 5. Initial predictions & alerts
    const activeFl = state.models.find((m) => m.isActive);
    if (activeFl && activeFl.artifact.kind === 'mlp') {
      const flArtifact = activeFl.artifact;
      const sample = records.slice(0, 60);
      const scaled = sample.map((rec) =>
        flArtifact.scaler.featureNames.map((fn, j) => {
          const v = Number((rec as unknown as Record<string, number>)[fn] ?? 0);
          return (v - flArtifact.scaler.means[j]) / flArtifact.scaler.stds[j];
        }),
      );
      const probs = predictMLPProbs(flArtifact, scaled);
      const sensors = ['Hospital-East', 'FinTech-Core', 'Campus-Net', 'Cloud-Edge', 'Telecom-West'];

      sample.forEach((rec, i) => {
        const p = probs[i];
        let best = 0;
        for (let c = 1; c < p.length; c++) if (p[c] > p[best]) best = c;
        const predLabel = flArtifact.classes[best];
        const conf = Number(p[best].toFixed(4));
        const isMal = predLabel !== 'Benign';
        const sev = computeSeverity(predLabel, conf);
        const sensor = sensors[i % sensors.length];
        const ts = rec.timestamp || now;
        const predId = `pred-seed-${i + 1}`;

        state.predictions.push({
          id: predId,
          batch_id: 'batch-seed-001',
          model_id: activeFl.id,
          client_sensor: sensor,
          ingestion_mode: 'offline_csv_benchmark',
          predicted_label: predLabel,
          true_label: rec.label ?? null,
          is_malicious: isMal,
          confidence: conf,
          severity: sev,
          flow_duration: rec.flow_duration,
          flow_bytes_per_sec: rec.flow_bytes_per_sec,
          syn_flag_count: rec.syn_flag_count,
          created_at: ts,
        });

        if (isMal) {
          state.alerts.push({
            id: `alert-seed-${i + 1}`,
            prediction_id: predId,
            client_sensor: sensor,
            attack_category: predLabel,
            severity: sev,
            confidence: conf,
            status: 'open',
            summary: `${predLabel} detected on ${sensor} (${(conf * 100).toFixed(1)}% confidence)`,
            created_at: ts,
          });
        }
      });
    }

    state.securityEvents.push({
      id: 'sec-seed-1',
      event_type: 'FEDAVG_ROUND_VERIFIED',
      severity: 'low',
      client_id: 'client-hospital',
      description: 'Initial 5-round federated training completed with 25/25 WebCrypto signed & encrypted client updates',
      signature_status: 'verified',
      integrity_status: 'verified',
      encryption_status: 'aes-256-gcm',
      blocked: 0,
      created_at: now,
    });

    state.auditLogs.push({
      id: 'audit-seed-1',
      actor_email: 'system@fl-ids.local',
      actor_role: 'admin',
      action: 'BOOTSTRAP_PIPELINE',
      resource: 'models/federated_mlp',
      outcome: 'success',
      details: 'Initialized browser-local ML baselines and 5-round FedAvg MLP on synthetic CIC-IDS2017 split',
      created_at: now,
    });

    state.initialized = true;
    saveStateToStorage();
  })();

  return initPromise;
}

function decodeBrowserToken(token: string | undefined): { id: string; email: string; name: string; role: UserRole } | null {
  if (!token) return null;
  try {
    const parsed = JSON.parse(atob(token)) as { email: string; exp: number };
    if (parsed.exp < Date.now()) return null;
    const u = DEMO_USERS[parsed.email];
    return u ? { id: u.id, email: u.email, name: u.name, role: u.role } : null;
  } catch {
    return null;
  }
}

function runArtifactInference(
  artifact: StoredModel['artifact'],
  records: FlowRecord[],
): { probs: number[][]; preds: Array<{ predictedLabel: string; confidence: number; isMalicious: boolean; severity: 'low' | 'medium' | 'high' | 'critical' }> } {
  const scaled = records.map((rec) =>
    artifact.scaler.featureNames.map((fn, idx) => {
      const val = Number((rec as unknown as Record<string, number>)[fn] ?? 0);
      return (val - artifact.scaler.means[idx]) / artifact.scaler.stds[idx];
    }),
  );

  const probs =
    artifact.kind === 'random_forest'
      ? predictRandomForestProbs(artifact, scaled)
      : artifact.kind === 'logistic_regression'
        ? predictLogisticRegressionProbs(artifact, scaled)
        : predictMLPProbs(artifact, scaled);

  const preds = probs.map((p) => {
    let best = 0;
    for (let i = 1; i < p.length; i++) if (p[i] > p[best]) best = i;
    const label = artifact.classes[best];
    const confidence = Number(p[best].toFixed(4));
    return {
      predictedLabel: label,
      confidence,
      isMalicious: label !== 'Benign',
      severity: computeSeverity(label, confidence),
    };
  });

  return { probs, preds };
}

export async function handleBrowserApiRequest<T>(
  rawPath: string,
  options: RequestInit = {},
): Promise<T> {
  await ensureBrowserEngineInitialized();

  const url = new URL(rawPath, 'https://fl-ids.local');
  const pathname = url.pathname;
  const method = (options.method || 'GET').toUpperCase();
  const body = options.body ? (JSON.parse(String(options.body)) as Record<string, unknown>) : {};
  const headers = (options.headers || {}) as Record<string, string>;
  const authHeader = headers.Authorization || headers.authorization || '';
  const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : undefined;

  // Auth endpoints
  if (pathname === '/api/auth/login' && method === 'POST') {
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const user = DEMO_USERS[email];
    if (!user || user.password !== password) {
      throw new Error('Invalid credentials');
    }
    const token = btoa(JSON.stringify({ email: user.email, exp: Date.now() + 86400_000 }));
    state.auditLogs.unshift({
      id: randomId('audit'),
      actor_email: user.email,
      actor_role: user.role,
      action: 'LOGIN_SUCCESS',
      resource: 'auth/login',
      outcome: 'success',
      details: 'Authenticated in static GitHub Pages runtime',
      created_at: new Date().toISOString(),
    });
    saveStateToStorage();
    return {
      token,
      user: { id: user.id, email: user.email, name: user.name, role: user.role, permissions: user.permissions },
    } as T;
  }

  const currentUser = decodeBrowserToken(bearerToken);
  if (!currentUser) {
    throw new Error('Authentication required');
  }

  if (pathname === '/api/auth/me' && method === 'GET') {
    return { user: currentUser } as T;
  }

  const requireAdmin = () => {
    if (currentUser.role !== 'admin') {
      throw new Error('Insufficient permissions. Required role: admin');
    }
  };

  // Overview
  if (pathname === '/api/overview' && method === 'GET') {
    const total = state.predictions.length;
    const malicious = state.predictions.filter((p) => p.is_malicious).length;
    const benign = total - malicious;
    const activeClients = state.clients.filter((c) => c.active).length;
    const activeModel = state.models.find((m) => m.isActive) || state.models[0] || null;
    const latestRound = state.rounds[state.rounds.length - 1] || null;
    return {
      totalRecordsAnalyzed: total,
      maliciousRecords: malicious,
      benignRecords: benign,
      activeFederatedClients: activeClients,
      globalModelVersion: latestRound?.model_version || activeModel?.version || 'v1.0.0',
      latestRoundNumber: latestRound?.round_number || 0,
      activeModel,
      latestRound,
      recentAlerts: state.alerts.slice(0, 8),
      modelsSummary: state.models.slice(0, 6),
    } as T;
  }

  // Datasets
  if (pathname === '/api/datasets' && method === 'GET') {
    return { datasets: state.datasets } as T;
  }

  if (pathname === '/api/datasets/upload' && method === 'POST') {
    const csvText = String(body.csvText || '');
    const { records, report } = parseAndCleanCsv(csvText, body.columnMapping as Record<string, string> | undefined, false);
    if (records.length === 0) {
      throw new Error('No valid flow records remained after cleaning');
    }
    const id = randomId('ds');
    const name = String(body.name || 'Uploaded Network Flows').trim();
    state.datasets.unshift({
      id,
      name,
      source_type: String(body.sourceType || 'custom_csv'),
      isSynthetic: false,
      raw_rows: report.rawRows,
      clean_rows: report.cleanRows,
      dropped_missing: report.droppedMissing,
      dropped_infinite: report.droppedInfinite,
      dropped_duplicates: report.droppedDuplicates,
      removedLeakageColumns: report.removedLeakageColumns,
      classDistribution: report.classDistribution,
      featureColumns: report.featureColumns,
      csvText: recordsToCsv(records),
      created_at: new Date().toISOString(),
    });
    saveStateToStorage();
    return { id, name, report, preview: records.slice(0, 15) } as T;
  }

  // Models
  if (pathname === '/api/models' && method === 'GET') {
    return { models: state.models } as T;
  }

  if (pathname === '/api/models/train' && method === 'POST') {
    requireAdmin();
    const architecture = String(body.architecture || 'random_forest') as 'random_forest' | 'logistic_regression' | 'centralized_mlp';
    const classificationMode = (body.classificationMode || 'multiclass') as ClassificationMode;
    const datasetId = String(body.datasetId || state.datasets[0]?.id);
    const ds = state.datasets.find((d) => d.id === datasetId) || state.datasets[0];
    const { records } = parseAndCleanCsv(ds.csvText, undefined, ds.isSynthetic);
    const split = prepareStratifiedSplit(records, classificationMode, 42);
    const start = Date.now();
    let artifact: StoredModel['artifact'];
    let probs: number[][];
    let loss: number | undefined;
    let extra: Record<string, unknown> = { imbalanceRatio: split.imbalanceRatio };

    if (architecture === 'random_forest') {
      const rf = trainRandomForest({ XTrain: split.XTrain, yTrain: split.yTrain, classes: split.classes, mode: classificationMode, scaler: split.scaler, numTrees: 18, maxDepth: 7, seed: 42 });
      artifact = rf;
      probs = predictRandomForestProbs(rf, split.XTest);
      extra = { ...extra, featureImportances: rf.featureImportances };
    } else if (architecture === 'logistic_regression') {
      const lr = trainLogisticRegression({ XTrain: split.XTrain, yTrain: split.yTrain, classes: split.classes, mode: classificationMode, scaler: split.scaler, classWeights: split.classWeights });
      artifact = lr;
      probs = predictLogisticRegressionProbs(lr, split.XTest);
    } else {
      const init = initializeMLPWeights(split.XTrain[0].length, split.classes, classificationMode, split.scaler, 42);
      const res = trainMLPEpochs({ initialModel: init, XTrain: split.XTrain, yTrain: split.yTrain, classWeights: split.classWeights, epochs: 28, lr: 0.06, seed: 42 });
      artifact = { kind: 'mlp', ...res.model };
      loss = res.finalLoss;
      probs = predictMLPProbs(res.model, split.XTest);
    }

    const elapsed = Math.max(1, Date.now() - start);
    const metrics = evaluatePredictions({ yTrue: split.yTest, probs, classes: split.classes, loss, trainingTimeMs: elapsed, communicationBytes: 0 });
    const modelId = randomId(`model-${architecture}`);
    const labelMap = { random_forest: 'Random Forest Baseline', logistic_regression: 'Logistic Regression Baseline', centralized_mlp: 'Centralized PyTorch-style MLP' };
    const version = `v1.${Math.floor(Date.now() / 1000) % 1000}.0`;
    state.models.unshift({
      id: modelId,
      name: labelMap[architecture],
      architecture,
      training_paradigm: 'centralized',
      classification_mode: classificationMode,
      version,
      dataset_id: ds.id,
      accuracy: metrics.accuracy,
      precision_score: metrics.precision,
      recall_score: metrics.recall,
      f1_score: metrics.f1Score,
      false_positive_rate: metrics.falsePositiveRate,
      roc_auc: metrics.rocAuc,
      training_time_ms: elapsed,
      communication_bytes: 0,
      metrics: { ...metrics, ...extra },
      artifact,
      isActive: false,
      created_at: new Date().toISOString(),
    });
    const jobId = randomId('train');
    state.trainingJobs[jobId] = {
      jobId,
      status: 'completed',
      modelId,
      message: `Completed ${labelMap[architecture]} (Accuracy ${(metrics.accuracy * 100).toFixed(1)}%)`,
    };
    saveStateToStorage();
    return { job: state.trainingJobs[jobId] } as T;
  }

  if (pathname.startsWith('/api/models/jobs/') && method === 'GET') {
    const jobId = pathname.split('/').pop()!;
    const job = state.trainingJobs[jobId];
    if (!job) throw new Error('Training job not found');
    return { job } as T;
  }

  // Federated Learning
  if (pathname === '/api/federated/status' && method === 'GET') {
    return { job: state.federatedJob } as T;
  }

  if (pathname === '/api/federated/clients' && method === 'GET') {
    const latestRound = state.rounds[state.rounds.length - 1];
    const byClient = new Map((latestRound?.clientOutcomes || []).map((o) => [o.client_id, o]));
    return {
      clients: state.clients.map((c) => {
        const key = state.publicKeys.find((k) => k.client_id === c.id);
        const latest = byClient.get(c.id);
        return {
          ...c,
          key_id: key?.key_id || null,
          fingerprint: key?.fingerprint || null,
          revoked: Boolean(key?.revoked),
          latestMetrics: latest || null,
        };
      }),
    } as T;
  }

  if (pathname === '/api/federated/clients/register' && method === 'POST') {
    requireAdmin();
    const name = String(body.name || '').trim();
    const organization = String(body.organization || '').trim();
    if (!name || !organization) throw new Error('Client name and organization are required');
    const clientId = randomId('client');
    const now = new Date().toISOString();
    state.clients.push({ id: clientId, name, organization, subnet_cidr: String(body.subnetCidr || '10.90.0.0/16'), active: true, last_seen_at: now, created_at: now });
    await ensureClientCryptoKeys();
    const keyRec = state.publicKeys.find((k) => k.client_id === clientId)!;
    state.auditLogs.unshift({
      id: randomId('audit'),
      actor_email: currentUser.email,
      actor_role: currentUser.role,
      action: 'REGISTER_FL_CLIENT',
      resource: `federated_clients/${clientId}`,
      outcome: 'success',
      details: `Registered client '${name}' with WebCrypto key ${keyRec.key_id}`,
      created_at: now,
    });
    saveStateToStorage();
    return { client: { id: clientId, name, organization, keyId: keyRec.key_id, fingerprint: keyRec.fingerprint } } as T;
  }

  if (pathname.match(/^\/api\/federated\/clients\/[^/]+\/toggle$/) && method === 'POST') {
    requireAdmin();
    const clientId = pathname.split('/')[4];
    const client = state.clients.find((c) => c.id === clientId);
    if (!client) throw new Error('Federated client not found');
    client.active = !client.active;
    saveStateToStorage();
    return { id: clientId, active: client.active } as T;
  }

  if (pathname === '/api/federated/rounds' && method === 'GET') {
    return { rounds: state.rounds } as T;
  }

  if (pathname === '/api/federated/start' && method === 'POST') {
    requireAdmin();
    const rounds = Math.min(12, Math.max(1, Number(body.rounds || 5)));
    const localEpochs = Math.min(10, Math.max(1, Number(body.localEpochs || 4)));
    const nonIidAlpha = Number(body.nonIidAlpha || 0.65);
    const classificationMode = (body.classificationMode || 'multiclass') as ClassificationMode;
    const dpEnabled = Boolean(body.dpEnabled);
    const ds = state.datasets[0];
    const { records } = parseAndCleanCsv(ds.csvText, undefined, ds.isSynthetic);
    const jobId = randomId('fl-job');

    state.federatedJob = {
      jobId,
      status: 'running',
      totalRounds: rounds,
      currentRound: 0,
      classificationMode,
      dpEnabled,
      message: 'Running WebCrypto-secured FedAvg rounds in browser...',
    };

    await runFederatedRoundsBrowser({
      jobId,
      records,
      rounds,
      localEpochs,
      learningRate: 0.06,
      nonIidAlpha,
      classificationMode,
      dpEnabled,
      dpClipNorm: 1.5,
      dpNoiseMultiplier: 0.08,
      seed: 42 + Math.floor(Date.now() % 500),
      datasetId: ds.id,
      versionPrefix: `v2.${Math.floor(Date.now() / 1000) % 1000}`,
      actor: { email: currentUser.email, role: currentUser.role },
    });

    state.federatedJob.status = 'completed';
    saveStateToStorage();
    return { job: state.federatedJob } as T;
  }

  // Cryptography & Security
  if (pathname === '/api/security/keys' && method === 'GET') {
    return {
      keys: state.publicKeys.map((k) => {
        const c = state.clients.find((cl) => cl.id === k.client_id);
        return {
          ...k,
          client_name: c?.name || k.client_id,
          organization: c?.organization || 'Unknown',
          clientActive: Boolean(c?.active),
        };
      }),
    } as T;
  }

  if (pathname.match(/^\/api\/security\/keys\/[^/]+\/rotate$/) && method === 'POST') {
    requireAdmin();
    const clientId = pathname.split('/')[4];
    const kp = await generateWebSigningKeyPair();
    clientCryptoKeys.set(clientId, kp);
    const now = new Date().toISOString();
    const rec = state.publicKeys.find((k) => k.client_id === clientId);
    if (!rec) throw new Error('Client key not found');
    rec.key_id = kp.keyId;
    rec.algorithm = kp.algorithm;
    rec.public_key_pem = kp.publicKeyPem;
    rec.fingerprint = kp.fingerprint;
    rec.revoked = false;
    rec.revoked_reason = null;
    rec.rotated_at = now;
    state.securityEvents.unshift({
      id: randomId('sec'),
      event_type: 'KEY_ROTATED',
      severity: 'low',
      client_id: clientId,
      description: `Rotated ${kp.algorithm} key pair for ${clientId} (new keyId ${kp.keyId})`,
      signature_status: 'verified',
      integrity_status: 'verified',
      encryption_status: 'aes-256-gcm',
      blocked: 0,
      created_at: now,
    });
    saveStateToStorage();
    return { clientId, keyId: kp.keyId, fingerprint: kp.fingerprint, rotatedAt: now } as T;
  }

  if (pathname.match(/^\/api\/security\/keys\/[^/]+\/revoke$/) && method === 'POST') {
    requireAdmin();
    const clientId = pathname.split('/')[4];
    const rec = state.publicKeys.find((k) => k.client_id === clientId);
    if (!rec) throw new Error('Client key not found');
    rec.revoked = true;
    rec.revoked_reason = String(body.reason || 'Administrative revocation');
    state.securityEvents.unshift({
      id: randomId('sec'),
      event_type: 'KEY_REVOKED',
      severity: 'high',
      client_id: clientId,
      description: `Revoked key for ${clientId}: ${rec.revoked_reason}`,
      signature_status: 'revoked',
      integrity_status: 'n/a',
      encryption_status: 'n/a',
      blocked: 1,
      created_at: new Date().toISOString(),
    });
    saveStateToStorage();
    return { clientId, revoked: true } as T;
  }

  if (pathname === '/api/security/simulate-attack' && method === 'POST') {
    await ensureClientCryptoKeys();
    const attackType = String(body.attackType || 'tamper_payload');
    const clientId = String(body.clientId || 'client-hospital');
    const client = state.clients.find((c) => c.id === clientId);
    const keyMat = clientCryptoKeys.get(clientId);
    const flModel = state.models.find((m) => m.training_paradigm === 'federated') || state.models[0];
    if (!client || !keyMat || !flModel || flModel.artifact.kind !== 'mlp') {
      throw new Error('Target client or federated model unavailable');
    }
    const baseMlp = flModel.artifact;
    const cleanPayload = { weights: baseMlp.weights, biases: baseMlp.biases, localLoss: 0.21, localAccuracy: 0.93, localF1: 0.92 };
    let res: Awaited<ReturnType<typeof verifyAndDecryptEnvelopeWeb>> & { shapeError?: string };
    let eventType = '';

    if (attackType === 'tamper_payload') {
      const env = await buildSignedEncryptedEnvelopeWeb({
        clientId,
        round: 99,
        modelVersion: flModel.version,
        sampleCount: 140,
        payload: cleanPayload,
        keyMaterial: keyMat,
      });
      // Flip characters in base64 ciphertext to corrupt AES-256-GCM tag verification
      env.ciphertextBase64 = 'AAAA' + env.ciphertextBase64.slice(4);
      res = await verifyAndDecryptEnvelopeWeb({
        envelope: env,
        keyMaterial: keyMat,
        clientActive: client.active,
        keyRevoked: false,
        replayGuard,
      });
      eventType = 'PAYLOAD_TAMPER_REJECTED';
    } else if (attackType === 'replay_nonce') {
      const fixedNonce = 'deadbeefcafebabe00112233';
      const env = await buildSignedEncryptedEnvelopeWeb({
        clientId,
        round: 99,
        modelVersion: flModel.version,
        sampleCount: 140,
        payload: cleanPayload,
        keyMaterial: keyMat,
        forcedNonce: fixedNonce,
      });
      await verifyAndDecryptEnvelopeWeb({ envelope: env, keyMaterial: keyMat, clientActive: true, keyRevoked: false, replayGuard });
      res = await verifyAndDecryptEnvelopeWeb({ envelope: env, keyMaterial: keyMat, clientActive: true, keyRevoked: false, replayGuard });
      eventType = 'REPLAY_ATTACK_REJECTED';
    } else if (attackType === 'unauthorized_client') {
      const rogueKey = await generateWebSigningKeyPair();
      const env = await buildSignedEncryptedEnvelopeWeb({
        clientId: 'rogue-node-99',
        round: 99,
        modelVersion: flModel.version,
        sampleCount: 140,
        payload: cleanPayload,
        keyMaterial: rogueKey,
      });
      res = await verifyAndDecryptEnvelopeWeb({ envelope: env, keyMaterial: null, clientActive: false, keyRevoked: false, replayGuard });
      eventType = 'UNAUTHORIZED_CLIENT_REJECTED';
    } else {
      const poisonedWeights = baseMlp.weights.map((l) => l.map((r) => [...r]));
      poisonedWeights[0][0][0] = 999999;
      const env = await buildSignedEncryptedEnvelopeWeb({
        clientId,
        round: 99,
        modelVersion: flModel.version,
        sampleCount: 140,
        payload: { ...cleanPayload, weights: poisonedWeights },
        keyMaterial: keyMat,
      });
      const dec = await verifyAndDecryptEnvelopeWeb<typeof cleanPayload>({
        envelope: env,
        keyMaterial: keyMat,
        clientActive: true,
        keyRevoked: false,
        replayGuard,
      });
      const shapeCheck = dec.payload ? validateWeightPayloadWeb(dec.payload, baseMlp) : { valid: false, reason: 'Invalid' };
      res = {
        ok: shapeCheck.valid,
        code: 'DECRYPTION_FAILED',
        reason: shapeCheck.reason,
        signatureVerified: dec.signatureVerified,
        decryptionVerified: dec.decryptionVerified,
        integrityVerified: dec.integrityVerified,
      };
      eventType = 'POISONED_UPDATE_REJECTED';
    }

    state.securityEvents.unshift({
      id: randomId('sec'),
      event_type: eventType,
      severity: 'critical',
      client_id: attackType === 'unauthorized_client' ? 'rogue-node-99' : clientId,
      description: res.reason || 'Adversarial update blocked',
      signature_status: res.signatureVerified ? 'verified' : 'failed',
      integrity_status: res.integrityVerified ? 'verified' : 'failed',
      encryption_status: res.decryptionVerified ? 'aes-256-gcm' : 'failed',
      blocked: res.ok ? 0 : 1,
      created_at: new Date().toISOString(),
    });
    saveStateToStorage();
    return {
      attackType,
      blocked: !res.ok,
      code: res.code || 'POISONED_TENSOR',
      reason: res.reason,
      signatureVerified: res.signatureVerified,
      decryptionVerified: res.decryptionVerified,
      integrityVerified: res.integrityVerified,
    } as T;
  }

  if (pathname === '/api/security/events' && method === 'GET') {
    return { events: state.securityEvents } as T;
  }

  if (pathname === '/api/security/audit-logs' && method === 'GET') {
    return { logs: state.auditLogs } as T;
  }

  // Inference & Monitoring
  if (pathname === '/api/inference/batch' && method === 'POST') {
    const useSyntheticSample = Boolean(body.useSyntheticSample);
    const classificationMode = (body.classificationMode || 'multiclass') as ClassificationMode;
    const records = useSyntheticSample
      ? generateSyntheticCicIdsDataset(180, Math.floor(Date.now() % 10000))
      : parseAndCleanCsv(String(body.csvText || '')).records;
    if (records.length === 0) throw new Error('No valid records to classify');

    const model =
      (body.modelId ? state.models.find((m) => m.id === body.modelId) : null) ||
      state.models.find((m) => m.isActive) ||
      state.models[0];
    if (!model) throw new Error('No trained model available');

    const { probs, preds } = runArtifactInference(model.artifact, records);
    const batchId = randomId('batch');
    const now = new Date().toISOString();
    const sensor = String(body.clientSensor || 'Offline-CSV-Upload');

    const classes =
      classificationMode === 'binary' && model.artifact.classes.length > 2
        ? ['Benign', 'Malicious']
        : model.artifact.classes;
    const yTrue: number[] = [];
    const labeledProbs: number[][] = [];

    const rowsOut = records.map((rec, i) => {
      const raw = preds[i];
      const predLabel =
        classificationMode === 'binary' ? (raw.predictedLabel === 'Benign' ? 'Benign' : 'Malicious') : raw.predictedLabel;
      const p = probs[i];
      const conf =
        classificationMode === 'binary' && model.artifact.classes.length > 2
          ? Number((raw.predictedLabel === 'Benign' ? p[0] : 1 - p[0]).toFixed(4))
          : raw.confidence;
      const predId = `pred-${batchId}-${i}`;

      if (rec.label) {
        const mapped = classificationMode === 'binary' ? (rec.label === 'Benign' ? 'Benign' : 'Malicious') : rec.label;
        const idx = classes.indexOf(mapped);
        if (idx !== -1) {
          yTrue.push(idx);
          if (classificationMode === 'binary' && model.artifact.classes.length > 2) {
            const bIdx = Math.max(0, model.artifact.classes.indexOf('Benign'));
            labeledProbs.push([p[bIdx] ?? 0, 1 - (p[bIdx] ?? 0)]);
          } else {
            labeledProbs.push(p);
          }
        }
      }

      if (i < 80) {
        state.predictions.unshift({
          id: predId,
          batch_id: batchId,
          model_id: model.id,
          client_sensor: sensor,
          ingestion_mode: useSyntheticSample ? 'synthetic_batch_csv' : 'uploaded_csv',
          predicted_label: predLabel,
          true_label: rec.label ?? null,
          is_malicious: predLabel !== 'Benign',
          confidence: conf,
          severity: raw.severity,
          flow_duration: rec.flow_duration,
          flow_bytes_per_sec: rec.flow_bytes_per_sec,
          syn_flag_count: rec.syn_flag_count,
          created_at: now,
        });
        if (predLabel !== 'Benign' && i < 40) {
          state.alerts.unshift({
            id: `alert-${predId}`,
            prediction_id: predId,
            client_sensor: sensor,
            attack_category: raw.predictedLabel,
            severity: raw.severity,
            confidence: conf,
            status: 'open',
            summary: `${raw.predictedLabel} detected in CSV batch (${(conf * 100).toFixed(1)}% confidence)`,
            created_at: now,
          });
        }
      }

      return {
        id: predId,
        predictedLabel: predLabel,
        rawCategory: raw.predictedLabel,
        trueLabel: rec.label ?? null,
        isMalicious: predLabel !== 'Benign',
        confidence: conf,
        severity: raw.severity,
        flowDuration: rec.flow_duration,
        flowBytesPerSec: rec.flow_bytes_per_sec,
        synFlagCount: rec.syn_flag_count,
        totalFwdPackets: rec.total_fwd_packets,
      };
    });

    const evaluation = yTrue.length > 0 ? evaluatePredictions({ yTrue, probs: labeledProbs, classes }) : null;
    saveStateToStorage();
    return {
      batchId,
      modelUsed: { id: model.id, name: model.name, architecture: model.architecture },
      totalRecords: rowsOut.length,
      maliciousCount: rowsOut.filter((r) => r.isMalicious).length,
      benignCount: rowsOut.filter((r) => !r.isMalicious).length,
      predictions: rowsOut,
      evaluation,
    } as T;
  }

  if (pathname === '/api/monitoring/stream-tick' && method === 'POST') {
    const n = Math.min(24, Math.max(1, Number(body.count || 8)));
    const model = state.models.find((m) => m.isActive) || state.models[0];
    if (!model) throw new Error('No active model');
    const flows = generateSyntheticCicIdsDataset(n, Math.floor(Date.now() % 100000));
    const { preds } = runArtifactInference(model.artifact, flows);
    const sensors = ['Hospital-East', 'FinTech-Core', 'Campus-Net', 'Cloud-Edge', 'Telecom-West'];
    const now = new Date().toISOString();

    const created = flows.map((flow, i) => {
      const p = preds[i];
      const sensor = sensors[(i + Math.floor(Date.now() / 1000)) % sensors.length];
      const predId = randomId('pred-live');
      state.predictions.unshift({
        id: predId,
        batch_id: 'live-flow-adapter',
        model_id: model.id,
        client_sensor: sensor,
        ingestion_mode: 'simulated_flow_adapter',
        predicted_label: p.predictedLabel,
        true_label: flow.label ?? null,
        is_malicious: p.isMalicious,
        confidence: p.confidence,
        severity: p.severity,
        flow_duration: flow.flow_duration,
        flow_bytes_per_sec: flow.flow_bytes_per_sec,
        syn_flag_count: flow.syn_flag_count,
        created_at: now,
      });
      if (p.isMalicious) {
        state.alerts.unshift({
          id: `alert-${predId}`,
          prediction_id: predId,
          client_sensor: sensor,
          attack_category: p.predictedLabel,
          severity: p.severity,
          confidence: p.confidence,
          status: 'open',
          summary: `${p.predictedLabel} flagged by flow adapter on ${sensor} (${(p.confidence * 100).toFixed(1)}%)`,
          created_at: now,
        });
      }
      return { id: predId, sensor, ...p, createdAt: now };
    });
    saveStateToStorage();
    return { ingested: created.length, records: created } as T;
  }

  if (pathname === '/api/alerts' && method === 'GET') {
    const sev = url.searchParams.get('severity');
    const status = url.searchParams.get('status');
    let list = state.alerts;
    if (sev && sev !== 'all') list = list.filter((a) => a.severity === sev);
    if (status && status !== 'all') list = list.filter((a) => a.status === status);
    return { alerts: list.slice(0, 150) } as T;
  }

  if (pathname.match(/^\/api\/alerts\/[^/]+\/ack$/) && method === 'POST') {
    const alertId = pathname.split('/')[3];
    const alert = state.alerts.find((a) => a.id === alertId);
    if (!alert) throw new Error('Alert not found');
    alert.status = alert.status === 'acknowledged' ? 'open' : 'acknowledged';
    saveStateToStorage();
    return { id: alertId, status: alert.status } as T;
  }

  if (pathname === '/api/metrics' && method === 'GET') {
    const catMap = new Map<string, number>();
    const sensorMap = new Map<string, { sensor: string; total: number; malicious: number; benign: number }>();
    for (const p of state.predictions) {
      catMap.set(p.predicted_label, (catMap.get(p.predicted_label) || 0) + 1);
      const cur = sensorMap.get(p.client_sensor) || { sensor: p.client_sensor, total: 0, malicious: 0, benign: 0 };
      cur.total++;
      if (p.is_malicious) cur.malicious++;
      else cur.benign++;
      sensorMap.set(p.client_sensor, cur);
    }
    const sevMap = new Map<string, number>();
    for (const a of state.alerts) {
      sevMap.set(a.severity, (sevMap.get(a.severity) || 0) + 1);
    }
    return {
      models: state.models,
      attackDistribution: Array.from(catMap.entries()).map(([category, count]) => ({ category, count })),
      sensorActivity: Array.from(sensorMap.values()),
      severityDistribution: Array.from(sevMap.entries()).map(([severity, count]) => ({ severity, count })),
      timeline: [],
    } as T;
  }

  throw new Error(`Unsupported endpoint in browser runtime: ${method} ${pathname}`);
}
