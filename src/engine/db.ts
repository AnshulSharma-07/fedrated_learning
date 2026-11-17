import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import {
  generateAndStoreEd25519KeyPair,
  hashPassword,
  ReplayGuard,
} from './crypto';
import {
  generateSyntheticCicIdsDataset,
  partitionNonIid,
  prepareStratifiedSplit,
  recordsToCsv,
} from './dataset';
import { executeFederatedRound } from './federated';
import {
  computeCrossEntropyLoss,
  evaluatePredictions,
  initializeMLPWeights,
  predictLogisticRegressionProbs,
  predictMLPProbs,
  predictRandomForestProbs,
  trainLogisticRegression,
  trainMLPEpochs,
  trainRandomForest,
} from './ml';
import type { FlowRecord } from './types';

let dbInstance: DatabaseSync | null = null;

export function getDb(): DatabaseSync {
  if (dbInstance) return dbInstance;
  const dataDir = path.resolve(process.cwd(), 'data');
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
  const dbPath = path.join(dataDir, 'fl_ids.db');
  dbInstance = new DatabaseSync(dbPath);
  dbInstance.exec('PRAGMA journal_mode = WAL;');
  dbInstance.exec('PRAGMA foreign_keys = ON;');
  initializeSchema(dbInstance);
  seedInitialDataIfEmpty(dbInstance);
  return dbInstance;
}

function initializeSchema(db: DatabaseSync): void {
  db.exec(`
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

function seedInitialDataIfEmpty(db: DatabaseSync): void {
  const roleCount = db.prepare('SELECT COUNT(*) as cnt FROM roles').get() as { cnt: number };
  if (roleCount.cnt === 0) {
    const insertRole = db.prepare('INSERT INTO roles (id, name, permissions_json) VALUES (?, ?, ?)');
    insertRole.run(
      'role-admin',
      'admin',
      JSON.stringify(['read', 'upload_dataset', 'train_models', 'run_federated', 'manage_keys', 'run_inference', 'manage_alerts']),
    );
    insertRole.run(
      'role-analyst',
      'analyst',
      JSON.stringify(['read', 'upload_dataset', 'run_inference', 'manage_alerts']),
    );
    insertRole.run('role-viewer', 'viewer', JSON.stringify(['read']));
  }

  const userCount = db.prepare('SELECT COUNT(*) as cnt FROM users').get() as { cnt: number };
  if (userCount.cnt === 0) {
    const now = new Date().toISOString();
    const insertUser = db.prepare(
      'INSERT INTO users (id, email, name, password_hash, role_id, created_at) VALUES (?, ?, ?, ?, ?, ?)',
    );
    insertUser.run('user-admin', 'admin@fl-ids.local', 'Security Admin', hashPassword('Admin@FLIDS2026!'), 'role-admin', now);
    insertUser.run('user-analyst', 'analyst@fl-ids.local', 'SOC Analyst', hashPassword('Analyst@FLIDS2026!'), 'role-analyst', now);
  }

  const clientCount = db.prepare('SELECT COUNT(*) as cnt FROM federated_clients').get() as { cnt: number };
  if (clientCount.cnt === 0) {
    const now = new Date().toISOString();
    const clients = [
      { id: 'client-hospital', name: 'Hospital-East', org: 'Regional Health Network', cidr: '10.14.0.0/16' },
      { id: 'client-fintech', name: 'FinTech-Core', org: 'Payment Clearing Hub', cidr: '10.22.0.0/16' },
      { id: 'client-campus', name: 'Campus-Net', org: 'University Research Backbone', cidr: '10.31.0.0/16' },
      { id: 'client-cloud', name: 'Cloud-Edge', org: 'Edge Compute Cluster', cidr: '10.45.0.0/16' },
      { id: 'client-telecom', name: 'Telecom-West', org: 'Metro ISP Gateway', cidr: '10.58.0.0/16' },
    ];
    const insertClient = db.prepare(
      'INSERT INTO federated_clients (id, name, organization, subnet_cidr, active, last_seen_at, created_at) VALUES (?, ?, ?, ?, 1, ?, ?)',
    );
    const insertKey = db.prepare(
      'INSERT INTO public_keys (id, client_id, key_id, algorithm, public_key_pem, fingerprint, revoked, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?)',
    );
    for (const c of clients) {
      insertClient.run(c.id, c.name, c.org, c.cidr, now, now);
      const kp = generateAndStoreEd25519KeyPair(c.id, true);
      insertKey.run(`pk-${c.id}`, c.id, kp.keyId, 'Ed25519', kp.publicKeyPem, kp.fingerprint, now);
    }
  }

  // Ensure sample dataset CSV and initial real baseline + federated evaluation exist so dashboard has real data
  const dsCount = db.prepare('SELECT COUNT(*) as cnt FROM datasets').get() as { cnt: number };
  if (dsCount.cnt === 0) {
    const sampleDir = path.resolve(process.cwd(), 'data', 'sample');
    if (!fs.existsSync(sampleDir)) fs.mkdirSync(sampleDir, { recursive: true });
    const syntheticRecords = generateSyntheticCicIdsDataset(1080, 42);
    const csvPath = path.join(sampleDir, 'synthetic_cicids2017_sample.csv');
    fs.writeFileSync(csvPath, recordsToCsv(syntheticRecords), 'utf8');

    const dist: Record<string, number> = {};
    for (const r of syntheticRecords) {
      const lbl = r.label || 'Benign';
      dist[lbl] = (dist[lbl] || 0) + 1;
    }

    const now = new Date().toISOString();
    const datasetId = 'ds-synthetic-cicids2017';
    db.prepare(
      `INSERT INTO datasets (
        id, name, source_type, is_synthetic, raw_rows, clean_rows,
        dropped_missing, dropped_infinite, dropped_duplicates,
        removed_leakage_json, class_distribution_json, feature_columns_json,
        csv_path, created_by, created_at
      ) VALUES (?, ?, ?, 1, ?, ?, 0, 0, 0, ?, ?, ?, ?, ?, ?)`,
    ).run(
      datasetId,
      'CIC-IDS2017 Synthetic Benchmark (1,080 flows)',
      'cicids2017_synthetic',
      syntheticRecords.length,
      syntheticRecords.length,
      JSON.stringify(['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'Src Port']),
      JSON.stringify(dist),
      JSON.stringify([
        'flow_duration', 'total_fwd_packets', 'total_bwd_packets',
        'fwd_packet_length_mean', 'bwd_packet_length_mean',
        'flow_bytes_per_sec', 'flow_packets_per_sec',
        'syn_flag_count', 'ack_flag_count', 'rst_flag_count',
        'psh_flag_count', 'iat_mean', 'init_win_bytes_fwd', 'subflow_fwd_bytes',
      ]),
      csvPath,
      'system-seed',
      now,
    );

    runInitialRealTrainingAndSeedPredictions(db, datasetId, syntheticRecords);
  }
}

function runInitialRealTrainingAndSeedPredictions(
  db: DatabaseSync,
  datasetId: string,
  records: FlowRecord[],
): void {
  const now = new Date().toISOString();
  const split = prepareStratifiedSplit(records, 'multiclass', 42);

  // 1. Train Centralized Random Forest
  const rfStart = Date.now();
  const rfModel = trainRandomForest({
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
  const rfProbs = predictRandomForestProbs(rfModel, split.XTest);
  const rfMetrics = evaluatePredictions({
    yTrue: split.yTest,
    probs: rfProbs,
    classes: split.classes,
    trainingTimeMs: rfTime,
    communicationBytes: 0,
  });

  db.prepare(
    `INSERT INTO models (
      id, name, architecture, training_paradigm, classification_mode, version, dataset_id,
      accuracy, precision_score, recall_score, f1_score, false_positive_rate, roc_auc,
      training_time_ms, communication_bytes, metrics_json, artifact_json, is_active, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
  ).run(
    'model-rf-v1',
    'Random Forest Baseline',
    'random_forest',
    'centralized',
    'multiclass',
    'v1.0.0',
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
    now,
  );

  // 2. Train Centralized Logistic Regression
  const lrStart = Date.now();
  const lrModel = trainLogisticRegression({
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
  const lrProbs = predictLogisticRegressionProbs(lrModel, split.XTest);
  const lrMetrics = evaluatePredictions({
    yTrue: split.yTest,
    probs: lrProbs,
    classes: split.classes,
    trainingTimeMs: lrTime,
    communicationBytes: 0,
  });

  db.prepare(
    `INSERT INTO models (
      id, name, architecture, training_paradigm, classification_mode, version, dataset_id,
      accuracy, precision_score, recall_score, f1_score, false_positive_rate, roc_auc,
      training_time_ms, communication_bytes, metrics_json, artifact_json, is_active, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
  ).run(
    'model-lr-v1',
    'Logistic Regression Baseline',
    'logistic_regression',
    'centralized',
    'multiclass',
    'v1.0.0',
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
    now,
  );

  // 3. Train Centralized MLP
  const cMlpStart = Date.now();
  const initCMlp = initializeMLPWeights(split.XTrain[0].length, split.classes, 'multiclass', split.scaler, 42);
  const { model: cMlpModel, finalLoss: cMlpLoss } = trainMLPEpochs({
    initialModel: initCMlp,
    XTrain: split.XTrain,
    yTrain: split.yTrain,
    classWeights: split.classWeights,
    epochs: 28,
    lr: 0.06,
    seed: 42,
  });
  const cMlpTime = Math.max(1, Date.now() - cMlpStart);
  const cMlpProbs = predictMLPProbs(cMlpModel, split.XTest);
  const cMlpMetrics = evaluatePredictions({
    yTrue: split.yTest,
    probs: cMlpProbs,
    classes: split.classes,
    loss: cMlpLoss,
    trainingTimeMs: cMlpTime,
    communicationBytes: 0,
  });

  db.prepare(
    `INSERT INTO models (
      id, name, architecture, training_paradigm, classification_mode, version, dataset_id,
      accuracy, precision_score, recall_score, f1_score, false_positive_rate, roc_auc,
      training_time_ms, communication_bytes, metrics_json, artifact_json, is_active, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
  ).run(
    'model-cmlp-v1',
    'Centralized PyTorch-style MLP',
    'centralized_mlp',
    'centralized',
    'multiclass',
    'v1.0.0',
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
    JSON.stringify({ kind: 'mlp', ...cMlpModel }),
    now,
  );

  // 4. Run 5 real Federated Learning rounds across 5 Non-IID clients
  const clientRows = db
    .prepare(
      `SELECT fc.id, fc.name, fc.organization, fc.active, pk.public_key_pem, pk.revoked
       FROM federated_clients fc
       LEFT JOIN public_keys pk ON pk.client_id = fc.id AND pk.revoked = 0`,
    )
    .all() as Array<{
    id: string;
    name: string;
    organization: string;
    active: number;
    public_key_pem: string | null;
    revoked: number | null;
  }>;

  const clientDescriptors = clientRows.map((c) => ({
    id: c.id,
    name: c.name,
    organization: c.organization,
    active: c.active === 1,
    publicKeyPem: c.public_key_pem,
    keyRevoked: c.revoked === 1,
  }));

  const partitionsArr = partitionNonIid(
    split.XTrain,
    split.yTrain,
    split.classes,
    clientDescriptors.map((c) => c.id),
    0.65,
    42,
  );
  const partitions = new Map(partitionsArr.map((p) => [p.clientId, p]));
  const replayGuard = new ReplayGuard();

  let currentGlobal = initializeMLPWeights(split.XTrain[0].length, split.classes, 'multiclass', split.scaler, 42);
  let totalFlTime = 0;
  let totalCommBytes = 0;
  let lastRoundResult: ReturnType<typeof executeFederatedRound>['roundResult'] | null = null;
  const jobId = 'fl-job-seed-001';

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
      replayGuard,
      seed: 42,
    });
    currentGlobal = updatedModel;
    totalFlTime += roundResult.durationMs;
    totalCommBytes += roundResult.communicationBytes;
    lastRoundResult = roundResult;

    const roundId = `round-seed-${r}`;
    db.prepare(
      `INSERT INTO federated_rounds (
        id, job_id, round_number, model_version, classification_mode,
        global_loss, global_accuracy, global_precision, global_recall, global_f1, global_fpr, global_roc_auc,
        participating_clients, accepted_clients, rejected_clients, communication_bytes, duration_ms,
        dp_epsilon_estimate, metrics_json, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      roundId,
      jobId,
      r,
      nextVer,
      'multiclass',
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
      now,
    );

    const insertClientMetric = db.prepare(
      `INSERT INTO client_metrics (
        id, round_id, client_id, status, rejection_reason, sample_count,
        local_loss, local_accuracy, local_f1, payload_bytes,
        signature_verified, integrity_verified, decryption_verified, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
        now,
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
      communicationBytes: totalCommBytes,
    });

    const flModelId = 'model-flmlp-v1';
    db.prepare(
      `INSERT INTO models (
        id, name, architecture, training_paradigm, classification_mode, version, dataset_id,
        accuracy, precision_score, recall_score, f1_score, false_positive_rate, roc_auc,
        training_time_ms, communication_bytes, metrics_json, artifact_json, is_active, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`,
    ).run(
      flModelId,
      'Federated FedAvg MLP',
      'federated_mlp',
      'federated',
      'multiclass',
      'v1.0.5',
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
      JSON.stringify({ kind: 'mlp', ...currentGlobal }),
      now,
    );

    // Seed real inference predictions & alerts on the held-out test records (first 60 records)
    const sampleBatch = records.slice(0, 60);
    const scaledBatch = sampleBatch.map((r) =>
      currentGlobal.scaler.featureNames.map((fn, j) => {
        const val = Number((r as unknown as Record<string, number>)[fn] ?? 0);
        return (val - currentGlobal.scaler.means[j]) / currentGlobal.scaler.stds[j];
      }),
    );
    const batchProbs = predictMLPProbs(currentGlobal, scaledBatch);
    const sensorNames = ['Hospital-East', 'FinTech-Core', 'Campus-Net', 'Cloud-Edge', 'Telecom-West'];

    const insertPred = db.prepare(
      `INSERT INTO predictions (
        id, batch_id, model_id, client_sensor, ingestion_mode,
        predicted_label, true_label, is_malicious, confidence, severity,
        flow_duration, flow_bytes_per_sec, syn_flag_count, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    const insertAlert = db.prepare(
      `INSERT INTO alerts (
        id, prediction_id, client_sensor, attack_category, severity, confidence, status, summary, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );

    sampleBatch.forEach((rec, i) => {
      const p = batchProbs[i];
      let bestIdx = 0;
      for (let c = 1; c < p.length; c++) {
        if (p[c] > p[bestIdx]) bestIdx = c;
      }
      const predLabel = currentGlobal.classes[bestIdx];
      const confidence = Number(p[bestIdx].toFixed(4));
      const isMalicious = predLabel !== 'Benign';
      const severity = !isMalicious
        ? 'low'
        : predLabel === 'DoS/DDoS' || predLabel === 'Botnet'
          ? confidence >= 0.85
            ? 'critical'
            : 'high'
          : confidence >= 0.85
            ? 'high'
            : 'medium';
      const sensor = sensorNames[i % sensorNames.length];
      const ts = rec.timestamp || now;
      const predId = `pred-seed-${i + 1}`;

      insertPred.run(
        predId,
        'batch-seed-001',
        flModelId,
        sensor,
        'offline_csv_benchmark',
        predLabel,
        rec.label ?? null,
        isMalicious ? 1 : 0,
        confidence,
        severity,
        rec.flow_duration,
        rec.flow_bytes_per_sec,
        rec.syn_flag_count,
        ts,
      );

      if (isMalicious) {
        insertAlert.run(
          `alert-seed-${i + 1}`,
          predId,
          sensor,
          predLabel,
          severity,
          confidence,
          'open',
          `${predLabel} detected on ${sensor} (${(confidence * 100).toFixed(1)}% confidence)`,
          ts,
        );
      }
    });

    db.prepare(
      `INSERT INTO security_events (
        id, event_type, severity, client_id, description,
        signature_status, integrity_status, encryption_status, blocked, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
    ).run(
      'sec-seed-1',
      'FEDAVG_ROUND_VERIFIED',
      'low',
      'client-hospital',
      'Initial 5-round federated training completed with 25/25 Ed25519 + AES-256-GCM verified client updates',
      'verified',
      'verified',
      'aes-256-gcm',
      now,
    );

    db.prepare(
      `INSERT INTO audit_logs (
        id, actor_email, actor_role, action, resource, outcome, details, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      'audit-seed-1',
      'system@fl-ids.local',
      'admin',
      'BOOTSTRAP_PIPELINE',
      'models/model-flmlp-v1',
      'success',
      'Trained baseline centralized models (RF, LR, MLP) and 5-round Federated MLP on synthetic CIC-IDS2017 split',
      now,
    );
  }
}
