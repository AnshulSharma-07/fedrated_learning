import 'dotenv/config';
import express, { type NextFunction, type Request, type Response } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  buildSignedEncryptedEnvelope,
  generateAndStoreEd25519KeyPair,
  loadClientPrivateKey,
  ReplayGuard,
  signJwt,
  verifyJwt,
  verifyPassword,
  type JwtPayload,
} from './src/engine/crypto';
import {
  CORE_FEATURES,
  generateSyntheticCicIdsDataset,
  parseAndCleanCsv,
  partitionNonIid,
  prepareStratifiedSplit,
  recordsToCsv,
} from './src/engine/dataset';
import { getDb } from './src/engine/db';
import {
  executeFederatedRound,
  processIncomingClientEnvelope,
  type FederatedClientDescriptor,
} from './src/engine/federated';
import {
  evaluatePredictions,
  initializeMLPWeights,
  predictLogisticRegressionProbs,
  predictMLPProbs,
  predictRandomForestProbs,
  trainLogisticRegression,
  trainMLPEpochs,
  trainRandomForest,
} from './src/engine/ml';
import type {
  ClassificationMode,
  FlowRecord,
  LogisticRegressionModel,
  MLPWeights,
  RandomForestModel,
  UserRole,
} from './src/engine/types';

interface AuthedRequest extends Request {
  user?: JwtPayload;
}

interface FederatedJobState {
  jobId: string;
  status: 'idle' | 'running' | 'completed' | 'failed';
  totalRounds: number;
  currentRound: number;
  classificationMode: ClassificationMode;
  dpEnabled: boolean;
  message: string;
  startedAt: string;
  completedAt: string | null;
}

interface TrainingJobState {
  jobId: string;
  status: 'running' | 'completed' | 'failed';
  architecture: string;
  modelId: string | null;
  message: string;
  startedAt: string;
  completedAt: string | null;
}

const PORT = Number(process.env.PORT || 3000);
const app = express();
app.use(express.json({ limit: '25mb' }));

// Simple in-memory sliding-window rate limiter per IP
const rateBuckets = new Map<string, number[]>();
function rateLimiter(maxRequests = 180, windowMs = 60_000) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.path.startsWith('/api')) return next();
    const ip = req.ip || 'local';
    const now = Date.now();
    const history = (rateBuckets.get(ip) || []).filter((t) => now - t < windowMs);
    if (history.length >= maxRequests) {
      return res.status(429).json({ error: 'Rate limit exceeded. Retry shortly.' });
    }
    history.push(now);
    rateBuckets.set(ip, history);
    next();
  };
}
app.use(rateLimiter());

// Initialize SQLite database & global replay guard
const db = getDb();
const replayGuard = new ReplayGuard();

let federatedJob: FederatedJobState = {
  jobId: 'fl-job-seed-001',
  status: 'completed',
  totalRounds: 5,
  currentRound: 5,
  classificationMode: 'multiclass',
  dpEnabled: false,
  message: 'Initial 5-round federated run completed',
  startedAt: new Date().toISOString(),
  completedAt: new Date().toISOString(),
};

const trainingJobs = new Map<string, TrainingJobState>();

function writeAuditLog(
  actor: { email: string; role: string },
  action: string,
  resource: string,
  outcome: 'success' | 'denied' | 'error',
  details: string,
): void {
  db.prepare(
    `INSERT INTO audit_logs (id, actor_email, actor_role, action, resource, outcome, details, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    `audit-${crypto.randomUUID().slice(0, 8)}`,
    actor.email,
    actor.role,
    action,
    resource,
    outcome,
    details,
    new Date().toISOString(),
  );
}

function writeSecurityEvent(params: {
  eventType: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  clientId?: string | null;
  description: string;
  signatureStatus: string;
  integrityStatus: string;
  encryptionStatus: string;
  blocked: boolean;
}): void {
  db.prepare(
    `INSERT INTO security_events (
      id, event_type, severity, client_id, description,
      signature_status, integrity_status, encryption_status, blocked, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    `sec-${crypto.randomUUID().slice(0, 8)}`,
    params.eventType,
    params.severity,
    params.clientId ?? null,
    params.description,
    params.signatureStatus,
    params.integrityStatus,
    params.encryptionStatus,
    params.blocked ? 1 : 0,
    new Date().toISOString(),
  );
}

function requireAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  const token = header.slice(7).trim();
  const payload = verifyJwt(token);
  if (!payload) {
    return res.status(401).json({ error: 'Invalid or expired authentication token' });
  }
  req.user = payload;
  next();
}

function requireRole(...allowed: UserRole[]) {
  return (req: AuthedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    if (!allowed.includes(req.user.role)) {
      writeAuditLog(
        { email: req.user.email, role: req.user.role },
        'ACCESS_DENIED',
        req.originalUrl,
        'denied',
        `Role '${req.user.role}' lacks permission (${allowed.join(', ')})`,
      );
      return res.status(403).json({ error: `Insufficient permissions. Required role: ${allowed.join(' or ')}` });
    }
    next();
  };
}

function loadDatasetRecords(datasetId: string): { records: FlowRecord[]; name: string; isSynthetic: boolean } {
  const row = db
    .prepare('SELECT id, name, csv_path, is_synthetic FROM datasets WHERE id = ?')
    .get(datasetId) as { id: string; name: string; csv_path: string; is_synthetic: number } | undefined;
  if (!row) {
    throw new Error(`Dataset '${datasetId}' not found`);
  }
  const csvText = fs.readFileSync(row.csv_path, 'utf8');
  const { records } = parseAndCleanCsv(csvText, undefined, row.is_synthetic === 1);
  return { records, name: row.name, isSynthetic: row.is_synthetic === 1 };
}

function computeSeverity(label: string, confidence: number): 'low' | 'medium' | 'high' | 'critical' {
  if (label === 'Benign') return 'low';
  if ((label === 'DoS/DDoS' || label === 'Botnet') && confidence >= 0.85) return 'critical';
  if (label === 'DoS/DDoS' || label === 'Botnet' || confidence >= 0.85) return 'high';
  return 'medium';
}

function runModelInference(
  modelRow: { id: string; architecture: string; artifact_json: string },
  records: FlowRecord[],
): Array<{ predictedLabel: string; confidence: number; isMalicious: boolean; severity: string }> {
  const artifact = JSON.parse(modelRow.artifact_json) as
    | ({ kind: 'mlp' } & MLPWeights)
    | LogisticRegressionModel
    | RandomForestModel;

  const scaled = records.map((rec) =>
    artifact.scaler.featureNames.map((fn, idx) => {
      const val = Number((rec as unknown as Record<string, number>)[fn] ?? 0);
      return (val - artifact.scaler.means[idx]) / artifact.scaler.stds[idx];
    }),
  );

  let probs: number[][];
  if (artifact.kind === 'random_forest') {
    probs = predictRandomForestProbs(artifact, scaled);
  } else if (artifact.kind === 'logistic_regression') {
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
    const isMalicious = label !== 'Benign';
    return {
      predictedLabel: label,
      confidence,
      isMalicious,
      severity: computeSeverity(label, confidence),
    };
  });
}

// ============================================================================
// Authentication Endpoints
// ============================================================================
app.post('/api/auth/login', (req: Request, res: Response) => {
  const { email, password } = req.body as { email?: string; password?: string };
  if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const user = db
    .prepare(
      `SELECT u.id, u.email, u.name, u.password_hash, r.name as role_name, r.permissions_json
       FROM users u JOIN roles r ON u.role_id = r.id WHERE u.email = ?`,
    )
    .get(email.trim().toLowerCase()) as
    | {
        id: string;
        email: string;
        name: string;
        password_hash: string;
        role_name: UserRole;
        permissions_json: string;
      }
    | undefined;

  if (!user || !verifyPassword(password, user.password_hash)) {
    writeAuditLog(
      { email: email.trim(), role: 'unknown' },
      'LOGIN_FAILED',
      'auth/login',
      'denied',
      'Invalid email or password',
    );
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = signJwt({
    sub: user.id,
    email: user.email,
    name: user.name,
    role: user.role_name,
  });

  writeAuditLog(
    { email: user.email, role: user.role_name },
    'LOGIN_SUCCESS',
    'auth/login',
    'success',
    'Authenticated via scrypt + HS256 JWT',
  );

  return res.json({
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role_name,
      permissions: JSON.parse(user.permissions_json),
    },
  });
});

app.get('/api/auth/me', requireAuth, (req: AuthedRequest, res: Response) => {
  return res.json({ user: req.user });
});

// ============================================================================
// Overview Endpoint
// ============================================================================
app.get('/api/overview', requireAuth, (_req: AuthedRequest, res: Response) => {
  const predStats = db
    .prepare(
      `SELECT COUNT(*) as total,
              SUM(CASE WHEN is_malicious = 1 THEN 1 ELSE 0 END) as malicious,
              SUM(CASE WHEN is_malicious = 0 THEN 1 ELSE 0 END) as benign
       FROM predictions`,
    )
    .get() as { total: number; malicious: number | null; benign: number | null };

  const activeClients = db
    .prepare('SELECT COUNT(*) as cnt FROM federated_clients WHERE active = 1')
    .get() as { cnt: number };

  const latestRound = db
    .prepare(
      `SELECT round_number, model_version, global_accuracy, global_f1, global_loss, global_fpr,
              accepted_clients, rejected_clients, communication_bytes, created_at
       FROM federated_rounds ORDER BY created_at DESC, round_number DESC LIMIT 1`,
    )
    .get() as Record<string, unknown> | undefined;

  const activeModel = db
    .prepare(
      `SELECT id, name, architecture, classification_mode, version, accuracy, precision_score, recall_score, f1_score, false_positive_rate, roc_auc
       FROM models WHERE is_active = 1 ORDER BY created_at DESC LIMIT 1`,
    )
    .get() as Record<string, unknown> | undefined;

  const recentAlerts = db
    .prepare('SELECT * FROM alerts ORDER BY created_at DESC LIMIT 8')
    .all();

  const modelsSummary = db
    .prepare(
      `SELECT id, name, architecture, training_paradigm, classification_mode, version, accuracy, precision_score, recall_score, f1_score, false_positive_rate
       FROM models ORDER BY created_at DESC LIMIT 6`,
    )
    .all();

  return res.json({
    totalRecordsAnalyzed: predStats.total || 0,
    maliciousRecords: predStats.malicious || 0,
    benignRecords: predStats.benign || 0,
    activeFederatedClients: activeClients.cnt || 0,
    globalModelVersion: (latestRound?.model_version as string) || (activeModel?.version as string) || 'v1.0.0',
    latestRoundNumber: (latestRound?.round_number as number) || 0,
    activeModel,
    latestRound,
    recentAlerts,
    modelsSummary,
  });
});

// ============================================================================
// Datasets Endpoints
// ============================================================================
app.get('/api/datasets', requireAuth, (_req: AuthedRequest, res: Response) => {
  const rows = db.prepare('SELECT * FROM datasets ORDER BY created_at DESC').all() as Array<Record<string, unknown>>;
  return res.json({
    datasets: rows.map((r) => ({
      ...r,
      isSynthetic: r.is_synthetic === 1,
      removedLeakageColumns: JSON.parse(String(r.removed_leakage_json)),
      classDistribution: JSON.parse(String(r.class_distribution_json)),
      featureColumns: JSON.parse(String(r.feature_columns_json)),
    })),
  });
});

app.get('/api/datasets/:id/preview', requireAuth, (req: AuthedRequest, res: Response) => {
  try {
    const { records, name, isSynthetic } = loadDatasetRecords(String(req.params.id));
    return res.json({
      id: req.params.id,
      name,
      isSynthetic,
      totalRows: records.length,
      preview: records.slice(0, 25),
      featureColumns: CORE_FEATURES,
    });
  } catch (err) {
    return res.status(404).json({ error: (err as Error).message });
  }
});

app.post('/api/datasets/upload', requireAuth, requireRole('admin', 'analyst'), (req: AuthedRequest, res: Response) => {
  try {
    const { name, csvText, columnMapping, sourceType } = req.body as {
      name?: string;
      csvText?: string;
      columnMapping?: Record<string, string>;
      sourceType?: string;
    };
    if (!csvText || typeof csvText !== 'string') {
      return res.status(400).json({ error: 'csvText is required' });
    }
    const { records, report } = parseAndCleanCsv(csvText, columnMapping, false);
    if (records.length === 0) {
      return res.status(400).json({ error: 'No valid flow records remained after cleaning NaN/Inf/duplicates' });
    }

    const id = `ds-${crypto.randomUUID().slice(0, 8)}`;
    const uploadDir = path.resolve(process.cwd(), 'data', 'uploads');
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
    const csvPath = path.join(uploadDir, `${id}.csv`);
    fs.writeFileSync(csvPath, recordsToCsv(records), 'utf8');

    const now = new Date().toISOString();
    const datasetName = (name || 'Uploaded Network Flows').trim();
    db.prepare(
      `INSERT INTO datasets (
        id, name, source_type, is_synthetic, raw_rows, clean_rows,
        dropped_missing, dropped_infinite, dropped_duplicates,
        removed_leakage_json, class_distribution_json, feature_columns_json,
        csv_path, created_by, created_at
      ) VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      id,
      datasetName,
      sourceType || 'custom_csv',
      report.rawRows,
      report.cleanRows,
      report.droppedMissing,
      report.droppedInfinite,
      report.droppedDuplicates,
      JSON.stringify(report.removedLeakageColumns),
      JSON.stringify(report.classDistribution),
      JSON.stringify(report.featureColumns),
      csvPath,
      req.user!.email,
      now,
    );

    writeAuditLog(
      { email: req.user!.email, role: req.user!.role },
      'UPLOAD_DATASET',
      `datasets/${id}`,
      'success',
      `Uploaded '${datasetName}' (${report.cleanRows}/${report.rawRows} clean rows)`,
    );

    return res.status(201).json({ id, name: datasetName, report, preview: records.slice(0, 15) });
  } catch (err) {
    return res.status(400).json({ error: (err as Error).message });
  }
});

// ============================================================================
// Centralized ML Training & Models Endpoints
// ============================================================================
app.get('/api/models', requireAuth, (_req: AuthedRequest, res: Response) => {
  const rows = db
    .prepare(
      `SELECT id, name, architecture, training_paradigm, classification_mode, version, dataset_id,
              accuracy, precision_score, recall_score, f1_score, false_positive_rate, roc_auc,
              training_time_ms, communication_bytes, metrics_json, is_active, created_at
       FROM models ORDER BY created_at DESC`,
    )
    .all() as Array<Record<string, unknown>>;

  return res.json({
    models: rows.map((r) => ({
      ...r,
      isActive: r.is_active === 1,
      metrics: JSON.parse(String(r.metrics_json)),
    })),
  });
});

app.post('/api/models/train', requireAuth, requireRole('admin'), (req: AuthedRequest, res: Response) => {
  const {
    datasetId = 'ds-synthetic-cicids2017',
    architecture = 'random_forest',
    classificationMode = 'multiclass',
    seed = 42,
  } = req.body as {
    datasetId?: string;
    architecture?: 'random_forest' | 'logistic_regression' | 'centralized_mlp';
    classificationMode?: ClassificationMode;
    seed?: number;
  };

  if (!['random_forest', 'logistic_regression', 'centralized_mlp'].includes(architecture)) {
    return res.status(400).json({ error: 'Unsupported centralized architecture' });
  }

  const jobId = `train-${crypto.randomUUID().slice(0, 8)}`;
  const job: TrainingJobState = {
    jobId,
    status: 'running',
    architecture,
    modelId: null,
    message: `Training ${architecture} (${classificationMode}) on ${datasetId}...`,
    startedAt: new Date().toISOString(),
    completedAt: null,
  };
  trainingJobs.set(jobId, job);

  setTimeout(() => {
    try {
      const { records } = loadDatasetRecords(datasetId);
      const split = prepareStratifiedSplit(records, classificationMode, seed);
      const start = Date.now();
      let artifact: unknown;
      let probs: number[][];
      let loss: number | undefined;
      let extra: Record<string, unknown> = { imbalanceRatio: split.imbalanceRatio };

      if (architecture === 'random_forest') {
        const rf = trainRandomForest({
          XTrain: split.XTrain,
          yTrain: split.yTrain,
          classes: split.classes,
          mode: classificationMode,
          scaler: split.scaler,
          numTrees: 18,
          maxDepth: 7,
          seed,
        });
        artifact = rf;
        probs = predictRandomForestProbs(rf, split.XTest);
        extra = { ...extra, featureImportances: rf.featureImportances };
      } else if (architecture === 'logistic_regression') {
        const lr = trainLogisticRegression({
          XTrain: split.XTrain,
          yTrain: split.yTrain,
          classes: split.classes,
          mode: classificationMode,
          scaler: split.scaler,
          classWeights: split.classWeights,
          epochs: 140,
          lr: 0.18,
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
          seed,
        });
        artifact = { kind: 'mlp', ...trained.model };
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
        communicationBytes: 0,
      });

      const modelId = `model-${architecture}-${crypto.randomUUID().slice(0, 6)}`;
      const labelMap = {
        random_forest: 'Random Forest Baseline',
        logistic_regression: 'Logistic Regression Baseline',
        centralized_mlp: 'Centralized PyTorch-style MLP',
      };
      const version = `v1.${Math.floor(Date.now() / 1000) % 1000}.0`;
      db.prepare(
        `INSERT INTO models (
          id, name, architecture, training_paradigm, classification_mode, version, dataset_id,
          accuracy, precision_score, recall_score, f1_score, false_positive_rate, roc_auc,
          training_time_ms, communication_bytes, metrics_json, artifact_json, is_active, created_at
        ) VALUES (?, ?, ?, 'centralized', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 0, ?)`,
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
        new Date().toISOString(),
      );

      writeAuditLog(
        { email: req.user!.email, role: req.user!.role },
        'TRAIN_CENTRALIZED_MODEL',
        `models/${modelId}`,
        'success',
        `Trained ${architecture} (${classificationMode}) -> Accuracy ${(metrics.accuracy * 100).toFixed(1)}%`,
      );

      job.status = 'completed';
      job.modelId = modelId;
      job.message = `Completed ${labelMap[architecture]} (Accuracy ${(metrics.accuracy * 100).toFixed(1)}%)`;
      job.completedAt = new Date().toISOString();
    } catch (err) {
      job.status = 'failed';
      job.message = (err as Error).message;
      job.completedAt = new Date().toISOString();
    }
  }, 20);

  return res.status(202).json({ job });
});

app.get('/api/models/jobs/:jobId', requireAuth, (req: AuthedRequest, res: Response) => {
  const job = trainingJobs.get(String(req.params.jobId));
  if (!job) return res.status(404).json({ error: 'Training job not found' });
  return res.json({ job });
});

// ============================================================================
// Federated Learning Endpoints
// ============================================================================
app.get('/api/federated/status', requireAuth, (_req: AuthedRequest, res: Response) => {
  return res.json({ job: federatedJob });
});

app.get('/api/federated/clients', requireAuth, (_req: AuthedRequest, res: Response) => {
  const clients = db
    .prepare(
      `SELECT fc.*, pk.key_id, pk.fingerprint, pk.revoked, pk.created_at as key_created_at, pk.rotated_at
       FROM federated_clients fc
       LEFT JOIN public_keys pk ON pk.client_id = fc.id
       ORDER BY fc.created_at ASC`,
    )
    .all() as Array<Record<string, unknown>>;

  const latestClientStats = db
    .prepare(
      `SELECT cm.client_id, cm.status, cm.sample_count, cm.local_loss, cm.local_accuracy, cm.local_f1, cm.payload_bytes, cm.rejection_reason
       FROM client_metrics cm
       WHERE cm.round_id = (SELECT id FROM federated_rounds ORDER BY created_at DESC, round_number DESC LIMIT 1)`,
    )
    .all() as Array<Record<string, unknown>>;

  const statByClient = new Map(latestClientStats.map((s) => [String(s.client_id), s]));

  return res.json({
    clients: clients.map((c) => ({
      ...c,
      active: c.active === 1,
      revoked: c.revoked === 1,
      latestMetrics: statByClient.get(String(c.id)) || null,
    })),
  });
});

app.post('/api/federated/clients/register', requireAuth, requireRole('admin'), (req: AuthedRequest, res: Response) => {
  const { name, organization, subnetCidr } = req.body as {
    name?: string;
    organization?: string;
    subnetCidr?: string;
  };
  if (!name || !organization) {
    return res.status(400).json({ error: 'Client name and organization are required' });
  }
  const clientId = `client-${name.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 18)}-${crypto.randomUUID().slice(0, 4)}`;
  const now = new Date().toISOString();
  const kp = generateAndStoreEd25519KeyPair(clientId, true);

  db.prepare(
    `INSERT INTO federated_clients (id, name, organization, subnet_cidr, active, last_seen_at, created_at)
     VALUES (?, ?, ?, ?, 1, ?, ?)`,
  ).run(clientId, name.trim(), organization.trim(), (subnetCidr || '10.90.0.0/16').trim(), now, now);

  db.prepare(
    `INSERT INTO public_keys (id, client_id, key_id, algorithm, public_key_pem, fingerprint, revoked, created_at)
     VALUES (?, ?, ?, 'Ed25519', ?, ?, 0, ?)`,
  ).run(`pk-${clientId}`, clientId, kp.keyId, kp.publicKeyPem, kp.fingerprint, now);

  writeAuditLog(
    { email: req.user!.email, role: req.user!.role },
    'REGISTER_FL_CLIENT',
    `federated_clients/${clientId}`,
    'success',
    `Registered client '${name.trim()}' and provisioned Ed25519 key ${kp.keyId}`,
  );

  return res.status(201).json({
    client: { id: clientId, name: name.trim(), organization: organization.trim(), keyId: kp.keyId, fingerprint: kp.fingerprint },
  });
});

app.post('/api/federated/clients/:id/toggle', requireAuth, requireRole('admin'), (req: AuthedRequest, res: Response) => {
  const clientId = String(req.params.id);
  const existing = db.prepare('SELECT id, name, active FROM federated_clients WHERE id = ?').get(clientId) as
    | { id: string; name: string; active: number }
    | undefined;
  if (!existing) {
    return res.status(404).json({ error: 'Federated client not found' });
  }
  const nextActive = existing.active === 1 ? 0 : 1;
  db.prepare('UPDATE federated_clients SET active = ? WHERE id = ?').run(nextActive, clientId);
  writeAuditLog(
    { email: req.user!.email, role: req.user!.role },
    nextActive === 1 ? 'ENABLE_FL_CLIENT' : 'PAUSE_FL_CLIENT',
    `federated_clients/${clientId}`,
    'success',
    `${existing.name} participation set to ${nextActive === 1 ? 'active' : 'paused'}`,
  );
  return res.json({ id: clientId, active: nextActive === 1 });
});

app.get('/api/federated/rounds', requireAuth, (_req: AuthedRequest, res: Response) => {
  const rounds = db
    .prepare('SELECT * FROM federated_rounds ORDER BY created_at ASC, round_number ASC LIMIT 60')
    .all() as Array<Record<string, unknown>>;

  const clientMetrics = db
    .prepare(
      `SELECT cm.*, fc.name as client_name, fc.organization
       FROM client_metrics cm
       JOIN federated_clients fc ON fc.id = cm.client_id
       ORDER BY cm.created_at ASC`,
    )
    .all() as Array<Record<string, unknown>>;

  const byRound = new Map<string, Array<Record<string, unknown>>>();
  for (const cm of clientMetrics) {
    const rid = String(cm.round_id);
    if (!byRound.has(rid)) byRound.set(rid, []);
    byRound.get(rid)!.push({
      ...cm,
      signatureVerified: cm.signature_verified === 1,
      integrityVerified: cm.integrity_verified === 1,
      decryptionVerified: cm.decryption_verified === 1,
    });
  }

  return res.json({
    rounds: rounds.map((r) => ({
      ...r,
      metrics: JSON.parse(String(r.metrics_json)),
      clientOutcomes: byRound.get(String(r.id)) || [],
    })),
  });
});

app.post('/api/federated/start', requireAuth, requireRole('admin'), (req: AuthedRequest, res: Response) => {
  if (federatedJob.status === 'running') {
    return res.status(409).json({ error: 'A federated training job is already running' });
  }

  const {
    datasetId = 'ds-synthetic-cicids2017',
    rounds = 5,
    localEpochs = 4,
    learningRate = 0.06,
    nonIidAlpha = 0.65,
    classificationMode = 'multiclass',
    dpEnabled = false,
    dpClipNorm = 1.5,
    dpNoiseMultiplier = 0.08,
    seed = 42,
  } = req.body as {
    datasetId?: string;
    rounds?: number;
    localEpochs?: number;
    learningRate?: number;
    nonIidAlpha?: number;
    classificationMode?: ClassificationMode;
    dpEnabled?: boolean;
    dpClipNorm?: number;
    dpNoiseMultiplier?: number;
    seed?: number;
  };

  const clampedRounds = Math.min(12, Math.max(1, Number(rounds)));
  const clampedEpochs = Math.min(10, Math.max(1, Number(localEpochs)));
  const jobId = `fl-job-${crypto.randomUUID().slice(0, 8)}`;

  federatedJob = {
    jobId,
    status: 'running',
    totalRounds: clampedRounds,
    currentRound: 0,
    classificationMode,
    dpEnabled: Boolean(dpEnabled),
    message: `Initializing global MLP and dispatching to active clients...`,
    startedAt: new Date().toISOString(),
    completedAt: null,
  };

  const actor = { email: req.user!.email, role: req.user!.role };

  // Execute rounds asynchronously one tick at a time so /api/federated/status reports live progress
  (async () => {
    try {
      const { records } = loadDatasetRecords(datasetId);
      const split = prepareStratifiedSplit(records, classificationMode, seed);

      const clientRows = db
        .prepare(
          `SELECT fc.id, fc.name, fc.organization, fc.active, pk.public_key_pem, pk.revoked
           FROM federated_clients fc
           LEFT JOIN public_keys pk ON pk.client_id = fc.id`,
        )
        .all() as Array<{
        id: string;
        name: string;
        organization: string;
        active: number;
        public_key_pem: string | null;
        revoked: number | null;
      }>;

      const activeClients: FederatedClientDescriptor[] = clientRows
        .filter((c) => c.active === 1)
        .map((c) => ({
          id: c.id,
          name: c.name,
          organization: c.organization,
          active: true,
          publicKeyPem: c.public_key_pem,
          keyRevoked: c.revoked === 1,
        }));

      if (activeClients.length < 2) {
        throw new Error('At least 2 active federated clients are required for FedAvg');
      }

      const partitionsArr = partitionNonIid(
        split.XTrain,
        split.yTrain,
        split.classes,
        activeClients.map((c) => c.id),
        nonIidAlpha,
        seed,
      );
      const partitions = new Map(partitionsArr.map((p) => [p.clientId, p]));

      let globalModel = initializeMLPWeights(split.XTrain[0].length, split.classes, classificationMode, split.scaler, seed);
      const versionBase = Math.floor(Date.now() / 1000) % 1000;
      let totalDurationMs = 0;
      let totalCommBytes = 0;
      let lastRoundResult: ReturnType<typeof executeFederatedRound>['roundResult'] | null = null;

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
              severity: 'high',
              clientId: outcome.clientId,
              description: `Round ${r} update from ${outcome.clientName} rejected: ${outcome.reason}`,
              signatureStatus: outcome.signatureVerified ? 'verified' : 'failed',
              integrityStatus: outcome.integrityVerified ? 'verified' : 'failed',
              encryptionStatus: outcome.decryptionVerified ? 'aes-256-gcm' : 'failed',
              blocked: true,
            });
          },
        });

        globalModel = updatedModel;
        totalDurationMs += roundResult.durationMs;
        totalCommBytes += roundResult.communicationBytes;
        lastRoundResult = roundResult;

        const now = new Date().toISOString();
        const roundId = `round-${jobId}-${r}`;
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
          db.prepare('UPDATE federated_clients SET last_seen_at = ? WHERE id = ?').run(now, outcome.clientId);
        }

        federatedJob.currentRound = r;
        federatedJob.message = `Round ${r}/${clampedRounds} aggregated (${roundResult.acceptedClients} accepted, accuracy ${(roundResult.globalAccuracy * 100).toFixed(1)}%)`;
      }

      if (lastRoundResult) {
        const modelId = `model-flmlp-${jobId}`;
        db.prepare('UPDATE models SET is_active = 0 WHERE training_paradigm = ?').run('federated');
        db.prepare(
          `INSERT INTO models (
            id, name, architecture, training_paradigm, classification_mode, version, dataset_id,
            accuracy, precision_score, recall_score, f1_score, false_positive_rate, roc_auc,
            training_time_ms, communication_bytes, metrics_json, artifact_json, is_active, created_at
          ) VALUES (?, ?, 'federated_mlp', 'federated', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`,
        ).run(
          modelId,
          dpEnabled ? 'Federated FedAvg MLP (DP-SGD)' : 'Federated FedAvg MLP',
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
          JSON.stringify({ kind: 'mlp', ...globalModel }),
          new Date().toISOString(),
        );

        writeAuditLog(
          actor,
          'RUN_FEDERATED_TRAINING',
          `models/${modelId}`,
          'success',
          `Completed ${clampedRounds} rounds (${classificationMode}, DP=${dpEnabled}) -> Accuracy ${(lastRoundResult.globalAccuracy * 100).toFixed(1)}%`,
        );
      }

      federatedJob.status = 'completed';
      federatedJob.completedAt = new Date().toISOString();
    } catch (err) {
      federatedJob.status = 'failed';
      federatedJob.message = (err as Error).message;
      federatedJob.completedAt = new Date().toISOString();
    }
  })();

  return res.status(202).json({ job: federatedJob });
});

// ============================================================================
// Cryptography & Security Endpoints
// ============================================================================
app.get('/api/security/keys', requireAuth, (_req: AuthedRequest, res: Response) => {
  const keys = db
    .prepare(
      `SELECT pk.id, pk.client_id, fc.name as client_name, fc.organization, fc.active as client_active,
              pk.key_id, pk.algorithm, pk.public_key_pem, pk.fingerprint, pk.revoked, pk.revoked_reason,
              pk.created_at, pk.rotated_at
       FROM public_keys pk
       JOIN federated_clients fc ON fc.id = pk.client_id
       ORDER BY pk.created_at ASC`,
    )
    .all() as Array<Record<string, unknown>>;

  return res.json({
    keys: keys.map((k) => ({
      ...k,
      clientActive: k.client_active === 1,
      revoked: k.revoked === 1,
    })),
  });
});

app.post('/api/security/keys/:clientId/rotate', requireAuth, requireRole('admin'), (req: AuthedRequest, res: Response) => {
  const clientId = String(req.params.clientId);
  const client = db.prepare('SELECT id, name FROM federated_clients WHERE id = ?').get(clientId) as
    | { id: string; name: string }
    | undefined;
  if (!client) return res.status(404).json({ error: 'Client not found' });

  const kp = generateAndStoreEd25519KeyPair(clientId, true);
  const now = new Date().toISOString();
  db.prepare(
    `UPDATE public_keys SET key_id = ?, public_key_pem = ?, fingerprint = ?, revoked = 0, revoked_reason = NULL, rotated_at = ?
     WHERE client_id = ?`,
  ).run(kp.keyId, kp.publicKeyPem, kp.fingerprint, now, clientId);

  writeSecurityEvent({
    eventType: 'KEY_ROTATED',
    severity: 'low',
    clientId,
    description: `Rotated Ed25519 key pair for ${client.name} (new keyId ${kp.keyId})`,
    signatureStatus: 'verified',
    integrityStatus: 'verified',
    encryptionStatus: 'aes-256-gcm',
    blocked: false,
  });

  writeAuditLog(
    { email: req.user!.email, role: req.user!.role },
    'ROTATE_CLIENT_KEY',
    `public_keys/${clientId}`,
    'success',
    `Provisioned new Ed25519 key ${kp.keyId} (fingerprint ${kp.fingerprint.slice(0, 12)})`,
  );

  return res.json({ clientId, keyId: kp.keyId, fingerprint: kp.fingerprint, rotatedAt: now });
});

app.post('/api/security/keys/:clientId/revoke', requireAuth, requireRole('admin'), (req: AuthedRequest, res: Response) => {
  const clientId = String(req.params.clientId);
  const { reason = 'Compromised key / administrative revocation' } = req.body as { reason?: string };
  const client = db.prepare('SELECT id, name FROM federated_clients WHERE id = ?').get(clientId) as
    | { id: string; name: string }
    | undefined;
  if (!client) return res.status(404).json({ error: 'Client not found' });

  db.prepare('UPDATE public_keys SET revoked = 1, revoked_reason = ? WHERE client_id = ?').run(reason, clientId);
  writeSecurityEvent({
    eventType: 'KEY_REVOKED',
    severity: 'high',
    clientId,
    description: `Revoked Ed25519 public key for ${client.name}: ${reason}`,
    signatureStatus: 'revoked',
    integrityStatus: 'n/a',
    encryptionStatus: 'n/a',
    blocked: true,
  });
  writeAuditLog(
    { email: req.user!.email, role: req.user!.role },
    'REVOKE_CLIENT_KEY',
    `public_keys/${clientId}`,
    'success',
    reason,
  );
  return res.json({ clientId, revoked: true });
});

app.post('/api/security/simulate-attack', requireAuth, requireRole('admin', 'analyst'), (req: AuthedRequest, res: Response) => {
  const {
    attackType,
    clientId = 'client-hospital',
  } = req.body as {
    attackType?: 'tamper_payload' | 'replay_nonce' | 'unauthorized_client' | 'nan_poisoning';
    clientId?: string;
  };

  if (!attackType) {
    return res.status(400).json({ error: 'attackType is required' });
  }

  const activeModelRow = db
    .prepare("SELECT version, artifact_json FROM models WHERE training_paradigm = 'federated' ORDER BY created_at DESC LIMIT 1")
    .get() as { version: string; artifact_json: string } | undefined;
  if (!activeModelRow) {
    return res.status(400).json({ error: 'No federated model found' });
  }
  const baseModel = JSON.parse(activeModelRow.artifact_json) as MLPWeights;

  const clientRow = db
    .prepare(
      `SELECT fc.id, fc.name, fc.organization, fc.active, pk.public_key_pem, pk.revoked
       FROM federated_clients fc LEFT JOIN public_keys pk ON pk.client_id = fc.id WHERE fc.id = ?`,
    )
    .get(clientId) as
    | { id: string; name: string; organization: string; active: number; public_key_pem: string | null; revoked: number | null }
    | undefined;

  const privateKeyPem = loadClientPrivateKey(clientId);
  if (!clientRow || !privateKeyPem) {
    return res.status(404).json({ error: 'Target client or local key missing' });
  }

  const cleanPayload = {
    weights: baseModel.weights,
    biases: baseModel.biases,
    localLoss: 0.21,
    localAccuracy: 0.93,
    localF1: 0.92,
  };

  const descriptor: FederatedClientDescriptor = {
    id: clientRow.id,
    name: clientRow.name,
    organization: clientRow.organization,
    active: clientRow.active === 1,
    publicKeyPem: clientRow.public_key_pem,
    keyRevoked: clientRow.revoked === 1,
  };

  let verificationResult: ReturnType<typeof processIncomingClientEnvelope>;
  let eventType = '';

  if (attackType === 'tamper_payload') {
    const env = buildSignedEncryptedEnvelope({
      clientId,
      round: 99,
      modelVersion: activeModelRow.version,
      sampleCount: 140,
      payload: cleanPayload,
      privateKeyPem,
    });
    // Tamper with ciphertext / auth tag in transit
    const tamperedBytes = Buffer.from(env.ciphertextBase64, 'base64');
    tamperedBytes[0] = tamperedBytes[0] ^ 0xff;
    env.ciphertextBase64 = tamperedBytes.toString('base64');

    verificationResult = processIncomingClientEnvelope({
      envelope: env,
      client: descriptor,
      expectedModel: baseModel,
      expectedModelVersion: activeModelRow.version,
      expectedRound: 99,
      replayGuard,
    });
    eventType = 'PAYLOAD_TAMPER_REJECTED';
  } else if (attackType === 'replay_nonce') {
    const fixedNonce = crypto.randomBytes(12).toString('hex');
    const env1 = buildSignedEncryptedEnvelope({
      clientId,
      round: 99,
      modelVersion: activeModelRow.version,
      sampleCount: 140,
      payload: cleanPayload,
      privateKeyPem,
      forcedNonce: fixedNonce,
    });
    // First submission succeeds and registers nonce
    processIncomingClientEnvelope({
      envelope: env1,
      client: descriptor,
      expectedModel: baseModel,
      expectedModelVersion: activeModelRow.version,
      expectedRound: 99,
      replayGuard,
    });
    // Replayed submission with same nonce must be rejected
    verificationResult = processIncomingClientEnvelope({
      envelope: env1,
      client: descriptor,
      expectedModel: baseModel,
      expectedModelVersion: activeModelRow.version,
      expectedRound: 99,
      replayGuard,
    });
    eventType = 'REPLAY_ATTACK_REJECTED';
  } else if (attackType === 'unauthorized_client') {
    const rogueKp = generateAndStoreEd25519KeyPair('rogue-unregistered', false);
    const env = buildSignedEncryptedEnvelope({
      clientId: 'rogue-node-99',
      round: 99,
      modelVersion: activeModelRow.version,
      sampleCount: 140,
      payload: cleanPayload,
      privateKeyPem: rogueKp.privateKeyPem,
    });
    verificationResult = processIncomingClientEnvelope({
      envelope: env,
      client: undefined,
      expectedModel: baseModel,
      expectedModelVersion: activeModelRow.version,
      expectedRound: 99,
      replayGuard,
    });
    eventType = 'UNAUTHORIZED_CLIENT_REJECTED';
  } else {
    // NaN / extreme poisoning payload signed with valid key, caught by tensor validator
    const poisonedWeights = baseModel.weights.map((l) => l.map((r) => [...r]));
    poisonedWeights[0][0][0] = 999999;
    const env = buildSignedEncryptedEnvelope({
      clientId,
      round: 99,
      modelVersion: activeModelRow.version,
      sampleCount: 140,
      payload: { ...cleanPayload, weights: poisonedWeights },
      privateKeyPem,
    });
    verificationResult = processIncomingClientEnvelope({
      envelope: env,
      client: descriptor,
      expectedModel: baseModel,
      expectedModelVersion: activeModelRow.version,
      expectedRound: 99,
      replayGuard,
    });
    eventType = 'POISONED_UPDATE_REJECTED';
  }

  writeSecurityEvent({
    eventType,
    severity: 'critical',
    clientId: attackType === 'unauthorized_client' ? 'rogue-node-99' : clientId,
    description: verificationResult.reason || 'Adversarial update blocked by coordinator',
    signatureStatus: verificationResult.signatureVerified ? 'verified' : 'failed',
    integrityStatus: verificationResult.integrityVerified ? 'verified' : 'failed',
    encryptionStatus: verificationResult.decryptionVerified ? 'aes-256-gcm' : 'failed',
    blocked: !verificationResult.accepted,
  });

  writeAuditLog(
    { email: req.user!.email, role: req.user!.role },
    'SECURITY_VERIFICATION_TEST',
    `security/simulate-attack/${attackType}`,
    'success',
    `Verified coordinator blocked ${attackType}: ${verificationResult.reason}`,
  );

  return res.json({
    attackType,
    blocked: !verificationResult.accepted,
    code: verificationResult.code,
    reason: verificationResult.reason,
    signatureVerified: verificationResult.signatureVerified,
    decryptionVerified: verificationResult.decryptionVerified,
    integrityVerified: verificationResult.integrityVerified,
  });
});

app.get('/api/security/events', requireAuth, (_req: AuthedRequest, res: Response) => {
  const events = db.prepare('SELECT * FROM security_events ORDER BY created_at DESC LIMIT 80').all();
  return res.json({ events });
});

app.get('/api/security/audit-logs', requireAuth, (_req: AuthedRequest, res: Response) => {
  const logs = db.prepare('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 100').all();
  return res.json({ logs });
});

// ============================================================================
// Inference & Network Security Endpoints
// ============================================================================
app.post('/api/inference/predict', requireAuth, requireRole('admin', 'analyst'), (req: AuthedRequest, res: Response) => {
  const { record, modelId, clientSensor = 'Lab-Sensor-01' } = req.body as {
    record?: FlowRecord;
    modelId?: string;
    clientSensor?: string;
  };
  if (!record) return res.status(400).json({ error: 'Flow record is required' });

  const modelRow = (
    modelId
      ? db.prepare('SELECT id, name, architecture, artifact_json FROM models WHERE id = ?').get(modelId)
      : db.prepare('SELECT id, name, architecture, artifact_json FROM models WHERE is_active = 1 ORDER BY created_at DESC LIMIT 1').get()
  ) as { id: string; name: string; architecture: string; artifact_json: string } | undefined;

  if (!modelRow) return res.status(404).json({ error: 'No trained model available' });

  const [result] = runModelInference(modelRow, [record]);
  const predId = `pred-${crypto.randomUUID().slice(0, 8)}`;
  const now = new Date().toISOString();

  db.prepare(
    `INSERT INTO predictions (
      id, batch_id, model_id, client_sensor, ingestion_mode,
      predicted_label, true_label, is_malicious, confidence, severity,
      flow_duration, flow_bytes_per_sec, syn_flag_count, created_at
    ) VALUES (?, ?, ?, ?, 'single_api', ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
    now,
  );

  if (result.isMalicious) {
    db.prepare(
      `INSERT INTO alerts (id, prediction_id, client_sensor, attack_category, severity, confidence, status, summary, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?)`,
    ).run(
      `alert-${crypto.randomUUID().slice(0, 8)}`,
      predId,
      clientSensor,
      result.predictedLabel,
      result.severity,
      result.confidence,
      `${result.predictedLabel} flow flagged on ${clientSensor} (${(result.confidence * 100).toFixed(1)}% confidence)`,
      now,
    );
  }

  return res.json({ id: predId, modelName: modelRow.name, ...result });
});

app.post('/api/inference/batch', requireAuth, requireRole('admin', 'analyst'), (req: AuthedRequest, res: Response) => {
  try {
    const {
      csvText,
      useSyntheticSample = false,
      modelId,
      classificationMode = 'multiclass',
      clientSensor = 'Offline-CSV-Upload',
    } = req.body as {
      csvText?: string;
      useSyntheticSample?: boolean;
      modelId?: string;
      classificationMode?: ClassificationMode;
      clientSensor?: string;
    };

    let records: FlowRecord[] = [];
    if (useSyntheticSample) {
      records = generateSyntheticCicIdsDataset(180, Math.floor(Date.now() % 10000));
    } else if (csvText && typeof csvText === 'string') {
      const parsed = parseAndCleanCsv(csvText);
      records = parsed.records;
    } else {
      return res.status(400).json({ error: 'Provide csvText or set useSyntheticSample=true' });
    }

    if (records.length === 0) {
      return res.status(400).json({ error: 'No valid records to classify' });
    }

    // Pick model matching requested mode/id
    let modelRow = (
      modelId
        ? db.prepare('SELECT id, name, architecture, classification_mode, artifact_json FROM models WHERE id = ?').get(modelId)
        : db
            .prepare(
              'SELECT id, name, architecture, classification_mode, artifact_json FROM models WHERE classification_mode = ? ORDER BY is_active DESC, created_at DESC LIMIT 1',
            )
            .get(classificationMode)
    ) as { id: string; name: string; architecture: string; classification_mode: string; artifact_json: string } | undefined;

    if (!modelRow) {
      modelRow = db
        .prepare('SELECT id, name, architecture, classification_mode, artifact_json FROM models ORDER BY is_active DESC, created_at DESC LIMIT 1')
        .get() as typeof modelRow;
    }
    if (!modelRow) return res.status(404).json({ error: 'No trained models available' });

    const artifact = JSON.parse(modelRow.artifact_json) as
      | ({ kind: 'mlp' } & MLPWeights)
      | LogisticRegressionModel
      | RandomForestModel;

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

    const batchId = `batch-${crypto.randomUUID().slice(0, 8)}`;
    const now = new Date().toISOString();

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
      ) VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?)`,
    );

    const labeledIndices: number[] = [];
    const yTrue: number[] = [];
    const labeledProbs: number[][] = [];
    const classes =
      classificationMode === 'binary' && artifact.classes.length > 2
        ? ['Benign', 'Malicious']
        : artifact.classes;

    const rowsOut = records.map((rec, i) => {
      const p = probs[i];
      let best = 0;
      for (let c = 1; c < p.length; c++) {
        if (p[c] > p[best]) best = c;
      }
      const rawPredLabel = artifact.classes[best];
      const predLabel = classificationMode === 'binary' ? (rawPredLabel === 'Benign' ? 'Benign' : 'Malicious') : rawPredLabel;
      const confidence =
        classificationMode === 'binary' && artifact.classes.length > 2
          ? Number((rawPredLabel === 'Benign' ? p[0] : 1 - p[0]).toFixed(4))
          : Number(p[best].toFixed(4));
      const isMalicious = predLabel !== 'Benign';
      const severity = computeSeverity(rawPredLabel, confidence);
      const predId = `pred-${batchId}-${i}`;

      if (rec.label) {
        const mappedTrue =
          classificationMode === 'binary' ? (rec.label === 'Benign' ? 'Benign' : 'Malicious') : rec.label;
        const idx = classes.indexOf(mappedTrue);
        if (idx !== -1) {
          labeledIndices.push(i);
          yTrue.push(idx);
          if (classificationMode === 'binary' && artifact.classes.length > 2) {
            const benignIdx = Math.max(0, artifact.classes.indexOf('Benign'));
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
          modelRow!.id,
          clientSensor,
          useSyntheticSample ? 'synthetic_batch_csv' : 'uploaded_csv',
          predLabel,
          rec.label ?? null,
          isMalicious ? 1 : 0,
          confidence,
          severity,
          rec.flow_duration,
          rec.flow_bytes_per_sec,
          rec.syn_flag_count,
          now,
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
            now,
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
        totalFwdPackets: rec.total_fwd_packets,
      };
    });

    const evaluation =
      yTrue.length > 0
        ? evaluatePredictions({
            yTrue,
            probs: labeledProbs,
            classes,
          })
        : null;

    writeAuditLog(
      { email: req.user!.email, role: req.user!.role },
      'RUN_BATCH_INFERENCE',
      `inference/${batchId}`,
      'success',
      `Classified ${records.length} flows using ${modelRow.name} (${classificationMode})`,
    );

    return res.json({
      batchId,
      modelUsed: { id: modelRow.id, name: modelRow.name, architecture: modelRow.architecture },
      totalRecords: rowsOut.length,
      maliciousCount: rowsOut.filter((r) => r.isMalicious).length,
      benignCount: rowsOut.filter((r) => !r.isMalicious).length,
      predictions: rowsOut,
      evaluation,
    });
  } catch (err) {
    return res.status(400).json({ error: (err as Error).message });
  }
});

app.post('/api/monitoring/stream-tick', requireAuth, requireRole('admin', 'analyst'), (req: AuthedRequest, res: Response) => {
  const { count = 8 } = req.body as { count?: number };
  const n = Math.min(24, Math.max(1, Number(count)));
  const modelRow = db
    .prepare('SELECT id, name, architecture, artifact_json FROM models WHERE is_active = 1 ORDER BY created_at DESC LIMIT 1')
    .get() as { id: string; name: string; architecture: string; artifact_json: string } | undefined;
  if (!modelRow) return res.status(404).json({ error: 'No active model found' });

  const sensors = ['Hospital-East', 'FinTech-Core', 'Campus-Net', 'Cloud-Edge', 'Telecom-West'];
  const flows = generateSyntheticCicIdsDataset(n, Math.floor(Date.now() % 100000));
  const preds = runModelInference(modelRow, flows);
  const now = new Date().toISOString();

  const insertPred = db.prepare(
    `INSERT INTO predictions (
      id, batch_id, model_id, client_sensor, ingestion_mode,
      predicted_label, true_label, is_malicious, confidence, severity,
      flow_duration, flow_bytes_per_sec, syn_flag_count, created_at
    ) VALUES (?, ?, ?, ?, 'simulated_flow_adapter', ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  const insertAlert = db.prepare(
    `INSERT INTO alerts (
      id, prediction_id, client_sensor, attack_category, severity, confidence, status, summary, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?)`,
  );

  const created = flows.map((flow, i) => {
    const p = preds[i];
    const sensor = sensors[(i + Math.floor(Date.now() / 1000)) % sensors.length];
    const predId = `pred-live-${crypto.randomUUID().slice(0, 8)}`;
    insertPred.run(
      predId,
      'live-flow-adapter',
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
      now,
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
        now,
      );
    }
    return { id: predId, sensor, ...p, createdAt: now };
  });

  return res.json({ ingested: created.length, records: created });
});

app.get('/api/alerts', requireAuth, (req: AuthedRequest, res: Response) => {
  const severity = req.query.severity ? String(req.query.severity) : null;
  const status = req.query.status ? String(req.query.status) : null;
  const query = 'SELECT * FROM alerts ORDER BY created_at DESC LIMIT 150';
  let rows = db.prepare(query).all() as Array<Record<string, unknown>>;
  if (severity && severity !== 'all') {
    rows = rows.filter((r) => r.severity === severity);
  }
  if (status && status !== 'all') {
    rows = rows.filter((r) => r.status === status);
  }
  return res.json({ alerts: rows });
});

app.post('/api/alerts/:id/ack', requireAuth, requireRole('admin', 'analyst'), (req: AuthedRequest, res: Response) => {
  const id = String(req.params.id);
  const existing = db.prepare('SELECT id, status FROM alerts WHERE id = ?').get(id) as
    | { id: string; status: string }
    | undefined;
  if (!existing) return res.status(404).json({ error: 'Alert not found' });
  const nextStatus = existing.status === 'acknowledged' ? 'open' : 'acknowledged';
  db.prepare('UPDATE alerts SET status = ? WHERE id = ?').run(nextStatus, id);
  writeAuditLog(
    { email: req.user!.email, role: req.user!.role },
    'UPDATE_ALERT_STATUS',
    `alerts/${id}`,
    'success',
    `Set alert status to ${nextStatus}`,
  );
  return res.json({ id, status: nextStatus });
});

app.get('/api/metrics', requireAuth, (_req: AuthedRequest, res: Response) => {
  const models = db
    .prepare(
      `SELECT id, name, architecture, training_paradigm, classification_mode, version,
              accuracy, precision_score, recall_score, f1_score, false_positive_rate, roc_auc,
              training_time_ms, communication_bytes, metrics_json, is_active, created_at
       FROM models ORDER BY created_at DESC`,
    )
    .all() as Array<Record<string, unknown>>;

  const attackDist = db
    .prepare(
      `SELECT predicted_label as category, COUNT(*) as count
       FROM predictions GROUP BY predicted_label ORDER BY count DESC`,
    )
    .all();

  const sensorActivity = db
    .prepare(
      `SELECT client_sensor as sensor,
              COUNT(*) as total,
              SUM(CASE WHEN is_malicious = 1 THEN 1 ELSE 0 END) as malicious,
              SUM(CASE WHEN is_malicious = 0 THEN 1 ELSE 0 END) as benign
       FROM predictions GROUP BY client_sensor ORDER BY total DESC`,
    )
    .all();

  const severityDist = db
    .prepare(
      `SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity`,
    )
    .all();

  const timeline = db
    .prepare(
      `SELECT substr(created_at, 1, 16) as bucket,
              SUM(CASE WHEN is_malicious = 1 THEN 1 ELSE 0 END) as malicious,
              SUM(CASE WHEN is_malicious = 0 THEN 1 ELSE 0 END) as benign
       FROM predictions
       GROUP BY substr(created_at, 1, 16)
       ORDER BY bucket ASC
       LIMIT 24`,
    )
    .all();

  return res.json({
    models: models.map((m) => ({
      ...m,
      isActive: m.is_active === 1,
      metrics: JSON.parse(String(m.metrics_json)),
    })),
    attackDistribution: attackDist,
    sensorActivity,
    severityDistribution: severityDist,
    timeline,
  });
});

// ============================================================================
// Vite / Static Asset Serving
// ============================================================================
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`FL-IDS server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
