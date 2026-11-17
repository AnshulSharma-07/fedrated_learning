export type NavPage =
  | 'overview'
  | 'detection'
  | 'federated'
  | 'crypto'
  | 'monitoring'
  | 'evaluation';

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'analyst' | 'viewer';
  permissions?: string[];
}

export interface ConfusionMatrixData {
  labels: string[];
  matrix: number[][];
}

export interface PerClassMetric {
  label: string;
  precision: number;
  recall: number;
  f1Score: number;
  support: number;
}

export interface EvaluationMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  falsePositiveRate: number;
  rocAuc: number | null;
  loss?: number;
  confusionMatrix: ConfusionMatrixData;
  perClass: PerClassMetric[];
  sampleCount: number;
  trainingTimeMs: number;
  communicationBytes: number;
  featureImportances?: Record<string, number>;
  imbalanceRatio?: number;
  dpEnabled?: boolean;
  dpEpsilonEstimate?: number | null;
}

export interface ModelSummary {
  id: string;
  name: string;
  architecture: string;
  training_paradigm: string;
  classification_mode: string;
  version: string;
  accuracy: number;
  precision_score: number;
  recall_score: number;
  f1_score: number;
  false_positive_rate: number;
  roc_auc: number | null;
  training_time_ms: number;
  communication_bytes: number;
  isActive?: boolean;
  metrics?: EvaluationMetrics;
  created_at?: string;
}

export interface AlertItem {
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

export interface OverviewResponse {
  totalRecordsAnalyzed: number;
  maliciousRecords: number;
  benignRecords: number;
  activeFederatedClients: number;
  globalModelVersion: string;
  latestRoundNumber: number;
  activeModel: ModelSummary | null;
  latestRound: {
    round_number: number;
    model_version: string;
    global_accuracy: number;
    global_f1: number;
    global_loss: number;
    global_fpr: number;
    accepted_clients: number;
    rejected_clients: number;
    communication_bytes: number;
    created_at: string;
  } | null;
  recentAlerts: AlertItem[];
  modelsSummary: ModelSummary[];
}

export interface DatasetSummary {
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
  created_at: string;
}

export interface FederatedClient {
  id: string;
  name: string;
  organization: string;
  subnet_cidr: string;
  active: boolean;
  last_seen_at: string | null;
  key_id: string | null;
  fingerprint: string | null;
  revoked: boolean;
  latestMetrics: {
    status: string;
    sample_count: number;
    local_loss: number;
    local_accuracy: number;
    local_f1: number;
    payload_bytes: number;
    rejection_reason: string | null;
  } | null;
}

export interface FederatedRoundItem {
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

export interface PublicKeyRecord {
  id: string;
  client_id: string;
  client_name: string;
  organization: string;
  clientActive: boolean;
  key_id: string;
  algorithm: string;
  public_key_pem: string;
  fingerprint: string;
  revoked: boolean;
  revoked_reason: string | null;
  created_at: string;
  rotated_at: string | null;
}

export interface SecurityEventItem {
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

export interface AuditLogItem {
  id: string;
  actor_email: string;
  actor_role: string;
  action: string;
  resource: string;
  outcome: string;
  details: string;
  created_at: string;
}
