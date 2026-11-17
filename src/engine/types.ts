export type AttackCategory =
  | 'Benign'
  | 'DoS/DDoS'
  | 'PortScan'
  | 'BruteForce'
  | 'Botnet'
  | 'WebAttack';

export type ClassificationMode = 'binary' | 'multiclass';

export type ModelArchitecture = 'federated_mlp' | 'centralized_mlp' | 'random_forest' | 'logistic_regression';

export type AlertSeverity = 'low' | 'medium' | 'high' | 'critical';

export type UserRole = 'admin' | 'analyst' | 'viewer';

export interface FlowRecord {
  flow_duration: number;
  total_fwd_packets: number;
  total_bwd_packets: number;
  fwd_packet_length_mean: number;
  bwd_packet_length_mean: number;
  flow_bytes_per_sec: number;
  flow_packets_per_sec: number;
  syn_flag_count: number;
  ack_flag_count: number;
  rst_flag_count: number;
  psh_flag_count: number;
  iat_mean: number;
  init_win_bytes_fwd: number;
  subflow_fwd_bytes: number;
  label?: AttackCategory;
  source_ip?: string;
  destination_ip?: string;
  timestamp?: string;
}

export interface DatasetCleanReport {
  rawRows: number;
  cleanRows: number;
  droppedMissing: number;
  droppedInfinite: number;
  droppedDuplicates: number;
  removedLeakageColumns: string[];
  classDistribution: Record<string, number>;
  featureColumns: string[];
  isSynthetic: boolean;
}

export interface ScalerParams {
  featureNames: string[];
  means: number[];
  stds: number[];
}

export interface PreparedSplit {
  XTrain: number[][];
  yTrain: number[];
  XVal: number[][];
  yVal: number[];
  XTest: number[][];
  yTest: number[];
  classes: string[];
  scaler: ScalerParams;
  classWeights: Record<number, number>;
  imbalanceRatio: number;
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
  confusionMatrix: {
    labels: string[];
    matrix: number[][];
  };
  perClass: PerClassMetric[];
  sampleCount: number;
  trainingTimeMs: number;
  communicationBytes: number;
}

export interface MLPWeights {
  architecture: number[];
  weights: number[][][];
  biases: number[][];
  classes: string[];
  mode: ClassificationMode;
  scaler: ScalerParams;
}

export interface LogisticRegressionModel {
  kind: 'logistic_regression';
  weights: number[][];
  biases: number[];
  classes: string[];
  mode: ClassificationMode;
  scaler: ScalerParams;
}

export interface DecisionTreeNode {
  featureIndex?: number;
  threshold?: number;
  left?: DecisionTreeNode;
  right?: DecisionTreeNode;
  classProbs?: number[];
}

export interface RandomForestModel {
  kind: 'random_forest';
  trees: DecisionTreeNode[];
  classes: string[];
  mode: ClassificationMode;
  scaler: ScalerParams;
  featureImportances: Record<string, number>;
}

export interface FederatedEnvelope {
  clientId: string;
  round: number;
  modelVersion: string;
  sampleCount: number;
  nonce: string;
  timestamp: string;
  payloadSha256: string;
  signatureBase64: string;
  ivBase64: string;
  authTagBase64: string;
  ciphertextBase64: string;
}

export interface ClientRoundOutcome {
  clientId: string;
  clientName: string;
  status: 'accepted' | 'rejected';
  reason?: string;
  sampleCount: number;
  localLoss: number;
  localAccuracy: number;
  localF1: number;
  payloadBytes: number;
  signatureVerified: boolean;
  integrityVerified: boolean;
  decryptionVerified: boolean;
}

export interface FederatedRoundResult {
  round: number;
  modelVersion: string;
  globalLoss: number;
  globalAccuracy: number;
  globalPrecision: number;
  globalRecall: number;
  globalF1: number;
  globalFpr: number;
  globalRocAuc: number | null;
  participatingClients: number;
  acceptedClients: number;
  rejectedClients: number;
  communicationBytes: number;
  durationMs: number;
  dpEpsilonEstimate: number | null;
  clientOutcomes: ClientRoundOutcome[];
  metrics: EvaluationMetrics;
}
