import {
  buildSignedEncryptedEnvelope,
  loadClientPrivateKey,
  ReplayGuard,
  verifyAndDecryptEnvelope,
} from './crypto';
import type { ClientPartition } from './dataset';
import {
  cloneMLPWeights,
  computeCrossEntropyLoss,
  evaluatePredictions,
  predictMLPProbs,
  trainMLPEpochs,
} from './ml';
import type {
  ClientRoundOutcome,
  FederatedEnvelope,
  FederatedRoundResult,
  MLPWeights,
} from './types';

export interface FederatedClientDescriptor {
  id: string;
  name: string;
  organization: string;
  active: boolean;
  publicKeyPem: string | null;
  keyRevoked: boolean;
}

export interface WeightUpdatePayload {
  weights: number[][][];
  biases: number[][];
  localLoss: number;
  localAccuracy: number;
  localF1: number;
}

export function validateWeightPayload(
  payload: WeightUpdatePayload,
  expected: MLPWeights,
): { valid: boolean; reason?: string } {
  if (!payload || !Array.isArray(payload.weights) || !Array.isArray(payload.biases)) {
    return { valid: false, reason: 'Malformed weight update structure' };
  }
  if (payload.weights.length !== expected.weights.length || payload.biases.length !== expected.biases.length) {
    return {
      valid: false,
      reason: `Layer count mismatch: expected ${expected.weights.length}, got ${payload.weights.length}`,
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
      if (typeof bVal !== 'number' || !Number.isFinite(bVal)) {
        return { valid: false, reason: `Non-finite bias detected in layer ${l}` };
      }
      sqNorm += bVal * bVal;
      if (payload.weights[l][o].length !== expected.weights[l][o].length) {
        return { valid: false, reason: `Layer ${l} row ${o} input dimension mismatch` };
      }
      for (let i = 0; i < expected.weights[l][o].length; i++) {
        const wVal = payload.weights[l][o][i];
        if (typeof wVal !== 'number' || !Number.isFinite(wVal)) {
          return { valid: false, reason: `Non-finite weight (NaN/Inf) detected in layer ${l}` };
        }
        sqNorm += wVal * wVal;
      }
    }
  }
  if (Math.sqrt(sqNorm) > 5000) {
    return { valid: false, reason: 'Weight norm exceeds safe bound (potential gradient explosion/poisoning)' };
  }
  return { valid: true };
}

export function fedAvgAggregate(
  baseModel: MLPWeights,
  updates: Array<{ sampleCount: number; weights: number[][][]; biases: number[][] }>,
): MLPWeights {
  if (updates.length === 0) {
    throw new Error('Cannot aggregate zero valid client updates');
  }
  const totalSamples = updates.reduce((sum, u) => sum + u.sampleCount, 0);
  if (totalSamples <= 0) {
    throw new Error('Total sample count across valid updates must be positive');
  }

  const nextModel = cloneMLPWeights(baseModel);
  for (let l = 0; l < nextModel.weights.length; l++) {
    for (let o = 0; o < nextModel.weights[l].length; o++) {
      let bAcc = 0;
      for (const u of updates) {
        bAcc += (u.sampleCount / totalSamples) * u.biases[l][o];
      }
      nextModel.biases[l][o] = bAcc;
      for (let i = 0; i < nextModel.weights[l][o].length; i++) {
        let wAcc = 0;
        for (const u of updates) {
          wAcc += (u.sampleCount / totalSamples) * u.weights[l][o][i];
        }
        nextModel.weights[l][o][i] = wAcc;
      }
    }
  }
  return nextModel;
}

export function processIncomingClientEnvelope(params: {
  envelope: FederatedEnvelope;
  client: FederatedClientDescriptor | undefined;
  expectedModel: MLPWeights;
  expectedModelVersion: string;
  expectedRound: number;
  replayGuard: ReplayGuard;
}): {
  accepted: boolean;
  reason?: string;
  code?: string;
  payload?: WeightUpdatePayload;
  signatureVerified: boolean;
  decryptionVerified: boolean;
  integrityVerified: boolean;
} {
  const { envelope, client, expectedModel, expectedModelVersion, expectedRound, replayGuard } = params;

  if (!client) {
    return {
      accepted: false,
      code: 'UNAUTHORIZED_CLIENT',
      reason: `Client '${envelope.clientId}' is not registered with coordinator`,
      signatureVerified: false,
      decryptionVerified: false,
      integrityVerified: false,
    };
  }

  if (envelope.modelVersion !== expectedModelVersion) {
    return {
      accepted: false,
      code: 'VERSION_MISMATCH',
      reason: `Model version mismatch: expected ${expectedModelVersion}, got ${envelope.modelVersion}`,
      signatureVerified: false,
      decryptionVerified: false,
      integrityVerified: false,
    };
  }

  if (envelope.round !== expectedRound) {
    return {
      accepted: false,
      code: 'ROUND_MISMATCH',
      reason: `Round mismatch: expected round ${expectedRound}, got ${envelope.round}`,
      signatureVerified: false,
      decryptionVerified: false,
      integrityVerified: false,
    };
  }

  const cryptoRes = verifyAndDecryptEnvelope<WeightUpdatePayload>({
    envelope,
    publicKeyPem: client.publicKeyPem,
    clientActive: client.active,
    keyRevoked: client.keyRevoked,
    replayGuard,
  });

  if (!cryptoRes.ok || !cryptoRes.payload) {
    return {
      accepted: false,
      code: cryptoRes.code,
      reason: cryptoRes.reason,
      signatureVerified: cryptoRes.signatureVerified,
      decryptionVerified: cryptoRes.decryptionVerified,
      integrityVerified: cryptoRes.integrityVerified,
    };
  }

  const shapeCheck = validateWeightPayload(cryptoRes.payload, expectedModel);
  if (!shapeCheck.valid) {
    return {
      accepted: false,
      code: 'INVALID_TENSOR',
      reason: shapeCheck.reason,
      signatureVerified: true,
      decryptionVerified: true,
      integrityVerified: true,
    };
  }

  if (envelope.sampleCount <= 0 || envelope.sampleCount > 1_000_000) {
    return {
      accepted: false,
      code: 'INVALID_SAMPLE_COUNT',
      reason: `Invalid sample count ${envelope.sampleCount}`,
      signatureVerified: true,
      decryptionVerified: true,
      integrityVerified: true,
    };
  }

  return {
    accepted: true,
    payload: cryptoRes.payload,
    signatureVerified: true,
    decryptionVerified: true,
    integrityVerified: true,
  };
}

export function executeFederatedRound(params: {
  round: number;
  globalModel: MLPWeights;
  modelVersion: string;
  nextModelVersion: string;
  clients: FederatedClientDescriptor[];
  partitions: Map<string, ClientPartition>;
  XTest: number[][];
  yTest: number[];
  classWeights: Record<number, number>;
  localEpochs: number;
  learningRate: number;
  dpClipNorm?: number | null;
  dpNoiseMultiplier?: number | null;
  replayGuard: ReplayGuard;
  seed?: number;
  onSecurityRejection?: (outcome: ClientRoundOutcome, code: string) => void;
}): { updatedModel: MLPWeights; roundResult: FederatedRoundResult } {
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
    replayGuard,
    seed = 42,
    onSecurityRejection,
  } = params;

  const clientOutcomes: ClientRoundOutcome[] = [];
  const validUpdates: Array<{ sampleCount: number; weights: number[][][]; biases: number[][] }> = [];
  let totalCommunicationBytes = 0;

  // Broadcast size (global model parameters sent to each active client)
  const globalPayloadBytes = Buffer.byteLength(
    JSON.stringify({ weights: globalModel.weights, biases: globalModel.biases }),
    'utf8',
  );

  for (let idx = 0; idx < clients.length; idx++) {
    const client = clients[idx];
    const partition = partitions.get(client.id);
    if (!client.active || !partition || partition.X.length === 0) {
      continue;
    }

    const privateKeyPem = loadClientPrivateKey(client.id);
    if (!privateKeyPem) {
      const rejected: ClientRoundOutcome = {
        clientId: client.id,
        clientName: client.name,
        status: 'rejected',
        reason: 'Missing local Ed25519 private key for client signing',
        sampleCount: partition.X.length,
        localLoss: 0,
        localAccuracy: 0,
        localF1: 0,
        payloadBytes: 0,
        signatureVerified: false,
        integrityVerified: false,
        decryptionVerified: false,
      };
      clientOutcomes.push(rejected);
      onSecurityRejection?.(rejected, 'UNAUTHORIZED_CLIENT');
      continue;
    }

    // Local training strictly on client's isolated partition
    const { model: localModel, finalLoss } = trainMLPEpochs({
      initialModel: globalModel,
      XTrain: partition.X,
      yTrain: partition.y,
      classWeights,
      epochs: localEpochs,
      lr: learningRate,
      dpClipNorm,
      dpNoiseMultiplier,
      seed: seed + round * 100 + idx,
    });

    const localProbs = predictMLPProbs(localModel, partition.X);
    const localMetrics = evaluatePredictions({
      yTrue: partition.y,
      probs: localProbs,
      classes: globalModel.classes,
      loss: finalLoss,
    });

    const updatePayload: WeightUpdatePayload = {
      weights: localModel.weights,
      biases: localModel.biases,
      localLoss: finalLoss,
      localAccuracy: localMetrics.accuracy,
      localF1: localMetrics.f1Score,
    };

    const envelope = buildSignedEncryptedEnvelope({
      clientId: client.id,
      round,
      modelVersion,
      sampleCount: partition.X.length,
      payload: updatePayload,
      privateKeyPem,
    });

    const envelopeBytes = Buffer.byteLength(JSON.stringify(envelope), 'utf8');
    totalCommunicationBytes += globalPayloadBytes + envelopeBytes;

    const verification = processIncomingClientEnvelope({
      envelope,
      client,
      expectedModel: globalModel,
      expectedModelVersion: modelVersion,
      expectedRound: round,
      replayGuard,
    });

    if (!verification.accepted || !verification.payload) {
      const rejected: ClientRoundOutcome = {
        clientId: client.id,
        clientName: client.name,
        status: 'rejected',
        reason: verification.reason,
        sampleCount: partition.X.length,
        localLoss: finalLoss,
        localAccuracy: localMetrics.accuracy,
        localF1: localMetrics.f1Score,
        payloadBytes: envelopeBytes,
        signatureVerified: verification.signatureVerified,
        integrityVerified: verification.integrityVerified,
        decryptionVerified: verification.decryptionVerified,
      };
      clientOutcomes.push(rejected);
      onSecurityRejection?.(rejected, verification.code || 'REJECTED');
      continue;
    }

    validUpdates.push({
      sampleCount: partition.X.length,
      weights: verification.payload.weights,
      biases: verification.payload.biases,
    });

    clientOutcomes.push({
      clientId: client.id,
      clientName: client.name,
      status: 'accepted',
      sampleCount: partition.X.length,
      localLoss: finalLoss,
      localAccuracy: localMetrics.accuracy,
      localF1: localMetrics.f1Score,
      payloadBytes: envelopeBytes,
      signatureVerified: true,
      integrityVerified: true,
      decryptionVerified: true,
    });
  }

  const updatedModel =
    validUpdates.length > 0 ? fedAvgAggregate(globalModel, validUpdates) : cloneMLPWeights(globalModel);

  const testProbs = predictMLPProbs(updatedModel, XTest);
  const testLoss = computeCrossEntropyLoss(testProbs, yTest, classWeights);
  const durationMs = Math.max(1, Date.now() - start);
  const metrics = evaluatePredictions({
    yTrue: yTest,
    probs: testProbs,
    classes: updatedModel.classes,
    loss: testLoss,
    trainingTimeMs: durationMs,
    communicationBytes: totalCommunicationBytes,
  });

  const dpEpsilonEstimate =
    dpClipNorm && dpNoiseMultiplier && dpNoiseMultiplier > 0
      ? Number(((round * localEpochs * 1.2) / Math.max(0.1, dpNoiseMultiplier)).toFixed(2))
      : null;

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
      metrics,
    },
  };
}
