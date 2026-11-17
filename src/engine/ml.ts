import { CORE_FEATURES, createSeededRng } from './dataset';
import type {
  ClassificationMode,
  DecisionTreeNode,
  EvaluationMetrics,
  LogisticRegressionModel,
  MLPWeights,
  PerClassMetric,
  RandomForestModel,
  ScalerParams,
} from './types';

function softmax(logits: number[]): number[] {
  const max = Math.max(...logits);
  const exps = logits.map((v) => Math.exp(Math.min(50, v - max)));
  const sum = exps.reduce((a, b) => a + b, 0) || 1;
  return exps.map((e) => e / sum);
}

export function computeRocAucBinary(yTrue: number[], yScore: number[]): number | null {
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
      auc += ((fp - prevFp) * (tp + prevTp)) / 2;
      prevTp = tp;
      prevFp = fp;
    }
  }
  return Number((auc / (positives * negatives)).toFixed(4));
}

export function evaluatePredictions(params: {
  yTrue: number[];
  probs: number[][];
  classes: string[];
  loss?: number;
  trainingTimeMs?: number;
  communicationBytes?: number;
}): EvaluationMetrics {
  const { yTrue, probs, classes } = params;
  const k = classes.length;
  const matrix: number[][] = Array.from({ length: k }, () => new Array(k).fill(0));
  const yPred: number[] = probs.map((p) => {
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

  const perClass: PerClassMetric[] = [];
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
    const f1Score = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
    perClass.push({
      label: classes[c],
      precision: Number(precision.toFixed(4)),
      recall: Number(recall.toFixed(4)),
      f1Score: Number(f1Score.toFixed(4)),
      support,
    });
    totalSupport += support;
    weightedPrecision += precision * support;
    weightedRecall += recall * support;
    weightedF1 += f1Score * support;
  }

  // False Positive Rate with respect to Benign (class 0) vs Any Attack
  const benignIdx = Math.max(0, classes.findIndex((c) => c.toLowerCase() === 'benign'));
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

  // Binary ROC-AUC (Benign vs Attack probability = 1 - P(Benign))
  const binaryTrue = yTrue.map((y) => (y === benignIdx ? 0 : 1));
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
    loss: params.loss !== undefined ? Number(params.loss.toFixed(4)) : undefined,
    confusionMatrix: { labels: classes, matrix },
    perClass,
    sampleCount: yTrue.length,
    trainingTimeMs: params.trainingTimeMs ?? 0,
    communicationBytes: params.communicationBytes ?? 0,
  };
}

// ============================================================================
// 1. Logistic Regression (L2-Regularized Softmax with Class Weights)
// ============================================================================
export function trainLogisticRegression(params: {
  XTrain: number[][];
  yTrain: number[];
  classes: string[];
  mode: ClassificationMode;
  scaler: ScalerParams;
  classWeights: Record<number, number>;
  epochs?: number;
  lr?: number;
  l2?: number;
}): LogisticRegressionModel {
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

  return { kind: 'logistic_regression', weights, biases, classes, mode, scaler };
}

export function predictLogisticRegressionProbs(model: LogisticRegressionModel, XScaled: number[][]): number[][] {
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

// ============================================================================
// 2. Random Forest (CART Trees + Gini Impurity + Feature Importance)
// ============================================================================
function giniFromCounts(counts: number[], total: number): number {
  if (total === 0) return 0;
  let sumSq = 0;
  for (let i = 0; i < counts.length; i++) {
    const p = counts[i] / total;
    sumSq += p * p;
  }
  return 1 - sumSq;
}

function buildCartTree(
  X: number[][],
  y: number[],
  indices: number[],
  numClasses: number,
  depth: number,
  maxDepth: number,
  minSamplesSplit: number,
  mtry: number,
  rng: () => number,
  importances: number[],
): DecisionTreeNode {
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
    // Sample up to 16 candidate thresholds for fast, deterministic splitting
    const step = Math.max(1, Math.floor(sorted.length / 16));
    const leftCounts = new Array(numClasses).fill(0);
    let leftTotal = 0;
    let prevPos = 0;

    for (let pos = 0; pos < sorted.length - 1; pos++) {
      const idx = sorted[pos];
      leftCounts[y[idx]]++;
      leftTotal++;
      if ((pos - prevPos < step && pos < sorted.length - 2) || X[sorted[pos]][feat] === X[sorted[pos + 1]][feat]) {
        continue;
      }
      prevPos = pos;
      const rightTotal = n - leftTotal;
      if (leftTotal === 0 || rightTotal === 0) continue;
      const rightCounts = counts.map((c, ci) => c - leftCounts[ci]);
      const gLeft = giniFromCounts(leftCounts, leftTotal);
      const gRight = giniFromCounts(rightCounts, rightTotal);
      const weightedGini = (leftTotal / n) * gLeft + (rightTotal / n) * gRight;
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
  const leftIdx: number[] = [];
  const rightIdx: number[] = [];
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
    right: buildCartTree(X, y, rightIdx, numClasses, depth + 1, maxDepth, minSamplesSplit, mtry, rng, importances),
  };
}

function predictTreeProbs(node: DecisionTreeNode, x: number[]): number[] {
  if (node.classProbs) return node.classProbs;
  if (x[node.featureIndex!] <= node.threshold!) {
    return predictTreeProbs(node.left!, x);
  }
  return predictTreeProbs(node.right!, x);
}

export function trainRandomForest(params: {
  XTrain: number[][];
  yTrain: number[];
  classes: string[];
  mode: ClassificationMode;
  scaler: ScalerParams;
  numTrees?: number;
  maxDepth?: number;
  seed?: number;
}): RandomForestModel {
  const { XTrain, yTrain, classes, mode, scaler, numTrees = 18, maxDepth = 7, seed = 42 } = params;
  const n = XTrain.length;
  const d = XTrain[0].length;
  const mtry = Math.max(2, Math.floor(Math.sqrt(d)));
  const rng = createSeededRng(seed);
  const importances = new Array(d).fill(0);
  const trees: DecisionTreeNode[] = [];

  for (let t = 0; t < numTrees; t++) {
    const bootIdx: number[] = [];
    for (let i = 0; i < n; i++) {
      bootIdx.push(Math.floor(rng() * n));
    }
    trees.push(buildCartTree(XTrain, yTrain, bootIdx, classes.length, 0, maxDepth, 6, mtry, rng, importances));
  }

  const impSum = importances.reduce((a, b) => a + b, 0) || 1;
  const featureImportances: Record<string, number> = {};
  CORE_FEATURES.forEach((feat, idx) => {
    featureImportances[feat] = Number((importances[idx] / impSum).toFixed(4));
  });

  return { kind: 'random_forest', trees, classes, mode, scaler, featureImportances };
}

export function predictRandomForestProbs(model: RandomForestModel, XScaled: number[][]): number[][] {
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

// ============================================================================
// 3. Multi-Layer Perceptron (Federated & Centralized Neural Network)
// ============================================================================
export function initializeMLPWeights(
  inputDim: number,
  classes: string[],
  mode: ClassificationMode,
  scaler: ScalerParams,
  seed = 42,
): MLPWeights {
  const rng = createSeededRng(seed);
  const architecture = [inputDim, 32, 16, classes.length];
  const weights: number[][][] = [];
  const biases: number[][] = [];

  for (let l = 0; l < architecture.length - 1; l++) {
    const inDim = architecture[l];
    const outDim = architecture[l + 1];
    const scale = Math.sqrt(2 / inDim);
    const layerW: number[][] = [];
    for (let o = 0; o < outDim; o++) {
      const row: number[] = [];
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

export function cloneMLPWeights(model: MLPWeights): MLPWeights {
  return {
    architecture: [...model.architecture],
    weights: model.weights.map((layer) => layer.map((row) => [...row])),
    biases: model.biases.map((b) => [...b]),
    classes: [...model.classes],
    mode: model.mode,
    scaler: {
      featureNames: [...model.scaler.featureNames],
      means: [...model.scaler.means],
      stds: [...model.scaler.stds],
    },
  };
}

function forwardSingle(model: MLPWeights, x: number[]): { activations: number[][]; preActs: number[][] } {
  const activations: number[][] = [x];
  const preActs: number[][] = [];
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
      cur = out.map((v) => (v > 0 ? v : 0)); // ReLU
    } else {
      cur = softmax(out);
    }
    activations.push(cur);
  }
  return { activations, preActs };
}

export function predictMLPProbs(model: MLPWeights, XScaled: number[][]): number[][] {
  return XScaled.map((x) => {
    const { activations } = forwardSingle(model, x);
    return activations[activations.length - 1];
  });
}

export function computeCrossEntropyLoss(probs: number[][], yTrue: number[], classWeights?: Record<number, number>): number {
  let loss = 0;
  let wSum = 0;
  for (let i = 0; i < yTrue.length; i++) {
    const y = yTrue[i];
    const w = classWeights ? (classWeights[y] ?? 1) : 1;
    const p = Math.max(1e-7, probs[i][y] ?? 1e-7);
    loss -= w * Math.log(p);
    wSum += w;
  }
  return wSum > 0 ? loss / wSum : 0;
}

export function trainMLPEpochs(params: {
  initialModel: MLPWeights;
  XTrain: number[][];
  yTrain: number[];
  classWeights?: Record<number, number>;
  epochs: number;
  lr: number;
  batchSize?: number;
  l2?: number;
  dpClipNorm?: number | null;
  dpNoiseMultiplier?: number | null;
  seed?: number;
}): { model: MLPWeights; finalLoss: number } {
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
    seed = 42,
  } = params;

  const model = cloneMLPWeights(initialModel);
  const rng = createSeededRng(seed);
  const n = XTrain.length;
  const numLayers = model.weights.length;

  const gaussianNoise = (std: number): number => {
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
        const cw = classWeights ? (classWeights[y] ?? 1) : 1;

        const { activations, preActs } = forwardSingle(model, x);
        const probs = activations[numLayers];
        let delta = probs.map((p, c) => (p - (c === y ? 1 : 0)) * cw);

        // Per-sample gradients for optional DP clipping
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

        // Optional DP-SGD per-sample L2 gradient clipping
        let clipFactor = 1.0;
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

      // Apply averaged gradient step + optional Gaussian DP noise
      const noiseStd =
        dpClipNorm && dpNoiseMultiplier && dpClipNorm > 0 && dpNoiseMultiplier > 0
          ? (dpClipNorm * dpNoiseMultiplier) / batchCount
          : 0;

      for (let l = 0; l < numLayers; l++) {
        for (let o = 0; o < model.biases[l].length; o++) {
          const gB = gradB[l][o] / batchCount + (noiseStd > 0 ? gaussianNoise(noiseStd) : 0);
          model.biases[l][o] -= lr * gB;
          for (let i = 0; i < model.weights[l][o].length; i++) {
            const gW =
              gradW[l][o][i] / batchCount +
              l2 * model.weights[l][o][i] +
              (noiseStd > 0 ? gaussianNoise(noiseStd) : 0);
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
