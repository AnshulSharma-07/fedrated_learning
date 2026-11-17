import { useEffect, useState } from 'react';
import { Play, RefreshCw } from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { apiRequest } from '../api/client';
import { ConfusionMatrixTable } from '../components/ConfusionMatrixTable';
import type { ModelSummary } from '../types';

export function ModelEvaluationPage() {
  const [models, setModels] = useState<ModelSummary[]>([]);
  const [selectedModelId, setSelectedModelId] = useState<string>('');
  const [trainingArch, setTrainingArch] = useState<'random_forest' | 'logistic_regression' | 'centralized_mlp'>('random_forest');
  const [trainingMsg, setTrainingMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function loadModels() {
    try {
      const res = await apiRequest<{ models: ModelSummary[] }>('/api/models');
      setModels(res.models);
      if (!selectedModelId && res.models.length > 0) {
        setSelectedModelId(res.models[0].id);
      }
    } catch (err) {
      setError((err as Error).message);
    }
  }

  useEffect(() => {
    loadModels();
  }, []);

  async function handleTrainBaseline() {
    setBusy(true);
    setError(null);
    setTrainingMsg('Training centralized baseline on stratified split...');
    try {
      const res = await apiRequest<{ job: { jobId: string } }>('/api/models/train', {
        method: 'POST',
        body: JSON.stringify({ architecture: trainingArch, classificationMode: 'multiclass' }),
      });
      const poll = setInterval(async () => {
        try {
          const st = await apiRequest<{ job: { status: string; message: string; modelId: string | null } }>(
            `/api/models/jobs/${res.job.jobId}`,
          );
          setTrainingMsg(st.job.message);
          if (st.job.status === 'completed' || st.job.status === 'failed') {
            clearInterval(poll);
            setBusy(false);
            if (st.job.status === 'failed') setError(st.job.message);
            loadModels();
            if (st.job.modelId) setSelectedModelId(st.job.modelId);
          }
        } catch (err) {
          clearInterval(poll);
          setBusy(false);
          setError((err as Error).message);
        }
      }, 300);
    } catch (err) {
      setBusy(false);
      setError((err as Error).message);
    }
  }

  const selectedModel = models.find((m) => m.id === selectedModelId) || models[0] || null;
  const rfModel = models.find((m) => m.architecture === 'random_forest' && m.metrics?.featureImportances);
  const featureImportanceData = rfModel?.metrics?.featureImportances
    ? Object.entries(rfModel.metrics.featureImportances)
        .map(([feature, importance]) => ({ feature, importance: Number((importance * 100).toFixed(2)) }))
        .sort((a, b) => b.importance - a.importance)
        .slice(0, 8)
    : [];

  const shortArchLabel = (arch: string) => {
    if (arch === 'random_forest') return 'RF';
    if (arch === 'logistic_regression') return 'LogReg';
    if (arch === 'centralized_mlp') return 'Central MLP';
    if (arch === 'federated_mlp') return 'FedAvg MLP';
    return arch;
  };

  const comparisonChartData = models.slice(0, 6).map((m) => ({
    name: `${shortArchLabel(m.architecture)} ${m.version}`,
    accuracy: Number((m.accuracy * 100).toFixed(2)),
    precision: Number((m.precision_score * 100).toFixed(2)),
    recall: Number((m.recall_score * 100).toFixed(2)),
    f1: Number((m.f1_score * 100).toFixed(2)),
  }));

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="max-w-2xl">
          <h2 className="text-xl font-semibold text-slate-900 dark:text-slate-50">
            Centralized vs. Federated Model Evaluation
          </h2>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-0.5">
            All metrics are computed from real test-split inference runs. Centralized baselines train on pooled training data; Federated MLP trains across non-IID clients via FedAvg.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <select
            aria-label="Select baseline architecture to retrain"
            value={trainingArch}
            onChange={(e) => setTrainingArch(e.target.value as typeof trainingArch)}
            className="px-3 py-1.5 text-xs rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
          >
            <option value="random_forest">Random Forest</option>
            <option value="logistic_regression">Logistic Regression</option>
            <option value="centralized_mlp">Centralized MLP</option>
          </select>
          <button
            type="button"
            disabled={busy}
            onClick={handleTrainBaseline}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-sky-600 hover:bg-sky-700 disabled:opacity-50 text-white text-xs font-medium whitespace-nowrap"
          >
            <Play className="w-3.5 h-3.5" />
            Train Centralized Baseline
          </button>
          <button
            type="button"
            aria-label="Reload model metrics"
            onClick={loadModels}
            className="p-2 rounded-lg border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {trainingMsg && (
        <div className="text-xs text-sky-700 dark:text-sky-300 bg-sky-50 dark:bg-sky-950/40 border border-sky-200 dark:border-sky-900 rounded-lg px-4 py-2.5">
          {trainingMsg}
        </div>
      )}
      {error && (
        <div role="alert" className="text-xs text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900 rounded-lg px-4 py-2.5">
          {error}
        </div>
      )}

      {/* Model Comparison Table */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-4">
        <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
          Model Benchmark Matrix (Same Stratified Test Split)
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400">
                <th className="py-2 pr-3 text-left font-medium">Model</th>
                <th className="py-2 px-2 text-left font-medium">Paradigm</th>
                <th className="py-2 px-2 text-right font-medium">Accuracy</th>
                <th className="py-2 px-2 text-right font-medium">Precision</th>
                <th className="py-2 px-2 text-right font-medium">Recall</th>
                <th className="py-2 px-2 text-right font-medium">F1-Score</th>
                <th className="py-2 px-2 text-right font-medium">FPR</th>
                <th className="py-2 px-2 text-right font-medium">ROC-AUC</th>
                <th className="py-2 px-2 text-right font-medium">Train Time</th>
                <th className="py-2 pl-2 text-right font-medium">Comm Overhead</th>
              </tr>
            </thead>
            <tbody>
              {models.map((m) => (
                <tr
                  key={m.id}
                  onClick={() => setSelectedModelId(m.id)}
                  className={`border-b last:border-b-0 border-slate-100 dark:border-slate-800/80 cursor-pointer transition-colors ${
                    selectedModel?.id === m.id
                      ? 'bg-sky-50/60 dark:bg-sky-950/30'
                      : 'hover:bg-slate-50 dark:hover:bg-slate-800/50'
                  }`}
                >
                  <td className="py-2.5 pr-3 font-medium text-slate-900 dark:text-slate-100">
                    {m.name}
                    <span className="ml-1.5 font-mono text-[11px] text-slate-500">{m.version}</span>
                  </td>
                  <td className="py-2.5 px-2 capitalize text-slate-600 dark:text-slate-300">{m.training_paradigm}</td>
                  <td className="py-2.5 px-2 text-right font-mono tabular-nums">{(m.accuracy * 100).toFixed(2)}%</td>
                  <td className="py-2.5 px-2 text-right font-mono tabular-nums">{(m.precision_score * 100).toFixed(2)}%</td>
                  <td className="py-2.5 px-2 text-right font-mono tabular-nums">{(m.recall_score * 100).toFixed(2)}%</td>
                  <td className="py-2.5 px-2 text-right font-mono tabular-nums">{(m.f1_score * 100).toFixed(2)}%</td>
                  <td className="py-2.5 px-2 text-right font-mono tabular-nums">{(m.false_positive_rate * 100).toFixed(2)}%</td>
                  <td className="py-2.5 px-2 text-right font-mono tabular-nums">
                    {m.roc_auc !== null ? m.roc_auc.toFixed(4) : 'N/A'}
                  </td>
                  <td className="py-2.5 px-2 text-right font-mono tabular-nums">{m.training_time_ms} ms</td>
                  <td className="py-2.5 pl-2 text-right font-mono tabular-nums">
                    {m.communication_bytes > 0 ? `${(m.communication_bytes / 1024).toFixed(1)} KB` : '0 KB (Local)'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Visual Comparison + Feature Importance */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-3">
          <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            Accuracy, Precision, Recall & F1 Comparison
          </h3>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={comparisonChartData} margin={{ top: 12, right: 12, left: 0, bottom: 4 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.2} />
                <XAxis dataKey="name" interval={0} tick={{ fontSize: 11 }} stroke="#64748b" />
                <YAxis domain={[0, 105]} ticks={[0, 25, 50, 75, 100]} tick={{ fontSize: 11 }} stroke="#64748b" />
                <Tooltip />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Bar dataKey="accuracy" name="Accuracy (%)" fill="#0284c7" />
                <Bar dataKey="f1" name="F1 (%)" fill="#16a34a" />
                <Bar dataKey="recall" name="Recall (%)" fill="#d97706" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-3">
          <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            Random Forest Gini Feature Importance (Top 8 Flow Features)
          </h3>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={featureImportanceData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.2} />
                <XAxis type="number" tick={{ fontSize: 11 }} stroke="#64748b" />
                <YAxis dataKey="feature" type="category" width={135} tick={{ fontSize: 10 }} stroke="#64748b" />
                <Tooltip />
                <Bar dataKey="importance" name="Gini Importance (%)" fill="#0284c7" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>
      </div>

      {/* Selected Model Per-Class Breakdown & Confusion Matrix */}
      {selectedModel?.metrics && (
        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="space-y-3">
            <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              Per-Class Evaluation · {selectedModel.name} ({selectedModel.version})
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400">
                    <th className="py-2 text-left font-medium">Attack Class</th>
                    <th className="py-2 text-right font-medium">Precision</th>
                    <th className="py-2 text-right font-medium">Recall</th>
                    <th className="py-2 text-right font-medium">F1-Score</th>
                    <th className="py-2 text-right font-medium">Support</th>
                  </tr>
                </thead>
                <tbody>
                  {selectedModel.metrics.perClass.map((pc) => (
                    <tr key={pc.label} className="border-b last:border-b-0 border-slate-100 dark:border-slate-800/80">
                      <td className="py-2 font-medium">{pc.label}</td>
                      <td className="py-2 text-right font-mono tabular-nums">{(pc.precision * 100).toFixed(1)}%</td>
                      <td className="py-2 text-right font-mono tabular-nums">{(pc.recall * 100).toFixed(1)}%</td>
                      <td className="py-2 text-right font-mono tabular-nums">{(pc.f1Score * 100).toFixed(1)}%</td>
                      <td className="py-2 text-right font-mono tabular-nums">{pc.support}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <ConfusionMatrixTable
            data={selectedModel.metrics.confusionMatrix}
            title={`Test-Set Confusion Matrix (${selectedModel.metrics.sampleCount} samples)`}
          />
        </section>
      )}

      {/* Research Methodology & Privacy/Security Limitations */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-2">
        <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
          Dataset Distribution, Non-IID Effects & Security Limitations
        </h3>
        <ul className="text-xs text-slate-600 dark:text-slate-300 space-y-1.5 list-disc pl-5 leading-relaxed">
          <li>
            <strong>Non-IID Client Divergence:</strong> Clients receive organization-skewed traffic partitions (e.g., FinTech-Core sees more BruteForce/WebAttack while Campus-Net sees PortScan/DoS), which can cause slight weight drift across local epochs compared to centralized training on pooled data.
          </li>
          <li>
            <strong>Metadata & Gradient Leakage:</strong> Standard FedAvg keeps raw records local and encrypts payloads in transit (TLS + AES-256-GCM), yet sample counts and unperturbed model updates can still reveal statistical properties to an honest-but-curious coordinator unless Differential Privacy (DP-SGD) or cryptographic Secure Aggregation is enabled.
          </li>
          <li>
            <strong>Zero Preprocessing Leakage:</strong> Z-score feature scaling is fit strictly on the training split; identifier columns (Flow ID, Source/Destination IP, Timestamp) are stripped before feature extraction.
          </li>
        </ul>
      </section>
    </div>
  );
}
