import { useEffect, useState, type ChangeEvent } from 'react';
import { Download, FileSpreadsheet, Play, Search, Upload } from 'lucide-react';
import { apiRequest } from '../api/client';
import { ConfusionMatrixTable } from '../components/ConfusionMatrixTable';
import type { DatasetSummary, EvaluationMetrics, ModelSummary } from '../types';

interface PredictionRow {
  id: string;
  predictedLabel: string;
  rawCategory: string;
  trueLabel: string | null;
  isMalicious: boolean;
  confidence: number;
  severity: string;
  flowDuration: number;
  flowBytesPerSec: number;
  synFlagCount: number;
  totalFwdPackets: number;
}

interface BatchResponse {
  batchId: string;
  modelUsed: { id: string; name: string; architecture: string };
  totalRecords: number;
  maliciousCount: number;
  benignCount: number;
  predictions: PredictionRow[];
  evaluation: EvaluationMetrics | null;
}

export function IntrusionDetectionPage() {
  const [models, setModels] = useState<ModelSummary[]>([]);
  const [datasets, setDatasets] = useState<DatasetSummary[]>([]);
  const [selectedModelId, setSelectedModelId] = useState('');
  const [classificationMode, setClassificationMode] = useState<'multiclass' | 'binary'>('multiclass');
  const [csvText, setCsvText] = useState('');
  const [csvFileName, setCsvFileName] = useState('');
  const [previewRows, setPreviewRows] = useState<string[][]>([]);
  const [uploadReport, setUploadReport] = useState<string | null>(null);
  const [result, setResult] = useState<BatchResponse | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([
      apiRequest<{ models: ModelSummary[] }>('/api/models'),
      apiRequest<{ datasets: DatasetSummary[] }>('/api/datasets'),
    ])
      .then(([mRes, dRes]) => {
        setModels(mRes.models);
        setDatasets(dRes.datasets);
        const active = mRes.models.find((m) => m.isActive) || mRes.models[0];
        if (active) setSelectedModelId(active.id);
      })
      .catch((err) => setError((err as Error).message));
  }, []);

  async function handleFileSelect(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setError(null);
    setUploadReport(null);
    const text = await file.text();
    setCsvText(text);
    setCsvFileName(file.name);
    const lines = text
      .replace(/\r\n/g, '\n')
      .split('\n')
      .filter((l) => l.trim().length > 0)
      .slice(0, 6);
    setPreviewRows(lines.map((l) => l.split(',').slice(0, 8)));
  }

  async function handlePersistUploadedDataset() {
    if (!csvText) return;
    setError(null);
    try {
      const res = await apiRequest<{ id: string; name: string; report: { cleanRows: number; rawRows: number; droppedMissing: number; droppedInfinite: number; droppedDuplicates: number; removedLeakageColumns: string[] } }>(
        '/api/datasets/upload',
        {
          method: 'POST',
          body: JSON.stringify({
            name: csvFileName || 'Uploaded CSV Flow Batch',
            csvText,
            sourceType: 'uploaded_csv',
          }),
        },
      );
      setUploadReport(
        `Saved dataset "${res.name}" (${res.report.cleanRows}/${res.report.rawRows} clean rows; dropped ${res.report.droppedMissing} missing, ${res.report.droppedInfinite} Inf, ${res.report.droppedDuplicates} duplicates).`,
      );
      const dRes = await apiRequest<{ datasets: DatasetSummary[] }>('/api/datasets');
      setDatasets(dRes.datasets);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function runInference(useSyntheticSample: boolean) {
    setLoading(true);
    setError(null);
    try {
      const res = await apiRequest<BatchResponse>('/api/inference/batch', {
        method: 'POST',
        body: JSON.stringify({
          csvText: useSyntheticSample ? undefined : csvText,
          useSyntheticSample,
          modelId: selectedModelId || undefined,
          classificationMode,
          clientSensor: useSyntheticSample ? 'CIC-IDS2017-Synthetic-Batch' : csvFileName || 'Uploaded-CSV',
        }),
      });
      setResult(res);
      setCategoryFilter('all');
      setSeverityFilter('all');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  function exportPredictionsCsv() {
    if (!result) return;
    const headers = ['id', 'predicted_label', 'true_label', 'is_malicious', 'confidence', 'severity', 'flow_duration', 'flow_bytes_per_sec', 'syn_flag_count'];
    const lines = result.predictions.map((p) =>
      [p.id, p.predictedLabel, p.trueLabel || '', p.isMalicious, p.confidence, p.severity, p.flowDuration, p.flowBytesPerSec, p.synFlagCount].join(','),
    );
    const blob = new Blob([[headers.join(','), ...lines].join('\n')], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `fl-ids-predictions-${result.batchId}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  }

  const filteredPredictions = (result?.predictions || []).filter((p) => {
    if (categoryFilter !== 'all' && p.predictedLabel !== categoryFilter) return false;
    if (severityFilter !== 'all' && p.severity !== severityFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        p.predictedLabel.toLowerCase().includes(q) ||
        (p.trueLabel || '').toLowerCase().includes(q) ||
        p.id.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const uniqueCategories = Array.from(new Set((result?.predictions || []).map((p) => p.predictedLabel)));

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-semibold text-slate-900 dark:text-slate-50">
            Intrusion Detection & CSV Batch Inference
          </h2>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-0.5">
            Upload CIC-IDS2017 / UNSW-NB15 flow CSVs or test with the synthetic benchmark sample. Offline CSV batch inference is distinct from live flow-adapter ingestion.
          </p>
        </div>
      </div>

      {/* Controls Card */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-5">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="space-y-1.5">
            <label htmlFor="ids-model-select" className="block text-xs font-medium text-slate-600 dark:text-slate-300">
              Inference Model
            </label>
            <select
              id="ids-model-select"
              value={selectedModelId}
              onChange={(e) => setSelectedModelId(e.target.value)}
              className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100"
            >
              {models.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.name} ({m.version} · {(m.accuracy * 100).toFixed(1)}%)
                </option>
              ))}
            </select>
          </div>

          <div className="space-y-1.5">
            <span className="block text-xs font-medium text-slate-600 dark:text-slate-300">
              Detection Granularity
            </span>
            <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-800 rounded-lg">
              <button
                type="button"
                onClick={() => setClassificationMode('multiclass')}
                className={`flex-1 px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                  classificationMode === 'multiclass'
                    ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 shadow-sm'
                    : 'text-slate-600 dark:text-slate-400'
                }`}
              >
                Multiclass Attacks
              </button>
              <button
                type="button"
                onClick={() => setClassificationMode('binary')}
                className={`flex-1 px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                  classificationMode === 'binary'
                    ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 shadow-sm'
                    : 'text-slate-600 dark:text-slate-400'
                }`}
              >
                Binary (Benign / Malicious)
              </button>
            </div>
          </div>

          <div className="space-y-1.5">
            <label htmlFor="csv-file-input" className="block text-xs font-medium text-slate-600 dark:text-slate-300">
              Upload Network Flow CSV
            </label>
            <div className="flex items-center gap-2">
              <label
                htmlFor="csv-file-input"
                className="flex-1 flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium rounded-lg border border-dashed border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer truncate"
              >
                <Upload className="w-3.5 h-3.5 shrink-0" />
                <span className="truncate">{csvFileName || 'Choose .csv file'}</span>
              </label>
              <input
                id="csv-file-input"
                type="file"
                accept=".csv,text/csv"
                onChange={handleFileSelect}
                className="sr-only"
              />
            </div>
          </div>
        </div>

        {/* Preview of uploaded CSV */}
        {previewRows.length > 0 && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-600 dark:text-slate-300">
                CSV Preview ({csvFileName}, first 5 rows · first 8 columns)
              </span>
              <button
                type="button"
                onClick={handlePersistUploadedDataset}
                className="text-xs font-medium text-sky-600 dark:text-sky-400 hover:underline"
              >
                Save cleaned dataset to library
              </button>
            </div>
            <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-lg">
              <table className="w-full text-xs font-mono">
                <tbody>
                  {previewRows.map((row, rIdx) => (
                    <tr
                      key={rIdx}
                      className={
                        rIdx === 0
                          ? 'bg-slate-100 dark:bg-slate-800 font-semibold'
                          : 'border-t border-slate-100 dark:border-slate-800'
                      }
                    >
                      {row.map((cell, cIdx) => (
                        <td key={cIdx} className="px-2.5 py-1.5 whitespace-nowrap">
                          {cell}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {uploadReport && (
          <div className="text-xs text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-900 rounded-lg px-3.5 py-2.5">
            {uploadReport}
          </div>
        )}

        {error && (
          <div role="alert" className="text-xs text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900 rounded-lg px-3.5 py-2.5">
            {error}
          </div>
        )}

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            disabled={loading || !csvText}
            onClick={() => runInference(false)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-700 disabled:opacity-50 text-white text-xs font-medium transition-colors"
          >
            <Play className="w-3.5 h-3.5" />
            Run Detection on Uploaded CSV
          </button>

          <button
            type="button"
            disabled={loading}
            onClick={() => runInference(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-900 dark:text-slate-100 text-xs font-medium transition-colors"
          >
            <FileSpreadsheet className="w-3.5 h-3.5" />
            {loading ? 'Analyzing flows...' : 'Run Detection on Synthetic CIC-IDS2017 Sample (180 flows)'}
          </button>

          <span className="text-xs text-slate-500 dark:text-slate-400 ml-auto">
            Registered Datasets: {datasets.length}
          </span>
        </div>
      </section>

      {/* Results Area */}
      {result && (
        <div className="space-y-6">
          {/* Summary Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
              <div className="text-xs text-slate-500 dark:text-slate-400">Analyzed Flows</div>
              <div className="mt-1 text-xl font-semibold font-mono tabular-nums">{result.totalRecords}</div>
            </div>
            <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
              <div className="text-xs text-slate-500 dark:text-slate-400">Malicious Flagged</div>
              <div className="mt-1 text-xl font-semibold font-mono tabular-nums text-rose-600 dark:text-rose-400">
                {result.maliciousCount}
              </div>
            </div>
            <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
              <div className="text-xs text-slate-500 dark:text-slate-400">Benign Flows</div>
              <div className="mt-1 text-xl font-semibold font-mono tabular-nums text-emerald-600 dark:text-emerald-400">
                {result.benignCount}
              </div>
            </div>
            <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
              <div className="text-xs text-slate-500 dark:text-slate-400">Batch Accuracy</div>
              <div className="mt-1 text-xl font-semibold font-mono tabular-nums text-sky-600 dark:text-sky-400">
                {result.evaluation ? `${(result.evaluation.accuracy * 100).toFixed(1)}%` : 'Unlabeled'}
              </div>
            </div>
          </div>

          {/* Metrics & Confusion Matrix (if labels present) */}
          {result.evaluation && (
            <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="space-y-4">
                <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                  Batch Classification Metrics
                </h3>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
                  <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800">
                    <div className="text-slate-500 dark:text-slate-400">Precision</div>
                    <div className="mt-1 text-base font-semibold font-mono tabular-nums">
                      {(result.evaluation.precision * 100).toFixed(2)}%
                    </div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800">
                    <div className="text-slate-500 dark:text-slate-400">Recall</div>
                    <div className="mt-1 text-base font-semibold font-mono tabular-nums">
                      {(result.evaluation.recall * 100).toFixed(2)}%
                    </div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800">
                    <div className="text-slate-500 dark:text-slate-400">F1-Score</div>
                    <div className="mt-1 text-base font-semibold font-mono tabular-nums">
                      {(result.evaluation.f1Score * 100).toFixed(2)}%
                    </div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800">
                    <div className="text-slate-500 dark:text-slate-400">False Positive Rate</div>
                    <div className="mt-1 text-base font-semibold font-mono tabular-nums">
                      {(result.evaluation.falsePositiveRate * 100).toFixed(2)}%
                    </div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800">
                    <div className="text-slate-500 dark:text-slate-400">ROC-AUC (Binary)</div>
                    <div className="mt-1 text-base font-semibold font-mono tabular-nums">
                      {result.evaluation.rocAuc !== null ? result.evaluation.rocAuc.toFixed(4) : 'N/A'}
                    </div>
                  </div>
                </div>
              </div>

              <ConfusionMatrixTable data={result.evaluation.confusionMatrix} title="Batch Confusion Matrix" />
            </section>
          )}

          {/* Filterable Predictions Table */}
          <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex flex-wrap items-center gap-3 flex-1">
                <div className="relative min-w-[200px]">
                  <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Filter predictions..."
                    aria-label="Search predictions"
                    className="w-full pl-8 pr-3 py-1.5 text-xs rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
                  />
                </div>
                <select
                  aria-label="Filter by attack category"
                  value={categoryFilter}
                  onChange={(e) => setCategoryFilter(e.target.value)}
                  className="px-3 py-1.5 text-xs rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
                >
                  <option value="all">All Categories</option>
                  {uniqueCategories.map((c) => (
                    <option key={c} value={c}>
                      {c}
                    </option>
                  ))}
                </select>
                <select
                  aria-label="Filter by severity"
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="px-3 py-1.5 text-xs rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
                >
                  <option value="all">All Severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
              <button
                type="button"
                onClick={exportPredictionsCsv}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 whitespace-nowrap"
              >
                <Download className="w-3.5 h-3.5" />
                Export CSV
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400">
                    <th className="py-2 pr-3 text-left font-medium">Flow ID</th>
                    <th className="py-2 px-2 text-left font-medium">Predicted Class</th>
                    <th className="py-2 px-2 text-left font-medium">Ground Truth</th>
                    <th className="py-2 px-2 text-left font-medium">Severity</th>
                    <th className="py-2 px-2 text-right font-medium">Confidence</th>
                    <th className="py-2 px-2 text-right font-medium">Duration (us)</th>
                    <th className="py-2 pl-2 text-right font-medium">Bytes/s</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredPredictions.slice(0, 60).map((p) => (
                    <tr key={p.id} className="border-b last:border-b-0 border-slate-100 dark:border-slate-800/80">
                      <td className="py-2 pr-3 font-mono text-slate-600 dark:text-slate-400">{p.id.slice(0, 18)}</td>
                      <td
                        className={`py-2 px-2 font-medium ${
                          p.isMalicious ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'
                        }`}
                      >
                        {p.predictedLabel}
                      </td>
                      <td className="py-2 px-2 text-slate-600 dark:text-slate-300">{p.trueLabel || '—'}</td>
                      <td className="py-2 px-2 capitalize text-slate-700 dark:text-slate-300">{p.severity}</td>
                      <td className="py-2 px-2 text-right font-mono tabular-nums">{(p.confidence * 100).toFixed(1)}%</td>
                      <td className="py-2 px-2 text-right font-mono tabular-nums">{p.flowDuration.toLocaleString()}</td>
                      <td className="py-2 pl-2 text-right font-mono tabular-nums">
                        {p.flowBytesPerSec.toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
