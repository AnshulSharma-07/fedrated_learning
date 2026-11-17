import { useEffect, useState } from 'react';
import { ArrowRight, RefreshCw } from 'lucide-react';
import { apiRequest } from '../api/client';
import type { NavPage, OverviewResponse } from '../types';

interface OverviewPageProps {
  onNavigate: (page: NavPage) => void;
}

function severityTextClass(severity: string): string {
  switch (severity) {
    case 'critical':
      return 'text-rose-700 dark:text-rose-400 font-semibold';
    case 'high':
      return 'text-amber-700 dark:text-amber-400 font-semibold';
    case 'medium':
      return 'text-sky-700 dark:text-sky-400 font-medium';
    default:
      return 'text-slate-600 dark:text-slate-400';
  }
}

export function OverviewPage({ onNavigate }: OverviewPageProps) {
  const [data, setData] = useState<OverviewResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function loadOverview() {
    setLoading(true);
    setError(null);
    try {
      const res = await apiRequest<OverviewResponse>('/api/overview');
      setData(res);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadOverview();
  }, []);

  if (loading && !data) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {Array.from({ length: 6 }).map((_, idx) => (
            <div
              key={idx}
              className="h-28 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5"
            />
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-xl border border-rose-200 dark:border-rose-900 bg-rose-50 dark:bg-rose-950/40 p-6 space-y-3">
        <h2 className="text-base font-semibold text-rose-800 dark:text-rose-200">Unable to load overview</h2>
        <p className="text-sm text-rose-700 dark:text-rose-300">{error}</p>
        <button
          type="button"
          onClick={loadOverview}
          className="px-4 py-2 text-xs font-medium rounded-lg bg-rose-700 text-white hover:bg-rose-800"
        >
          Retry
        </button>
      </div>
    );
  }

  if (!data) return null;

  const maliciousPct =
    data.totalRecordsAnalyzed > 0
      ? ((data.maliciousRecords / data.totalRecordsAnalyzed) * 100).toFixed(1)
      : '0.0';

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-semibold text-slate-900 dark:text-slate-50">
            Security Operations Summary
          </h2>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-0.5">
            Decentralized intrusion detection telemetry, global model state, and recent alerts.
          </p>
        </div>
        <button
          type="button"
          onClick={loadOverview}
          className="flex items-center gap-2 px-3.5 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh
        </button>
      </div>

      {/* Primary KPI Grid */}
      <section aria-label="System metrics" className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5">
          <div className="text-xs font-medium text-slate-500 dark:text-slate-400">Total Records Analyzed</div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-slate-900 dark:text-slate-50">
            {data.totalRecordsAnalyzed.toLocaleString()}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Across uploaded CSVs and flow adapters
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5">
          <div className="text-xs font-medium text-slate-500 dark:text-slate-400">Detected Malicious Records</div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-rose-600 dark:text-rose-400">
            {data.maliciousRecords.toLocaleString()}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400 tabular-nums">
            {maliciousPct}% of inspected flows
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5">
          <div className="text-xs font-medium text-slate-500 dark:text-slate-400">Benign Traffic Count</div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-emerald-600 dark:text-emerald-400">
            {data.benignRecords.toLocaleString()}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Normal baseline connections
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5">
          <div className="text-xs font-medium text-slate-500 dark:text-slate-400">Active Federated Clients</div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-slate-900 dark:text-slate-50">
            {data.activeFederatedClients}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Independent organizations with Ed25519 keys
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5">
          <div className="text-xs font-medium text-slate-500 dark:text-slate-400">Current Global Model Version</div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-sky-600 dark:text-sky-400">
            {data.globalModelVersion}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            {data.activeModel ? `${data.activeModel.name} · ${data.activeModel.classification_mode}` : 'No active model'}
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5">
          <div className="text-xs font-medium text-slate-500 dark:text-slate-400">Latest Federated Training Round</div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-slate-900 dark:text-slate-50">
            Round {data.latestRoundNumber}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400 tabular-nums">
            {data.latestRound
              ? `Accuracy ${(data.latestRound.global_accuracy * 100).toFixed(1)}% · F1 ${(data.latestRound.global_f1 * 100).toFixed(1)}%`
              : 'No rounds recorded yet'}
          </div>
        </div>
      </section>

      {/* Model Performance Summary + Recent Alerts */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-4">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                Model Performance Summary
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Metrics computed on held-out stratified test splits
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('evaluation')}
              className="flex items-center gap-1 text-xs font-medium text-sky-600 dark:text-sky-400 hover:underline whitespace-nowrap"
            >
              Full comparison
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400">
                  <th className="py-2 pr-3 text-left font-medium">Model</th>
                  <th className="py-2 px-2 text-left font-medium">Mode</th>
                  <th className="py-2 px-2 text-right font-medium">Accuracy</th>
                  <th className="py-2 px-2 text-right font-medium">F1-Score</th>
                  <th className="py-2 pl-2 text-right font-medium">FPR</th>
                </tr>
              </thead>
              <tbody>
                {data.modelsSummary.map((m) => (
                  <tr
                    key={m.id}
                    className="border-b last:border-b-0 border-slate-100 dark:border-slate-800/80"
                  >
                    <td className="py-2.5 pr-3 font-medium text-slate-900 dark:text-slate-100">
                      {m.name}
                      <span className="ml-1.5 font-mono text-[11px] text-slate-500 dark:text-slate-400">
                        {m.version}
                      </span>
                    </td>
                    <td className="py-2.5 px-2 text-slate-600 dark:text-slate-300 capitalize">
                      {m.training_paradigm}
                    </td>
                    <td className="py-2.5 px-2 text-right font-mono tabular-nums text-slate-900 dark:text-slate-100">
                      {(m.accuracy * 100).toFixed(1)}%
                    </td>
                    <td className="py-2.5 px-2 text-right font-mono tabular-nums text-slate-900 dark:text-slate-100">
                      {(m.f1_score * 100).toFixed(1)}%
                    </td>
                    <td className="py-2.5 pl-2 text-right font-mono tabular-nums text-slate-700 dark:text-slate-300">
                      {(m.false_positive_rate * 100).toFixed(2)}%
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-4">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                Recent Security Alerts
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Malicious flows detected across monitored sensors
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('monitoring')}
              className="flex items-center gap-1 text-xs font-medium text-sky-600 dark:text-sky-400 hover:underline whitespace-nowrap"
            >
              View all alerts
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {data.recentAlerts.length === 0 ? (
            <p className="text-sm text-slate-500 dark:text-slate-400 py-6 text-center">
              No malicious traffic alerts recorded yet.
            </p>
          ) : (
            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              {data.recentAlerts.slice(0, 6).map((alert) => (
                <div key={alert.id} className="py-2.5 flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="text-xs font-medium text-slate-900 dark:text-slate-100 truncate">
                      {alert.attack_category} · {alert.client_sensor}
                    </div>
                    <div className="text-xs text-slate-500 dark:text-slate-400 truncate mt-0.5">
                      {alert.summary}
                    </div>
                  </div>
                  <div className="text-right shrink-0">
                    <div className={`text-xs capitalize ${severityTextClass(alert.severity)}`}>
                      {alert.severity}
                    </div>
                    <div className="text-[11px] font-mono tabular-nums text-slate-500 dark:text-slate-400">
                      {(alert.confidence * 100).toFixed(1)}%
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
