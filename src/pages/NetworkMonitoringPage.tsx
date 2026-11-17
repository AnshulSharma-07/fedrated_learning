import { useEffect, useState } from 'react';
import { CheckCircle2, Radio, RefreshCw } from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { apiRequest } from '../api/client';
import type { AlertItem } from '../types';

interface MetricsData {
  attackDistribution: Array<{ category: string; count: number }>;
  sensorActivity: Array<{ sensor: string; total: number; malicious: number; benign: number }>;
  severityDistribution: Array<{ severity: string; count: number }>;
  timeline: Array<{ bucket: string; malicious: number; benign: number }>;
}

const PIE_COLORS = ['#16a34a', '#dc2626', '#d97706', '#0284c7', '#7c3aed', '#0d9488'];

export function NetworkMonitoringPage() {
  const [metrics, setMetrics] = useState<MetricsData | null>(null);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [streaming, setStreaming] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function loadMonitoring() {
    try {
      const [mRes, aRes] = await Promise.all([
        apiRequest<MetricsData>('/api/metrics'),
        apiRequest<{ alerts: AlertItem[] }>(
          `/api/alerts?severity=${severityFilter}&status=${statusFilter}`,
        ),
      ]);
      setMetrics(mRes);
      setAlerts(aRes.alerts);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  useEffect(() => {
    loadMonitoring();
  }, [severityFilter, statusFilter]);

  useEffect(() => {
    if (!streaming) return;
    const timer = setInterval(async () => {
      try {
        await apiRequest('/api/monitoring/stream-tick', {
          method: 'POST',
          body: JSON.stringify({ count: 6 }),
        });
        loadMonitoring();
      } catch (err) {
        setError((err as Error).message);
        setStreaming(false);
      }
    }, 3000);
    return () => clearInterval(timer);
  }, [streaming]);

  async function handleIngestBatch() {
    setError(null);
    try {
      await apiRequest('/api/monitoring/stream-tick', {
        method: 'POST',
        body: JSON.stringify({ count: 8 }),
      });
      loadMonitoring();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleAckAlert(id: string) {
    try {
      await apiRequest(`/api/alerts/${id}/ack`, { method: 'POST' });
      loadMonitoring();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  const totalMalicious = metrics?.attackDistribution
    .filter((d) => d.category !== 'Benign')
    .reduce((s, d) => s + d.count, 0) || 0;
  const totalBenign = metrics?.attackDistribution.find((d) => d.category === 'Benign')?.count || 0;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-semibold text-slate-900 dark:text-slate-50">
            Network Traffic Monitoring & Alert Triage
          </h2>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-0.5">
            Simulated lab flow-adapter ingestion (distinct from offline CSV evaluation). In production, compatible Zeek/CICFlowMeter adapters feed normalized 14-feature vectors to the inference API.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={handleIngestBatch}
            className="px-3.5 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-xs font-medium hover:bg-slate-100 dark:hover:bg-slate-800 whitespace-nowrap"
          >
            Ingest 8 Lab Flows
          </button>
          <button
            type="button"
            onClick={() => setStreaming((s) => !s)}
            className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-medium transition-colors whitespace-nowrap ${
              streaming
                ? 'bg-rose-600 hover:bg-rose-700 text-white'
                : 'bg-sky-600 hover:bg-sky-700 text-white'
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            {streaming ? 'Stop Flow Adapter Stream' : 'Start Flow Adapter Stream'}
          </button>
        </div>
      </div>

      {error && (
        <div role="alert" className="text-xs text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900 rounded-lg px-4 py-3">
          {error}
        </div>
      )}

      {/* Ingestion Status Summary */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
          <div className="text-xs text-slate-500 dark:text-slate-400">Ingestion Mode</div>
          <div className="mt-1 text-sm font-semibold text-slate-900 dark:text-slate-100">
            {streaming ? 'Active Simulated Stream' : 'On-Demand Flow Adapter'}
          </div>
        </div>
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
          <div className="text-xs text-slate-500 dark:text-slate-400">Benign Traffic</div>
          <div className="mt-1 text-xl font-semibold font-mono tabular-nums text-emerald-600 dark:text-emerald-400">
            {totalBenign.toLocaleString()}
          </div>
        </div>
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
          <div className="text-xs text-slate-500 dark:text-slate-400">Malicious Flows</div>
          <div className="mt-1 text-xl font-semibold font-mono tabular-nums text-rose-600 dark:text-rose-400">
            {totalMalicious.toLocaleString()}
          </div>
        </div>
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
          <div className="text-xs text-slate-500 dark:text-slate-400">Open Alerts</div>
          <div className="mt-1 text-xl font-semibold font-mono tabular-nums text-amber-600 dark:text-amber-400">
            {alerts.filter((a) => a.status === 'open').length}
          </div>
        </div>
      </div>

      {/* Charts Grid */}
      {metrics && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-3">
            <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              Attack Category Distribution
            </h3>
            <div className="h-60 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={metrics.attackDistribution}
                    dataKey="count"
                    nameKey="category"
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={78}
                  >
                    {metrics.attackDistribution.map((entry, idx) => (
                      <Cell
                        key={entry.category}
                        fill={entry.category === 'Benign' ? '#16a34a' : PIE_COLORS[(idx % (PIE_COLORS.length - 1)) + 1]}
                      />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </section>

          <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-3">
            <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              Client / Sensor Activity (Benign vs Malicious)
            </h3>
            <div className="h-60 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={metrics.sensorActivity}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.2} />
                  <XAxis dataKey="sensor" tick={{ fontSize: 10 }} stroke="#64748b" />
                  <YAxis tick={{ fontSize: 11 }} stroke="#64748b" />
                  <Tooltip />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                  <Bar dataKey="benign" name="Benign" stackId="a" fill="#16a34a" />
                  <Bar dataKey="malicious" name="Malicious" stackId="a" fill="#dc2626" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </section>

          <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-3">
            <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              Alert Severity Distribution
            </h3>
            <div className="h-60 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={metrics.severityDistribution}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.2} />
                  <XAxis dataKey="severity" tick={{ fontSize: 11 }} stroke="#64748b" />
                  <YAxis tick={{ fontSize: 11 }} stroke="#64748b" />
                  <Tooltip />
                  <Bar dataKey="count" name="Alerts" fill="#0284c7" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </section>
        </div>
      )}

      {/* Alert History Table */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            Intrusion Alert History
          </h3>
          <div className="flex flex-wrap items-center gap-2">
            <select
              aria-label="Filter alerts by severity"
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
            <select
              aria-label="Filter alerts by status"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-3 py-1.5 text-xs rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
            >
              <option value="all">All Statuses</option>
              <option value="open">Open</option>
              <option value="acknowledged">Acknowledged</option>
            </select>
            <button
              type="button"
              aria-label="Refresh alerts"
              onClick={loadMonitoring}
              className="p-1.5 rounded-lg border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400">
                <th className="py-2 pr-3 text-left font-medium">Timestamp</th>
                <th className="py-2 px-2 text-left font-medium">Sensor</th>
                <th className="py-2 px-2 text-left font-medium">Attack Category</th>
                <th className="py-2 px-2 text-left font-medium">Severity</th>
                <th className="py-2 px-2 text-right font-medium">Confidence</th>
                <th className="py-2 px-2 text-left font-medium">Status</th>
                <th className="py-2 pl-2 text-right font-medium">Action</th>
              </tr>
            </thead>
            <tbody>
              {alerts.slice(0, 40).map((a) => (
                <tr key={a.id} className="border-b last:border-b-0 border-slate-100 dark:border-slate-800/80">
                  <td className="py-2 pr-3 font-mono text-[11px] text-slate-500 dark:text-slate-400 whitespace-nowrap">
                    {a.created_at.slice(0, 19).replace('T', ' ')}
                  </td>
                  <td className="py-2 px-2 font-medium text-slate-800 dark:text-slate-200">{a.client_sensor}</td>
                  <td className="py-2 px-2 text-rose-600 dark:text-rose-400 font-medium">{a.attack_category}</td>
                  <td className="py-2 px-2 capitalize">{a.severity}</td>
                  <td className="py-2 px-2 text-right font-mono tabular-nums">{(a.confidence * 100).toFixed(1)}%</td>
                  <td className="py-2 px-2 capitalize">
                    <span className={a.status === 'open' ? 'text-amber-600 dark:text-amber-400 font-medium' : 'text-emerald-600 dark:text-emerald-400'}>
                      {a.status}
                    </span>
                  </td>
                  <td className="py-2 pl-2 text-right">
                    <button
                      type="button"
                      onClick={() => handleAckAlert(a.id)}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800"
                    >
                      <CheckCircle2 className="w-3 h-3" />
                      {a.status === 'open' ? 'Acknowledge' : 'Reopen'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
