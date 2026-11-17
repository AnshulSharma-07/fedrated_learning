import { useEffect, useState, type FormEvent } from 'react';
import { Play, Plus, RefreshCw } from 'lucide-react';
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { apiRequest } from '../api/client';
import type { FederatedClient, FederatedRoundItem } from '../types';

interface FederatedJobStatus {
  jobId: string;
  status: 'idle' | 'running' | 'completed' | 'failed';
  totalRounds: number;
  currentRound: number;
  classificationMode: string;
  dpEnabled: boolean;
  message: string;
}

export function FederatedLearningPage() {
  const [clients, setClients] = useState<FederatedClient[]>([]);
  const [rounds, setRounds] = useState<FederatedRoundItem[]>([]);
  const [job, setJob] = useState<FederatedJobStatus | null>(null);
  const [numRounds, setNumRounds] = useState(5);
  const [localEpochs, setLocalEpochs] = useState(4);
  const [nonIidAlpha, setNonIidAlpha] = useState(0.65);
  const [dpEnabled, setDpEnabled] = useState(false);
  const [classificationMode, setClassificationMode] = useState<'multiclass' | 'binary'>('multiclass');
  const [newName, setNewName] = useState('');
  const [newOrg, setNewOrg] = useState('');
  const [newCidr, setNewCidr] = useState('10.72.0.0/16');
  const [error, setError] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  async function loadAll() {
    try {
      const [cRes, rRes, sRes] = await Promise.all([
        apiRequest<{ clients: FederatedClient[] }>('/api/federated/clients'),
        apiRequest<{ rounds: FederatedRoundItem[] }>('/api/federated/rounds'),
        apiRequest<{ job: FederatedJobStatus }>('/api/federated/status'),
      ]);
      setClients(cRes.clients);
      setRounds(rRes.rounds);
      setJob(sRes.job);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  useEffect(() => {
    loadAll();
  }, []);

  useEffect(() => {
    if (job?.status !== 'running') return;
    const timer = setInterval(() => {
      loadAll();
    }, 500);
    return () => clearInterval(timer);
  }, [job?.status]);

  async function handleStartTraining() {
    setError(null);
    setStatusMessage(null);
    try {
      const res = await apiRequest<{ job: FederatedJobStatus }>('/api/federated/start', {
        method: 'POST',
        body: JSON.stringify({
          rounds: numRounds,
          localEpochs,
          nonIidAlpha,
          dpEnabled,
          classificationMode,
        }),
      });
      setJob(res.job);
      setStatusMessage('Federated training job started across active clients.');
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleRegisterClient(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (!newName.trim() || !newOrg.trim()) {
      setError('Client name and organization are required.');
      return;
    }
    try {
      await apiRequest('/api/federated/clients/register', {
        method: 'POST',
        body: JSON.stringify({ name: newName.trim(), organization: newOrg.trim(), subnetCidr: newCidr.trim() }),
      });
      setNewName('');
      setNewOrg('');
      setStatusMessage('Registered new federated client with fresh Ed25519 key pair.');
      loadAll();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleToggleClient(clientId: string) {
    setError(null);
    try {
      await apiRequest(`/api/federated/clients/${clientId}/toggle`, { method: 'POST' });
      loadAll();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  const latestRound = rounds[rounds.length - 1] || null;
  const chartData = rounds.slice(-15).map((r) => ({
    round: `R${r.round_number}`,
    accuracy: Number((r.global_accuracy * 100).toFixed(2)),
    f1: Number((r.global_f1 * 100).toFixed(2)),
    loss: Number(r.global_loss.toFixed(4)),
  }));

  const rejectedOutcomes = rounds
    .flatMap((r) =>
      r.clientOutcomes
        .filter((o) => o.status === 'rejected')
        .map((o) => ({ round: r.round_number, version: r.model_version, ...o })),
    )
    .slice(-10);

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div className="max-w-2xl">
          <h2 className="text-xl font-semibold text-slate-900 dark:text-slate-50">
            Federated Learning & FedAvg Coordinator
          </h2>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-0.5">
            Each client trains locally on its non-IID partition and submits Ed25519-signed, AES-256-GCM encrypted weight updates. Raw client records never leave the local client.
          </p>
        </div>
        <button
          type="button"
          onClick={loadAll}
          className="flex items-center gap-2 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-xs font-medium hover:bg-slate-100 dark:hover:bg-slate-800 shrink-0 whitespace-nowrap"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Sync State
        </button>
      </div>

      {error && (
        <div role="alert" className="text-xs text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900 rounded-lg px-4 py-3">
          {error}
        </div>
      )}
      {statusMessage && (
        <div className="text-xs text-sky-700 dark:text-sky-300 bg-sky-50 dark:bg-sky-950/40 border border-sky-200 dark:border-sky-900 rounded-lg px-4 py-3">
          {statusMessage}
        </div>
      )}

      {/* Training Configurator & Live Progress */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              Training Round Configuration
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              {job ? `${job.status.toUpperCase()} · Round ${job.currentRound}/${job.totalRounds} · ${job.message}` : 'Ready'}
            </p>
          </div>
          <button
            type="button"
            disabled={job?.status === 'running'}
            onClick={handleStartTraining}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-700 disabled:opacity-50 text-white text-xs font-medium transition-colors"
          >
            <Play className="w-3.5 h-3.5" />
            {job?.status === 'running' ? `Running Round ${job.currentRound}/${job.totalRounds}...` : 'Start Federated Training'}
          </button>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
          <div className="space-y-1">
            <label htmlFor="fl-rounds" className="block text-xs text-slate-500 dark:text-slate-400">
              Rounds
            </label>
            <input
              id="fl-rounds"
              type="number"
              min={1}
              max={12}
              value={numRounds}
              onChange={(e) => setNumRounds(Number(e.target.value))}
              className="w-full px-3 py-1.5 text-sm font-mono rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
            />
          </div>
          <div className="space-y-1">
            <label htmlFor="fl-epochs" className="block text-xs text-slate-500 dark:text-slate-400">
              Local Epochs
            </label>
            <input
              id="fl-epochs"
              type="number"
              min={1}
              max={10}
              value={localEpochs}
              onChange={(e) => setLocalEpochs(Number(e.target.value))}
              className="w-full px-3 py-1.5 text-sm font-mono rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
            />
          </div>
          <div className="space-y-1">
            <label htmlFor="fl-alpha" className="block text-xs text-slate-500 dark:text-slate-400">
              Non-IID Alpha
            </label>
            <input
              id="fl-alpha"
              type="number"
              step={0.1}
              min={0.2}
              max={2.0}
              value={nonIidAlpha}
              onChange={(e) => setNonIidAlpha(Number(e.target.value))}
              className="w-full px-3 py-1.5 text-sm font-mono rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
            />
          </div>
          <div className="space-y-1">
            <label htmlFor="fl-mode" className="block text-xs text-slate-500 dark:text-slate-400">
              Task Mode
            </label>
            <select
              id="fl-mode"
              value={classificationMode}
              onChange={(e) => setClassificationMode(e.target.value as 'multiclass' | 'binary')}
              className="w-full px-3 py-1.5 text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
            >
              <option value="multiclass">Multiclass</option>
              <option value="binary">Binary</option>
            </select>
          </div>
          <div className="flex items-end pb-1.5">
            <label className="flex items-center gap-2 text-xs font-medium text-slate-700 dark:text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={dpEnabled}
                onChange={(e) => setDpEnabled(e.target.checked)}
                className="rounded border-slate-300 dark:border-slate-700"
              />
              DP-SGD Clipping & Noise
            </label>
          </div>
        </div>
      </section>

      {/* Round Convergence Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-3">
          <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            Global Accuracy & F1-Score Across Rounds
          </h3>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData} margin={{ top: 12, right: 16, left: 0, bottom: 4 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.2} />
                <XAxis dataKey="round" tick={{ fontSize: 12 }} stroke="#64748b" />
                <YAxis domain={[0, 105]} ticks={[0, 25, 50, 75, 100]} tick={{ fontSize: 12 }} stroke="#64748b" />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="accuracy" name="Accuracy (%)" stroke="#0284c7" strokeWidth={2} dot={{ r: 3 }} />
                <Line type="monotone" dataKey="f1" name="Weighted F1 (%)" stroke="#16a34a" strokeWidth={2} dot={{ r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-3">
          <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            Global Cross-Entropy Loss Across Rounds
          </h3>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData} margin={{ top: 12, right: 16, left: 0, bottom: 4 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.2} />
                <XAxis dataKey="round" tick={{ fontSize: 12 }} stroke="#64748b" />
                <YAxis tick={{ fontSize: 12 }} stroke="#64748b" />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="loss" name="Test Cross-Entropy Loss" stroke="#d97706" strokeWidth={2} dot={{ r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </section>
      </div>

      {/* Clients Table & Registration */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              Registered Federated Clients ({clients.length})
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Latest round participation and local training performance. Sample counts are reported only for FedAvg weighting.
            </p>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400">
                <th className="py-2 pr-3 text-left font-medium">Client</th>
                <th className="py-2 px-2 text-left font-medium">Organization / Subnet</th>
                <th className="py-2 px-2 text-left font-medium">Participation</th>
                <th className="py-2 px-2 text-right font-medium">Local Samples</th>
                <th className="py-2 px-2 text-right font-medium">Local Loss</th>
                <th className="py-2 px-2 text-right font-medium">Local Acc</th>
                <th className="py-2 px-2 text-right font-medium">Update Size</th>
                <th className="py-2 pl-2 text-right font-medium">Action</th>
              </tr>
            </thead>
            <tbody>
              {clients.map((c) => (
                <tr key={c.id} className="border-b last:border-b-0 border-slate-100 dark:border-slate-800/80">
                  <td className="py-2.5 pr-3 font-medium text-slate-900 dark:text-slate-100">
                    {c.name}
                    <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">{c.key_id || 'No key'}</div>
                  </td>
                  <td className="py-2.5 px-2 text-slate-600 dark:text-slate-300">
                    {c.organization} · <span className="font-mono">{c.subnet_cidr}</span>
                  </td>
                  <td className="py-2.5 px-2">
                    <span className={c.active && !c.revoked ? 'text-emerald-600 dark:text-emerald-400 font-medium' : 'text-amber-600 dark:text-amber-400'}>
                      {c.revoked ? 'Key Revoked' : c.active ? 'Active' : 'Paused'}
                    </span>
                  </td>
                  <td className="py-2.5 px-2 text-right font-mono tabular-nums">
                    {c.latestMetrics ? c.latestMetrics.sample_count : '—'}
                  </td>
                  <td className="py-2.5 px-2 text-right font-mono tabular-nums">
                    {c.latestMetrics ? c.latestMetrics.local_loss.toFixed(4) : '—'}
                  </td>
                  <td className="py-2.5 px-2 text-right font-mono tabular-nums">
                    {c.latestMetrics ? `${(c.latestMetrics.local_accuracy * 100).toFixed(1)}%` : '—'}
                  </td>
                  <td className="py-2.5 px-2 text-right font-mono tabular-nums">
                    {c.latestMetrics ? `${(c.latestMetrics.payload_bytes / 1024).toFixed(1)} KB` : '—'}
                  </td>
                  <td className="py-2.5 pl-2 text-right">
                    <button
                      type="button"
                      onClick={() => handleToggleClient(c.id)}
                      className="px-2.5 py-1 text-xs rounded border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800"
                    >
                      {c.active ? 'Leave' : 'Join'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <form onSubmit={handleRegisterClient} className="pt-4 border-t border-slate-200 dark:border-slate-800 grid grid-cols-1 sm:grid-cols-4 gap-3 items-end">
          <div className="space-y-1">
            <label htmlFor="new-client-name" className="block text-xs text-slate-500 dark:text-slate-400">
              New Client Name
            </label>
            <input
              id="new-client-name"
              type="text"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Energy-Grid-North"
              className="w-full px-3 py-1.5 text-xs rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
            />
          </div>
          <div className="space-y-1">
            <label htmlFor="new-client-org" className="block text-xs text-slate-500 dark:text-slate-400">
              Organization
            </label>
            <input
              id="new-client-org"
              type="text"
              value={newOrg}
              onChange={(e) => setNewOrg(e.target.value)}
              placeholder="Utility SCADA Operations"
              className="w-full px-3 py-1.5 text-xs rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
            />
          </div>
          <div className="space-y-1">
            <label htmlFor="new-client-cidr" className="block text-xs text-slate-500 dark:text-slate-400">
              Subnet CIDR
            </label>
            <input
              id="new-client-cidr"
              type="text"
              value={newCidr}
              onChange={(e) => setNewCidr(e.target.value)}
              className="w-full px-3 py-1.5 text-xs font-mono rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
            />
          </div>
          <button
            type="submit"
            className="flex items-center justify-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700"
          >
            <Plus className="w-3.5 h-3.5" />
            Register Client
          </button>
        </form>
      </section>

      {/* Checkpoints & Rejected Updates */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-3">
          <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            Global Model Checkpoints
          </h3>
          {latestRound ? (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400">
                    <th className="py-2 text-left font-medium">Version</th>
                    <th className="py-2 text-right font-medium">Round</th>
                    <th className="py-2 text-right font-medium">Acc</th>
                    <th className="py-2 text-right font-medium">Accepted</th>
                    <th className="py-2 text-right font-medium">Comm Overhead</th>
                  </tr>
                </thead>
                <tbody>
                  {rounds.slice(-6).reverse().map((r) => (
                    <tr key={r.id} className="border-b last:border-b-0 border-slate-100 dark:border-slate-800/80">
                      <td className="py-2 font-mono">{r.model_version}</td>
                      <td className="py-2 text-right font-mono tabular-nums">R{r.round_number}</td>
                      <td className="py-2 text-right font-mono tabular-nums">{(r.global_accuracy * 100).toFixed(1)}%</td>
                      <td className="py-2 text-right font-mono tabular-nums">
                        {r.accepted_clients}/{r.participating_clients}
                      </td>
                      <td className="py-2 text-right font-mono tabular-nums">
                        {(r.communication_bytes / 1024).toFixed(1)} KB
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-xs text-slate-500 dark:text-slate-400">No checkpoints saved yet.</p>
          )}
        </section>

        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-3">
          <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            Rejected Updates & Validation Reasons
          </h3>
          {rejectedOutcomes.length === 0 ? (
            <p className="text-xs text-slate-500 dark:text-slate-400 py-4">
              All submitted updates during training rounds passed Ed25519 signature, AES-256-GCM decryption, SHA-256 hash, and tensor shape checks. Revoke a key or simulate an attack in Cryptography & Security to observe rejections.
            </p>
          ) : (
            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              {rejectedOutcomes.map((o, idx) => (
                <div key={`${o.id}-${idx}`} className="py-2 text-xs">
                  <div className="font-medium text-rose-600 dark:text-rose-400">
                    Round {o.round} · {o.client_name} ({o.version})
                  </div>
                  <div className="text-slate-600 dark:text-slate-300 mt-0.5">{o.rejection_reason}</div>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
