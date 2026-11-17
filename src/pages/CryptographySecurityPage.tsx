import { useEffect, useState } from 'react';
import { Ban, KeyRound, RefreshCw, ShieldAlert } from 'lucide-react';
import { apiRequest } from '../api/client';
import type { AuditLogItem, PublicKeyRecord, SecurityEventItem } from '../types';

export function CryptographySecurityPage() {
  const [keys, setKeys] = useState<PublicKeyRecord[]>([]);
  const [events, setEvents] = useState<SecurityEventItem[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogItem[]>([]);
  const [simResult, setSimResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function loadAll() {
    try {
      const [kRes, eRes, aRes] = await Promise.all([
        apiRequest<{ keys: PublicKeyRecord[] }>('/api/security/keys'),
        apiRequest<{ events: SecurityEventItem[] }>('/api/security/events'),
        apiRequest<{ logs: AuditLogItem[] }>('/api/security/audit-logs'),
      ]);
      setKeys(kRes.keys);
      setEvents(eRes.events);
      setAuditLogs(aRes.logs);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  useEffect(() => {
    loadAll();
  }, []);

  async function handleRotateKey(clientId: string) {
    setError(null);
    setSimResult(null);
    try {
      const res = await apiRequest<{ keyId: string; fingerprint: string }>(
        `/api/security/keys/${clientId}/rotate`,
        { method: 'POST' },
      );
      setSimResult(`Rotated Ed25519 key for ${clientId}. New key ID: ${res.keyId}`);
      loadAll();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleRevokeKey(clientId: string) {
    setError(null);
    setSimResult(null);
    try {
      await apiRequest(`/api/security/keys/${clientId}/revoke`, {
        method: 'POST',
        body: JSON.stringify({ reason: 'Manual administrative key revocation' }),
      });
      setSimResult(`Revoked Ed25519 key for ${clientId}. Future updates from this key will be rejected.`);
      loadAll();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleSimulateAttack(
    attackType: 'tamper_payload' | 'replay_nonce' | 'unauthorized_client' | 'nan_poisoning',
  ) {
    setBusy(true);
    setError(null);
    try {
      const res = await apiRequest<{
        attackType: string;
        blocked: boolean;
        code: string;
        reason: string;
      }>('/api/security/simulate-attack', {
        method: 'POST',
        body: JSON.stringify({ attackType }),
      });
      setSimResult(
        `${res.blocked ? 'Blocked' : 'Accepted'} (${res.code}): ${res.reason}`,
      );
      loadAll();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-semibold text-slate-900 dark:text-slate-50">
            Cryptography, Key Lifecycle & Security Audit
          </h2>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-0.5">
            Ed25519 digital signatures authenticate metadata, SHA-256 verifies canonical integrity, and AES-256-GCM provides confidentiality. Private keys never leave client key vaults and are never exposed in API responses.
          </p>
        </div>
        <button
          type="button"
          onClick={loadAll}
          className="flex items-center gap-2 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-xs font-medium hover:bg-slate-100 dark:hover:bg-slate-800"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh Logs
        </button>
      </div>

      {/* Cryptographic Mechanism Matrix */}
      <section className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
          <div className="text-xs text-slate-500 dark:text-slate-400">Transport & Payload Encryption</div>
          <div className="mt-1 text-sm font-semibold text-slate-900 dark:text-slate-100">
            TLS + AES-256-GCM
          </div>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Unique 96-bit CSPRNG IV per message with AAD binding client, round, and model version.
          </p>
        </div>
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
          <div className="text-xs text-slate-500 dark:text-slate-400">Integrity Verification</div>
          <div className="mt-1 text-sm font-semibold text-slate-900 dark:text-slate-100">
            SHA-256 Canonical Digest
          </div>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Detects payload tampering; hashing alone does not provide confidentiality.
          </p>
        </div>
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
          <div className="text-xs text-slate-500 dark:text-slate-400">Client Authentication</div>
          <div className="mt-1 text-sm font-semibold text-slate-900 dark:text-slate-100">
            Ed25519 Digital Signatures
          </div>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Authenticates update origin and non-repudiation; signatures do not encrypt payloads.
          </p>
        </div>
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
          <div className="text-xs text-slate-500 dark:text-slate-400">Replay & Privacy Scope</div>
          <div className="mt-1 text-sm font-semibold text-slate-900 dark:text-slate-100">
            Nonce Registry + Optional DP
          </div>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Blocks duplicate nonces. Note: standard FedAvg sample counts/gradients can still leak metadata without DP.
          </p>
        </div>
      </section>

      {/* Interactive Adversarial Verification Controls */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-4">
        <div>
          <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            Coordinator Cryptographic Verification Tests
          </h3>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Execute real malformed or adversarial envelopes against the coordinator verification pipeline and inspect the security event log.
          </p>
        </div>
        <div className="flex flex-wrap gap-2.5">
          <button
            type="button"
            disabled={busy}
            onClick={() => handleSimulateAttack('tamper_payload')}
            className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
            Test Ciphertext Tampering
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => handleSimulateAttack('replay_nonce')}
            className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
            Test Replay Attack (Duplicate Nonce)
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => handleSimulateAttack('unauthorized_client')}
            className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-rose-600 dark:text-rose-400" />
            Test Unauthorized Client
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => handleSimulateAttack('nan_poisoning')}
            className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-rose-600 dark:text-rose-400" />
            Test Weight Norm Poisoning
          </button>
        </div>

        {simResult && (
          <div className="text-xs text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-900 rounded-lg px-3.5 py-2.5">
            {simResult}
          </div>
        )}
        {error && (
          <div role="alert" className="text-xs text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900 rounded-lg px-3.5 py-2.5">
            {error}
          </div>
        )}
      </section>

      {/* Client Public-Key Registry */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-4">
        <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
          Client Ed25519 Public-Key Registry
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400">
                <th className="py-2 pr-3 text-left font-medium">Client</th>
                <th className="py-2 px-2 text-left font-medium">Key ID</th>
                <th className="py-2 px-2 text-left font-medium">SHA-256 Fingerprint</th>
                <th className="py-2 px-2 text-left font-medium">Key Status</th>
                <th className="py-2 px-2 text-left font-medium">Last Rotated</th>
                <th className="py-2 pl-2 text-right font-medium">Lifecycle Actions</th>
              </tr>
            </thead>
            <tbody>
              {keys.map((k) => (
                <tr key={k.id} className="border-b last:border-b-0 border-slate-100 dark:border-slate-800/80">
                  <td className="py-2.5 pr-3 font-medium text-slate-900 dark:text-slate-100">
                    {k.client_name}
                    <div className="text-[11px] text-slate-500 dark:text-slate-400">{k.organization}</div>
                  </td>
                  <td className="py-2.5 px-2 font-mono">{k.key_id}</td>
                  <td className="py-2.5 px-2 font-mono text-slate-600 dark:text-slate-400">{k.fingerprint}</td>
                  <td className="py-2.5 px-2">
                    <span className={k.revoked ? 'text-rose-600 dark:text-rose-400 font-medium' : 'text-emerald-600 dark:text-emerald-400 font-medium'}>
                      {k.revoked ? 'Revoked' : 'Registered & Active'}
                    </span>
                  </td>
                  <td className="py-2.5 px-2 font-mono text-slate-500 dark:text-slate-400">
                    {k.rotated_at ? k.rotated_at.slice(0, 19).replace('T', ' ') : 'Initial'}
                  </td>
                  <td className="py-2.5 pl-2 text-right space-x-2 whitespace-nowrap">
                    <button
                      type="button"
                      onClick={() => handleRotateKey(k.client_id)}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800"
                    >
                      <KeyRound className="w-3 h-3" />
                      Rotate Key
                    </button>
                    {!k.revoked && (
                      <button
                        type="button"
                        onClick={() => handleRevokeKey(k.client_id)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-rose-300 dark:border-rose-800 text-rose-700 dark:text-rose-300 hover:bg-rose-50 dark:hover:bg-rose-950/50"
                      >
                        <Ban className="w-3 h-3" />
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Security Events & Audit Logs */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-3">
          <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            Cryptographic Verification & Rejection Events
          </h3>
          <div className="overflow-x-auto max-h-80">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400">
                  <th className="py-2 pr-2 text-left font-medium">Event</th>
                  <th className="py-2 px-2 text-left font-medium">Sig / Integrity / Enc</th>
                  <th className="py-2 pl-2 text-left font-medium">Details</th>
                </tr>
              </thead>
              <tbody>
                {events.map((ev) => (
                  <tr key={ev.id} className="border-b last:border-b-0 border-slate-100 dark:border-slate-800/80">
                    <td className="py-2 pr-2 font-mono font-medium whitespace-nowrap">
                      <span className={ev.blocked ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}>
                        {ev.event_type}
                      </span>
                    </td>
                    <td className="py-2 px-2 font-mono text-[11px] text-slate-500 dark:text-slate-400 whitespace-nowrap">
                      {ev.signature_status} / {ev.integrity_status} / {ev.encryption_status}
                    </td>
                    <td className="py-2 pl-2 text-slate-700 dark:text-slate-300">{ev.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-3">
          <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            Security Audit Trail
          </h3>
          <div className="overflow-x-auto max-h-80">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400">
                  <th className="py-2 pr-2 text-left font-medium">Actor</th>
                  <th className="py-2 px-2 text-left font-medium">Action</th>
                  <th className="py-2 px-2 text-left font-medium">Outcome</th>
                  <th className="py-2 pl-2 text-left font-medium">Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.map((log) => (
                  <tr key={log.id} className="border-b last:border-b-0 border-slate-100 dark:border-slate-800/80">
                    <td className="py-2 pr-2">
                      <div className="font-medium text-slate-800 dark:text-slate-200">{log.actor_email}</div>
                      <div className="text-[11px] text-slate-500 capitalize">{log.actor_role}</div>
                    </td>
                    <td className="py-2 px-2">
                      <div className="font-mono text-[11px]">{log.action}</div>
                      <div className="text-slate-500 dark:text-slate-400 truncate max-w-[220px]">{log.details}</div>
                    </td>
                    <td className="py-2 px-2 capitalize font-medium">{log.outcome}</td>
                    <td className="py-2 pl-2 font-mono text-[11px] text-slate-500 dark:text-slate-400 whitespace-nowrap">
                      {log.created_at.slice(0, 19).replace('T', ' ')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  );
}
