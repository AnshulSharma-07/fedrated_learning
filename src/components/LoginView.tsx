import { useState, type FormEvent } from 'react';
import { Lock, Moon, ShieldCheck, Sun } from 'lucide-react';
import { apiRequest } from '../api/client';
import type { AuthUser } from '../types';

interface LoginViewProps {
  onSuccess: (token: string, user: AuthUser) => void;
  isDark: boolean;
  onToggleTheme: () => void;
}

export function LoginView({ onSuccess, isDark, onToggleTheme }: LoginViewProps) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (!email.trim() || !password) {
      setError('Enter both email and password.');
      return;
    }
    setLoading(true);
    try {
      const res = await apiRequest<{ token: string; user: AuthUser }>('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email: email.trim(), password }),
      });
      onSuccess(res.token, res.user);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  function fillDemoCredentials(role: 'admin' | 'analyst') {
    setError(null);
    if (role === 'admin') {
      setEmail('admin@fl-ids.local');
      setPassword('Admin@FLIDS2026!');
    } else {
      setEmail('analyst@fl-ids.local');
      setPassword('Analyst@FLIDS2026!');
    }
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex flex-col justify-between p-6">
      <div className="flex items-center justify-between max-w-5xl w-full mx-auto">
        <div className="flex items-center gap-2.5">
          <ShieldCheck className="w-6 h-6 text-sky-600 dark:text-sky-400" />
          <span className="text-lg font-semibold tracking-tight">FL-IDS Security Operations</span>
        </div>
        <button
          type="button"
          onClick={onToggleTheme}
          aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
          className="p-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
        >
          {isDark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
        </button>
      </div>

      <main className="max-w-md w-full mx-auto my-auto py-8">
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-8 space-y-6">
          <div className="space-y-2">
            <h1 className="text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-50">
              Sign in to FL-IDS
            </h1>
            <p className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
              Role-based access control protects federated training, Ed25519 key management, and intrusion inference APIs.
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label htmlFor="login-email" className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                Email address
              </label>
              <input
                id="login-email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin@fl-ids.local"
                className="w-full px-3.5 py-2.5 text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-500"
              />
            </div>

            <div className="space-y-1.5">
              <label htmlFor="login-password" className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                Password
              </label>
              <input
                id="login-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                className="w-full px-3.5 py-2.5 text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-500"
              />
            </div>

            {error && (
              <div
                role="alert"
                className="text-sm text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/50 border border-rose-200 dark:border-rose-900 rounded-lg px-3.5 py-2.5"
              >
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg bg-sky-600 hover:bg-sky-700 disabled:opacity-60 text-white text-sm font-medium transition-colors"
            >
              <Lock className="w-4 h-4" />
              {loading ? 'Signing in...' : 'Sign In'}
            </button>
          </form>

          <div className="pt-4 border-t border-slate-200 dark:border-slate-800 space-y-2.5">
            <p className="text-xs font-medium text-slate-500 dark:text-slate-400">
              Demo Credentials (populates form)
            </p>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => fillDemoCredentials('admin')}
                className="px-3 py-2 text-xs font-medium rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors text-left"
              >
                Fill Admin
                <span className="block text-[11px] font-mono text-slate-500 dark:text-slate-400 mt-0.5 truncate">
                  admin@fl-ids.local
                </span>
              </button>
              <button
                type="button"
                onClick={() => fillDemoCredentials('analyst')}
                className="px-3 py-2 text-xs font-medium rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors text-left"
              >
                Fill Analyst
                <span className="block text-[11px] font-mono text-slate-500 dark:text-slate-400 mt-0.5 truncate">
                  analyst@fl-ids.local
                </span>
              </button>
            </div>
          </div>
        </div>
      </main>

      <footer className="max-w-5xl w-full mx-auto text-center text-xs text-slate-500 dark:text-slate-400">
        Federated Learning for Intrusion Detection System · Ed25519 · AES-256-GCM · SHA-256
      </footer>
    </div>
  );
}
