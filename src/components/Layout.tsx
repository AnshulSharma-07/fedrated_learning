import { useState, type ReactNode } from 'react';
import {
  Activity,
  BarChart3,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  Network,
  Radar,
  ShieldCheck,
  Sun,
  X,
} from 'lucide-react';
import type { AuthUser, NavPage } from '../types';

interface LayoutProps {
  activePage: NavPage;
  onNavigate: (page: NavPage) => void;
  user: AuthUser;
  onLogout: () => void;
  isDark: boolean;
  onToggleTheme: () => void;
  children: ReactNode;
}

const NAV_ITEMS: Array<{ id: NavPage; label: string; icon: typeof LayoutDashboard }> = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'detection', label: 'Intrusion Detection', icon: Radar },
  { id: 'federated', label: 'Federated Learning', icon: Network },
  { id: 'crypto', label: 'Cryptography & Security', icon: KeyRound },
  { id: 'monitoring', label: 'Network Monitoring', icon: Activity },
  { id: 'evaluation', label: 'Model Evaluation', icon: BarChart3 },
];

export function Layout({
  activePage,
  onNavigate,
  user,
  onLogout,
  isDark,
  onToggleTheme,
  children,
}: LayoutProps) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const currentItem = NAV_ITEMS.find((n) => n.id === activePage) || NAV_ITEMS[0];

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex">
      {/* Desktop Sidebar */}
      <aside className="hidden lg:flex lg:flex-col w-64 shrink-0 border-r border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
        <div className="h-16 px-5 flex items-center gap-2.5 border-b border-slate-200 dark:border-slate-800">
          <ShieldCheck className="w-5 h-5 text-sky-600 dark:text-sky-400 shrink-0" />
          <span className="text-base font-semibold tracking-tight whitespace-nowrap">FL-IDS Console</span>
        </div>

        <nav aria-label="Primary navigation" className="flex-1 p-3 space-y-1">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const active = activePage === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => onNavigate(item.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors whitespace-nowrap ${
                  active
                    ? 'bg-sky-50 dark:bg-sky-950/60 text-sky-700 dark:text-sky-300'
                    : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/70 hover:text-slate-900 dark:hover:text-slate-100'
                }`}
              >
                <Icon className="w-4 h-4 shrink-0" />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t border-slate-200 dark:border-slate-800 space-y-3">
          <div className="text-xs space-y-0.5">
            <div className="font-medium text-slate-900 dark:text-slate-100 truncate">{user.name}</div>
            <div className="text-slate-500 dark:text-slate-400 truncate">
              {user.email} · <span className="capitalize">{user.role}</span>
            </div>
          </div>
          <button
            type="button"
            onClick={onLogout}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium rounded-lg border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          >
            <LogOut className="w-3.5 h-3.5" />
            Sign Out
          </button>
        </div>
      </aside>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div className="fixed inset-0 bg-slate-950/60" onClick={() => setMobileMenuOpen(false)} />
          <aside className="relative w-64 max-w-[80vw] bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 flex flex-col z-10">
            <div className="h-16 px-4 flex items-center justify-between border-b border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-sky-600 dark:text-sky-400" />
                <span className="font-semibold">FL-IDS Console</span>
              </div>
              <button
                type="button"
                aria-label="Close menu"
                onClick={() => setMobileMenuOpen(false)}
                className="p-1.5 rounded-lg text-slate-500 hover:text-slate-900 dark:hover:text-slate-100"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <nav className="flex-1 p-3 space-y-1">
              {NAV_ITEMS.map((item) => {
                const Icon = item.icon;
                const active = activePage === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => {
                      onNavigate(item.id);
                      setMobileMenuOpen(false);
                    }}
                    className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium ${
                      active
                        ? 'bg-sky-50 dark:bg-sky-950/60 text-sky-700 dark:text-sky-300'
                        : 'text-slate-600 dark:text-slate-400'
                    }`}
                  >
                    <Icon className="w-4 h-4 shrink-0" />
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </nav>
            <div className="p-4 border-t border-slate-200 dark:border-slate-800">
              <button
                type="button"
                onClick={onLogout}
                className="w-full flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium rounded-lg border border-slate-200 dark:border-slate-700"
              >
                <LogOut className="w-3.5 h-3.5" />
                Sign Out
              </button>
            </div>
          </aside>
        </div>
      )}

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-16 px-4 lg:px-8 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 flex items-center justify-between gap-4 shrink-0">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              aria-label="Open navigation menu"
              onClick={() => setMobileMenuOpen(true)}
              className="lg:hidden p-2 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300"
            >
              <Menu className="w-4 h-4" />
            </button>
            <div className="flex items-center gap-2 text-sm truncate">
              <span className="text-slate-500 dark:text-slate-400 hidden sm:inline">FL-IDS</span>
              <span className="text-slate-400 dark:text-slate-600 hidden sm:inline">/</span>
              <h1 className="font-semibold text-slate-900 dark:text-slate-100 truncate">
                {currentItem.label}
              </h1>
            </div>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <span className="hidden sm:inline text-xs text-slate-500 dark:text-slate-400">
              Role: <span className="font-medium text-slate-800 dark:text-slate-200 capitalize">{user.role}</span>
            </span>
            <button
              type="button"
              onClick={onToggleTheme}
              aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors whitespace-nowrap"
            >
              {isDark ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
              <span>{isDark ? 'Light Mode' : 'Dark Mode'}</span>
            </button>
          </div>
        </header>

        <main className="flex-1 p-4 lg:p-8 max-w-[1440px] w-full mx-auto space-y-6">
          {children}
        </main>
      </div>
    </div>
  );
}
