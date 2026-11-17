import { useEffect, useState } from 'react';
import { apiRequest, getStoredToken, setStoredToken } from './api/client';
import { Layout } from './components/Layout';
import { LoginView } from './components/LoginView';
import { CryptographySecurityPage } from './pages/CryptographySecurityPage';
import { FederatedLearningPage } from './pages/FederatedLearningPage';
import { IntrusionDetectionPage } from './pages/IntrusionDetectionPage';
import { ModelEvaluationPage } from './pages/ModelEvaluationPage';
import { NetworkMonitoringPage } from './pages/NetworkMonitoringPage';
import { OverviewPage } from './pages/OverviewPage';
import type { AuthUser, NavPage } from './types';

export default function App() {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [activePage, setActivePage] = useState<NavPage>('overview');
  const [isDark, setIsDark] = useState<boolean>(() => {
    const saved = localStorage.getItem('fl_ids_theme');
    return saved ? saved === 'dark' : true;
  });

  useEffect(() => {
    const root = document.documentElement;
    if (isDark) {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
    localStorage.setItem('fl_ids_theme', isDark ? 'dark' : 'light');
  }, [isDark]);

  useEffect(() => {
    const token = getStoredToken();
    if (!token) {
      setAuthChecked(true);
      return;
    }
    apiRequest<{ user: AuthUser }>('/api/auth/me')
      .then((res) => setUser(res.user))
      .catch(() => {
        setStoredToken(null);
        setUser(null);
      })
      .finally(() => setAuthChecked(true));
  }, []);

  function handleLoginSuccess(token: string, loggedInUser: AuthUser) {
    setStoredToken(token);
    setUser(loggedInUser);
    setActivePage('overview');
  }

  function handleLogout() {
    setStoredToken(null);
    setUser(null);
  }

  if (!authChecked) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex items-center justify-center text-sm text-slate-500">
        Verifying session...
      </div>
    );
  }

  if (!user) {
    return (
      <LoginView
        onSuccess={handleLoginSuccess}
        isDark={isDark}
        onToggleTheme={() => setIsDark((d) => !d)}
      />
    );
  }

  return (
    <Layout
      activePage={activePage}
      onNavigate={setActivePage}
      user={user}
      onLogout={handleLogout}
      isDark={isDark}
      onToggleTheme={() => setIsDark((d) => !d)}
    >
      {activePage === 'overview' && <OverviewPage onNavigate={setActivePage} />}
      {activePage === 'detection' && <IntrusionDetectionPage />}
      {activePage === 'federated' && <FederatedLearningPage />}
      {activePage === 'crypto' && <CryptographySecurityPage />}
      {activePage === 'monitoring' && <NetworkMonitoringPage />}
      {activePage === 'evaluation' && <ModelEvaluationPage />}
    </Layout>
  );
}
