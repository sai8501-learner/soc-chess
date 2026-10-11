import React, { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Sidebar } from './components/Sidebar';
import { DashboardPage } from './pages/DashboardPage';
import { AiAlertsPage } from './pages/AiAlertsPage';
import { AiAnalysisPage } from './pages/AiAnalysisPage';
import { IocIntelligencePage } from './pages/IocIntelligencePage';
import { IncidentResponsePage } from './pages/IncidentResponsePage';
import { SocCasesPage } from './pages/SocCasesPage';
import { MonitorPage } from './pages/MonitorPage';
import { SiemPage } from './pages/SiemPage';
import { AuthPage } from './components/AuthPage';
import { authApi } from './services/auth';

type AppState = 'loading' | 'authenticated' | 'login' | 'register' | 'setup' | 'configuration';

export const App: React.FC = () => {
  const [appState, setAppState] = useState<AppState>('loading');

  const refreshAuthentication = async () => {
    try {
      const status = await authApi.getStatus();
      if (!status.enabled) {
        setAppState('authenticated');
        return;
      }
      if (!status.configured) {
        setAppState('configuration');
        return;
      }
      try {
        await authApi.getCurrentUser();
        setAppState('authenticated');
      } catch {
        setAppState(status.bootstrap_required ? 'setup' : 'login');
      }
    } catch {
      setAppState('login');
    }
  };

  useEffect(() => {
    void refreshAuthentication();
  }, []);

  if (appState === 'loading') {
    return <main className="min-h-screen bg-[#0a0e17]" />;
  }

  if (appState !== 'authenticated') {
    return <AuthPage mode={appState} onAuthenticated={() => setAppState('authenticated')} onRetry={refreshAuthentication} onModeChange={setAppState} />;
  }

  const signOut = () => {
    authApi.signOut();
    void refreshAuthentication();
  };

  return (
    <BrowserRouter>
      <div className="min-h-screen bg-[#0a0e17] text-slate-100 flex flex-row font-body antialiased selection:bg-cyan-500 selection:text-black">
        {/* Left Vertical Sidebar */}
        <Sidebar onLogout={signOut} />

        {/* Main Content Area */}
        <main className="flex-1 h-screen overflow-y-auto p-6 lg:p-8 bg-radial-gradient">
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/monitor" element={<MonitorPage />} />
            <Route path="/siem" element={<SiemPage />} />
            <Route path="/ai-analysis" element={<AiAnalysisPage />} />
            <Route path="/ai-alerts" element={<AiAlertsPage />} />
            <Route path="/ioc-intelligence" element={<IocIntelligencePage />} />
            <Route path="/incident-response" element={<IncidentResponsePage />} />
            <Route path="/soc-cases" element={<SocCasesPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
};
