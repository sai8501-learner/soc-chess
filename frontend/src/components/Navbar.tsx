import React, { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';
import { Shield, Activity, Database, Cpu, HardDrive, Terminal } from 'lucide-react';
import { api } from '../services/api';
import { SystemDiagnostics } from '../types';

export const Navbar: React.FC = () => {
  const [diag, setDiag] = useState<SystemDiagnostics | null>(null);
  const [timeStr, setTimeStr] = useState<string>('');

  useEffect(() => {
    const fetchStatus = () => {
      api.getSystemStatus().then(setDiag).catch(() => {});
    };
    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTimeStr(`UTC: ${now.toUTCString().slice(17, 25)} | LOCAL: ${now.toLocaleTimeString()}`);
    };
    updateTime();
    const tInterval = setInterval(updateTime, 1000);
    return () => clearInterval(tInterval);
  }, []);

  return (
    <header className="sticky top-0 z-50 bg-[#0f172a]/90 backdrop-blur-xl border-b border-white/10 px-6 py-3">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        
        {/* Brand & Nav */}
        <div className="flex items-center gap-8">
          <NavLink to="/monitor" className="flex items-center gap-2.5 text-xl font-extrabold tracking-wider font-heading text-white">
            <span className="text-2xl">♟️</span>
            <span>SOC <span className="text-emerald-400">CHESS</span></span>
          </NavLink>

          <nav className="flex items-center gap-2">
            <NavLink
              to="/monitor"
              className={({ isActive }) =>
                `flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-sm font-heading font-semibold transition-all ${
                  isActive
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 shadow-[0_0_12px_rgba(6,182,212,0.3)]'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                }`
              }
            >
              <Activity className="w-4 h-4" />
              <span>MONITOR</span>
            </NavLink>

            <NavLink
              to="/siem"
              className={({ isActive }) =>
                `flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-sm font-heading font-semibold transition-all ${
                  isActive
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 shadow-[0_0_12px_rgba(6,182,212,0.3)]'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                }`
              }
            >
              <Database className="w-4 h-4" />
              <span>SIEM</span>
            </NavLink>

            <NavLink
              to="/ai-alerts"
              className={({ isActive }) =>
                `flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-sm font-heading font-semibold transition-all ${
                  isActive
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 shadow-[0_0_12px_rgba(6,182,212,0.3)]'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                }`
              }
            >
              <Cpu className="w-4 h-4" />
              <span>AI ALERTS</span>
            </NavLink>
          </nav>
        </div>

        {/* Real-time System Diagnostics Bar */}
        <div className="flex items-center gap-3 text-xs font-mono">
          <div className="hidden lg:flex items-center gap-2 bg-slate-900/80 px-3 py-1.5 rounded-md border border-white/5">
            <span className="text-slate-400">{timeStr}</span>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {/* MySQL Status */}
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-white/5" title={diag?.services.mysql.host}>
              <HardDrive className="w-3.5 h-3.5 text-slate-400" />
              <span className="text-slate-400">MySQL</span>
              <span className={`w-2 h-2 rounded-full ${diag?.services.mysql.available ? 'bg-emerald-500 shadow-[0_0_6px_#10b981]' : 'bg-red-500'}`}></span>
            </div>

            {/* TShark Status */}
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-white/5" title={diag?.services.tshark.path}>
              <Terminal className="w-3.5 h-3.5 text-slate-400" />
              <span className="text-slate-400">TShark</span>
              <span className={`w-2 h-2 rounded-full ${diag?.services.tshark.available ? 'bg-emerald-500 shadow-[0_0_6px_#10b981]' : 'bg-red-500'}`}></span>
            </div>

            {/* Wireshark GUI Status */}
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-white/5" title={diag?.services.wireshark.path}>
              <Shield className="w-3.5 h-3.5 text-slate-400" />
              <span className="text-slate-400">Wireshark</span>
              <span className={`w-2 h-2 rounded-full ${diag?.services.wireshark.available ? 'bg-emerald-500 shadow-[0_0_6px_#10b981]' : 'bg-amber-500'}`}></span>
            </div>

            {/* Splunk Status */}
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-white/5" title={diag?.services.splunk.host}>
              <span className="text-slate-400">Splunk</span>
              <span className={`w-2 h-2 rounded-full ${diag?.services.splunk.available ? 'bg-emerald-500 shadow-[0_0_6px_#10b981]' : 'bg-red-500'}`}></span>
            </div>

            {/* ML Model Status */}
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-white/5" title={diag?.services.ml_model.path}>
              <span className="text-slate-400">ML</span>
              <span className={`w-2 h-2 rounded-full ${diag?.services.ml_model.available ? 'bg-emerald-500 shadow-[0_0_6px_#10b981]' : 'bg-amber-500'}`}></span>
            </div>
          </div>
        </div>

      </div>
    </header>
  );
};
