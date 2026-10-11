import React, { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Shield,
  Database,
  Cpu,
  Terminal,
  HardDrive,
  Clock,
  Radio,
  Search,
  AlertTriangle,
  FolderOpen,
  BrainCircuit,
  LogOut,
  Zap,
  ExternalLink
} from 'lucide-react';
import { api } from '../services/api';
import { SystemDiagnostics } from '../types';

interface SidebarProps {
  onLogout: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ onLogout }) => {
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
      setTimeStr(now.toLocaleTimeString());
    };
    updateTime();
    const tInterval = setInterval(updateTime, 1000);
    return () => clearInterval(tInterval);
  }, []);

  return (
    <aside className="w-64 lg:w-72 bg-[#0b101b]/95 backdrop-blur-2xl border-r border-white/10 flex flex-col justify-between p-5 h-screen sticky top-0 shrink-0 z-40">
      
      {/* Brand & Logo */}
      <div className="space-y-5">
        <NavLink to="/" className="flex items-center gap-3 pb-4 border-b border-white/10 group">
          <span className="text-3xl filter drop-shadow-[0_0_10px_rgba(16,185,129,0.5)] group-hover:scale-105 transition-transform">♟️</span>
          <div>
            <div className="text-xl font-extrabold tracking-wider font-heading text-white flex items-center gap-1.5">
              <span>SOC</span>
              <span className="text-emerald-400">CHESS</span>
            </div>
            <div className="text-[10px] font-heading font-semibold text-cyan-400 tracking-widest uppercase">
              Autonomous Cyber Defense
            </div>
          </div>
        </NavLink>

        {/* Primary Navigation Links */}
        <nav className="space-y-2.5">
          <div className="text-[11px] font-heading font-bold text-slate-500 tracking-wider px-3 mb-1">
            CORE PLATFORM
          </div>

          {/* 1. DASHBOARD */}
          <NavLink
            to="/"
            end
            className={({ isActive }) =>
              `flex items-center gap-3 px-3.5 py-3 rounded-xl text-sm font-heading font-bold transition-all ${
                isActive
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 shadow-[0_0_16px_rgba(6,182,212,0.25)] translate-x-1'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`
            }
          >
            <LayoutDashboard className="w-4 h-4 text-cyan-400" />
            <div className="flex-1">
              <div>DASHBOARD</div>
              <div className="text-[10px] font-mono font-normal text-slate-400">Main Command Center</div>
            </div>
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          </NavLink>

          {/* 2. DIRECT WIRESHARK LAUNCHER / MONITOR */}
          <NavLink
            to="/monitor"
            className={({ isActive }) =>
              `flex items-center gap-3 px-3.5 py-3 rounded-xl text-sm font-heading font-bold transition-all ${
                isActive
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/50 shadow-[0_0_16px_rgba(6,182,212,0.25)] translate-x-1'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60 border border-transparent'
              }`
            }
            title="Live Packet Monitor & Wireshark Stream"
          >
            <Shield className="w-4 h-4 text-cyan-400" />
            <div className="flex-1">
              <div className="flex items-center justify-between">
                <span>MONITOR</span>
                <Zap className="w-3 h-3 text-cyan-400 fill-current opacity-70" />
              </div>
              <div className="text-[10px] font-mono font-normal text-slate-400">Packet &amp; Wireshark</div>
            </div>
            <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
          </NavLink>

          {/* 3. DIRECT SPLUNK REDIRECT / SIEM */}
          <NavLink
            to="/siem"
            className={({ isActive }) =>
              `flex items-center gap-3 px-3.5 py-3 rounded-xl text-sm font-heading font-bold transition-all ${
                isActive
                  ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/50 shadow-[0_0_16px_rgba(16,185,129,0.25)] translate-x-1'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60 border border-transparent'
              }`
            }
            title="Splunk SIEM Enterprise & Log Intelligence"
          >
            <Database className="w-4 h-4 text-emerald-400" />
            <div className="flex-1">
              <div className="flex items-center justify-between">
                <span>SIEM</span>
                <ExternalLink className="w-3 h-3 text-emerald-400 opacity-70" />
              </div>
              <div className="text-[10px] font-mono font-normal text-slate-400">Splunk Log Analytics</div>
            </div>
            <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
          </NavLink>

          {/* 3.5 AI THREAT ANALYSIS STUDIO */}
          <NavLink
            to="/ai-analysis"
            className={({ isActive }) =>
              `flex items-center gap-3 px-3.5 py-3 rounded-xl text-sm font-heading font-bold transition-all ${
                isActive
                  ? 'bg-indigo-500/20 text-indigo-400 border border-indigo-500/40 shadow-[0_0_16px_rgba(99,102,241,0.25)] translate-x-1'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`
            }
          >
            <BrainCircuit className="w-4 h-4 text-cyan-400" />
            <div className="flex-1">
              <div>AI COPILOT</div>
              <div className="text-[10px] font-mono font-normal text-cyan-400/80">Universal Cyber Assistant</div>
            </div>
            <span className="w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.8)]"></span>
          </NavLink>

          {/* 4. AI ALERTS PAGE */}
          <NavLink
            to="/ai-alerts"
            className={({ isActive }) =>
              `flex items-center gap-3 px-3.5 py-3 rounded-xl text-sm font-heading font-bold transition-all ${
                isActive
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 shadow-[0_0_16px_rgba(6,182,212,0.25)] translate-x-1'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`
            }
          >
            <Cpu className="w-4 h-4 text-purple-400" />
            <div className="flex-1">
              <div>AI ALERTS</div>
              <div className="text-[10px] font-mono font-normal text-slate-400">ML Threat &amp; Kill Chain</div>
            </div>
            <span className="w-2 h-2 rounded-full bg-purple-400"></span>
          </NavLink>

          {/* SOC INTELLIGENCE SECTION */}
          <div className="text-[11px] font-heading font-bold text-slate-500 tracking-wider px-3 mb-1 mt-3">
            SOC INTELLIGENCE
          </div>

          {/* 5. IOC INTELLIGENCE */}
          <NavLink
            to="/ioc-intelligence"
            className={({ isActive }) =>
              `flex items-center gap-3 px-3.5 py-3 rounded-xl text-sm font-heading font-bold transition-all ${
                isActive
                  ? 'bg-violet-500/20 text-violet-300 border border-violet-500/40 shadow-[0_0_16px_rgba(139,92,246,0.25)] translate-x-1'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`
            }
          >
            <Search className="w-4 h-4 text-violet-400" />
            <div className="flex-1">
              <div>IOC INTELLIGENCE</div>
              <div className="text-[10px] font-mono font-normal text-slate-400">Indicator Threat Analysis</div>
            </div>
            <span className="w-2 h-2 rounded-full bg-violet-400"></span>
          </NavLink>

          {/* 6. INCIDENT RESPONSE */}
          <NavLink
            to="/incident-response"
            className={({ isActive }) =>
              `flex items-center gap-3 px-3.5 py-3 rounded-xl text-sm font-heading font-bold transition-all ${
                isActive
                  ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40 shadow-[0_0_16px_rgba(249,115,22,0.25)] translate-x-1'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`
            }
          >
            <AlertTriangle className="w-4 h-4 text-orange-400" />
            <div className="flex-1">
              <div>INCIDENT RESPONSE</div>
              <div className="text-[10px] font-mono font-normal text-slate-400">9-Stage IR Workflow</div>
            </div>
            <span className="w-2 h-2 rounded-full bg-orange-400"></span>
          </NavLink>

          {/* 7. SOC CASES & REPORTS */}
          <NavLink
            to="/soc-cases"
            className={({ isActive }) =>
              `flex items-center gap-3 px-3.5 py-3 rounded-xl text-sm font-heading font-bold transition-all ${
                isActive
                  ? 'bg-teal-500/20 text-teal-300 border border-teal-500/40 shadow-[0_0_16px_rgba(20,184,166,0.25)] translate-x-1'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`
            }
          >
            <FolderOpen className="w-4 h-4 text-teal-400" />
            <div className="flex-1">
              <div>SOC CASES</div>
              <div className="text-[10px] font-mono font-normal text-slate-400">Case Mgmt & Reports</div>
            </div>
            <span className="w-2 h-2 rounded-full bg-teal-400"></span>
          </NavLink>
        </nav>
      </div>

      {/* Real-time Infrastructure Status Widget */}
      <div className="space-y-3 pt-3 border-t border-white/10">
        
        <div className="bg-slate-900/90 p-3 rounded-xl border border-white/5 space-y-2 font-mono text-xs">
          <div className="flex items-center justify-between text-[11px] font-heading font-bold text-slate-400 border-b border-white/5 pb-1">
            <span className="flex items-center gap-1.5">
              <Radio className="w-3.5 h-3.5 text-cyan-400" />
              <span>SYSTEM HEALTH</span>
            </span>
            <span className="text-emerald-400 text-[10px]">ALL SYSTEMS GO</span>
          </div>

          {/* Service Status Rows */}
          <div className="flex items-center justify-between text-[11px]">
            <span className="flex items-center gap-1.5 text-slate-400">
              <HardDrive className="w-3 h-3 text-slate-400" /> MySQL
            </span>
            <span className={`w-2 h-2 rounded-full ${diag?.services.mysql.available ? 'bg-emerald-400 shadow-[0_0_6px_#10b981]' : 'bg-red-500'}`}></span>
          </div>

          <div className="flex items-center justify-between text-[11px]">
            <span className="flex items-center gap-1.5 text-slate-400">
              <Terminal className="w-3 h-3 text-slate-400" /> TShark
            </span>
            <span className={`w-2 h-2 rounded-full ${diag?.services.tshark.available ? 'bg-emerald-400 shadow-[0_0_6px_#10b981]' : 'bg-red-500'}`}></span>
          </div>

          <div className="flex items-center justify-between text-[11px]">
            <span className="flex items-center gap-1.5 text-slate-400">
              <Shield className="w-3 h-3 text-slate-400" /> Wireshark
            </span>
            <span className={`w-2 h-2 rounded-full ${diag?.services.wireshark.available ? 'bg-emerald-400 shadow-[0_0_6px_#10b981]' : 'bg-amber-500'}`}></span>
          </div>

          <div className="flex items-center justify-between text-[11px]">
            <span className="flex items-center gap-1.5 text-slate-400">
              <Database className="w-3 h-3 text-slate-400" /> Splunk
            </span>
            <span className={`w-2 h-2 rounded-full ${diag?.services.splunk.available ? 'bg-emerald-400 shadow-[0_0_6px_#10b981]' : 'bg-red-500'}`}></span>
          </div>

          <div className="flex items-center justify-between text-[11px]">
            <span className="flex items-center gap-1.5 text-slate-400">
              <Cpu className="w-3 h-3 text-slate-400" /> ML Model
            </span>
            <span className={`w-2 h-2 rounded-full ${diag?.services.ml_model.available ? 'bg-emerald-400 shadow-[0_0_6px_#10b981]' : 'bg-amber-500'}`}></span>
          </div>
        </div>

        {/* Bottom Time & Host Info */}
        <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 px-1">
          <span className="flex items-center gap-1">
            <Clock className="w-3 h-3 text-cyan-400" />
            <span>{timeStr}</span>
          </span>
          <span className="text-[10px] text-slate-500">WIN-HOST</span>
        </div>
        <button onClick={onLogout} className="w-full flex items-center justify-center gap-2 rounded-lg border border-white/10 px-3 py-2 text-xs font-heading text-slate-400 hover:border-cyan-500/50 hover:text-cyan-300">
          <LogOut className="w-3.5 h-3.5" /> Sign out
        </button>

      </div>

    </aside>
  );
};
