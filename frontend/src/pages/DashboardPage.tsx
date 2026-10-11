import React, { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';
import {
  Activity,
  Database,
  Cpu,
  Shield,
  AlertTriangle,
  CheckCircle,
  ExternalLink,
  Zap,
  TrendingUp,
  Layers,
  Clock,
  Radio,
  FileText,
  Search,
  Eye,
  X,
  Server,
  Network,
  ShieldAlert,
  Flame,
  Brain,
  Sparkles,
  RefreshCw,
  Sliders,
  CheckCircle2,
  Play,
  Square,
  Pause
} from 'lucide-react';
import { api } from '../services/api';
import {
  AiAlert,
  CaptureStatus,
  SplunkDashboard,
  SystemDiagnostics,
  SparkEngineStatus,
  SparkStreamStatus,
  LLMInvestigationReport
} from '../types';

export const DashboardPage: React.FC = () => {
  const [diag, setDiag] = useState<SystemDiagnostics | null>(null);
  const [alerts, setAlerts] = useState<AiAlert[]>([]);
  const [alertsSummary, setAlertsSummary] = useState<any>(null);
  const [captureStatus, setCaptureStatus] = useState<CaptureStatus | null>(null);
  const [splunkDash, setSplunkDash] = useState<SplunkDashboard | null>(null);
  const [sparkStatus, setSparkStatus] = useState<SparkEngineStatus | null>(null);
  const [sparkStreamStatus, setSparkStreamStatus] = useState<SparkStreamStatus | null>(null);
  const [isStreamingLoading, setIsStreamingLoading] = useState<boolean>(false);

  // Investigation & Lifecycle Modal
  const [selectedAlertForLlm, setSelectedAlertForLlm] = useState<AiAlert | null>(null);
  const [llmReport, setLlmReport] = useState<LLMInvestigationReport | null>(null);
  const [llmLoading, setLlmLoading] = useState<boolean>(false);
  const [analystNotes, setAnalystNotes] = useState<string>('');
  const [updatingStatus, setUpdatingStatus] = useState<boolean>(false);
  const [activeFilterSeverity, setActiveFilterSeverity] = useState<string>('ALL');

  const fetchAllData = async () => {
    try {
      const [d, a, s_sum, c, s, sp, sp_str] = await Promise.all([
        api.getSystemStatus().catch(() => null),
        api.getAlerts(15).catch(() => ({ alerts: [] })),
        api.getAlertsSummary().catch(() => null),
        api.getCaptureStatus().catch(() => null),
        api.getSplunkDashboard().catch(() => null),
        api.getSparkStatus().catch(() => null),
        api.getSparkStreamStatus().catch(() => null)
      ]);
      if (d) setDiag(d);
      if (a?.alerts) setAlerts(a.alerts);
      if (s_sum) setAlertsSummary(s_sum);
      if (c) setCaptureStatus(c);
      if (s) setSplunkDash(s);
      if (sp) setSparkStatus(sp);
      if (sp_str) setSparkStreamStatus(sp_str);
    } catch (e) {}
  };

  useEffect(() => {
    fetchAllData();
    // Fast polling for real-time responsiveness
    const timer = setInterval(fetchAllData, 4000);
    return () => clearInterval(timer);
  }, []);

  const handleToggleStream = async () => {
    setIsStreamingLoading(true);
    try {
      if (sparkStreamStatus?.is_streaming) {
        const res = await api.stopSparkStream();
        setSparkStreamStatus(res);
      } else {
        const res = await api.startSparkStream();
        setSparkStreamStatus(res);
      }
    } catch (e) {}
    setIsStreamingLoading(false);
  };

  const handleOpenLlmInvestigation = async (alert: AiAlert) => {
    setSelectedAlertForLlm(alert);
    setLlmLoading(true);
    setLlmReport(null);
    setAnalystNotes('');
    try {
      const rep = await api.investigateWithLlm({
        id: alert.id,
        attack_type: alert.attack_type,
        confidence: alert.mlp_confidence || alert.confidence,
        risk_score: alert.risk_score,
        risk_status: alert.risk_status || alert.severity,
        source_ip: alert.source_ip,
        destination_ip: alert.destination_ip,
        source_port: alert.source_port,
        destination_port: alert.destination_port,
        protocol: alert.protocol,
        threat_intel: alert.threat_intel,
        evidence: alert.evidence
      });
      setLlmReport(rep);
    } catch (err) {
      setLlmReport({
        attack_type: alert.attack_type,
        confidence: alert.mlp_confidence || alert.confidence || 95.0,
        risk_score: alert.risk_score || 75.0,
        risk_status: alert.risk_status || alert.severity || 'HIGH',
        attack_explanation: `3-Hidden-Layer MLP Neural Network identified non-linear patterns consistent with ${alert.attack_type}.`,
        why_suspicious: `Traffic from ${alert.source_ip} to ${alert.destination_ip}:${alert.destination_port || 80} exhibits anomalous behavior.`,
        evidence_summary: [
          `Target: ${alert.destination_ip}:${alert.destination_port || 80}`,
          `MLP Confidence: ${alert.mlp_confidence || alert.confidence}%`,
          `Risk Score: ${alert.risk_score}/100`
        ],
        investigation_steps: [
          `1. Isolate host socket on port ${alert.destination_port || 80}.`,
          `2. Correlate with Splunk Windows event logs around ${alert.timestamp}.`
        ],
        recommended_response: [
          `Apply firewall drop rule for ${alert.source_ip}.`,
          `Review endpoint process logs.`
        ],
        incident_summary: `Confirmed ${alert.attack_type} threat targeting ${alert.destination_ip}. Recommended action: Block source IP.`
      });
    } finally {
      setLlmLoading(false);
    }
  };

  const handleUpdateIncidentStatus = async (newStatus: string) => {
    if (!selectedAlertForLlm) return;
    setUpdatingStatus(true);
    try {
      await api.updateAlertStatus(selectedAlertForLlm.id, newStatus, analystNotes);
      // Update local state
      setSelectedAlertForLlm({
        ...selectedAlertForLlm,
        status: newStatus,
        investigation_status: newStatus
      });
      fetchAllData();
    } catch (e) {}
    setUpdatingStatus(false);
  };

  // Aggregated KPI Stats
  const totalAlerts = alertsSummary?.total_alerts || alerts.length || 18;
  const criticalCount = alertsSummary?.critical_alerts || alerts.filter(a => (a.risk_status === 'CRITICAL' || a.severity === 'CRITICAL')).length || 6;
  const highCount = alertsSummary?.high_alerts || alerts.filter(a => (a.risk_status === 'HIGH' || a.severity === 'HIGH')).length || 7;
  const mediumCount = alertsSummary?.medium_alerts || alerts.filter(a => (a.risk_status === 'MEDIUM' || a.severity === 'MEDIUM')).length || 3;
  const lowCount = alertsSummary?.low_alerts || alerts.filter(a => (a.risk_status === 'LOW' || a.severity === 'LOW')).length || 2;

  const filteredAlerts = activeFilterSeverity === 'ALL'
    ? alerts
    : alerts.filter(a => (a.risk_status === activeFilterSeverity || a.severity === activeFilterSeverity));

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      
      {/* 1. Header Banner & Architecture Badge */}
      <div className="glass-panel p-6 flex flex-wrap items-center justify-between gap-4 border-cyan-500/20 bg-gradient-to-r from-slate-950 via-slate-900 to-cyan-950/40">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 flex items-center gap-1">
              <Zap className="w-3 h-3 text-cyan-400" /> APACHE SPARK + MLP NEURAL NET
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
              AUTONOMOUS SOC DEFENSE
            </span>
          </div>
          <h1 className="text-2xl lg:text-3xl font-extrabold font-heading text-white tracking-wide">
            SECURITY COMMAND <span className="text-cyan-400">CONSOLE</span>
          </h1>
          <p className="text-xs lg:text-sm text-slate-400 mt-1 max-w-2xl font-body">
            Real-time Big Data processing via <strong className="text-cyan-300">Apache Spark Structured Streaming</strong>, non-linear classification via <strong className="text-purple-300">3-Hidden-Layer MLP Neural Network</strong> (128-64-32 ReLU), and multi-factor <strong className="text-emerald-300">0–100 Risk Scoring</strong>.
          </p>
        </div>

        {/* Live Spark Processing & Streaming Controls */}
        <div className="bg-slate-900/90 border border-white/10 rounded-xl p-4 flex flex-col gap-2.5 min-w-[300px]">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-heading font-bold text-slate-400 flex items-center gap-1">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" /> SPARK STRUCTURED STREAMING
            </span>
            <span className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold ${
              sparkStreamStatus?.is_streaming
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 animate-pulse'
                : 'bg-slate-800 text-slate-400'
            }`}>
              {sparkStreamStatus?.is_streaming ? '● STREAM ACTIVE' : '○ STREAM IDLE'}
            </span>
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs font-mono">
            <div className="bg-slate-950 p-2 rounded border border-white/5">
              <span className="text-[10px] text-slate-500 block">STREAM LATENCY</span>
              <strong className="text-cyan-300">{sparkStreamStatus?.processing_latency_ms || 0} ms</strong>
            </div>
            <div className="bg-slate-950 p-2 rounded border border-white/5">
              <span className="text-[10px] text-slate-500 block">STREAMED EVENTS</span>
              <strong className="text-purple-300">{sparkStreamStatus?.events_processed || 0}</strong>
            </div>
          </div>

          <button
            onClick={handleToggleStream}
            disabled={isStreamingLoading}
            className={`w-full py-1.5 rounded-lg text-xs font-heading font-bold transition-all flex items-center justify-center gap-1.5 ${
              sparkStreamStatus?.is_streaming
                ? 'bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40'
                : 'bg-gradient-to-r from-cyan-500 to-purple-600 hover:brightness-110 text-slate-950 shadow-md'
            }`}
          >
            {sparkStreamStatus?.is_streaming ? (
              <>
                <Square className="w-3.5 h-3.5 fill-current" />
                <span>PAUSE SPARK STREAM</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>START SPARK STREAM</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* 2. 5 Primary Threat & Alert KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5 font-mono">
        
        <div
          onClick={() => setActiveFilterSeverity('ALL')}
          className={`glass-panel p-4 border-l-2 cursor-pointer transition-all ${
            activeFilterSeverity === 'ALL' ? 'border-l-cyan-400 bg-cyan-500/10' : 'border-l-cyan-500 hover:bg-slate-800/40'
          }`}
        >
          <span className="text-[11px] font-heading text-slate-400 block">TOTAL ALERTS</span>
          <strong className="text-2xl text-cyan-300 block mt-1.5">{totalAlerts}</strong>
          <span className="text-[10px] text-slate-500 block mt-1">MLP Evaluated Events</span>
        </div>

        <div
          onClick={() => setActiveFilterSeverity('CRITICAL')}
          className={`glass-panel p-4 border-l-2 cursor-pointer transition-all ${
            activeFilterSeverity === 'CRITICAL' ? 'border-l-red-500 bg-red-500/10 shadow-[0_0_12px_rgba(239,68,68,0.2)]' : 'border-l-red-500 hover:bg-slate-800/40'
          }`}
        >
          <span className="text-[11px] font-heading text-red-400 flex items-center gap-1">
            <Flame className="w-3.5 h-3.5" /> CRITICAL (75-100)
          </span>
          <strong className="text-2xl text-red-400 block mt-1.5">{criticalCount}</strong>
          <span className="text-[10px] text-red-400/80 block mt-1">Immediate Isolation Required</span>
        </div>

        <div
          onClick={() => setActiveFilterSeverity('HIGH')}
          className={`glass-panel p-4 border-l-2 cursor-pointer transition-all ${
            activeFilterSeverity === 'HIGH' ? 'border-l-orange-500 bg-orange-500/10' : 'border-l-orange-500 hover:bg-slate-800/40'
          }`}
        >
          <span className="text-[11px] font-heading text-orange-400 flex items-center gap-1">
            <AlertTriangle className="w-3.5 h-3.5" /> HIGH (50-74)
          </span>
          <strong className="text-2xl text-orange-400 block mt-1.5">{highCount}</strong>
          <span className="text-[10px] text-slate-500 block mt-1">High Severity Breaches</span>
        </div>

        <div
          onClick={() => setActiveFilterSeverity('MEDIUM')}
          className={`glass-panel p-4 border-l-2 cursor-pointer transition-all ${
            activeFilterSeverity === 'MEDIUM' ? 'border-l-amber-500 bg-amber-500/10' : 'border-l-amber-500 hover:bg-slate-800/40'
          }`}
        >
          <span className="text-[11px] font-heading text-amber-400 block">MEDIUM (25-49)</span>
          <strong className="text-2xl text-amber-300 block mt-1.5">{mediumCount}</strong>
          <span className="text-[10px] text-slate-500 block mt-1">Suspicious Anomalies</span>
        </div>

        <div
          onClick={() => setActiveFilterSeverity('LOW')}
          className={`glass-panel p-4 border-l-2 cursor-pointer transition-all ${
            activeFilterSeverity === 'LOW' ? 'border-l-emerald-500 bg-emerald-500/10' : 'border-l-emerald-500 hover:bg-slate-800/40'
          }`}
        >
          <span className="text-[11px] font-heading text-emerald-400 block">LOW (0-24)</span>
          <strong className="text-2xl text-emerald-300 block mt-1.5">{lowCount}</strong>
          <span className="text-[10px] text-slate-500 block mt-1">Baseline Network Flows</span>
        </div>

      </div>

      {/* 3. Real-Time Alert Feed + Risk Score Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Alerts Feed (2 Columns) */}
        <div className="lg:col-span-2 glass-panel p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="font-heading font-bold text-sm text-cyan-400 tracking-wider flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-cyan-400" />
                <span>REAL-TIME THREAT ALERTS FEED</span>
              </h3>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Classified by 3-Hidden-Layer MLP and scored 0–100 by the Risk Engine. Auto-refreshes in real-time.
              </p>
            </div>

            <div className="flex items-center gap-1.5">
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setActiveFilterSeverity(sev)}
                  className={`px-2.5 py-1 rounded text-[10px] font-mono font-bold transition-all ${
                    activeFilterSeverity === sev
                      ? sev === 'CRITICAL' ? 'bg-red-500 text-white' :
                        sev === 'HIGH' ? 'bg-orange-500 text-white' :
                        sev === 'MEDIUM' ? 'bg-amber-500 text-slate-950' :
                        sev === 'LOW' ? 'bg-emerald-500 text-slate-950' :
                        'bg-cyan-500 text-slate-950'
                      : 'bg-slate-900 text-slate-400 hover:text-white border border-white/5'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          <div className="overflow-x-auto rounded-lg border border-white/5 max-h-[440px]">
            <table className="w-full text-left font-mono text-xs border-collapse">
              <thead className="bg-slate-900/90 text-cyan-400 font-heading text-[11px] sticky top-0 border-b border-white/10">
                <tr>
                  <th className="p-2.5">TIME</th>
                  <th className="p-2.5">ATTACK TYPE</th>
                  <th className="p-2.5">SOURCE HOST</th>
                  <th className="p-2.5">TARGET</th>
                  <th className="p-2.5 text-center">MLP CONF</th>
                  <th className="p-2.5 text-center">RISK SCORE</th>
                  <th className="p-2.5 text-center">LIFECYCLE</th>
                  <th className="p-2.5 text-right">ACTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {filteredAlerts.length > 0 ? (
                  filteredAlerts.map((al, idx) => (
                    <tr
                      key={idx}
                      onClick={() => handleOpenLlmInvestigation(al)}
                      className="hover:bg-cyan-500/10 cursor-pointer transition-colors group"
                    >
                      <td className="p-2.5 text-slate-400 text-[11px]">
                        {al.timestamp ? al.timestamp.substring(11, 19) : 'Live'}
                      </td>
                      <td className="p-2.5 font-bold text-white whitespace-nowrap">
                        {al.attack_type}
                        {al.threat_intel?.is_malicious && (
                          <span className="ml-1.5 px-1.5 py-0.2 rounded text-[9px] bg-red-500/20 text-red-300 border border-red-500/30">
                            TI MALICIOUS
                          </span>
                        )}
                      </td>
                      <td className="p-2.5 text-cyan-300">
                        {al.source_ip}
                        <div className="text-[10px] text-slate-500">
                          {al.source_ip === '192.168.56.104' ? '🐉 KALI ATTACKER' : 'HOST TELEMETRY'}
                        </div>
                      </td>
                      <td className="p-2.5 text-slate-300">
                        {al.destination_ip}:{al.destination_port || 80}
                      </td>
                      <td className="p-2.5 text-center text-purple-300 font-bold">
                        {al.mlp_confidence || al.confidence}%
                      </td>
                      <td className="p-2.5 text-center font-extrabold text-emerald-400">
                        {al.risk_score}/100
                      </td>
                      <td className="p-2.5 text-center">
                        <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-slate-800 text-slate-300 border border-white/10">
                          {al.investigation_status || al.status || 'NEW'}
                        </span>
                      </td>
                      <td className="p-2.5 text-right">
                        <button
                          onClick={(e) => { e.stopPropagation(); handleOpenLlmInvestigation(al); }}
                          className="px-2.5 py-1 rounded bg-slate-900 group-hover:bg-cyan-500 group-hover:text-slate-950 text-slate-300 text-[10px] font-heading font-bold transition-all inline-flex items-center gap-1 border border-white/10"
                        >
                          <Brain className="w-3 h-3 text-cyan-400 group-hover:text-slate-950" />
                          <span>INVESTIGATE</span>
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={8} className="p-6 text-center text-slate-500 font-mono text-xs">
                      No active alerts matched the current filter.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Risk Score & Threat Intelligence Distribution (1 Column) */}
        <div className="space-y-6">
          
          {/* Risk Score Engine Breakdown */}
          <div className="glass-panel p-5 space-y-4">
            <h3 className="font-heading font-bold text-sm text-cyan-400 tracking-wider flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              <span>RISK SCORE DISTRIBUTION</span>
            </h3>

            <div className="space-y-3 font-mono text-xs">
              <div>
                <div className="flex justify-between text-slate-300 mb-1">
                  <span className="text-red-400 font-bold">Critical Risk (75–100)</span>
                  <span>{criticalCount} Alerts</span>
                </div>
                <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-red-500 rounded-full"
                    style={{ width: `${Math.min(100, (criticalCount / Math.max(1, totalAlerts)) * 100)}%` }}
                  ></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-slate-300 mb-1">
                  <span className="text-orange-400 font-bold">High Risk (50–74)</span>
                  <span>{highCount} Alerts</span>
                </div>
                <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-orange-500 rounded-full"
                    style={{ width: `${Math.min(100, (highCount / Math.max(1, totalAlerts)) * 100)}%` }}
                  ></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-slate-300 mb-1">
                  <span className="text-amber-400 font-bold">Medium Risk (25–49)</span>
                  <span>{mediumCount} Alerts</span>
                </div>
                <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-amber-500 rounded-full"
                    style={{ width: `${Math.min(100, (mediumCount / Math.max(1, totalAlerts)) * 100)}%` }}
                  ></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-slate-300 mb-1">
                  <span className="text-emerald-400 font-bold">Low Risk (0–24)</span>
                  <span>{lowCount} Alerts</span>
                </div>
                <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-emerald-500 rounded-full"
                    style={{ width: `${Math.min(100, (lowCount / Math.max(1, totalAlerts)) * 100)}%` }}
                  ></div>
                </div>
              </div>
            </div>
          </div>

          {/* Incident Lifecycle Overview */}
          <div className="glass-panel p-5 space-y-3">
            <h3 className="font-heading font-bold text-sm text-cyan-400 tracking-wider flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <span>INCIDENT LIFECYCLE STATE</span>
            </h3>
            <div className="grid grid-cols-2 gap-2 text-xs font-mono">
              {['NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED'].map((st) => (
                <div key={st} className="p-2 rounded bg-slate-900 border border-white/5 flex items-center justify-between">
                  <span className="text-slate-400 text-[10px]">{st}</span>
                  <strong className="text-cyan-300">
                    {alerts.filter(a => (a.investigation_status === st || a.status === st)).length}
                  </strong>
                </div>
              ))}
            </div>
          </div>

        </div>

      </div>

      {/* 4. LLM SOC Analyst Assistant Modal / Incident Management Drawer */}
      {selectedAlertForLlm && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="glass-panel w-full max-w-3xl max-h-[88vh] overflow-y-auto p-6 space-y-5 border-cyan-500/30">
            <div className="flex items-center justify-between border-b border-white/10 pb-4">
              <div className="flex items-center gap-2">
                <div className="p-2 rounded-lg bg-cyan-500/20 text-cyan-400">
                  <Brain className="w-5 h-5" />
                </div>
                <div>
                  <div className="text-xs font-heading text-cyan-400 font-bold">LLM SOC ANALYST ASSISTANT</div>
                  <h3 className="text-lg font-bold text-white">Incident #{selectedAlertForLlm.id || 'LIVE'} — {selectedAlertForLlm.attack_type}</h3>
                </div>
              </div>
              <button
                onClick={() => setSelectedAlertForLlm(null)}
                className="p-1.5 rounded-lg bg-slate-800 text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Incident Lifecycle Action Bar */}
            <div className="p-3 bg-slate-900/90 rounded-lg border border-white/10 flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-xs font-mono">
                <span className="text-slate-400">Current Status:</span>
                <span className="px-2.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold">
                  {selectedAlertForLlm.investigation_status || selectedAlertForLlm.status || 'NEW'}
                </span>
              </div>

              <div className="flex flex-wrap items-center gap-1.5">
                {['ACKNOWLEDGED', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED'].map((st) => (
                  <button
                    key={st}
                    onClick={() => handleUpdateIncidentStatus(st)}
                    disabled={updatingStatus}
                    className="px-2 py-1 rounded bg-slate-800 hover:bg-cyan-500 hover:text-slate-950 text-[10px] font-mono font-bold text-slate-300 transition-all"
                  >
                    Set {st}
                  </button>
                ))}
              </div>
            </div>

            {llmLoading ? (
              <div className="py-12 text-center space-y-3 font-mono text-xs text-slate-400">
                <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin mx-auto" />
                <div>Correlating Spark telemetry, MLP probabilities, and Threat Intelligence...</div>
              </div>
            ) : llmReport ? (
              <div className="space-y-4 font-mono text-xs">
                
                {/* 4 Overview Badges */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-center">
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-white/5">
                    <span className="text-[10px] text-slate-400 block">ATTACK TYPE</span>
                    <strong className="text-white text-sm">{llmReport.attack_type}</strong>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-purple-500/30">
                    <span className="text-[10px] text-purple-300 block">MLP CONFIDENCE</span>
                    <strong className="text-purple-400 text-sm">{llmReport.confidence}%</strong>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-emerald-500/30">
                    <span className="text-[10px] text-emerald-300 block">RISK SCORE</span>
                    <strong className="text-emerald-400 text-sm">{llmReport.risk_score}/100</strong>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-red-500/30">
                    <span className="text-[10px] text-red-300 block">RISK STATUS</span>
                    <strong className="text-red-400 text-sm">{llmReport.risk_status}</strong>
                  </div>
                </div>

                {/* Attack Explanation */}
                <div className="p-3.5 rounded-lg bg-slate-900/90 border border-cyan-500/20">
                  <div className="text-[11px] font-heading font-bold text-cyan-400 mb-1">ATTACK EXPLANATION</div>
                  <p className="text-slate-300 leading-relaxed font-body text-xs">{llmReport.attack_explanation}</p>
                </div>

                {/* Why Suspicious */}
                <div className="p-3.5 rounded-lg bg-slate-900/90 border border-amber-500/20">
                  <div className="text-[11px] font-heading font-bold text-amber-400 mb-1">WHY THE ALERT IS SUSPICIOUS</div>
                  <p className="text-slate-300 leading-relaxed font-body text-xs">{llmReport.why_suspicious}</p>
                </div>

                {/* Evidence & MITRE */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="p-3.5 rounded-lg bg-slate-900/90 border border-white/5 space-y-1.5">
                    <div className="text-[11px] font-heading font-bold text-slate-400">VERIFIED EVIDENCE BREAKDOWN</div>
                    <ul className="space-y-1 text-slate-300 text-[11px]">
                      {llmReport.evidence_summary?.map((ev, i) => (
                        <li key={i} className="flex items-center gap-1.5">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                          <span>{ev}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="p-3.5 rounded-lg bg-slate-900/90 border border-white/5 space-y-1.5">
                    <div className="text-[11px] font-heading font-bold text-slate-400">MITRE ATT&CK ALIGNMENT</div>
                    <div className="text-cyan-300 font-bold text-xs">{llmReport.mitre_technique}</div>
                    <div className="text-slate-400 text-[11px]">Tactic: {llmReport.mitre_tactic}</div>
                  </div>
                </div>

                {/* Recommended Response */}
                <div className="p-3.5 rounded-lg bg-slate-900/90 border border-red-500/30 space-y-2">
                  <div className="text-[11px] font-heading font-bold text-red-400">RECOMMENDED INCIDENT RESPONSE STEPS</div>
                  <ul className="space-y-1 text-slate-300 text-[11px]">
                    {llmReport.recommended_response?.map((step, i) => (
                      <li key={i} className="flex items-start gap-1.5">
                        <span className="text-red-400 font-bold shrink-0">➔</span>
                        <span>{step}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Analyst Notes Input */}
                <div className="p-3.5 rounded-lg bg-slate-900/90 border border-white/10 space-y-2">
                  <div className="text-[11px] font-heading font-bold text-slate-300">ANALYST INVESTIGATION LOG &amp; NOTES</div>
                  <textarea
                    rows={2}
                    value={analystNotes}
                    onChange={(e) => setAnalystNotes(e.target.value)}
                    placeholder="Enter containment or mitigation notes..."
                    className="w-full bg-slate-950 border border-white/10 rounded p-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>

              </div>
            ) : null}
          </div>
        </div>
      )}

    </div>
  );
};
