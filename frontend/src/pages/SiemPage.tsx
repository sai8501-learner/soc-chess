import React, { useEffect, useState } from 'react';
import { Search, ExternalLink, RefreshCw, AlertTriangle, ShieldAlert, CheckCircle2, Database, Brain, Sparkles, Sliders } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { api } from '../services/api';
import { SplunkStatus, SplunkDashboard, SplunkEvent, LLMInvestigationReport } from '../types';

export const SiemPage: React.FC = () => {
  const [splunkStatus, setSplunkStatus] = useState<SplunkStatus | null>(null);
  const [dashboard, setDashboard] = useState<SplunkDashboard | null>(null);
  const [queryInput, setQueryInput] = useState<string>('search index=* | head 100');
  const [events, setEvents] = useState<SplunkEvent[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<SplunkEvent | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [offlineLoading, setOfflineLoading] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fetchSplunkData = async () => {
    try {
      setErrorMsg(null);
      const s = await api.getSplunkStatus();
      setSplunkStatus(s);

      const d = await api.getSplunkDashboard();
      setDashboard(d);
      if (d.recent_events) setEvents(d.recent_events);
    } catch (e: any) {
      setErrorMsg(e.message || 'Error querying Splunk');
    }
  };

  useEffect(() => {
    fetchSplunkData();
    const interval = setInterval(fetchSplunkData, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleSearch = async (splQuery: string) => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await api.searchSplunk(splQuery);
      setEvents(res.events || []);
    } catch (e: any) {
      setErrorMsg(e.message || 'Splunk search failed');
    } finally {
      setLoading(false);
    }
  };

  const handleRunOfflineDatasetTest = async () => {
    setOfflineLoading(true);
    setErrorMsg(null);
    try {
      const res = await api.testOfflineSplunkLogs();
      if (res.events) {
        const mapped: SplunkEvent[] = res.events.map((e: any) => ({
          timestamp: 'Dataset Event',
          host: e.raw?.ComputerName || 'WIN-VICTIM10',
          source: 'Dataset: Windows Security Log',
          sourcetype: 'WinEventLog:Security',
          event_code: e.event_code,
          source_ip: e.source_ip,
          destination_ip: '192.168.56.107',
          attack_type: e.prediction,
          confidence: e.mlp_confidence,
          mlp_confidence: e.mlp_confidence,
          risk_score: e.risk_score,
          risk_status: e.risk_status,
          severity: e.risk_status,
          threat_intel: e.threat_intel,
          raw_event: JSON.stringify(e.raw)
        }));
        setEvents(mapped);
      }
    } catch (e: any) {
      setErrorMsg(e.message || 'Offline dataset evaluation failed');
    } finally {
      setOfflineLoading(false);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      
      {/* Top Splunk Status Banner */}
      <div className="glass-panel p-5 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <span className={`w-3 h-3 rounded-full ${splunkStatus?.connected ? 'bg-emerald-400 animate-pulse shadow-[0_0_10px_#10b981]' : 'bg-amber-400'}`}></span>
            <span className="font-heading font-bold text-sm tracking-wider">
              SPLUNK SIEM: <strong className={splunkStatus?.connected ? 'text-emerald-400' : 'text-amber-400'}>
                {splunkStatus?.connected ? 'CONNECTED (PORT 8089)' : 'OFFLINE MODE (DATASET READY)'}
              </strong>
            </span>
          </div>

          <span className="text-xs font-mono text-slate-400">
            Host: <span className="text-cyan-400">{splunkStatus?.host || '127.0.0.1'}:{splunkStatus?.port || '8089'}</span>
          </span>

          {splunkStatus?.version && (
            <span className="text-xs font-mono text-slate-400">
              Version: <span className="text-purple-400">{splunkStatus.version}</span>
            </span>
          )}
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleRunOfflineDatasetTest}
            disabled={offlineLoading}
            className="btn-cyber-primary text-xs py-2 px-3.5"
          >
            <Database className="w-3.5 h-3.5" />
            <span>{offlineLoading ? 'EVALUATING...' : 'TEST OFFLINE DATASET LOGS'}</span>
          </button>

          <button
            onClick={fetchSplunkData}
            className="btn-cyber-ghost text-xs py-2 px-3"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>REFRESH</span>
          </button>

          <a
            href={splunkStatus?.web_url || 'http://localhost:8000'}
            target="_blank"
            rel="noreferrer"
            className="btn-cyber-cyan text-xs py-2 px-3.5"
          >
            <ExternalLink className="w-3.5 h-3.5" />
            <span>OPEN SPLUNK</span>
          </a>
        </div>
      </div>

      {errorMsg && (
        <div className="bg-amber-500/10 border border-amber-500/30 text-amber-300 px-4 py-2.5 rounded-lg font-mono text-xs">
          ℹ️ {errorMsg}
        </div>
      )}

      {/* 5 KPI Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
        <div className="glass-panel p-4 flex flex-col justify-between">
          <span className="text-xs font-heading text-slate-400">TOTAL LOG EVENTS</span>
          <strong className="text-2xl font-mono text-white mt-2">{dashboard?.total_events ?? events.length}</strong>
        </div>
        <div className="glass-panel p-4 flex flex-col justify-between border-l-2 border-l-red-500">
          <span className="text-xs font-heading text-red-400 flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> CRITICAL (75-100)</span>
          <strong className="text-2xl font-mono text-red-400 mt-2">{dashboard?.critical_events ?? events.filter(e => e.risk_status === 'CRITICAL' || e.severity === 'CRITICAL').length}</strong>
        </div>
        <div className="glass-panel p-4 flex flex-col justify-between border-l-2 border-l-amber-500">
          <span className="text-xs font-heading text-amber-400 flex items-center gap-1"><ShieldAlert className="w-3 h-3" /> HIGH (50-74)</span>
          <strong className="text-2xl font-mono text-amber-400 mt-2">{dashboard?.high_events ?? events.filter(e => e.risk_status === 'HIGH' || e.severity === 'HIGH').length}</strong>
        </div>
        <div className="glass-panel p-4 flex flex-col justify-between border-l-2 border-l-yellow-500">
          <span className="text-xs font-heading text-yellow-400">MEDIUM (25-49)</span>
          <strong className="text-2xl font-mono text-yellow-400 mt-2">{dashboard?.medium_events ?? events.filter(e => e.risk_status === 'MEDIUM' || e.severity === 'MEDIUM').length}</strong>
        </div>
        <div className="glass-panel p-4 flex flex-col justify-between border-l-2 border-l-emerald-500">
          <span className="text-xs font-heading text-emerald-400 flex items-center gap-1"><CheckCircle2 className="w-3 h-3" /> LOW (0-24)</span>
          <strong className="text-2xl font-mono text-emerald-400 mt-2">{dashboard?.low_events ?? events.filter(e => e.risk_status === 'LOW' || e.severity === 'LOW').length}</strong>
        </div>
      </div>

      {/* SPL Search Bar & Quick Queries */}
      <div className="glass-panel p-5 space-y-3">
        <div className="flex gap-2.5">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-cyan-400 absolute left-3.5 top-3" />
            <input
              type="text"
              value={queryInput}
              onChange={(e) => setQueryInput(e.target.value)}
              placeholder="search index=main OR index=* | head 100"
              className="w-full bg-slate-950/80 border border-white/10 rounded-lg pl-10 pr-4 py-2.5 text-xs font-mono text-cyan-300 outline-none focus:border-cyan-500"
            />
          </div>
          <button
            onClick={() => handleSearch(queryInput)}
            disabled={loading}
            className="btn-cyber-cyan text-xs py-2 px-5"
          >
            {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
            <span>RUN SPL SEARCH</span>
          </button>
        </div>

        {/* Quick Query Buttons */}
        <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
          <span className="text-slate-500 font-heading text-[11px]">PRESETS:</span>
          {[
            { label: 'All Events', spl: 'search index=* | head 100' },
            { label: 'EventCode=4625 (Brute Force)', spl: 'search EventCode=4625' },
            { label: 'EventCode=5156 (Firewall)', spl: 'search EventCode=5156' },
            { label: 'EventCode=4720 (User Created)', spl: 'search EventCode=4720' },
            { label: 'EventCode=1102 (Log Cleared)', spl: 'search EventCode=1102' },
          ].map(p => (
            <button
              key={p.label}
              onClick={() => {
                setQueryInput(p.spl);
                handleSearch(p.spl);
              }}
              className="px-2.5 py-1 bg-slate-900 hover:bg-slate-800 border border-white/5 rounded text-slate-400 hover:text-cyan-400 transition-colors"
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {/* Events Table & Top Hosts Chart */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        
        {/* Top Hosts Chart */}
        <div className="glass-panel p-5 flex flex-col justify-between">
          <div>
            <h3 className="font-heading font-bold text-sm text-cyan-400 tracking-wider mb-2">
              TOP EVENT HOSTS
            </h3>
            <p className="text-[11px] text-slate-400 mb-4">Event frequency by Windows ComputerName</p>
          </div>

          <div className="h-56 w-full">
            {dashboard?.top_hosts && dashboard.top_hosts.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={dashboard.top_hosts} layout="vertical" margin={{ top: 5, right: 20, left: 10, bottom: 5 }}>
                  <XAxis type="number" stroke="#64748b" fontSize={10} />
                  <YAxis type="category" dataKey="name" stroke="#64748b" fontSize={10} width={80} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px', fontSize: '11px', fontFamily: 'monospace' }}
                  />
                  <Bar dataKey="count" fill="#38bdf8" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-slate-500 font-mono text-xs text-center p-4">
                No active host distribution telemetry available.
              </div>
            )}
          </div>
        </div>

        {/* Real Splunk & Dataset Events Table */}
        <div className="lg:col-span-3 glass-panel p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-heading font-bold text-sm text-cyan-400 tracking-wider flex items-center gap-2">
              <Brain className="w-4 h-4 text-cyan-400" />
              <span>SPARK + MLP SCORED SIEM LOG EVENTS</span>
            </h3>
            <span className="text-xs font-mono text-slate-400">Showing {events.length} records</span>
          </div>

          <div className="overflow-x-auto rounded-lg border border-white/5 max-h-[460px]">
            <table className="w-full text-left font-mono text-xs border-collapse">
              <thead className="bg-slate-900/90 text-cyan-400 font-heading text-[11px] sticky top-0 border-b border-white/10">
                <tr>
                  <th className="p-2.5">TIMESTAMP</th>
                  <th className="p-2.5">HOST / CODE</th>
                  <th className="p-2.5">SOURCE IP</th>
                  <th className="p-2.5">ATTACK CLASS</th>
                  <th className="p-2.5 text-center">MLP CONF</th>
                  <th className="p-2.5 text-center">RISK SCORE</th>
                  <th className="p-2.5 text-right">RAW LOG</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {events.length > 0 ? (
                  events.map((ev, idx) => (
                    <tr
                      key={idx}
                      onClick={() => setSelectedEvent(ev)}
                      className="hover:bg-cyan-500/10 cursor-pointer transition-colors"
                    >
                      <td className="p-2.5 text-slate-400 text-[11px] whitespace-nowrap">
                        {ev.timestamp ? ev.timestamp.substring(0, 19) : 'Live'}
                      </td>
                      <td className="p-2.5 text-white font-bold whitespace-nowrap">
                        {ev.host}
                        <span className="ml-1 text-[10px] text-cyan-400 font-mono">
                          (Code {ev.event_code})
                        </span>
                      </td>
                      <td className="p-2.5 text-cyan-300">
                        {ev.source_ip}
                      </td>
                      <td className="p-2.5 font-bold text-white whitespace-nowrap">
                        {ev.attack_type || 'Normal'}
                      </td>
                      <td className="p-2.5 text-center text-purple-300 font-bold">
                        {ev.mlp_confidence || ev.confidence || 95}%
                      </td>
                      <td className="p-2.5 text-center font-extrabold text-emerald-400">
                        {ev.risk_score || 15}/100
                      </td>
                      <td className="p-2.5 text-right text-slate-500 text-[10px] max-w-[200px] truncate">
                        {ev.raw_event}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={7} className="p-8 text-center text-slate-500 font-mono text-xs">
                      No security log events found. Click "TEST OFFLINE DATASET LOGS" to evaluate sample Windows event logs.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>

      {/* Raw Event Detail Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="glass-panel w-full max-w-2xl p-6 space-y-4 font-mono text-xs border-cyan-500/30">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <h3 className="text-sm font-bold font-heading text-white">Log Event Detail — {selectedEvent.host} (Code {selectedEvent.event_code})</h3>
              <button onClick={() => setSelectedEvent(null)} className="text-slate-400 hover:text-white">✕</button>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center">
              <div className="p-2 bg-slate-900 rounded border border-white/5">
                <span className="text-[10px] text-slate-400 block">ATTACK</span>
                <strong className="text-white">{selectedEvent.attack_type || 'Normal'}</strong>
              </div>
              <div className="p-2 bg-slate-900 rounded border border-purple-500/30">
                <span className="text-[10px] text-purple-300 block">MLP CONF</span>
                <strong className="text-purple-400">{selectedEvent.mlp_confidence || 95}%</strong>
              </div>
              <div className="p-2 bg-slate-900 rounded border border-emerald-500/30">
                <span className="text-[10px] text-emerald-300 block">RISK SCORE</span>
                <strong className="text-emerald-400">{selectedEvent.risk_score || 15}/100</strong>
              </div>
              <div className="p-2 bg-slate-900 rounded border border-cyan-500/30">
                <span className="text-[10px] text-cyan-300 block">EVENT CODE</span>
                <strong className="text-cyan-400">{selectedEvent.event_code}</strong>
              </div>
            </div>

            <div className="p-3 bg-slate-950 rounded border border-white/10 overflow-x-auto max-h-60">
              <pre className="text-slate-300 whitespace-pre-wrap text-[11px]">{selectedEvent.raw_event}</pre>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
