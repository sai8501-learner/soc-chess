import React, { useState, useCallback } from 'react';
import { Search, Shield, AlertTriangle, CheckCircle, Clock, Activity, BarChart2, ChevronDown, ChevronUp, RefreshCw, Loader2, Globe, Server, Radio, Database } from 'lucide-react';
import { api } from '../services/api';
import { IOCSearchResult, LLMAnalysisResult, IOCRecord } from '../types';

const classColor: Record<string, string> = {
  MALICIOUS: 'text-red-400 bg-red-500/10 border-red-500/40',
  SUSPICIOUS: 'text-amber-400 bg-amber-500/10 border-amber-500/40',
  CLEAN: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/40',
  UNKNOWN: 'text-slate-400 bg-slate-500/10 border-slate-500/40',
};
const sourceColor: Record<string, string> = {
  LIVE: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
  CACHE: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
  LOCAL: 'bg-blue-500/20 text-blue-300 border-blue-500/40',
  UNAVAILABLE: 'bg-slate-500/20 text-slate-400 border-slate-500/40',
};
const severityColor: Record<string, string> = {
  CRITICAL: 'text-red-400',
  HIGH: 'text-orange-400',
  MEDIUM: 'text-amber-400',
  LOW: 'text-emerald-400',
};

const ScoreGauge: React.FC<{ score: number }> = ({ score }) => {
  const pct = Math.min(100, Math.max(0, score));
  const color = pct >= 75 ? '#ef4444' : pct >= 50 ? '#f97316' : pct >= 25 ? '#f59e0b' : '#10b981';
  const r = 42;
  const circ = 2 * Math.PI * r;
  const offset = circ - (pct / 100) * circ;
  return (
    <div className="flex flex-col items-center gap-1">
      <svg width="100" height="100" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r={r} fill="none" stroke="#1e293b" strokeWidth="10" />
        <circle cx="50" cy="50" r={r} fill="none" stroke={color} strokeWidth="10"
          strokeDasharray={circ} strokeDashoffset={offset}
          strokeLinecap="round" style={{ transform: 'rotate(-90deg)', transformOrigin: '50px 50px', transition: 'stroke-dashoffset 0.8s ease' }} />
        <text x="50" y="54" textAnchor="middle" fill={color} fontSize="18" fontWeight="700">{Math.round(pct)}</text>
      </svg>
      <span className="text-[11px] text-slate-400 font-mono">THREAT SCORE</span>
    </div>
  );
};

const Badge: React.FC<{ label: string; cls: string }> = ({ label, cls }) => (
  <span className={`px-2.5 py-1 rounded-md border text-[11px] font-heading font-bold tracking-wider ${cls}`}>{label}</span>
);

const Section: React.FC<{ title: string; icon: React.ReactNode; children: React.ReactNode; defaultOpen?: boolean }> = ({ title, icon, children, defaultOpen = true }) => {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="bg-[#0d1424]/80 border border-white/8 rounded-xl overflow-hidden">
      <button onClick={() => setOpen(!open)} className="w-full flex items-center justify-between px-5 py-3.5 hover:bg-white/2 transition-colors">
        <span className="flex items-center gap-2.5 text-sm font-heading font-bold text-slate-200">{icon}{title}</span>
        {open ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
      </button>
      {open && <div className="px-5 pb-5 pt-1 border-t border-white/5">{children}</div>}
    </div>
  );
};

const AIProviderBadge: React.FC<{ result: LLMAnalysisResult }> = ({ result }) => (
  <div className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-mono border ${result.is_fallback ? 'bg-amber-500/10 border-amber-500/40 text-amber-300' : 'bg-violet-500/10 border-violet-500/40 text-violet-300'}`}>
    <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" />
    AI Provider: {result.provider} · {result.duration_ms}ms
  </div>
);

export const IocIntelligencePage: React.FC = () => {
  const [query, setQuery] = useState('');
  const [iocType, setIocType] = useState('Auto Detect');
  const [searchResult, setSearchResult] = useState<IOCSearchResult | null>(null);
  const [iocList, setIocList] = useState<IOCRecord[]>([]);
  const [aiResult, setAiResult] = useState<LLMAnalysisResult | null>(null);
  const [loadingSearch, setLoadingSearch] = useState(false);
  const [loadingAI, setLoadingAI] = useState(false);
  const [loadingList, setLoadingList] = useState(false);
  const [error, setError] = useState('');
  const [aiError, setAiError] = useState('');
  const [showHistory, setShowHistory] = useState(false);

  const fetchHistory = useCallback(async () => {
    setLoadingList(true);
    try {
      const r = await api.getIOCList(50) as { iocs: IOCRecord[] };
      setIocList(r.iocs || []);
    } catch { /* empty */ }
    finally { setLoadingList(false); }
  }, []);

  const handleSearch = async () => {
    if (!query.trim()) return;
    setLoadingSearch(true);
    setError('');
    setSearchResult(null);
    setAiResult(null);
    try {
      const r = await api.searchIOC(query.trim(), iocType) as IOCSearchResult;
      setSearchResult(r);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'IOC search failed. Check backend.');
    } finally {
      setLoadingSearch(false);
    }
  };

  const handleAIAnalysis = async () => {
    if (!searchResult) return;
    setLoadingAI(true);
    setAiError('');
    try {
      const r = await api.analyzeIOCWithAI({
        ioc: searchResult.ioc,
        ioc_type: searchResult.ioc_type,
        threat_score: searchResult.threat_score,
        reputation: searchResult.reputation,
        source: searchResult.source,
        observation_count: searchResult.observation_count,
        related_alerts: searchResult.related_alerts,
      }) as LLMAnalysisResult;
      setAiResult(r);
    } catch (e: unknown) {
      setAiError(e instanceof Error ? e.message : 'AI analysis failed.');
    } finally {
      setLoadingAI(false);
    }
  };

  const IOC_TYPES = ['Auto Detect', 'IPv4', 'IPv6', 'Domain', 'URL', 'MD5 Hash', 'SHA1 Hash', 'SHA256 Hash', 'Email Address', 'CVE Identifier', 'Port', 'Hostname'];

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-heading font-extrabold text-white flex items-center gap-3">
            <Search className="w-7 h-7 text-violet-400" />
            IOC Intelligence
          </h1>
          <p className="text-slate-400 text-sm mt-1">Indicator of Compromise — Threat Intelligence & AI Investigation Platform</p>
        </div>
        <button onClick={() => { setShowHistory(h => !h); if (!showHistory) fetchHistory(); }}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800/60 border border-white/10 text-slate-300 hover:text-white text-sm font-heading font-bold transition-colors">
          <Clock className="w-4 h-4" /> History
        </button>
      </div>

      {/* Search Panel */}
      <div className="bg-[#0d1424]/80 border border-white/8 rounded-2xl p-6 space-y-4">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="flex-1 relative">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-violet-400" />
            <input
              id="ioc-search-input"
              value={query}
              onChange={e => setQuery(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleSearch()}
              placeholder="Enter IOC: IP, Domain, URL, Hash, CVE, Email, Port..."
              className="w-full bg-slate-900/80 border border-white/10 rounded-xl pl-10 pr-4 py-3 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-violet-500/60 transition-colors font-mono"
            />
          </div>
          <select
            id="ioc-type-select"
            value={iocType}
            onChange={e => setIocType(e.target.value)}
            className="bg-slate-900/80 border border-white/10 rounded-xl px-4 py-3 text-sm text-slate-300 focus:outline-none focus:border-violet-500/60 font-heading font-bold min-w-[160px]"
          >
            {IOC_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        <div className="flex gap-3 flex-wrap">
          <button id="ioc-search-btn" onClick={handleSearch} disabled={loadingSearch || !query.trim()}
            className="btn-cyber-primary text-xs py-2.5 px-5 disabled:opacity-50">
            {loadingSearch ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            {loadingSearch ? 'SEARCHING...' : 'SEARCH IOC'}
          </button>
          {searchResult && (
            <button id="ioc-ai-analyze-btn" onClick={handleAIAnalysis} disabled={loadingAI}
              className="btn-cyber-cyan text-xs py-2.5 px-5 disabled:opacity-50">
              {loadingAI ? <Loader2 className="w-4 h-4 animate-spin" /> : <span>🤖</span>}
              {loadingAI ? 'INVESTIGATING...' : 'ANALYZE WITH NVIDIA AI'}
            </button>
          )}
          {query && (
            <button onClick={() => { setQuery(''); setSearchResult(null); setAiResult(null); setError(''); }}
              className="btn-cyber-ghost text-xs py-2.5 px-4">
              CLEAR
            </button>
          )}
        </div>
        {error && <div className="flex items-center gap-2 text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3"><AlertTriangle className="w-4 h-4 flex-shrink-0" />{error}</div>}
      </div>

      {/* IOC History Panel */}
      {showHistory && (
        <div className="bg-[#0d1424]/80 border border-white/8 rounded-2xl overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/5">
            <span className="text-sm font-heading font-bold text-slate-200 flex items-center gap-2"><Clock className="w-4 h-4 text-violet-400" />Investigation History</span>
            <button onClick={fetchHistory} disabled={loadingList} className="text-slate-400 hover:text-white"><RefreshCw className={`w-4 h-4 ${loadingList ? 'animate-spin' : ''}`} /></button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs font-mono">
              <thead><tr className="border-b border-white/5 text-slate-500">
                <th className="px-4 py-2 text-left">IOC</th><th className="px-4 py-2 text-left">Type</th>
                <th className="px-4 py-2 text-left">Classification</th><th className="px-4 py-2 text-right">Score</th>
                <th className="px-4 py-2 text-right">Observations</th><th className="px-4 py-2 text-left">Last Seen</th>
              </tr></thead>
              <tbody>
                {iocList.length === 0 ? (
                  <tr><td colSpan={6} className="px-4 py-8 text-center text-slate-500">No IOC investigation history available.</td></tr>
                ) : iocList.map(r => (
                  <tr key={r.id} onClick={() => { setQuery(r.ioc); setIocType(r.ioc_type); }}
                    className="border-b border-white/3 hover:bg-white/3 cursor-pointer transition-colors">
                    <td className="px-4 py-2.5 text-violet-300">{r.ioc}</td>
                    <td className="px-4 py-2.5 text-slate-400">{r.ioc_type}</td>
                    <td className="px-4 py-2.5"><Badge label={r.classification} cls={classColor[r.classification] || classColor.UNKNOWN} /></td>
                    <td className="px-4 py-2.5 text-right text-amber-400">{r.threat_score}/100</td>
                    <td className="px-4 py-2.5 text-right text-slate-300">{r.observation_count}</td>
                    <td className="px-4 py-2.5 text-slate-400">{r.last_seen ? String(r.last_seen).substring(0, 16) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Results */}
      {searchResult && (
        <div className="space-y-4">
          {/* IOC Overview Card */}
          <div className="bg-[#0d1424]/80 border border-violet-500/20 rounded-2xl p-6">
            <div className="flex flex-col lg:flex-row gap-6">
              <ScoreGauge score={searchResult.threat_score} />
              <div className="flex-1 space-y-3">
                <div className="flex flex-wrap items-center gap-3">
                  <span className="text-xl font-mono font-bold text-white">{searchResult.ioc}</span>
                  <Badge label={searchResult.ioc_type} cls="text-violet-300 bg-violet-500/10 border-violet-500/40" />
                  <Badge label={searchResult.classification} cls={classColor[searchResult.classification] || classColor.UNKNOWN} />
                  <Badge label={searchResult.source_type} cls={sourceColor[searchResult.source_type] || sourceColor.UNAVAILABLE} />
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4 text-xs font-mono">
                  {[
                    ['Reputation', searchResult.reputation],
                    ['Confidence', `${searchResult.confidence}%`],
                    ['Observations', String(searchResult.observation_count)],
                    ['Related Alerts', String(searchResult.related_alerts_count)],
                    ['First Seen', String(searchResult.first_seen).substring(0, 16)],
                    ['Last Seen', String(searchResult.last_seen).substring(0, 16)],
                    ['Source', searchResult.source],
                    ['Incidents', String(searchResult.related_incidents_count)],
                  ].map(([label, val]) => (
                    <div key={label} className="space-y-0.5">
                      <div className="text-slate-500 uppercase tracking-wider text-[10px]">{label}</div>
                      <div className="text-slate-200">{val || '—'}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Threat Intelligence */}
          <Section title="Threat Intelligence (Multi-Feed Synthesis)" icon={<Shield className="w-4 h-4 text-violet-400" />}>
            <div className="space-y-4 mt-2">
              {/* Live Feeds Grid */}
              {searchResult.threat_intel?.sources && Object.keys(searchResult.threat_intel.sources).length > 0 && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* AbuseIPDB Card */}
                  {searchResult.threat_intel.sources.abuseipdb && (
                    <div className="bg-slate-900/60 border border-red-500/20 rounded-xl p-4 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-heading font-bold text-red-400 flex items-center gap-1.5">
                          <Radio className="w-3.5 h-3.5 text-red-400" /> AbuseIPDB Feed
                        </span>
                        <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-red-500/10 text-red-300 border border-red-500/30">
                          {searchResult.threat_intel.sources.abuseipdb.abuse_confidence_score}% Abuse Score
                        </span>
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-[11px] font-mono pt-1 text-slate-300">
                        <div>Reports: <span className="text-white font-bold">{searchResult.threat_intel.sources.abuseipdb.total_reports}</span></div>
                        <div>Country: <span className="text-white font-bold">{searchResult.threat_intel.sources.abuseipdb.country_code || '—'}</span></div>
                        <div className="col-span-2 truncate">ISP: <span className="text-slate-200">{searchResult.threat_intel.sources.abuseipdb.isp || '—'}</span></div>
                      </div>
                    </div>
                  )}

                  {/* VirusTotal Card */}
                  {searchResult.threat_intel.sources.virustotal && (
                    <div className="bg-slate-900/60 border border-purple-500/20 rounded-xl p-4 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-heading font-bold text-purple-400 flex items-center gap-1.5">
                          <Shield className="w-3.5 h-3.5 text-purple-400" /> VirusTotal Engines
                        </span>
                        <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/30">
                          {searchResult.threat_intel.sources.virustotal.malicious_count} Malicious / {searchResult.threat_intel.sources.virustotal.harmless_count} Clean
                        </span>
                      </div>
                      <div className="grid grid-cols-3 gap-2 text-[11px] font-mono pt-1 text-slate-300">
                        <div>Malicious: <span className="text-red-400 font-bold">{searchResult.threat_intel.sources.virustotal.malicious_count}</span></div>
                        <div>Suspicious: <span className="text-amber-400 font-bold">{searchResult.threat_intel.sources.virustotal.suspicious_count || 0}</span></div>
                        <div>Harmless: <span className="text-emerald-400 font-bold">{searchResult.threat_intel.sources.virustotal.harmless_count}</span></div>
                      </div>
                    </div>
                  )}

                  {/* AlienVault OTX Card */}
                  {searchResult.threat_intel.sources.alienvault_otx && (
                    <div className="bg-slate-900/60 border border-blue-500/20 rounded-xl p-4 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-heading font-bold text-blue-400 flex items-center gap-1.5">
                          <Globe className="w-3.5 h-3.5 text-blue-400" /> AlienVault OTX
                        </span>
                        <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/30">
                          {searchResult.threat_intel.sources.alienvault_otx.pulse_count} Threat Pulses
                        </span>
                      </div>
                      <div className="text-[11px] font-mono space-y-1 pt-1 text-slate-300">
                        <div>ASN: <span className="text-slate-200">{searchResult.threat_intel.sources.alienvault_otx.asn || '—'}</span></div>
                        {searchResult.threat_intel.sources.alienvault_otx.pulses?.length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-1">
                            {searchResult.threat_intel.sources.alienvault_otx.pulses.slice(0, 3).map((p: any, idx: number) => (
                              <span key={idx} className="px-1.5 py-0.5 bg-blue-500/10 border border-blue-500/30 rounded text-[10px] text-blue-300 truncate max-w-[200px]" title={p.name}>
                                {p.name}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Shodan Card */}
                  {searchResult.threat_intel.sources.shodan && (
                    <div className="bg-slate-900/60 border border-cyan-500/20 rounded-xl p-4 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-heading font-bold text-cyan-400 flex items-center gap-1.5">
                          <Server className="w-3.5 h-3.5 text-cyan-400" /> Shodan Recon
                        </span>
                        <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                          {searchResult.threat_intel.sources.shodan.ports?.length || 0} Open Ports
                        </span>
                      </div>
                      <div className="text-[11px] font-mono space-y-1.5 pt-1 text-slate-300">
                        <div className="flex justify-between">
                          <span>Org: <strong className="text-white">{searchResult.threat_intel.sources.shodan.org || '—'}</strong></span>
                          <span>OS: <strong className="text-slate-200">{searchResult.threat_intel.sources.shodan.os || '—'}</strong></span>
                        </div>
                        {searchResult.threat_intel.sources.shodan.ports?.length > 0 && (
                          <div className="flex flex-wrap gap-1 items-center">
                            <span className="text-slate-500 text-[10px]">PORTS:</span>
                            {searchResult.threat_intel.sources.shodan.ports.slice(0, 8).map((port: number) => (
                              <span key={port} className="px-1.5 py-0.2 rounded bg-cyan-500/10 border border-cyan-500/30 text-[10px] text-cyan-300">
                                {port}
                              </span>
                            ))}
                          </div>
                        )}
                        {searchResult.threat_intel.sources.shodan.vulns?.length > 0 && (
                          <div className="flex flex-wrap gap-1 items-center">
                            <span className="text-red-400 text-[10px]">VULNS:</span>
                            {searchResult.threat_intel.sources.shodan.vulns.slice(0, 4).map((v: string) => (
                              <span key={v} className="px-1.5 py-0.2 rounded bg-red-500/10 border border-red-500/30 text-[10px] text-red-300">
                                {v}
                              </span>
                            ))}
                            {searchResult.threat_intel.sources.shodan.vulns.length > 4 && (
                              <span className="text-slate-500 text-[10px]">+{searchResult.threat_intel.sources.shodan.vulns.length - 4} more</span>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* General Metadata / Fallback Details */}
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4 text-xs font-mono pt-2 border-t border-white/5">
                {Object.entries(searchResult.threat_intel || {})
                  .filter(([k, v]) => v != null && typeof v !== 'object')
                  .map(([k, v]) => (
                    <div key={k} className="space-y-0.5">
                      <div className="text-slate-500 uppercase text-[10px]">{k.replace(/_/g, ' ')}</div>
                      <div className="text-slate-200 truncate">{String(v)}</div>
                    </div>
                  ))}
              </div>
            </div>
          </Section>

          {/* Timeline */}
          <Section title="IOC Timeline" icon={<Activity className="w-4 h-4 text-violet-400" />}>
            <div className="space-y-2 mt-2">
              {searchResult.timeline.length === 0 ? <p className="text-slate-500 text-sm">No timeline events available.</p> :
                searchResult.timeline.map((e, i) => (
                  <div key={i} className="flex gap-3 text-xs">
                    <div className="flex flex-col items-center"><div className="w-2 h-2 rounded-full bg-violet-500 mt-1.5 flex-shrink-0" />{i < searchResult.timeline.length - 1 && <div className="w-0.5 flex-1 bg-slate-700 mt-1" />}</div>
                    <div className="pb-3">
                      <div className="text-violet-300 font-mono">{String(e.timestamp).substring(0, 16)}</div>
                      <div className="text-slate-300">{e.event}</div>
                      <div className="text-slate-500">{e.source}</div>
                    </div>
                  </div>
                ))}
            </div>
          </Section>

          {/* Related Alerts */}
          {searchResult.related_alerts.length > 0 && (
            <Section title={`Related Alerts (${searchResult.related_alerts.length})`} icon={<AlertTriangle className="w-4 h-4 text-orange-400" />}>
              <div className="overflow-x-auto mt-2">
                <table className="w-full text-xs font-mono">
                  <thead><tr className="border-b border-white/5 text-slate-500">
                    <th className="px-3 py-2 text-left">ID</th><th className="px-3 py-2 text-left">Attack Type</th>
                    <th className="px-3 py-2 text-left">Source IP</th><th className="px-3 py-2 text-right">Risk</th>
                    <th className="px-3 py-2 text-left">Status</th><th className="px-3 py-2 text-left">Time</th>
                  </tr></thead>
                  <tbody>
                    {searchResult.related_alerts.map((a, i) => (
                      <tr key={i} className="border-b border-white/3 hover:bg-white/2">
                        <td className="px-3 py-2 text-slate-400">#{String(a.id || '')}</td>
                        <td className="px-3 py-2 text-orange-300">{String(a.attack_type || '—')}</td>
                        <td className="px-3 py-2 text-slate-300">{String(a.source_ip || '—')}</td>
                        <td className="px-3 py-2 text-right">
                          <span className={severityColor[String(a.risk_status)] || 'text-slate-400'}>{String(a.risk_score || 0)}/100</span>
                        </td>
                        <td className="px-3 py-2">
                          <Badge label={String(a.status || 'NEW')} cls="text-slate-300 bg-slate-500/10 border-slate-500/40" />
                        </td>
                        <td className="px-3 py-2 text-slate-500">{String(a.timestamp || '').substring(0, 16)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Section>
          )}

          {/* AI Analysis */}
          {loadingAI && (
            <div className="bg-indigo-900/20 border border-indigo-500/30 rounded-2xl p-8 flex items-center gap-4">
              <Loader2 className="w-6 h-6 text-indigo-400 animate-spin flex-shrink-0" />
              <div>
                <div className="text-indigo-300 font-heading font-bold">🤖 NVIDIA AI SOC Analyst is investigating...</div>
                <div className="text-slate-400 text-sm mt-1">Cascading Nemotron → DeepSeek → Kimi → Rule-Based Engine</div>
              </div>
            </div>
          )}
          {aiError && <div className="bg-red-500/10 border border-red-500/30 rounded-xl px-5 py-4 text-red-400 text-sm">⚠ {aiError}</div>}
          {aiResult && (
            <Section title="NVIDIA AI IOC Analysis" icon={<span>🤖</span>} defaultOpen={true}>
              <div className="space-y-3 mt-2">
                <AIProviderBadge result={aiResult} />
                {aiResult.notice && <div className="text-amber-400 text-xs bg-amber-500/10 border border-amber-500/30 rounded-lg px-3 py-2">⚠ {aiResult.notice}</div>}
                <div className="bg-slate-900/50 border border-white/5 rounded-xl p-4 text-sm text-slate-200 font-mono whitespace-pre-wrap leading-relaxed max-h-[500px] overflow-y-auto">
                  {aiResult.content}
                </div>
              </div>
            </Section>
          )}
        </div>
      )}

      {/* Empty State */}
      {!loadingSearch && !searchResult && !error && (
        <div className="flex flex-col items-center justify-center py-20 text-slate-500 space-y-4">
          <Search className="w-14 h-14 opacity-20" />
          <div className="text-center">
            <div className="text-lg font-heading font-bold text-slate-400">No IOC Searched</div>
            <div className="text-sm text-slate-500 mt-1">Enter an IP, domain, URL, hash, CVE, or email above to begin investigation.</div>
          </div>
        </div>
      )}
    </div>
  );
};
