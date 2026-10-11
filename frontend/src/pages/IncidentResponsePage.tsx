import React, { useState, useEffect, useCallback } from 'react';
import { AlertTriangle, Plus, RefreshCw, Loader2, ChevronDown, ChevronUp, CheckCircle, Clock, Shield, Activity, BarChart2, Search, Trash2 } from 'lucide-react';
import { api } from '../services/api';
import { Incident, IncidentsResponse, IncidentTimeline, LLMAnalysisResult, CreateIncidentPayload, IncidentStatus } from '../types';

const WORKFLOW: IncidentStatus[] = ['NEW', 'TRIAGE', 'INVESTIGATION', 'CONTAINMENT', 'ERADICATION', 'RECOVERY', 'MONITORING', 'RESOLVED', 'CLOSED'];

const severityBadge: Record<string, string> = {
  CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/40',
  HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/40',
  MEDIUM: 'bg-amber-500/15 text-amber-400 border-amber-500/40',
  LOW: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40',
};
const statusBadge: Record<string, string> = {
  NEW: 'bg-slate-500/15 text-slate-300 border-slate-500/40',
  TRIAGE: 'bg-blue-500/15 text-blue-300 border-blue-500/40',
  INVESTIGATION: 'bg-violet-500/15 text-violet-300 border-violet-500/40',
  CONTAINMENT: 'bg-orange-500/15 text-orange-300 border-orange-500/40',
  ERADICATION: 'bg-red-500/15 text-red-300 border-red-500/40',
  RECOVERY: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
  MONITORING: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40',
  RESOLVED: 'bg-teal-500/15 text-teal-300 border-teal-500/40',
  CLOSED: 'bg-slate-600/15 text-slate-400 border-slate-600/40',
};

const Badge: React.FC<{ label: string; cls: string }> = ({ label, cls }) => (
  <span className={`px-2 py-0.5 rounded border text-[10px] font-heading font-bold tracking-wider ${cls}`}>{label}</span>
);

const KPICard: React.FC<{ label: string; value: number | string; color: string; icon?: React.ReactNode }> = ({ label, value, color, icon }) => (
  <div className="bg-[#0d1424]/80 border border-white/8 rounded-xl p-4 flex items-center gap-4">
    {icon && <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${color.replace('text-', 'bg-').replace('400', '500/20')}`}>{icon}</div>}
    <div>
      <div className={`text-2xl font-heading font-extrabold ${color}`}>{value}</div>
      <div className="text-slate-500 text-[11px] font-heading font-bold uppercase tracking-wider">{label}</div>
    </div>
  </div>
);

const FormField: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div className="space-y-1">
    <label className="text-[11px] text-slate-400 font-heading font-bold uppercase tracking-wider">{label}</label>
    {children}
  </div>
);

const CreateIncidentModal: React.FC<{ onClose: () => void; onCreated: () => void }> = ({ onClose, onCreated }) => {
  const [form, setForm] = useState<CreateIncidentPayload>({ title: '', description: '', attack_type: 'DDoS', severity: 'HIGH', priority: 'P2', risk_score: 75, mlp_confidence: 95, source_ip: '', destination_ip: '', protocol: 'TCP', assigned_analyst: 'Senior SOC Analyst' });
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState('');

  const handleSave = async () => {
    if (!form.title.trim()) { setErr('Incident title is required.'); return; }
    setSaving(true);
    try {
      await api.createIncident(form);
      onCreated();
      onClose();
    } catch (e: unknown) { setErr(e instanceof Error ? e.message : 'Failed to create incident.'); }
    finally { setSaving(false); }
  };

  const inputCls = "w-full bg-slate-900/80 border border-white/10 rounded-lg px-3 py-2.5 text-sm text-white focus:outline-none focus:border-orange-500/60 font-mono";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-[#0b101b] border border-orange-500/20 rounded-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-6 border-b border-white/8">
          <h2 className="text-lg font-heading font-extrabold text-white flex items-center gap-2"><Plus className="w-5 h-5 text-orange-400" />Create Incident</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white text-xl">✕</button>
        </div>
        <div className="p-6 space-y-4">
          <FormField label="Incident Title *"><input value={form.title} onChange={e => setForm(p => ({ ...p, title: e.target.value }))} className={inputCls} placeholder="e.g. DDoS Attack on Web Server" /></FormField>
          <FormField label="Description"><textarea value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} className={`${inputCls} h-20 resize-none`} placeholder="Incident description and initial observations..." /></FormField>
          <div className="grid grid-cols-2 gap-4">
            <FormField label="Attack Type"><select value={form.attack_type} onChange={e => setForm(p => ({ ...p, attack_type: e.target.value }))} className={inputCls}>
              {['DDoS', 'DoS', 'Brute Force', 'Port Scan', 'Web Attack', 'Botnet', 'Infiltration', 'Exploits', 'Normal', 'Unknown'].map(t => <option key={t}>{t}</option>)}
            </select></FormField>
            <FormField label="Severity"><select value={form.severity} onChange={e => setForm(p => ({ ...p, severity: e.target.value as never }))} className={inputCls}>
              {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map(s => <option key={s}>{s}</option>)}
            </select></FormField>
            <FormField label="Priority"><select value={form.priority} onChange={e => setForm(p => ({ ...p, priority: e.target.value as never }))} className={inputCls}>
              {['P1', 'P2', 'P3', 'P4'].map(s => <option key={s}>{s}</option>)}
            </select></FormField>
            <FormField label="Protocol"><select value={form.protocol} onChange={e => setForm(p => ({ ...p, protocol: e.target.value }))} className={inputCls}>
              {['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP', 'Other'].map(s => <option key={s}>{s}</option>)}
            </select></FormField>
            <FormField label="Source IP"><input value={form.source_ip} onChange={e => setForm(p => ({ ...p, source_ip: e.target.value }))} className={inputCls} placeholder="192.168.56.104" /></FormField>
            <FormField label="Destination IP"><input value={form.destination_ip} onChange={e => setForm(p => ({ ...p, destination_ip: e.target.value }))} className={inputCls} placeholder="192.168.56.107" /></FormField>
            <FormField label="Risk Score (0-100)"><input type="number" min={0} max={100} value={form.risk_score} onChange={e => setForm(p => ({ ...p, risk_score: Number(e.target.value) }))} className={inputCls} /></FormField>
            <FormField label="MLP Confidence (%)"><input type="number" min={0} max={100} value={form.mlp_confidence} onChange={e => setForm(p => ({ ...p, mlp_confidence: Number(e.target.value) }))} className={inputCls} /></FormField>
          </div>
          <FormField label="Assigned Analyst"><input value={form.assigned_analyst} onChange={e => setForm(p => ({ ...p, assigned_analyst: e.target.value }))} className={inputCls} /></FormField>
          {err && <div className="text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3">{err}</div>}
        </div>
        <div className="flex gap-3 p-6 border-t border-white/8">
          <button onClick={handleSave} disabled={saving}
            className="flex-1 py-2.5 rounded-xl bg-orange-600 hover:bg-orange-500 disabled:opacity-50 text-white font-heading font-bold text-sm flex items-center justify-center gap-2">
            {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
            {saving ? 'Creating...' : 'Create Incident'}
          </button>
          <button onClick={onClose} className="px-6 py-2.5 rounded-xl bg-slate-700/50 text-slate-300 font-heading font-bold text-sm">Cancel</button>
        </div>
      </div>
    </div>
  );
};

const IncidentDetail: React.FC<{ incident: Incident; onClose: () => void; onRefresh: () => void }> = ({ incident, onClose, onRefresh }) => {
  const [timeline, setTimeline] = useState<IncidentTimeline[]>([]);
  const [aiResult, setAiResult] = useState<LLMAnalysisResult | null>(null);
  const [newNote, setNewNote] = useState('');
  const [loadingAI, setLoadingAI] = useState(false);
  const [loadingStatus, setLoadingStatus] = useState(false);
  const [aiError, setAiError] = useState('');
  const [selectedStatus, setSelectedStatus] = useState(incident.status);
  const [deleting, setDeleting] = useState(false);

  const handleDelete = async () => {
    if (!window.confirm(`Are you sure you want to permanently delete incident ${incident.incident_id}? This action cannot be undone.`)) {
      return;
    }
    setDeleting(true);
    try {
      await api.deleteIncident(incident.incident_id);
      onClose();
      onRefresh();
    } catch (e: unknown) {
      alert(`Failed to delete incident: ${e instanceof Error ? e.message : String(e)}`);
      setDeleting(false);
    }
  };

  useEffect(() => {
    api.getIncident(incident.incident_id).then((r: unknown) => {
      const res = r as { timeline: IncidentTimeline[] };
      setTimeline(res.timeline || []);
    }).catch(() => {});
  }, [incident.incident_id]);

  const changeStatus = async () => {
    if (selectedStatus === incident.status) return;
    setLoadingStatus(true);
    try {
      await api.updateIncidentStatus(incident.incident_id, selectedStatus, 'Senior SOC Analyst', `Status updated to ${selectedStatus}.`);
      onRefresh();
    } catch { /* empty */ }
    finally { setLoadingStatus(false); }
  };

  const addNote = async () => {
    if (!newNote.trim()) return;
    try {
      await api.addIncidentTimeline(incident.incident_id, 'Analyst Note', 'Senior SOC Analyst', newNote);
      setNewNote('');
      const r = await api.getIncident(incident.incident_id) as { timeline: IncidentTimeline[] };
      setTimeline(r.timeline || []);
    } catch { /* empty */ }
  };

  const investigateWithAI = async () => {
    setLoadingAI(true);
    setAiError('');
    try {
      const r = await api.investigateIncidentWithAI({
        incident_id: incident.incident_id,
        title: incident.title,
        attack_type: incident.attack_type,
        severity: incident.severity,
        status: incident.status,
        risk_score: incident.risk_score,
        risk_status: incident.risk_status,
        mlp_confidence: incident.mlp_confidence,
        source_ip: incident.source_ip,
        destination_ip: incident.destination_ip,
        source_port: incident.source_port,
        destination_port: incident.destination_port,
        protocol: incident.protocol,
        threat_intel: incident.threat_intel || {},
        evidence: incident.evidence || {},
      }) as LLMAnalysisResult;
      setAiResult(r);
    } catch (e: unknown) { setAiError(e instanceof Error ? e.message : 'AI investigation failed.'); }
    finally { setLoadingAI(false); }
  };

  const stageIdx = WORKFLOW.indexOf(incident.status);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-[#0b101b] border border-orange-500/20 rounded-2xl w-full max-w-4xl max-h-[92vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-white/8 sticky top-0 bg-[#0b101b] z-10">
          <div>
            <div className="text-xs font-mono text-orange-400 mb-1">{incident.incident_id}</div>
            <h2 className="text-lg font-heading font-extrabold text-white">{incident.title}</h2>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={handleDelete}
              disabled={deleting}
              className="px-3 py-1.5 rounded-xl bg-red-500/15 text-red-300 border border-red-500/30 hover:bg-red-500/25 transition-colors text-xs font-heading font-bold flex items-center gap-1.5"
              title="Delete Incident"
            >
              {deleting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
              <span>DELETE INCIDENT</span>
            </button>
            <button onClick={onClose} className="text-slate-400 hover:text-white text-xl">✕</button>
          </div>
        </div>
        <div className="p-6 space-y-6">
          {/* Workflow Tracker */}
          <div className="space-y-2">
            <div className="text-[11px] text-slate-500 font-heading font-bold uppercase tracking-wider">Response Workflow</div>
            <div className="flex items-center gap-1 overflow-x-auto pb-2">
              {WORKFLOW.map((stage, i) => (
                <React.Fragment key={stage}>
                  <div className={`flex-shrink-0 px-2.5 py-1.5 rounded-lg text-[10px] font-heading font-bold border transition-all ${i === stageIdx ? 'bg-orange-500/20 text-orange-300 border-orange-500/50' : i < stageIdx ? 'bg-teal-500/15 text-teal-400 border-teal-500/30' : 'bg-slate-800/50 text-slate-500 border-slate-700/50'}`}>{stage}</div>
                  {i < WORKFLOW.length - 1 && <div className={`flex-shrink-0 w-3 h-0.5 ${i < stageIdx ? 'bg-teal-500' : 'bg-slate-700'}`} />}
                </React.Fragment>
              ))}
            </div>
            <div className="flex gap-2">
              <select value={selectedStatus} onChange={e => setSelectedStatus(e.target.value as IncidentStatus)}
                className="bg-slate-900/80 border border-white/10 rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-orange-500/60">
                {WORKFLOW.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
              <button onClick={changeStatus} disabled={loadingStatus || selectedStatus === incident.status}
                className="px-4 py-2 rounded-lg bg-orange-600 hover:bg-orange-500 disabled:opacity-50 text-white text-sm font-heading font-bold flex items-center gap-1.5">
                {loadingStatus ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle className="w-3.5 h-3.5" />}
                Update Status
              </button>
            </div>
          </div>

          {/* Details Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
            {[
              ['Attack Type', incident.attack_type], ['Severity', incident.severity],
              ['Risk Score', `${incident.risk_score}/100`], ['Risk Status', incident.risk_status],
              ['MLP Confidence', `${incident.mlp_confidence}%`], ['Protocol', incident.protocol],
              ['Source IP:Port', `${incident.source_ip}:${incident.source_port}`],
              ['Dest IP:Port', `${incident.destination_ip}:${incident.destination_port}`],
              ['Assigned Analyst', incident.assigned_analyst], ['Priority', incident.priority],
              ['Created', String(incident.created_at).substring(0, 16)], ['Updated', String(incident.updated_at).substring(0, 16)],
            ].map(([label, val]) => (
              <div key={label} className="space-y-0.5 bg-slate-900/40 rounded-lg p-2.5">
                <div className="text-slate-500 text-[10px] uppercase tracking-wider">{label}</div>
                <div className="text-slate-200">{val || '—'}</div>
              </div>
            ))}
          </div>

          {/* AI Investigation */}
          <div className="space-y-3">
            <button id="incident-ai-btn" onClick={investigateWithAI} disabled={loadingAI}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-sm font-heading font-bold">
              {loadingAI ? <Loader2 className="w-4 h-4 animate-spin" /> : <span>🤖</span>}
              {loadingAI ? 'AI SOC Analyst Investigating...' : 'Investigate with NVIDIA AI'}
            </button>
            {loadingAI && <div className="text-sm text-indigo-300 bg-indigo-900/20 border border-indigo-500/30 rounded-xl px-4 py-3">🤖 AI SOC Analyst is investigating — generating incident response plan...</div>}
            {aiError && <div className="text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-xl px-4 py-3">⚠ NVIDIA AI temporarily unavailable — {aiError}</div>}
            {aiResult && (
              <div className="space-y-2">
                <div className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-mono border ${aiResult.is_fallback ? 'bg-amber-500/10 border-amber-500/40 text-amber-300' : 'bg-indigo-500/10 border-indigo-500/40 text-indigo-300'}`}>
                  <span className="w-1.5 h-1.5 rounded-full bg-current" />✓ AI Investigation Completed · AI Provider: {aiResult.provider}
                </div>
                {aiResult.notice && <div className="text-amber-400 text-xs bg-amber-500/10 border border-amber-500/30 rounded-lg px-3 py-2">⚠ {aiResult.notice}</div>}
                <div className="bg-slate-900/50 border border-white/5 rounded-xl p-4 text-sm text-slate-200 font-mono whitespace-pre-wrap leading-relaxed max-h-[400px] overflow-y-auto">
                  {aiResult.content}
                </div>
                <div className="text-amber-400 text-xs bg-amber-500/10 border border-amber-500/30 rounded-lg px-3 py-2">
                  ⚠ AI recommendations are ADVISORY. Destructive actions (block IP, isolate host, disable account) require MANUAL APPROVAL.
                </div>
              </div>
            )}
          </div>

          {/* Analyst Notes & Timeline */}
          <div className="space-y-3">
            <div className="text-[11px] text-slate-500 font-heading font-bold uppercase tracking-wider">Analyst Notes & Timeline</div>
            <div className="flex gap-2">
              <input value={newNote} onChange={e => setNewNote(e.target.value)}
                placeholder="Add analyst observation, finding, or action taken..."
                className="flex-1 bg-slate-900/80 border border-white/10 rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-orange-500/60" />
              <button onClick={addNote} disabled={!newNote.trim()}
                className="px-4 py-2 bg-orange-600 hover:bg-orange-500 disabled:opacity-50 text-white rounded-lg text-sm font-heading font-bold">Add</button>
            </div>
            <div className="space-y-1.5 max-h-[250px] overflow-y-auto">
              {timeline.map((t, i) => (
                <div key={i} className="flex gap-3 text-xs bg-slate-900/40 rounded-lg px-3 py-2.5">
                  <Clock className="w-3.5 h-3.5 text-orange-400 flex-shrink-0 mt-0.5" />
                  <div className="flex-1">
                    <div className="flex items-center gap-2 text-slate-300 font-mono">
                      <span className="text-orange-300">{t.action}</span>
                      {t.old_status !== 'LOG' && <span className="text-slate-500">{t.old_status} → {t.new_status}</span>}
                    </div>
                    <div className="text-slate-400 mt-0.5">{t.notes}</div>
                    <div className="text-slate-600 text-[10px] mt-0.5">{t.analyst} · {String(t.created_at).substring(0, 16)}</div>
                  </div>
                </div>
              ))}
              {timeline.length === 0 && <div className="text-slate-500 text-xs py-4 text-center">No timeline entries yet.</div>}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export const IncidentResponsePage: React.FC = () => {
  const [data, setData] = useState<IncidentsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [selected, setSelected] = useState<Incident | null>(null);
  const [searchQ, setSearchQ] = useState('');

  const handleDeleteIncident = async (incidentId: string) => {
    if (!window.confirm(`Are you sure you want to permanently delete incident ${incidentId}? This action cannot be undone.`)) {
      return;
    }
    try {
      await api.deleteIncident(incidentId);
      if (selected?.incident_id === incidentId) {
        setSelected(null);
      }
      await fetchData();
    } catch (err: unknown) {
      alert(`Failed to delete incident: ${err instanceof Error ? err.message : String(err)}`);
    }
  };
  const [filterSev, setFilterSev] = useState('ALL');
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [error, setError] = useState('');

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.getIncidents({ status: filterStatus === 'ALL' ? undefined : filterStatus, severity: filterSev === 'ALL' ? undefined : filterSev, search: searchQ || undefined }) as IncidentsResponse;
      setData(r);
      setError('');
    } catch (e: unknown) { setError(e instanceof Error ? e.message : 'Failed to load incidents.'); }
    finally { setLoading(false); }
  }, [filterStatus, filterSev, searchQ]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const kpis = data?.kpis;

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-heading font-extrabold text-white flex items-center gap-3"><AlertTriangle className="w-7 h-7 text-orange-400" />Incident Response</h1>
          <p className="text-slate-400 text-sm mt-1">9-Stage SOC Incident Investigation & Containment Workflow</p>
        </div>
        <div className="flex gap-3">
          <button onClick={fetchData} className="btn-cyber-ghost text-xs p-2.5">
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <button id="create-incident-btn" onClick={() => setShowCreate(true)}
            className="btn-cyber-primary text-xs py-2.5 px-5 bg-gradient-to-r from-orange-600 to-amber-600 border-orange-400/40 shadow-[0_0_20px_rgba(249,115,22,0.35)]">
            <Plus className="w-4 h-4" />CREATE INCIDENT
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      {kpis && (
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-5 gap-3">
          <KPICard label="Total" value={kpis.total} color="text-white" icon={<BarChart2 className="w-5 h-5 text-white" />} />
          <KPICard label="Open" value={kpis.open} color="text-blue-400" icon={<Activity className="w-5 h-5 text-blue-400" />} />
          <KPICard label="Critical" value={kpis.critical} color="text-red-400" icon={<AlertTriangle className="w-5 h-5 text-red-400" />} />
          <KPICard label="Investigating" value={kpis.investigating} color="text-violet-400" icon={<Search className="w-5 h-5 text-violet-400" />} />
          <KPICard label="Resolved" value={kpis.resolved} color="text-teal-400" icon={<CheckCircle className="w-5 h-5 text-teal-400" />} />
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-orange-400" />
          <input value={searchQ} onChange={e => setSearchQ(e.target.value)} onKeyDown={e => e.key === 'Enter' && fetchData()}
            placeholder="Search incidents..." className="w-full bg-slate-900/80 border border-white/10 rounded-xl pl-10 pr-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-orange-500/60" />
        </div>
        <select value={filterSev} onChange={e => setFilterSev(e.target.value)}
          className="bg-slate-900/80 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-slate-300 focus:outline-none font-heading font-bold">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(v => <option key={v}>{v}</option>)}
        </select>
        <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)}
          className="bg-slate-900/80 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-slate-300 focus:outline-none font-heading font-bold">
          {['ALL', ...WORKFLOW].map(v => <option key={v}>{v}</option>)}
        </select>
      </div>

      {error && <div className="bg-red-500/10 border border-red-500/30 rounded-xl px-5 py-4 text-red-400 text-sm">⚠ {error}</div>}

      {/* Incident Table */}
      <div className="bg-[#0d1424]/80 border border-white/8 rounded-2xl overflow-hidden">
        <div className="px-5 py-3.5 border-b border-white/5 flex items-center justify-between">
          <span className="text-sm font-heading font-bold text-slate-200">Incident Registry</span>
          <span className="text-xs text-slate-500 font-mono">{data?.incidents.length || 0} records</span>
        </div>
        {loading ? (
          <div className="flex items-center justify-center py-16 gap-3 text-slate-400"><Loader2 className="w-5 h-5 animate-spin" />Loading incidents...</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs font-mono">
              <thead><tr className="border-b border-white/5 text-slate-500">
                <th className="px-4 py-3 text-left">Incident ID</th><th className="px-4 py-3 text-left">Title</th>
                <th className="px-4 py-3 text-left">Attack Type</th><th className="px-4 py-3 text-left">Severity</th>
                <th className="px-4 py-3 text-right">Risk</th><th className="px-4 py-3 text-left">Status</th>
                <th className="px-4 py-3 text-left">Analyst</th><th className="px-4 py-3 text-left">Created</th>
                <th className="px-4 py-3 text-center">Action</th>
              </tr></thead>
              <tbody>
                {!data?.incidents.length ? (
                  <tr><td colSpan={9} className="px-4 py-12 text-center text-slate-500">No incidents found. Create your first incident to get started.</td></tr>
                ) : data.incidents.map(inc => (
                  <tr key={inc.id} className="border-b border-white/3 hover:bg-white/2 transition-colors">
                    <td className="px-4 py-3 text-orange-300">{inc.incident_id}</td>
                    <td className="px-4 py-3 text-slate-200 max-w-[200px] truncate">{inc.title}</td>
                    <td className="px-4 py-3 text-slate-300">{inc.attack_type}</td>
                    <td className="px-4 py-3"><Badge label={inc.severity} cls={severityBadge[inc.severity] || severityBadge.LOW} /></td>
                    <td className="px-4 py-3 text-right text-amber-400">{inc.risk_score}/100</td>
                    <td className="px-4 py-3"><Badge label={inc.status} cls={statusBadge[inc.status] || statusBadge.NEW} /></td>
                    <td className="px-4 py-3 text-slate-400 truncate max-w-[120px]">{inc.assigned_analyst}</td>
                    <td className="px-4 py-3 text-slate-500">{String(inc.created_at).substring(0, 10)}</td>
                    <td className="px-4 py-3 text-center">
                      <div className="flex items-center justify-center gap-1.5">
                        <button onClick={() => setSelected(inc)} className="px-2.5 py-1 rounded-lg bg-orange-500/15 text-orange-300 border border-orange-500/30 hover:bg-orange-500/25 transition-colors text-[10px] font-heading font-bold">VIEW</button>
                        <button
                          onClick={() => handleDeleteIncident(inc.incident_id)}
                          className="px-2.5 py-1 rounded-lg bg-red-500/15 text-red-300 border border-red-500/30 hover:bg-red-500/25 transition-colors text-[10px] font-heading font-bold flex items-center gap-1"
                          title="Delete Incident"
                        >
                          <Trash2 className="w-3 h-3" />
                          <span>DEL</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {showCreate && <CreateIncidentModal onClose={() => setShowCreate(false)} onCreated={fetchData} />}
      {selected && <IncidentDetail incident={selected} onClose={() => setSelected(null)} onRefresh={fetchData} />}
    </div>
  );
};
