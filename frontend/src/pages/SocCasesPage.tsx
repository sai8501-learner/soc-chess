import React, { useState, useEffect, useCallback } from 'react';
import { FolderOpen, Plus, RefreshCw, Loader2, FileText, CheckCircle, Clock, AlertTriangle, BarChart2, Search, MessageSquare, Paperclip, Download, Trash2 } from 'lucide-react';
import { api } from '../services/api';
import { apiClient } from '../services/apiClient';
import { SOCCase, CasesResponse, CaseDetail, CaseNote, CaseEvidence, LLMAnalysisResult } from '../types';

const priorityBadge: Record<string, string> = {
  CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/40',
  HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/40',
  MEDIUM: 'bg-amber-500/15 text-amber-400 border-amber-500/40',
  LOW: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40',
};
const statusBadge: Record<string, string> = {
  OPEN: 'bg-blue-500/15 text-blue-300 border-blue-500/40',
  INVESTIGATING: 'bg-violet-500/15 text-violet-300 border-violet-500/40',
  PENDING: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
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

const CASE_STATUSES = ['OPEN', 'INVESTIGATING', 'PENDING', 'RESOLVED', 'CLOSED'];

const FormField: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div className="space-y-1">
    <label className="text-[11px] text-slate-400 font-heading font-bold uppercase tracking-wider">{label}</label>
    {children}
  </div>
);

const CreateCaseModal: React.FC<{ onClose: () => void; onCreated: () => void }> = ({ onClose, onCreated }) => {
  const [form, setForm] = useState({ title: '', description: '', priority: 'MEDIUM', assigned_analyst: 'Lead Threat Analyst', related_incident_id: '', related_alert_id: '', related_ioc: '' });
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState('');
  const inputCls = "w-full bg-slate-900/80 border border-white/10 rounded-lg px-3 py-2.5 text-sm text-white focus:outline-none focus:border-teal-500/60 font-mono";
  const handleSave = async () => {
    if (!form.title.trim()) { setErr('Case title is required.'); return; }
    setSaving(true);
    try {
      await api.createCase({ ...form, related_alert_id: form.related_alert_id ? parseInt(form.related_alert_id) : undefined });
      onCreated(); onClose();
    } catch (e: unknown) { setErr(e instanceof Error ? e.message : 'Failed to create case.'); }
    finally { setSaving(false); }
  };
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-[#0b101b] border border-teal-500/20 rounded-2xl w-full max-w-xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-6 border-b border-white/8">
          <h2 className="text-lg font-heading font-extrabold text-white flex items-center gap-2"><Plus className="w-5 h-5 text-teal-400" />Create SOC Case</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white text-xl">✕</button>
        </div>
        <div className="p-6 space-y-4">
          <FormField label="Case Title *"><input value={form.title} onChange={e => setForm(p => ({ ...p, title: e.target.value }))} className={inputCls} placeholder="e.g. Coordinated DDoS Attack Investigation" /></FormField>
          <FormField label="Description"><textarea value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} className={`${inputCls} h-20 resize-none`} /></FormField>
          <div className="grid grid-cols-2 gap-4">
            <FormField label="Priority"><select value={form.priority} onChange={e => setForm(p => ({ ...p, priority: e.target.value }))} className={inputCls}>
              {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map(v => <option key={v}>{v}</option>)}
            </select></FormField>
            <FormField label="Assigned Analyst"><input value={form.assigned_analyst} onChange={e => setForm(p => ({ ...p, assigned_analyst: e.target.value }))} className={inputCls} /></FormField>
            <FormField label="Linked Incident ID"><input value={form.related_incident_id} onChange={e => setForm(p => ({ ...p, related_incident_id: e.target.value }))} className={inputCls} placeholder="INC-20240101-0001" /></FormField>
            <FormField label="Linked Alert ID"><input value={form.related_alert_id} onChange={e => setForm(p => ({ ...p, related_alert_id: e.target.value }))} className={inputCls} placeholder="123" /></FormField>
          </div>
          <FormField label="Related IOC"><input value={form.related_ioc} onChange={e => setForm(p => ({ ...p, related_ioc: e.target.value }))} className={inputCls} placeholder="192.168.56.104 / domain.com" /></FormField>
          {err && <div className="text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3">{err}</div>}
        </div>
        <div className="flex gap-3 p-6 border-t border-white/8">
          <button onClick={handleSave} disabled={saving}
            className="flex-1 py-2.5 rounded-xl bg-teal-600 hover:bg-teal-500 disabled:opacity-50 text-white font-heading font-bold text-sm flex items-center justify-center gap-2">
            {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}{saving ? 'Creating...' : 'Create Case'}
          </button>
          <button onClick={onClose} className="px-6 py-2.5 rounded-xl bg-slate-700/50 text-slate-300 font-heading font-bold text-sm">Cancel</button>
        </div>
      </div>
    </div>
  );
};

const CaseDetailPanel: React.FC<{ socCase: SOCCase; onClose: () => void; onRefresh: () => void }> = ({ socCase, onClose, onRefresh }) => {
  const [detail, setDetail] = useState<CaseDetail | null>(null);
  const [aiResult, setAiResult] = useState<LLMAnalysisResult | null>(null);
  const [newNote, setNewNote] = useState('');
  const [noteType, setNoteType] = useState('Investigation Note');
  const [newEvidence, setNewEvidence] = useState({ evidence_type: 'ALERT', reference_id: '', title: '' });
  const [selectedStatus, setSelectedStatus] = useState(socCase.status);
  const [loadingAI, setLoadingAI] = useState(false);
  const [loadingReport, setLoadingReport] = useState(false);
  const [saving, setSaving] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'notes' | 'evidence' | 'ai' | 'reports'>('overview');
  const [savedReportId, setSavedReportId] = useState<string | null>(null);
  const [aiError, setAiError] = useState('');
  const [deleting, setDeleting] = useState(false);

  const handleDelete = async () => {
    if (!window.confirm(`Are you sure you want to permanently delete case ${socCase.case_id}? This action cannot be undone.`)) {
      return;
    }
    setDeleting(true);
    try {
      await api.deleteCase(socCase.case_id);
      onClose();
      onRefresh();
    } catch (e: unknown) {
      alert(`Failed to delete case: ${e instanceof Error ? e.message : String(e)}`);
      setDeleting(false);
    }
  };

  const fetchDetail = useCallback(async () => {
    try {
      const r = await api.getCase(socCase.case_id) as CaseDetail;
      setDetail(r);
    } catch { /* empty */ }
  }, [socCase.case_id]);

  useEffect(() => { fetchDetail(); }, [fetchDetail]);

  const changeStatus = async () => {
    setSaving(true);
    try {
      await api.updateCaseStatus(socCase.case_id, selectedStatus, 'Lead Analyst', `Status changed to ${selectedStatus}.`);
      onRefresh(); fetchDetail();
    } catch { /* empty */ } finally { setSaving(false); }
  };

  const addNote = async () => {
    if (!newNote.trim()) return;
    setSaving(true);
    try {
      await api.addCaseNote(socCase.case_id, newNote, 'Lead Analyst', noteType);
      setNewNote(''); fetchDetail();
    } catch { /* empty */ } finally { setSaving(false); }
  };

  const addEvidence = async () => {
    if (!newEvidence.title.trim()) return;
    setSaving(true);
    try {
      await api.addCaseEvidence(socCase.case_id, { ...newEvidence, details: {} });
      setNewEvidence({ evidence_type: 'ALERT', reference_id: '', title: '' }); fetchDetail();
    } catch { /* empty */ } finally { setSaving(false); }
  };

  const generateAISummary = async () => {
    setLoadingAI(true); setAiError('');
    try {
      const r = await api.summarizeCaseWithAI({
        case_id: socCase.case_id, title: socCase.title, priority: socCase.priority, status: socCase.status,
        assigned_analyst: socCase.assigned_analyst,
        related_incidents: socCase.related_incident_id ? [{ incident_id: socCase.related_incident_id }] : [],
        related_alerts: socCase.related_alert_id ? [{ id: socCase.related_alert_id }] : [],
        notes: detail?.notes || [],
        evidence_summary: { evidence_count: (detail?.evidence || []).length }
      }) as LLMAnalysisResult;
      setAiResult(r); setActiveTab('ai');
    } catch (e: unknown) { setAiError(e instanceof Error ? e.message : 'AI summary failed.'); }
    finally { setLoadingAI(false); }
  };

  const generateReport = async () => {
    setLoadingReport(true);
    try {
      const r = await api.saveReport({
        report_type: 'SOC_CASE_REPORT', title: `SOC Case Report — ${socCase.title}`,
        reference_id: socCase.case_id,
        summary: aiResult?.content?.substring(0, 500) || socCase.title,
        content: { case: socCase, ai_summary: aiResult, notes: detail?.notes || [], evidence: detail?.evidence || [] }
      }) as { report_id: string };
      setSavedReportId(r.report_id);
    } catch { /* empty */ } finally { setLoadingReport(false); }
  };

  const Tab: React.FC<{ id: typeof activeTab; label: string; icon: React.ReactNode }> = ({ id, label, icon }) => (
    <button onClick={() => setActiveTab(id)} className={`flex items-center gap-1.5 px-3 py-2 text-xs font-heading font-bold rounded-lg transition-colors ${activeTab === id ? 'bg-teal-500/20 text-teal-300 border border-teal-500/40' : 'text-slate-400 hover:text-white hover:bg-slate-800/60'}`}>
      {icon}{label}
    </button>
  );

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-[#0b101b] border border-teal-500/20 rounded-2xl w-full max-w-4xl max-h-[92vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-white/8 sticky top-0 bg-[#0b101b] z-10">
          <div>
            <div className="text-xs font-mono text-teal-400 mb-1">{socCase.case_id}</div>
            <h2 className="text-lg font-heading font-extrabold text-white">{socCase.title}</h2>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={handleDelete}
              disabled={deleting}
              className="px-3 py-1.5 rounded-xl bg-red-500/15 text-red-300 border border-red-500/30 hover:bg-red-500/25 transition-colors text-xs font-heading font-bold flex items-center gap-1.5"
              title="Delete Case"
            >
              {deleting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
              <span>DELETE CASE</span>
            </button>
            <button onClick={onClose} className="text-slate-400 hover:text-white text-xl">✕</button>
          </div>
        </div>
        <div className="p-6 space-y-5">
          {/* Tabs */}
          <div className="flex flex-wrap gap-2">
            <Tab id="overview" label="Overview" icon={<FolderOpen className="w-3.5 h-3.5" />} />
            <Tab id="notes" label={`Notes (${detail?.notes.length || 0})`} icon={<MessageSquare className="w-3.5 h-3.5" />} />
            <Tab id="evidence" label={`Evidence (${detail?.evidence.length || 0})`} icon={<Paperclip className="w-3.5 h-3.5" />} />
            <Tab id="ai" label="AI Summary" icon={<span className="text-xs">🤖</span>} />
            <Tab id="reports" label="Reports" icon={<FileText className="w-3.5 h-3.5" />} />
          </div>

          {/* Overview Tab */}
          {activeTab === 'overview' && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs font-mono">
                {[
                  ['Priority', socCase.priority], ['Status', socCase.status],
                  ['Analyst', socCase.assigned_analyst], ['Incident', socCase.related_incident_id || '—'],
                  ['Alert ID', socCase.related_alert_id ? `#${socCase.related_alert_id}` : '—'], ['IOC', socCase.related_ioc || '—'],
                  ['Created', String(socCase.created_at).substring(0, 16)], ['Updated', String(socCase.updated_at).substring(0, 16)],
                ].map(([label, val]) => (
                  <div key={label} className="space-y-0.5 bg-slate-900/40 rounded-lg p-2.5">
                    <div className="text-slate-500 text-[10px] uppercase tracking-wider">{label}</div>
                    <div className="text-slate-200">{val}</div>
                  </div>
                ))}
              </div>
              {socCase.description && <div className="bg-slate-900/40 rounded-lg px-4 py-3 text-sm text-slate-300 font-mono">{socCase.description}</div>}
              <div className="flex gap-2 flex-wrap">
                <select value={selectedStatus} onChange={e => setSelectedStatus(e.target.value as never)}
                  className="bg-slate-900/80 border border-white/10 rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-teal-500/60">
                  {CASE_STATUSES.map(s => <option key={s}>{s}</option>)}
                </select>
                <button onClick={changeStatus} disabled={saving || selectedStatus === socCase.status}
                  className="px-4 py-2 rounded-lg bg-teal-600 hover:bg-teal-500 disabled:opacity-50 text-white text-sm font-heading font-bold flex items-center gap-1.5">
                  {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle className="w-3.5 h-3.5" />}Update Status
                </button>
                <button id="case-ai-summary-btn" onClick={generateAISummary} disabled={loadingAI}
                  className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-sm font-heading font-bold flex items-center gap-1.5">
                  {loadingAI ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <span>🤖</span>}
                  {loadingAI ? 'Generating...' : 'Generate AI Case Summary'}
                </button>
              </div>
              {aiError && <div className="text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-2">⚠ {aiError}</div>}
            </div>
          )}

          {/* Notes Tab */}
          {activeTab === 'notes' && (
            <div className="space-y-4">
              <div className="space-y-2">
                <div className="flex gap-2">
                  <select value={noteType} onChange={e => setNoteType(e.target.value)}
                    className="bg-slate-900/80 border border-white/10 rounded-lg px-3 py-2 text-xs text-slate-300 font-mono focus:outline-none min-w-[160px]">
                    {['Investigation Note', 'Evidence Note', 'Analyst Observation', 'Response Note', 'Resolution Note'].map(t => <option key={t}>{t}</option>)}
                  </select>
                </div>
                <div className="flex gap-2">
                  <textarea value={newNote} onChange={e => setNewNote(e.target.value)} rows={3}
                    placeholder="Add analyst note, finding, or observation..."
                    className="flex-1 bg-slate-900/80 border border-white/10 rounded-lg px-3 py-2.5 text-sm text-white font-mono focus:outline-none focus:border-teal-500/60 resize-none" />
                  <button onClick={addNote} disabled={saving || !newNote.trim()}
                    className="px-4 py-2 bg-teal-600 hover:bg-teal-500 disabled:opacity-50 text-white rounded-lg text-sm font-heading font-bold self-start">Add</button>
                </div>
              </div>
              <div className="space-y-2 max-h-[350px] overflow-y-auto">
                {(detail?.notes || []).length === 0 ? <div className="text-slate-500 text-sm py-6 text-center">No notes yet. Add your first analyst observation.</div> :
                  [...(detail?.notes || [])].reverse().map((n: CaseNote) => (
                    <div key={n.id} className="bg-slate-900/50 border border-white/5 rounded-lg px-4 py-3 text-sm space-y-1">
                      <div className="flex items-center gap-2 text-xs">
                        <Badge label={n.note_type} cls="text-teal-300 bg-teal-500/10 border-teal-500/30" />
                        <span className="text-slate-500">{n.analyst}</span>
                        <span className="text-slate-600">·</span>
                        <span className="text-slate-500 font-mono">{String(n.created_at).substring(0, 16)}</span>
                      </div>
                      <div className="text-slate-200">{n.note}</div>
                    </div>
                  ))}
              </div>
            </div>
          )}

          {/* Evidence Tab */}
          {activeTab === 'evidence' && (
            <div className="space-y-4">
              <div className="flex gap-2 flex-wrap">
                <select value={newEvidence.evidence_type} onChange={e => setNewEvidence(p => ({ ...p, evidence_type: e.target.value }))}
                  className="bg-slate-900/80 border border-white/10 rounded-lg px-3 py-2 text-xs text-slate-300 font-mono focus:outline-none">
                  {['ALERT', 'INCIDENT', 'IOC', 'SPLUNK', 'NETWORK', 'PCAP', 'PCAPNG', 'FILE', 'REPORT'].map(t => <option key={t}>{t}</option>)}
                </select>
                <input value={newEvidence.reference_id} onChange={e => setNewEvidence(p => ({ ...p, reference_id: e.target.value }))}
                  placeholder="Reference ID (e.g. INC-001, #123)" className="bg-slate-900/80 border border-white/10 rounded-lg px-3 py-2 text-xs text-white font-mono focus:outline-none w-40" />
                <input value={newEvidence.title} onChange={e => setNewEvidence(p => ({ ...p, title: e.target.value }))}
                  placeholder="Evidence title / description" className="flex-1 bg-slate-900/80 border border-white/10 rounded-lg px-3 py-2 text-xs text-white font-mono focus:outline-none min-w-[200px]" />
                <button onClick={addEvidence} disabled={saving || !newEvidence.title.trim()}
                  className="px-4 py-2 bg-teal-600 hover:bg-teal-500 disabled:opacity-50 text-white rounded-lg text-xs font-heading font-bold">Attach</button>
              </div>
              <div className="space-y-2 max-h-[350px] overflow-y-auto">
                {(detail?.evidence || []).length === 0 ? <div className="text-slate-500 text-sm py-6 text-center">No evidence attached. Use the form above to link alerts, incidents, IOCs, or log data.</div> :
                  (detail?.evidence || []).map((ev: CaseEvidence) => (
                    <div key={ev.id} className="flex items-center gap-4 bg-slate-900/50 border border-white/5 rounded-lg px-4 py-3">
                      <Badge label={ev.evidence_type} cls="text-violet-300 bg-violet-500/10 border-violet-500/30 flex-shrink-0" />
                      <div className="flex-1 text-sm text-slate-200">{ev.title}</div>
                      {ev.reference_id && <span className="text-xs text-slate-400 font-mono">{ev.reference_id}</span>}
                      <span className="text-xs text-slate-500 font-mono">{String(ev.created_at).substring(0, 10)}</span>
                    </div>
                  ))}
              </div>
            </div>
          )}

          {/* AI Tab */}
          {activeTab === 'ai' && (
            <div className="space-y-3">
              {!aiResult && !loadingAI && (
                <div className="py-8 text-center text-slate-500 space-y-3">
                  <span className="text-4xl">🤖</span>
                  <div className="text-slate-400 font-heading font-bold">No AI Summary Generated</div>
                  <div className="text-sm">Go to Overview tab and click "Generate AI Case Summary" to analyze this case.</div>
                </div>
              )}
              {loadingAI && <div className="py-8 text-center text-indigo-300 space-y-3"><Loader2 className="w-8 h-8 animate-spin mx-auto" /><div>🤖 NVIDIA AI SOC Analyst is investigating...</div></div>}
              {aiResult && (
                <div className="space-y-2">
                  <div className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-mono border ${aiResult.is_fallback ? 'bg-amber-500/10 border-amber-500/40 text-amber-300' : 'bg-teal-500/10 border-teal-500/40 text-teal-300'}`}>
                    <span className="w-1.5 h-1.5 rounded-full bg-current" />✓ AI Investigation Completed · {aiResult.provider} · {aiResult.duration_ms}ms
                  </div>
                  {aiResult.notice && <div className="text-amber-400 text-xs bg-amber-500/10 border border-amber-500/30 rounded-lg px-3 py-2">⚠ {aiResult.notice}</div>}
                  <div className="bg-slate-900/50 border border-white/5 rounded-xl p-4 text-sm text-slate-200 font-mono whitespace-pre-wrap leading-relaxed max-h-[450px] overflow-y-auto">{aiResult.content}</div>
                </div>
              )}
            </div>
          )}

          {/* Reports Tab */}
          {activeTab === 'reports' && (
            <div className="space-y-4">
              <button onClick={generateReport} disabled={loadingReport}
                className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-teal-600 hover:bg-teal-500 disabled:opacity-50 text-white text-sm font-heading font-bold">
                {loadingReport ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileText className="w-4 h-4" />}
                {loadingReport ? 'Generating...' : 'Generate SOC Case Report'}
              </button>
              {savedReportId && (
                <div className="bg-teal-900/20 border border-teal-500/30 rounded-xl p-4 space-y-3">
                  <div className="text-teal-300 font-heading font-bold flex items-center gap-2"><CheckCircle className="w-4 h-4" />Report Generated: {savedReportId}</div>
                  <div className="flex gap-2 flex-wrap">
                    {['json', 'markdown', 'txt'].map(fmt => (
                      <button key={fmt} onClick={() => apiClient.download(`/api/cases/reports/${savedReportId}/export?format=${fmt}`, `${savedReportId}.${fmt}`)}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-teal-500/15 border border-teal-500/30 text-teal-300 rounded-lg text-xs font-heading font-bold hover:bg-teal-500/25 transition-colors">
                        <Download className="w-3.5 h-3.5" />Export {fmt.toUpperCase()}
                      </button>
                    ))}
                  </div>
                </div>
              )}
              {!savedReportId && (
                <div className="py-8 text-center text-slate-500 space-y-2">
                  <FileText className="w-10 h-10 opacity-20 mx-auto" />
                  <div className="text-sm">Click the button above to generate and save a formal SOC Case Report with AI summary and evidence.</div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export const SocCasesPage: React.FC = () => {
  const [data, setData] = useState<CasesResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [selected, setSelected] = useState<SOCCase | null>(null);
  const [searchQ, setSearchQ] = useState('');

  const handleDeleteCase = async (caseId: string) => {
    if (!window.confirm(`Are you sure you want to permanently delete case ${caseId}? This action cannot be undone.`)) {
      return;
    }
    try {
      await api.deleteCase(caseId);
      if (selected?.case_id === caseId) {
        setSelected(null);
      }
      await fetchData();
    } catch (err: unknown) {
      alert(`Failed to delete case: ${err instanceof Error ? err.message : String(err)}`);
    }
  };
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [filterPriority, setFilterPriority] = useState('ALL');
  const [error, setError] = useState('');

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.getCases({ status: filterStatus === 'ALL' ? undefined : filterStatus, priority: filterPriority === 'ALL' ? undefined : filterPriority, search: searchQ || undefined }) as CasesResponse;
      setData(r); setError('');
    } catch (e: unknown) { setError(e instanceof Error ? e.message : 'Failed to load cases.'); }
    finally { setLoading(false); }
  }, [filterStatus, filterPriority, searchQ]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const kpis = data?.kpis;

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-heading font-extrabold text-white flex items-center gap-3"><FolderOpen className="w-7 h-7 text-teal-400" />SOC Case Management</h1>
          <p className="text-slate-400 text-sm mt-1">Investigation Case Lifecycle, Evidence Management & Executive Reports</p>
        </div>
        <div className="flex gap-3">
          <button onClick={fetchData} className="btn-cyber-ghost text-xs p-2.5">
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <button id="create-case-btn" onClick={() => setShowCreate(true)}
            className="btn-cyber-primary text-xs py-2.5 px-5 bg-gradient-to-r from-teal-600 to-cyan-600 border-teal-400/40 shadow-[0_0_20px_rgba(20,184,166,0.35)]">
            <Plus className="w-4 h-4" />CREATE SOC CASE
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      {kpis && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          <KPICard label="Total" value={kpis.total} color="text-white" icon={<BarChart2 className="w-5 h-5 text-white" />} />
          <KPICard label="Open" value={kpis.open} color="text-blue-400" icon={<FolderOpen className="w-5 h-5 text-blue-400" />} />
          <KPICard label="Investigating" value={kpis.investigating} color="text-violet-400" icon={<Search className="w-5 h-5 text-violet-400" />} />
          <KPICard label="Pending" value={kpis.pending} color="text-amber-400" icon={<Clock className="w-5 h-5 text-amber-400" />} />
          <KPICard label="Resolved" value={kpis.resolved} color="text-teal-400" icon={<CheckCircle className="w-5 h-5 text-teal-400" />} />
          <KPICard label="Closed" value={kpis.closed} color="text-slate-400" icon={<AlertTriangle className="w-5 h-5 text-slate-400" />} />
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-teal-400" />
          <input value={searchQ} onChange={e => setSearchQ(e.target.value)} onKeyDown={e => e.key === 'Enter' && fetchData()}
            placeholder="Search cases..." className="w-full bg-slate-900/80 border border-white/10 rounded-xl pl-10 pr-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-teal-500/60" />
        </div>
        <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)}
          className="bg-slate-900/80 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-slate-300 focus:outline-none font-heading font-bold">
          {['ALL', ...CASE_STATUSES].map(v => <option key={v}>{v}</option>)}
        </select>
        <select value={filterPriority} onChange={e => setFilterPriority(e.target.value)}
          className="bg-slate-900/80 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-slate-300 focus:outline-none font-heading font-bold">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(v => <option key={v}>{v}</option>)}
        </select>
      </div>

      {error && <div className="bg-red-500/10 border border-red-500/30 rounded-xl px-5 py-4 text-red-400 text-sm">⚠ {error}</div>}

      {/* Cases Table */}
      <div className="bg-[#0d1424]/80 border border-white/8 rounded-2xl overflow-hidden">
        <div className="px-5 py-3.5 border-b border-white/5 flex items-center justify-between">
          <span className="text-sm font-heading font-bold text-slate-200">Case Registry</span>
          <span className="text-xs text-slate-500 font-mono">{data?.cases.length || 0} cases</span>
        </div>
        {loading ? (
          <div className="flex items-center justify-center py-16 gap-3 text-slate-400"><Loader2 className="w-5 h-5 animate-spin" />Loading cases...</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs font-mono">
              <thead><tr className="border-b border-white/5 text-slate-500">
                <th className="px-4 py-3 text-left">Case ID</th><th className="px-4 py-3 text-left">Title</th>
                <th className="px-4 py-3 text-left">Priority</th><th className="px-4 py-3 text-left">Status</th>
                <th className="px-4 py-3 text-left">Analyst</th><th className="px-4 py-3 text-left">Incident</th>
                <th className="px-4 py-3 text-left">IOC</th><th className="px-4 py-3 text-left">Created</th>
                <th className="px-4 py-3 text-center">Action</th>
              </tr></thead>
              <tbody>
                {!data?.cases.length ? (
                  <tr><td colSpan={9} className="px-4 py-12 text-center text-slate-500">No cases found. Create your first SOC case to begin investigation management.</td></tr>
                ) : data.cases.map(c => (
                  <tr key={c.id} className="border-b border-white/3 hover:bg-white/2 transition-colors">
                    <td className="px-4 py-3 text-teal-300">{c.case_id}</td>
                    <td className="px-4 py-3 text-slate-200 max-w-[180px] truncate">{c.title}</td>
                    <td className="px-4 py-3"><Badge label={c.priority} cls={priorityBadge[c.priority] || priorityBadge.LOW} /></td>
                    <td className="px-4 py-3"><Badge label={c.status} cls={statusBadge[c.status] || statusBadge.OPEN} /></td>
                    <td className="px-4 py-3 text-slate-400 max-w-[100px] truncate">{c.assigned_analyst}</td>
                    <td className="px-4 py-3 text-slate-400">{c.related_incident_id || '—'}</td>
                    <td className="px-4 py-3 text-slate-400 max-w-[100px] truncate">{c.related_ioc || '—'}</td>
                    <td className="px-4 py-3 text-slate-500">{String(c.created_at).substring(0, 10)}</td>
                    <td className="px-4 py-3 text-center">
                      <div className="flex items-center justify-center gap-1.5">
                        <button onClick={() => setSelected(c)} className="px-2.5 py-1 rounded-lg bg-teal-500/15 text-teal-300 border border-teal-500/30 hover:bg-teal-500/25 transition-colors text-[10px] font-heading font-bold">VIEW</button>
                        <button
                          onClick={() => handleDeleteCase(c.case_id)}
                          className="px-2.5 py-1 rounded-lg bg-red-500/15 text-red-300 border border-red-500/30 hover:bg-red-500/25 transition-colors text-[10px] font-heading font-bold flex items-center gap-1"
                          title="Delete Case"
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

      {showCreate && <CreateCaseModal onClose={() => setShowCreate(false)} onCreated={fetchData} />}
      {selected && <CaseDetailPanel socCase={selected} onClose={() => setSelected(null)} onRefresh={fetchData} />}
    </div>
  );
};
