import { apiClient } from './apiClient';
import {
  SystemDiagnostics,
  NetworkInterface,
  CaptureStatus,
  PacketEvent,
  SplunkStatus,
  SplunkDashboard,
  SparkEngineStatus,
  SparkStreamStatus,
  SparkJobItem,
  ThreatIntelResult,
  LLMInvestigationReport,
  DatasetInventoryResponse,
  DatasetInventoryItem,
  TrainingStatus,
  ModelVersion,
  AiAlert,
  PredictionResult,
  EnhancedMlResult,
  FileAnalysisResponse,
  SampleFileInfo,
  RawTelemetryResponse
} from '../types';

export interface BackendHealthResponse {
  status: string;
  service: string;
  version: string;
  spark_engine?: string;
  mlp_model?: string;
  timestamp: string;
}

export interface MlHealthResponse {
  status: string;
  service: string;
  python_version: string;
  model_architecture?: string;
  hidden_layers?: number[];
  activation?: string;
  spark_layer?: string;
  spark_status?: string;
  model_available: boolean;
  mlp_model_available?: boolean;
}

export const api = {
  // ═══════════════════════════════════════════════════════════════
  // HEALTH CHECKS & DIAGNOSTICS
  // ═══════════════════════════════════════════════════════════════
  getBackendHealth: async (): Promise<BackendHealthResponse> => {
    return apiClient.get<BackendHealthResponse>('/api/health');
  },

  getMlHealth: async (): Promise<MlHealthResponse> => {
    return apiClient.get<MlHealthResponse>('/api/ml/health');
  },

  getSystemStatus: async (): Promise<SystemDiagnostics> => {
    return apiClient.get<SystemDiagnostics>('/api/system/status');
  },

  getDatasetsDirect: async (): Promise<DatasetInventoryResponse> => {
    return apiClient.get<DatasetInventoryResponse>('/api/datasets');
  },

  // ═══════════════════════════════════════════════════════════════
  // APACHE SPARK BIG DATA & STREAMING
  // ═══════════════════════════════════════════════════════════════
  getSparkStatus: async (): Promise<SparkEngineStatus> => {
    return apiClient.get<SparkEngineStatus>('/api/spark/status');
  },

  getSparkStreamStatus: async (): Promise<SparkStreamStatus> => {
    return apiClient.get<SparkStreamStatus>('/api/spark/stream/status');
  },

  startSparkStream: async (): Promise<SparkStreamStatus> => {
    return apiClient.post<SparkStreamStatus>('/api/spark/stream/start');
  },

  stopSparkStream: async (): Promise<SparkStreamStatus> => {
    return apiClient.post<SparkStreamStatus>('/api/spark/stream/stop');
  },

  feedSparkStream: async (events: any[]) => {
    return apiClient.post('/api/spark/stream/feed', { events });
  },

  getSparkJobs: async (limit = 50): Promise<{ jobs: SparkJobItem[] }> => {
    return apiClient.get<{ jobs: SparkJobItem[] }>(`/api/spark/jobs?limit=${limit}`);
  },

  processDatasetWithSpark: async (datasetPath: string, maxRecords = 50000) => {
    return apiClient.post('/api/spark/process-dataset', {
      dataset_path: datasetPath,
      max_records: maxRecords
    });
  },

  // ═══════════════════════════════════════════════════════════════
  // THREAT INTELLIGENCE ENGINE
  // ═══════════════════════════════════════════════════════════════
  lookupThreatIntel: async (ip: string): Promise<ThreatIntelResult> => {
    return apiClient.get<ThreatIntelResult>(`/api/threat-intel/lookup?ip=${encodeURIComponent(ip)}`);
  },

  getThreatIntelDatabase: async (): Promise<{ total_indicators: number; indicators: Record<string, any> }> => {
    return apiClient.get<{ total_indicators: number; indicators: Record<string, any> }>('/api/threat-intel/database');
  },

  // ═══════════════════════════════════════════════════════════════
  // LLM SOC ANALYST ASSISTANT
  // ═══════════════════════════════════════════════════════════════
  investigateWithLlm: async (alertData: Record<string, any>): Promise<LLMInvestigationReport> => {
    return apiClient.post<LLMInvestigationReport>('/api/llm/investigate', alertData);
  },

  runAlertLlmInvestigation: async (alertId: number): Promise<{ alert_id: number; investigation: LLMInvestigationReport }> => {
    return apiClient.post<{ alert_id: number; investigation: LLMInvestigationReport }>(`/api/alerts/${alertId}/investigate`);
  },

  // ═══════════════════════════════════════════════════════════════
  // NETWORK & WIRESHARK / TSHARK
  // ═══════════════════════════════════════════════════════════════
  getNetworkInterfaces: async (): Promise<{ interfaces: NetworkInterface[]; current_interface: string }> => {
    return apiClient.get<{ interfaces: NetworkInterface[]; current_interface: string }>('/api/network/interfaces');
  },

  startCapture: async (selectedInterface: string, packetLimit = 1000) => {
    return apiClient.post('/api/network/capture/start', {
      interface: selectedInterface,
      packet_limit: packetLimit
    });
  },

  stopCapture: async () => {
    return apiClient.post('/api/network/capture/stop');
  },

  getCaptureStatus: async (): Promise<CaptureStatus> => {
    return apiClient.get<CaptureStatus>('/api/network/capture/status');
  },

  getRecentPackets: async (limit = 100): Promise<{ total: number; data: PacketEvent[] }> => {
    return apiClient.get<{ total: number; data: PacketEvent[] }>(`/api/network/packets?limit=${limit}`);
  },

  openWireshark: async () => {
    return apiClient.post('/api/network/open-wireshark');
  },

  // ═══════════════════════════════════════════════════════════════
  // SPLUNK SIEM
  // ═══════════════════════════════════════════════════════════════
  getSplunkStatus: async (): Promise<SplunkStatus> => {
    return apiClient.get<SplunkStatus>('/api/splunk/status');
  },

  searchSplunk: async (query: string, maxResults = 100): Promise<{ events: any[]; count: number; execution_time_ms?: number }> => {
    return apiClient.post<{ events: any[]; count: number; execution_time_ms?: number }>('/api/splunk/search', {
      query,
      max_results: maxResults
    });
  },

  getSplunkDashboard: async (): Promise<SplunkDashboard> => {
    return apiClient.get<SplunkDashboard>('/api/splunk/dashboard');
  },

  testOfflineSplunkLogs: async (): Promise<{ status: string; records_evaluated: number; events: any[] }> => {
    return apiClient.get<{ status: string; records_evaluated: number; events: any[] }>('/api/splunk/test-offline');
  },

  // ═══════════════════════════════════════════════════════════════
  // SPARK & MLP NEURAL NETWORK TRAINING & INFERENCE
  // ═══════════════════════════════════════════════════════════════
  getDatasetInventory: async (forceRefresh = false): Promise<DatasetInventoryResponse> => {
    return apiClient.get<DatasetInventoryResponse>(`/api/ml/inventory?force_refresh=${forceRefresh}`);
  },

  inspectDataset: async (path: string): Promise<DatasetInventoryItem> => {
    return apiClient.get<DatasetInventoryItem>(`/api/ml/datasets/inspect?path=${encodeURIComponent(path)}`);
  },

  trainMlpModel: async (
    mode: 'all' | 'network' | 'windows_log' = 'all',
    classificationMode: 'multiclass' | 'binary' = 'multiclass',
    nEstimators = 150,
    maxSamples = 50000
  ): Promise<{ job_id: string; status: string; architecture?: string; message: string }> => {
    return apiClient.post<{ job_id: string; status: string; architecture?: string; message: string }>('/api/ml/train', {
      mode,
      classification_mode: classificationMode,
      n_estimators: nEstimators,
      max_samples_per_dataset: maxSamples
    });
  },

  getTrainingStatus: async (jobId?: string): Promise<TrainingStatus> => {
    const url = jobId ? `/api/ml/training-status/${encodeURIComponent(jobId)}` : '/api/ml/train/status';
    return apiClient.get<TrainingStatus>(url);
  },

  getModels: async (): Promise<{ models: ModelVersion[]; network_models: ModelVersion[] }> => {
    return apiClient.get<{ models: ModelVersion[]; network_models: ModelVersion[] }>('/api/ml/models');
  },

  analyzeFile: async (file: File): Promise<FileAnalysisResponse> => {
    const formData = new FormData();
    formData.append('file', file);
    return apiClient.upload<FileAnalysisResponse>('/api/ml/test-file', formData);
  },

  analyzeSampleFile: async (samplePath: string): Promise<FileAnalysisResponse> => {
    return apiClient.post<FileAnalysisResponse>(`/api/ml/analyze-sample?sample_path=${encodeURIComponent(samplePath)}`);
  },

  getSampleFiles: async (): Promise<{ samples: SampleFileInfo[] }> => {
    return apiClient.get<{ samples: SampleFileInfo[] }>('/api/ml/sample-files');
  },

  predictThreat: async (features: Record<string, any>): Promise<PredictionResult> => {
    return apiClient.post<PredictionResult>('/api/ml/predict', { features });
  },

  analyzePacketEnhanced: async (packetData: Record<string, any>): Promise<EnhancedMlResult> => {
    return apiClient.post<EnhancedMlResult>('/api/ml/analyze-packet-enhanced', packetData);
  },

  // ═══════════════════════════════════════════════════════════════
  // SOC AI ALERTS & INCIDENT LIFECYCLE
  // ═══════════════════════════════════════════════════════════════
  getAlerts: async (limit = 100, source?: string, severity?: string, status?: string): Promise<{ alerts: AiAlert[] }> => {
    let url = `/api/alerts?limit=${limit}`;
    if (source) url += `&source=${encodeURIComponent(source)}`;
    if (severity) url += `&severity=${encodeURIComponent(severity)}`;
    if (status) url += `&status=${encodeURIComponent(status)}`;
    return apiClient.get<{ alerts: AiAlert[] }>(url);
  },

  getAlertDetail: async (alertId: number): Promise<AiAlert> => {
    return apiClient.get<AiAlert>(`/api/alerts/${alertId}`);
  },

  updateAlertStatus: async (alertId: number, status: string, analystNotes?: string) => {
    return apiClient.patch(`/api/alerts/${alertId}/status`, {
      status,
      analyst_notes: analystNotes,
      assigned_analyst: 'Senior SOC Analyst'
    });
  },

  getAlertsSummary: async (): Promise<any> => {
    return apiClient.get<any>('/api/alerts/summary');
  },

  // ═══════════════════════════════════════════════════════════════
  // MULTI-FORMAT SECURITY DATA SCANNER (AI ALERTS PAGE UPGRADE)
  // ═══════════════════════════════════════════════════════════════
  uploadSecurityFiles: async (formData: FormData): Promise<{ status: string; total_uploaded: number; valid_count: number; files: any[]; errors: any[] }> => {
    return apiClient.upload<{ status: string; total_uploaded: number; valid_count: number; files: any[]; errors: any[] }>('/api/ai-alerts/upload', formData);
  },

  executeSecurityScan: async (filePaths: string[], scanId?: string, maxRows = 500): Promise<any> => {
    return apiClient.post<any>('/api/ai-alerts/scan', {
      file_paths: filePaths,
      scan_id: scanId,
      max_rows_per_file: maxRows
    });
  },

  autoScan: async (options?: {
    maxRows?: number;
    injectSyntheticDecoys?: boolean;
    scanMode?: 'network' | 'logs' | 'all';
  }): Promise<any> => {
    return apiClient.post<any>('/api/ai-alerts/auto-scan', {
      max_rows_per_file: options?.maxRows ?? 500,
      inject_synthetic_decoys: options?.injectSyntheticDecoys ?? true,
      scan_mode: options?.scanMode ?? 'all',
    });
  },

  getScanHistory: async (): Promise<{ scans: any[] }> => {
    return apiClient.get<{ scans: any[] }>('/api/ai-alerts/scans');
  },

  getScanDetails: async (scanId: string): Promise<any> => {
    return apiClient.get<any>(`/api/ai-alerts/scans/${scanId}`);
  },

  deleteScanRun: async (scanId: string): Promise<{ status: string; scan_id: string }> => {
    return apiClient.delete<{ status: string; scan_id: string }>(`/api/ai-alerts/scans/${scanId}`);
  },

  getScanResults: async (params?: { scan_id?: string; q?: string; risk_status?: string; attack_type?: string; protocol?: string; source_file?: string; sort_by?: string; limit?: number; offset?: number }): Promise<unknown> => {
    const query = new URLSearchParams();
    if (params?.scan_id) query.append('scan_id', params.scan_id);
    if (params?.q) query.append('q', params.q);
    if (params?.risk_status) query.append('risk_status', params.risk_status);
    if (params?.attack_type) query.append('attack_type', params.attack_type);
    if (params?.protocol) query.append('protocol', params.protocol);
    if (params?.source_file) query.append('source_file', params.source_file);
    if (params?.sort_by) query.append('sort_by', params.sort_by);
    if (params?.limit) query.append('limit', String(params.limit));
    if (params?.offset) query.append('offset', String(params.offset));
    return apiClient.get<unknown>(`/api/ai-alerts/results?${query.toString()}`);
  },

  investigateAlertWithAi: async (alertId: string): Promise<any> => {
    return apiClient.post<any>(`/api/ai-alerts/${encodeURIComponent(alertId)}/investigate`, {});
  },

  analyzeRawTelemetry: async (payload: {
    raw_text: string;
    input_type?: string;
    scanner_ip?: string;
    target_ip?: string;
    save_to_history?: boolean;
  }): Promise<RawTelemetryResponse> => {
    return apiClient.post<RawTelemetryResponse>('/api/ai-alerts/analyze-raw', payload);
  },

  // ═══════════════════════════════════════════════════════════════
  // IOC INTELLIGENCE
  // ═══════════════════════════════════════════════════════════════
  searchIOC: async (ioc: string, iocType = 'Auto Detect'): Promise<unknown> => {
    return apiClient.post<unknown>('/api/ioc/search', { ioc, ioc_type: iocType });
  },

  getIOCList: async (limit = 50): Promise<unknown> => {
    return apiClient.get<unknown>(`/api/ioc/list?limit=${limit}`);
  },

  analyzeIOCWithAI: async (payload: {
    ioc: string; ioc_type?: string; threat_score?: number; reputation?: string;
    source?: string; observation_count?: number; related_alerts?: unknown[];
  }): Promise<unknown> => {
    return apiClient.post<unknown>('/api/llm/ioc/analyze', payload);
  },

  saveIOCAnalysis: async (payload: {
    ioc: string; ioc_type: string; classification: string; threat_score: number;
    reputation: string; confidence?: number; source?: string;
    raw_threat_intel?: unknown; ai_analysis?: unknown;
  }): Promise<unknown> => {
    return apiClient.post<unknown>('/api/ioc/save', payload);
  },

  // ═══════════════════════════════════════════════════════════════
  // INCIDENT RESPONSE
  // ═══════════════════════════════════════════════════════════════
  getIncidents: async (params?: {
    status?: string; severity?: string; attack_type?: string; search?: string; limit?: number;
  }): Promise<unknown> => {
    const q = new URLSearchParams();
    if (params?.status) q.append('status', params.status);
    if (params?.severity) q.append('severity', params.severity);
    if (params?.attack_type) q.append('attack_type', params.attack_type);
    if (params?.search) q.append('search', params.search);
    if (params?.limit) q.append('limit', String(params.limit));
    return apiClient.get<unknown>(`/api/incidents?${q.toString()}`);
  },

  createIncident: async (payload: unknown): Promise<unknown> => {
    return apiClient.post<unknown>('/api/incidents', payload);
  },

  getIncident: async (incidentId: string): Promise<unknown> => {
    return apiClient.get<unknown>(`/api/incidents/${encodeURIComponent(incidentId)}`);
  },

  updateIncidentStatus: async (incidentId: string, status: string, analyst?: string, notes?: string): Promise<unknown> => {
    return apiClient.patch<unknown>(`/api/incidents/${encodeURIComponent(incidentId)}/status`, { status, analyst, notes });
  },

  addIncidentTimeline: async (incidentId: string, action: string, analyst: string, notes: string): Promise<unknown> => {
    return apiClient.post<unknown>(`/api/incidents/${encodeURIComponent(incidentId)}/timeline`, { action, analyst, notes });
  },

  investigateIncidentWithAI: async (payload: unknown): Promise<unknown> => {
    return apiClient.post<unknown>('/api/llm/incident/investigate', payload);
  },

  deleteIncident: async (incidentId: string): Promise<unknown> => {
    return apiClient.delete<unknown>(`/api/incidents/${encodeURIComponent(incidentId)}`);
  },

  // ═══════════════════════════════════════════════════════════════
  // SOC CASE MANAGEMENT
  // ═══════════════════════════════════════════════════════════════
  getCases: async (params?: {
    status?: string; priority?: string; search?: string; limit?: number;
  }): Promise<unknown> => {
    const q = new URLSearchParams();
    if (params?.status) q.append('status', params.status);
    if (params?.priority) q.append('priority', params.priority);
    if (params?.search) q.append('search', params.search);
    if (params?.limit) q.append('limit', String(params.limit));
    return apiClient.get<unknown>(`/api/cases?${q.toString()}`);
  },

  createCase: async (payload: unknown): Promise<unknown> => {
    return apiClient.post<unknown>('/api/cases', payload);
  },

  getCase: async (caseId: string): Promise<unknown> => {
    return apiClient.get<unknown>(`/api/cases/${encodeURIComponent(caseId)}`);
  },

  deleteCase: async (caseId: string): Promise<unknown> => {
    return apiClient.delete<unknown>(`/api/cases/${encodeURIComponent(caseId)}`);
  },

  updateCaseStatus: async (caseId: string, status: string, analyst?: string, notes?: string): Promise<unknown> => {
    return apiClient.patch<unknown>(`/api/cases/${encodeURIComponent(caseId)}/status`, { status, analyst, notes });
  },

  addCaseNote: async (caseId: string, note: string, analyst?: string, note_type?: string): Promise<unknown> => {
    return apiClient.post<unknown>(`/api/cases/${encodeURIComponent(caseId)}/notes`, { note, analyst, note_type });
  },

  addCaseEvidence: async (caseId: string, payload: unknown): Promise<unknown> => {
    return apiClient.post<unknown>(`/api/cases/${encodeURIComponent(caseId)}/evidence`, payload);
  },

  summarizeCaseWithAI: async (payload: unknown): Promise<unknown> => {
    return apiClient.post<unknown>('/api/llm/case/summarize', payload);
  },

  generateCaseReport: async (payload: unknown): Promise<unknown> => {
    return apiClient.post<unknown>('/api/llm/case/report', payload);
  },

  // ═══════════════════════════════════════════════════════════════
  // REPORTS
  // ═══════════════════════════════════════════════════════════════
  getReports: async (limit = 50): Promise<unknown> => {
    return apiClient.get<unknown>(`/api/cases/reports/all?limit=${limit}`);
  },

  saveReport: async (payload: unknown): Promise<unknown> => {
    return apiClient.post<unknown>('/api/cases/reports/generate', payload);
  },

  getReport: async (reportId: string): Promise<unknown> => {
    return apiClient.get<unknown>(`/api/cases/reports/${encodeURIComponent(reportId)}`);
  },

  exportReport: async (reportId: string, format = 'json'): Promise<unknown> => {
    return apiClient.get<unknown>(`/api/cases/reports/${encodeURIComponent(reportId)}/export?format=${format}`);
  },

  // ═══════════════════════════════════════════════════════════════
  // LLM GATEWAY
  // ═══════════════════════════════════════════════════════════════
  getLLMStatus: async (): Promise<unknown> => {
    return apiClient.get<unknown>('/api/llm/status');
  },

  // ═══════════════════════════════════════════════════════════════
  // AI THREAT ANALYSIS & ATTACK ANATOMY STUDIO
  // ═══════════════════════════════════════════════════════════════
  getAttackCatalog: async (): Promise<{ total_classes: number; classes: string[]; catalog: Record<string, any> }> => {
    return apiClient.get('/api/ai-analysis/catalog');
  },

  getAttackScenarios: async (): Promise<{ total_scenarios: number; scenarios: any[] }> => {
    return apiClient.get('/api/ai-analysis/scenarios');
  },

  analyzeThreatDeepDive: async (payload: {
    attack_type?: string;
    source_ip?: string;
    destination_ip?: string;
    source_port?: number;
    destination_port?: number;
    protocol?: string;
    confidence?: number;
    risk_score?: number;
    severity?: string;
    flow_duration_ms?: number;
    packet_count?: number;
    byte_count?: number;
    custom_notes?: string;
  }): Promise<any> => {
    return apiClient.post('/api/ai-analysis/analyze', payload);
  },

  getQuickQuestions: async (): Promise<{ categories: Array<{ category: string; icon: string; questions: string[] }> }> => {
    return apiClient.get('/api/ai-analysis/quick-questions');
  },

  askCyberQuestion: async (payload: {
    question: string;
    attack_type?: string;
    context?: Record<string, any>;
    conversation_history?: Array<{ role: string; content: string }>;
  }): Promise<{
    status: string;
    question: string;
    attack_type?: string;
    answer: string;
    provider: string;
    model: string;
    duration_ms: number;
    is_fallback: boolean;
    structured_data?: Record<string, any>;
  }> => {
    return apiClient.post('/api/ai-analysis/ask', payload, 90000);
  }
};

