export interface SystemServiceStatus {
  name: string;
  status: string;
  host?: string;
  path?: string;
  web_url?: string;
  version?: string;
  master?: string;
  architecture?: string;
  available: boolean;
}

export interface SystemDiagnostics {
  timestamp: string;
  services: {
    mysql: SystemServiceStatus;
    spark?: SystemServiceStatus;
    ml_model: SystemServiceStatus;
    threat_intel?: SystemServiceStatus;
    llm_analyst?: SystemServiceStatus;
    tshark: SystemServiceStatus;
    wireshark: SystemServiceStatus;
    splunk: SystemServiceStatus;
  };
}

export interface NetworkInterface {
  id: string;
  name: string;
  raw_device: string;
  description: string;
}

export interface PacketEvent {
  id?: number;
  packet_no: number;
  timestamp: string;
  session_id?: string;
  source_ip: string;
  destination_ip: string;
  source_port?: number;
  destination_port?: number;
  protocol: string;
  packet_length: number;
  tcp_flags?: string;
  interface?: string;
  classification?: string;
  confidence?: number;
  mlp_confidence?: number;
  attack_type?: string;
  risk_score?: number;
  risk_status?: string;
}

export interface CaptureStatus {
  is_capturing: boolean;
  interface: string;
  session_id?: string;
  packet_count: number;
  packets_per_second: number;
  duration_seconds: number;
  tshark_available: boolean;
  wireshark_available: boolean;
}

export interface SplunkStatus {
  status: 'connected' | 'disconnected';
  connected: boolean;
  host: string;
  port: number;
  web_url: string;
  index?: string;
  version?: string;
  server_name?: string;
  license_state?: string;
  message?: string;
}

export interface SplunkEvent {
  timestamp: string;
  host: string;
  source: string;
  sourcetype: string;
  event_code: number;
  source_ip: string;
  destination_ip: string;
  attack_type?: string;
  confidence?: number;
  mlp_confidence?: number;
  risk_score?: number;
  risk_status?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  threat_intel?: ThreatIntelResult;
  raw_event: string;
}

export interface SplunkDashboard {
  total_events: number;
  critical_events: number;
  high_events: number;
  medium_events: number;
  low_events: number;
  top_hosts: { name: string; count: number }[];
  top_sources: { ip: string; count: number }[];
  recent_events: SplunkEvent[];
  web_url: string;
}

// ═══════════════════════════════════════════════════════════════
// APACHE SPARK BIG DATA & STREAMING TYPES
// ═══════════════════════════════════════════════════════════════
export interface SparkStreamStatus {
  engine: string;
  streaming_status: 'ACTIVE' | 'PAUSED' | 'STOPPED';
  is_streaming: boolean;
  events_received: number;
  events_processed: number;
  events_queued: number;
  alerts_generated: number;
  failed_events: number;
  processing_latency_ms: number;
  average_latency_ms: number;
  throughput_events_per_sec: number;
  total_batches_processed: number;
  batch_interval_seconds: number;
  spark_job_status: string;
  uptime_seconds: number;
}

export interface SparkEngineStatus {
  engine: string;
  version: string;
  status: 'ONLINE' | 'INITIALIZING' | 'OFFLINE';
  master: string;
  app_name: string;
  driver_memory: string;
  executor_memory: string;
  partitions: number;
  java_home: string;
  java_available: boolean;
  pyspark_active: boolean;
  total_records_processed: number;
  total_jobs_executed: number;
  active_jobs_count: number;
  uptime_seconds: number;
  pipeline_stages: string[];
  streaming?: SparkStreamStatus;
}

export interface SparkJobItem {
  id: number;
  job_id: string;
  job_type: string;
  dataset_name?: string;
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
  records_processed: number;
  execution_time_ms: number;
  details?: Record<string, any>;
  created_at: string;
}

// ═══════════════════════════════════════════════════════════════
// THREAT INTELLIGENCE TYPES
// ═══════════════════════════════════════════════════════════════
export interface ThreatIntelResult {
  ip?: string;
  ioc?: string;
  indicator?: string;
  threat_score: number;
  reputation: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | string;
  category?: string;
  country?: string;
  isp?: string;
  is_malicious?: boolean;
  malicious_status?: boolean;
  reports_count?: number;
  malicious_votes?: number;
  source: string;
  source_type?: string;
  confidence?: number;
  cve?: string;
  hash?: string;
  observed_count?: number;
  last_updated?: string;
  sources?: Record<string, any>;
  virustotal?: any;
}

// ═══════════════════════════════════════════════════════════════
// LLM SOC ANALYST ASSISTANT TYPES
// ═══════════════════════════════════════════════════════════════
export interface LLMInvestigationReport {
  llm_engine?: string;
  attack_type: string;
  confidence: number;
  risk_score: number;
  risk_status: string;
  attack_explanation: string;
  why_suspicious: string;
  evidence_summary: string[];
  investigation_steps: string[];
  recommended_response: string[];
  incident_summary: string;
  mitre_technique?: string;
  mitre_tactic?: string;
  recommended_action?: string;
}

// ═══════════════════════════════════════════════════════════════
// MACHINE LEARNING & EVALUATION TYPES
// ═══════════════════════════════════════════════════════════════
export interface PerClassMetricItem {
  precision: number;
  recall: number;
  f1_score: number;
  support: number;
}

export interface FeatureAttributionItem {
  feature: string;
  importance_score: number;
  percentage: number;
  value?: number;
  contribution_pct?: number;
  impact?: 'HIGH' | 'MEDIUM' | 'LOW' | string;
}

export interface DatasetInventoryItem {
  filename: string;
  relative_path: string;
  format: string;
  size_bytes?: number;
  size_human?: string;
  size_mb: number;
  records: number;
  record_count?: number;
  columns: string[];
  column_count: number;
  feature_count?: number;
  candidate_targets: string[];
  target_candidate?: string;
  classes?: string[];
  classes_sample: string[];
  class_count: number;
  compatibility: 'Compatible' | 'Incompatible' | 'Feature Extraction Required' | 'Inference Only' | string;
  compatibility_reason?: string;
  modality?: string;
  detected_modality?: string;
  dataset_family?: string;
  model_family?: string;
  status: string;
  status_reason: string;
  sample_records?: Record<string, any>[];
  dtypes?: Record<string, string>;
}

export interface ExcludedFileItem {
  filename: string;
  relative_path: string;
  format: string;
  size_mb: number;
  size_human?: string;
  reason?: string;
  status_reason?: string;
}

export interface DatasetInventoryResponse {
  status?: string;
  root?: string;
  root_exists?: boolean;
  directories_scanned?: number;
  files_scanned?: number;
  supported_files?: number;
  errors?: string[];
  total_discovered: number;
  supported_discovered: number;
  compatible_count: number;
  incompatible_count: number;
  excluded_zip_count: number;
  datasets: DatasetInventoryItem[];
  excluded_files?: ExcludedFileItem[];
  excluded_files_list?: ExcludedFileItem[];
}

export interface TrainingLogEntry {
  timestamp: string;
  message: string;
  level: 'INFO' | 'WARNING' | 'ERROR';
}

export interface TrainingStatus {
  status: 'Idle' | 'Queued' | 'Running' | 'Completed' | 'Failed';
  stage: string;
  progress_percentage: number;
  progress_message: string;
  duration_seconds: number;
  logs: TrainingLogEntry[];
  network_metrics?: {
    accuracy: number;
    precision: number;
    recall: number;
    f1_score: number;
    training_duration_seconds?: number;
    loss_curve?: number[];
    confusion_matrix?: number[][];
    per_class_metrics?: Record<string, PerClassMetricItem>;
    feature_importance?: FeatureAttributionItem[];
    train_metrics?: {
      accuracy: number;
      f1_score: number;
      loss: number;
    };
    validation_metrics?: {
      accuracy: number;
      f1_score: number;
    };
    test_metrics?: {
      accuracy: number;
      precision: number;
      recall: number;
      f1_score: number;
      precision_macro?: number;
      recall_macro?: number;
      f1_score_macro?: number;
    };
    classes?: string[];
    architecture?: {
      input_features: number;
      hidden_layer_1: number;
      hidden_layer_2: number;
      hidden_layer_3: number;
      output_classes: number;
      activation: string;
      solver: string;
      iterations_completed?: number;
      best_loss?: number;
    };
  };
  log_metrics?: any;
  error?: string;
}

export interface ModelVersion {
  id?: number;
  version: string;
  algorithm?: string;
  classes?: string[];
  accuracy?: number;
  precision_score?: number;
  recall_score?: number;
  f1_score?: number;
  created_at?: string;
  status?: string;
  architecture?: Record<string, any>;
  loss_curve?: number[];
}

export interface AiAlert {
  id: number;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  source_port?: number;
  destination_port?: number;
  protocol?: string;
  attack_type: string;
  confidence: number;
  mlp_confidence?: number;
  risk_score: number;
  risk_status: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  source: 'NETWORK' | 'SPLUNK' | 'SPARK_STREAM' | 'DATASET_TEST' | 'MANUAL_TEST' | string;
  status: 'NEW' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED' | string;
  investigation_status?: 'NEW' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED' | string;
  recommended_action?: string;
  evidence?: Record<string, any>;
  threat_intel?: ThreatIntelResult;
  llm_explanation?: string;
  spark_job_id?: string;
  raw_event?: Record<string, any>;
}

export interface PredictionResult {
  prediction: string;
  attack_type: string;
  confidence: number;
  mlp_confidence?: number;
  risk_score: number;
  risk_status: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  is_attack: boolean;
  classification: 'Attack' | 'Normal';
  probabilities?: Record<string, number>;
  top_features?: FeatureAttributionItem[];
  threat_intel?: ThreatIntelResult;
  risk_evidence?: Record<string, any>;
  llm_report?: LLMInvestigationReport;
  recommended_action: string;
  model_architecture?: string;
}

export interface EnhancedMlResult {
  timestamp: string;
  alert_status: 'NORMAL' | 'SUSPICIOUS' | 'ATTACK' | 'CRITICAL';
  is_attack: boolean;
  attack_category: string;
  prediction?: string;
  confidence: number;
  mlp_confidence?: number;
  risk_score: number;
  risk_status?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  severity_score?: number;
  threat_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  source_ip: string;
  source_device: string;
  destination_ip: string;
  destination_device: string;
  protocol_details: {
    protocol: string;
    src_port: number;
    dst_port: number;
    flags?: string;
  };
  threat_intel?: ThreatIntelResult;
  mitre_technique: string;
  risk_evidence?: Record<string, any>;
  llm_report?: LLMInvestigationReport;
  recommendation: string;
  explanation?: string;
  raw_attributes: Record<string, any>;
}

export interface FileAnalysisResponse {
  filename: string;
  detected_format?: string;
  detected_modality?: string;
  dataset_family?: string;
  routed_pipeline?: string;
  routed_model?: string;
  model_family?: string;
  total_records: number;
  status?: string;
  message?: string;
  summary: {
    normal: number;
    suspicious: number;
    attack: number;
    critical: number;
    avg_risk_score: number;
    avg_confidence: number;
    top_sources: { source_ip: string; device: string; count: number }[];
  };
  results: EnhancedMlResult[];
}

export interface SampleFileInfo {
  name: string;
  path: string;
  type: string;
  size_kb: number;
}

export interface SecurityUploadedFile {
  valid: boolean;
  filename: string;
  file_type: string;
  status: string;
  size_bytes: number;
  size_human: string;
  path: string;
  absolute_path?: string;
  warning?: string;
  error?: string;
}

export interface SecurityCorrelationItem {
  ip: string;
  activity_count: number;
  associated_files: string[];
  attack_types: string[];
  max_risk_score: number;
  threat_score: number;
  correlation_insight: string;
}

export interface SecurityScanSummary {
  scan_id: string;
  spark_job_id: string;
  scan_date: string;
  status: string;
  duration_seconds: number;
  total_files: number;
  files: {
    filename: string;
    status: string;
    records: number;
    alerts: number;
    critical: number;
    high: number;
    pipeline?: string;
    error?: string;
  }[];
  total_records: number;
  total_alerts: number;
  summary: {
    total_records: number;
    total_alerts: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    normal: number;
    attack: number;
    avg_risk_score: number;
    avg_confidence: number;
  };
  correlations: SecurityCorrelationItem[];
  top_target_ports: { port: number; count: number }[];
}

export interface SecurityScanResponse {
  scan_id: string;
  status: string;
  summary: SecurityScanSummary;
  results: any[];
}

// ═══════════════════════════════════════════════════════════════
// IOC INTELLIGENCE TYPES
// ═══════════════════════════════════════════════════════════════
export type IOCType = 'IPv4' | 'IPv6' | 'Domain' | 'URL' | 'MD5 Hash' | 'SHA1 Hash' | 'SHA256 Hash' | 'Email Address' | 'CVE Identifier' | 'Port' | 'Hostname / String Indicator' | 'Auto Detect';
export type IOCClassification = 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
export type TISourceType = 'LIVE' | 'CACHE' | 'LOCAL' | 'UNAVAILABLE';


export interface IOCTimelineEvent {
  timestamp: string;
  event: string;
  source: string;
  severity?: string;
}

export interface IOCSearchResult {
  ioc: string;
  ioc_type: IOCType;
  classification: IOCClassification;
  threat_score: number;
  reputation: string;
  confidence: number;
  source: string;
  source_type: TISourceType;
  first_seen: string;
  last_seen: string;
  observation_count: number;
  related_alerts_count: number;
  related_incidents_count: number;
  threat_intel: ThreatIntelResult;
  related_alerts: AiAlert[];
  timeline: IOCTimelineEvent[];
  ai_analysis?: LLMAnalysisResult | null;
}

export interface IOCRecord {
  id: number;
  ioc: string;
  ioc_type: IOCType;
  classification: IOCClassification;
  threat_score: number;
  reputation: string;
  confidence: number;
  source: string;
  first_seen: string;
  last_seen: string;
  observation_count: number;
  related_alerts_count: number;
}

// ═══════════════════════════════════════════════════════════════
// INCIDENT RESPONSE TYPES
// ═══════════════════════════════════════════════════════════════
export type IncidentStatus = 'NEW' | 'TRIAGE' | 'INVESTIGATION' | 'CONTAINMENT' | 'ERADICATION' | 'RECOVERY' | 'MONITORING' | 'RESOLVED' | 'CLOSED';
export type IncidentSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type IncidentPriority = 'P1' | 'P2' | 'P3' | 'P4';

export interface IncidentTimeline {
  id: number;
  incident_id: string;
  action: string;
  old_status: string;
  new_status: string;
  analyst: string;
  notes: string;
  created_at: string;
}

export interface Incident {
  id: number;
  incident_id: string;
  title: string;
  description: string;
  alert_id?: number;
  attack_type: string;
  severity: IncidentSeverity;
  priority: IncidentPriority;
  status: IncidentStatus;
  risk_score: number;
  risk_status: string;
  mlp_confidence: number;
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  protocol: string;
  assigned_analyst: string;
  threat_intel?: ThreatIntelResult | null;
  evidence?: Record<string, unknown> | null;
  splunk_evidence?: unknown[] | null;
  ai_investigation?: LLMAnalysisResult | null;
  created_at: string;
  updated_at: string;
}

export interface CreateIncidentPayload {
  title: string;
  description?: string;
  alert_id?: number;
  attack_type?: string;
  severity?: IncidentSeverity;
  priority?: IncidentPriority;
  risk_score?: number;
  risk_status?: string;
  mlp_confidence?: number;
  source_ip?: string;
  destination_ip?: string;
  source_port?: number;
  destination_port?: number;
  protocol?: string;
  assigned_analyst?: string;
  threat_intel?: Record<string, unknown>;
  evidence?: Record<string, unknown>;
}

export interface IncidentKPIs {
  total: number;
  open: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  investigating: number;
  contained: number;
  resolved: number;
  closed: number;
}

export interface IncidentsResponse {
  incidents: Incident[];
  kpis: IncidentKPIs;
  charts: {
    severity_distribution: { name: string; value: number }[];
    attack_distribution: { name: string; value: number }[];
    status_distribution: { name: string; value: number }[];
  };
}

// ═══════════════════════════════════════════════════════════════
// SOC CASE MANAGEMENT TYPES
// ═══════════════════════════════════════════════════════════════
export type CaseStatus = 'OPEN' | 'INVESTIGATING' | 'PENDING' | 'RESOLVED' | 'CLOSED';
export type CasePriority = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface CaseNote {
  id: number;
  case_id: string;
  analyst: string;
  note_type: string;
  note: string;
  created_at: string;
}

export interface CaseEvidence {
  id: number;
  case_id: string;
  evidence_type: string;
  reference_id: string;
  title: string;
  details?: Record<string, unknown> | null;
  created_at: string;
}

export interface SOCCase {
  id: number;
  case_id: string;
  title: string;
  description: string;
  priority: CasePriority;
  status: CaseStatus;
  assigned_analyst: string;
  related_incident_id?: string | null;
  related_alert_id?: number | null;
  related_ioc?: string | null;
  ai_summary?: LLMAnalysisResult | null;
  created_at: string;
  updated_at: string;
}

export interface CaseKPIs {
  total: number;
  open: number;
  investigating: number;
  pending: number;
  resolved: number;
  closed: number;
}

export interface CasesResponse {
  cases: SOCCase[];
  kpis: CaseKPIs;
  charts: {
    priority_distribution: { name: string; value: number }[];
    status_distribution: { name: string; value: number }[];
  };
}

export interface CaseDetail {
  case: SOCCase;
  notes: CaseNote[];
  evidence: CaseEvidence[];
  statuses: CaseStatus[];
}

// ═══════════════════════════════════════════════════════════════
// LLM GATEWAY TYPES
// ═══════════════════════════════════════════════════════════════
export interface LLMModelInfo {
  name: string;
  id: string;
  role: string;
}

export interface LLMStatus {
  status: string;
  endpoint: string;
  models: {
    primary: string;
    secondary: string;
    tertiary: string;
  };
  api_key_configured: boolean;
  llm_enabled: boolean;
  failover_order: string[];
}

export interface LLMAnalysisResult {
  provider: string;
  model: string;
  status: string;
  content: string;
  structured_data?: Record<string, unknown>;
  duration_ms: number;
  is_fallback: boolean;
  notice?: string;
}

export interface LLMHistoryEntry {
  id: number;
  analysis_type: string;
  reference_id: string;
  provider: string;
  model: string;
  status: string;
  duration_ms: number;
  created_at: string;
  output_response?: LLMAnalysisResult;
}

// ═══════════════════════════════════════════════════════════════
// REPORTS TYPES
// ═══════════════════════════════════════════════════════════════
export type ReportType = 'SOC_CASE_REPORT' | 'INCIDENT_REPORT' | 'IOC_REPORT' | 'AI_INVESTIGATION_REPORT' | 'EXECUTIVE_REPORT';

export interface SOCReport {
  id: number;
  report_id: string;
  report_type: ReportType;
  title: string;
  reference_id: string;
  content: Record<string, unknown>;
  summary: string;
  generated_by: string;
  format: string;
  created_at: string;
}

// ═══════════════════════════════════════════════════════════════
// RAW TELEMETRY ANALYZER TYPES (NMAP & SPLUNK)
// ═══════════════════════════════════════════════════════════════
export interface RawTelemetrySummary {
  scan_id: string;
  input_type_detected: string;
  total_events_parsed: number;
  threats_detected: number;
  max_risk_score: number;
  overall_severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  target_hosts: string[];
  open_ports_identified: number[];
  primary_threat: string;
  model_used: string;
  mitre_techniques: string[];
}

export interface RawTelemetryAlert {
  id: string;
  alert_id?: string;
  timestamp: string;
  source_ip: string;
  source_port?: number;
  destination_ip: string;
  destination_port?: number;
  protocol: string;
  service?: string;
  attack_type: string;
  prediction: string;
  mlp_confidence: number;
  confidence: number;
  risk_score: number;
  risk_status: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  threat_title: string;
  mitre_technique: string;
  cve_note?: string;
  containment_command: string;
  detection_source: string;
  source_file: string;
  evidence: string[];
  raw_attributes?: Record<string, any>;
}

export interface RawTelemetryResponse {
  status: string;
  scan_id: string;
  input_type: string;
  summary: RawTelemetrySummary;
  alerts: RawTelemetryAlert[];
  ai_playbook: {
    executive_summary: string;
    immediate_containment: string;
    soc_investigation_steps: string[];
  };
  iocs?: {
    suspicious_ips: string[];
    target_ips: string[];
    urls_and_links: string[];
    emails: string[];
    domains: string[];
    file_hashes: string[];
    suspicious_files: string[];
    cves: string[];
    open_ports: number[];
    mitre_techniques: string[];
  };
}


