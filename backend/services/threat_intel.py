import os
import time
import json
import socket
import logging
import urllib.request
import urllib.parse
from typing import Dict, Any, Optional, List
from backend.config import settings

logger = logging.getLogger("socchess.services.threat_intel")

# Local High-Fidelity Threat Intelligence Cache / Known Indicators
KNOWN_IOC_DATABASE: Dict[str, Dict[str, Any]] = {
    "192.168.56.104": {
        "ip": "192.168.56.104",
        "threat_score": 95,
        "reputation": "MALICIOUS",
        "category": "Penetration Testing / Attack Simulation Host",
        "country": "Local Lab (Host-Only)",
        "isp": "VirtualBox Virtual Adapter",
        "is_malicious": True,
        "last_seen": "Recent",
        "reports_count": 42,
        "malicious_votes": 38,
        "source": "Local IOC Threat Database"
    },
    "192.168.56.107": {
        "ip": "192.168.56.107",
        "threat_score": 10,
        "reputation": "CLEAN",
        "category": "Internal Victim Endpoint (Windows 10)",
        "country": "Local Lab",
        "isp": "Local Subnet",
        "is_malicious": False,
        "last_seen": "Active",
        "reports_count": 0,
        "malicious_votes": 0,
        "source": "Local IOC Threat Database"
    },
    "8.8.8.8": {
        "ip": "8.8.8.8",
        "threat_score": 0,
        "reputation": "CLEAN",
        "category": "Legitimate Public DNS (Google)",
        "country": "United States",
        "isp": "Google LLC",
        "is_malicious": False,
        "last_seen": "Active",
        "reports_count": 0,
        "malicious_votes": 0,
        "source": "Local IOC Threat Database"
    },
    "1.1.1.1": {
        "ip": "1.1.1.1",
        "threat_score": 0,
        "reputation": "CLEAN",
        "category": "Legitimate Public DNS (Cloudflare)",
        "country": "Australia",
        "isp": "Cloudflare Inc.",
        "is_malicious": False,
        "last_seen": "Active",
        "reports_count": 0,
        "malicious_votes": 0,
        "source": "Local IOC Threat Database"
    },
    "185.220.101.5": {
        "ip": "185.220.101.5",
        "threat_score": 98,
        "reputation": "MALICIOUS",
        "category": "Tor Exit Node / Command & Control",
        "country": "Germany",
        "isp": "Zwiebelfreunde",
        "is_malicious": True,
        "last_seen": "Recent",
        "reports_count": 184,
        "malicious_votes": 179,
        "source": "Local IOC Threat Database"
    },
    "45.146.164.110": {
        "ip": "45.146.164.110",
        "threat_score": 92,
        "reputation": "MALICIOUS",
        "category": "Known Scanner / Exploitation Server",
        "country": "Russia",
        "isp": "Hostkey B.V.",
        "is_malicious": True,
        "last_seen": "Recent",
        "reports_count": 89,
        "malicious_votes": 85,
        "source": "Local IOC Threat Database"
    },
    "evil-c2.example": {
        "domain": "evil-c2.example",
        "threat_score": 98,
        "reputation": "MALICIOUS",
        "category": "Verified Cobalt Strike Team Server",
        "country": "Moldova",
        "isp": "Bulletproof Hosting ASN",
        "is_malicious": True,
        "last_seen": "Active",
        "reports_count": 210,
        "malicious_votes": 208,
        "source": "Local IOC Threat Database"
    },
    "tunnel.dnsexfil.net": {
        "domain": "tunnel.dnsexfil.net",
        "threat_score": 96,
        "reputation": "MALICIOUS",
        "category": "DNS Tunneling / Data Covert Channel",
        "country": "Unknown",
        "isp": "Adversary NS",
        "is_malicious": True,
        "last_seen": "Recent",
        "reports_count": 134,
        "malicious_votes": 130,
        "source": "Local IOC Threat Database"
    },
    "malware-test-domain.example.com": {
        "domain": "malware-test-domain.example.com",
        "threat_score": 88,
        "reputation": "MALICIOUS",
        "category": "Malware Dropper / Staging Host",
        "country": "Russian Federation",
        "isp": "RBN Hosting",
        "is_malicious": True,
        "last_seen": "Recent",
        "reports_count": 76,
        "malicious_votes": 72,
        "source": "Local IOC Threat Database"
    }
}


class ThreatIntelService:
    """
    Threat Intelligence Enrichment Service.
    Queries external threat feeds (e.g. AbuseIPDB) with local IOC database fallback,
    in-memory caching, and resilient failover.
    """

    def __init__(self):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.cache_timestamps: Dict[str, float] = {}

    def lookup_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Enriches an IP address with Threat Intelligence.
        Safe against timeouts and API errors.
        """
        if not ip_address:
            return self._default_clean("Empty IP")

        clean_ip = str(ip_address).strip()

        # Check Cache
        if clean_ip in self.cache:
            cached_time = self.cache_timestamps.get(clean_ip, 0)
            if time.time() - cached_time < settings.TI_CACHE_TTL_SECONDS:
                return self.cache[clean_ip]

        # 1. Private RFC 1918 IPs check
        if clean_ip.startswith("127.") or clean_ip == "::1":
            return self._default_clean("Localhost Loopback")
        if clean_ip in KNOWN_IOC_DATABASE:
            res = KNOWN_IOC_DATABASE[clean_ip]
            self._cache_result(clean_ip, res)
            return res
        if clean_ip.startswith("10.") or clean_ip.startswith("172.16.") or clean_ip.startswith("192.168."):
            return {
                "ip": clean_ip,
                "threat_score": 5,
                "reputation": "CLEAN",
                "category": "Internal Private Subnet",
                "country": "Private Network",
                "isp": "Internal LAN",
                "is_malicious": False,
                "reports_count": 0,
                "source": "Local Subnet Filter"
            }

        # 2. Query Live Threat Intelligence APIs (AbuseIPDB, VirusTotal, AlienVault OTX, Shodan)
        import ssl
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        sources: Dict[str, Any] = {}
        detected_country = "Unknown"
        detected_isp = "Public Internet"
        max_score = 0
        total_reports = 0

        # A. VirusTotal API (v3)
        vt_stats = None
        if settings.VIRUSTOTAL_API_KEY:
            try:
                vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{clean_ip}"
                vt_req = urllib.request.Request(
                    vt_url,
                    headers={
                        "x-apikey": settings.VIRUSTOTAL_API_KEY,
                        "Accept": "application/json",
                        "User-Agent": "SOC-Chess-TI-Engine/2.0"
                    }
                )
                with urllib.request.urlopen(vt_req, timeout=3.5, context=ssl_ctx) as vt_resp:
                    vt_json = json.loads(vt_resp.read().decode("utf-8"))
                    attr = vt_json.get("data", {}).get("attributes", {})
                    vt_stats = attr.get("last_analysis_stats", {})
                    mal_count = int(vt_stats.get("malicious", 0))
                    harmless_count = int(vt_stats.get("harmless", 0))
                    vt_score = min(100, mal_count * 10)
                    max_score = max(max_score, vt_score)
                    total_reports += mal_count
                    detected_country = attr.get("country", detected_country)
                    detected_isp = attr.get("as_owner", detected_isp)
                    sources["virustotal"] = {
                        "malicious_count": mal_count,
                        "harmless_count": harmless_count,
                        "suspicious_count": int(vt_stats.get("suspicious", 0)),
                        "threat_score": vt_score,
                        "reputation": attr.get("reputation", 0)
                    }
            except Exception as e:
                logger.debug(f"VirusTotal lookup note for {clean_ip}: {e}")

        # B. AbuseIPDB API (v2)
        if settings.ABUSEIPDB_API_KEY:
            try:
                url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={clean_ip}&maxAgeInDays=90"
                req = urllib.request.Request(
                    url,
                    headers={
                        "Key": settings.ABUSEIPDB_API_KEY,
                        "Accept": "application/json",
                        "User-Agent": "SOC-Chess-TI-Engine/2.0"
                    }
                )
                with urllib.request.urlopen(req, timeout=3.5, context=ssl_ctx) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    d = data.get("data", {})
                    abuse_score = int(d.get("abuseConfidenceScore", 0))
                    reports = int(d.get("totalReports", 0))
                    max_score = max(max_score, abuse_score)
                    total_reports += reports
                    detected_country = d.get("countryCode") or detected_country
                    detected_isp = d.get("isp") or detected_isp
                    sources["abuseipdb"] = {
                        "abuse_confidence_score": abuse_score,
                        "total_reports": reports,
                        "country_code": d.get("countryCode"),
                        "isp": d.get("isp"),
                        "domain": d.get("domain"),
                        "is_whitelisted": d.get("isWhitelisted", False)
                    }
            except Exception as e:
                logger.debug(f"AbuseIPDB lookup note for {clean_ip}: {e}")

        # C. AlienVault OTX API
        if settings.OTX_API_KEY:
            try:
                otx_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{clean_ip}/general"
                otx_req = urllib.request.Request(
                    otx_url,
                    headers={
                        "X-OTX-API-KEY": settings.OTX_API_KEY,
                        "Accept": "application/json",
                        "User-Agent": "SOC-Chess-TI-Engine/2.0"
                    }
                )
                with urllib.request.urlopen(otx_req, timeout=3.5, context=ssl_ctx) as otx_resp:
                    otx_data = json.loads(otx_resp.read().decode("utf-8"))
                    pulse_info = otx_data.get("pulse_info", {})
                    pulse_count = int(pulse_info.get("count", 0))
                    if pulse_count > 0:
                        max_score = max(max_score, min(100, 50 + pulse_count * 2))
                    detected_country = otx_data.get("country_code") or otx_data.get("country_name") or detected_country
                    pulses = pulse_info.get("pulses", [])[:5]
                    sources["alienvault_otx"] = {
                        "pulse_count": pulse_count,
                        "pulses": [{"name": p.get("name"), "tags": p.get("tags", [])} for p in pulses],
                        "asn": otx_data.get("asn", "")
                    }
            except Exception as e:
                logger.debug(f"AlienVault OTX lookup note for {clean_ip}: {e}")

        # D. Shodan API
        if settings.SHODAN_API_KEY:
            try:
                shodan_url = f"https://api.shodan.io/shodan/host/{clean_ip}?key={settings.SHODAN_API_KEY}"
                shodan_req = urllib.request.Request(shodan_url, headers={"Accept": "application/json", "User-Agent": "SOC-Chess-TI-Engine/2.0"})
                with urllib.request.urlopen(shodan_req, timeout=3.5, context=ssl_ctx) as shodan_resp:
                    shodan_data = json.loads(shodan_resp.read().decode("utf-8"))
                    open_ports = shodan_data.get("ports", [])
                    vulns = list(shodan_data.get("vulns", []))
                    if len(vulns) > 0:
                        max_score = max(max_score, min(100, 70 + len(vulns) * 10))
                    detected_isp = shodan_data.get("org") or detected_isp
                    detected_country = shodan_data.get("country_code") or detected_country
                    sources["shodan"] = {
                        "ports": open_ports,
                        "vulns": vulns,
                        "org": shodan_data.get("org"),
                        "os": shodan_data.get("os"),
                        "hostnames": shodan_data.get("hostnames", [])
                    }
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    sources["shodan"] = {"indexed": False, "ports": [], "vulns": []}
                else:
                    logger.debug(f"Shodan HTTP {e.code} for {clean_ip}")
            except Exception as e:
                logger.debug(f"Shodan lookup note for {clean_ip}: {e}")

        # If any live source responded
        if sources:
            source_names = [k.replace("_", " ").title() for k in sources.keys() if not (k == "shodan" and not sources[k].get("ports") and not sources[k].get("vulns"))]
            src_label = " & ".join(source_names) if source_names else "Live Threat Feeds"
            res = {
                "ip": clean_ip,
                "threat_score": max_score,
                "reputation": "MALICIOUS" if max_score >= 75 else ("SUSPICIOUS" if max_score >= 25 else "CLEAN"),
                "category": f"Flagged by {', '.join(source_names)}" if max_score >= 25 else "Benign Public Host",
                "country": detected_country,
                "isp": detected_isp,
                "is_malicious": max_score >= 50,
                "reports_count": total_reports,
                "virustotal": vt_stats,
                "sources": sources,
                "source": f"{src_label} Live Feed"
            }
            self._cache_result(clean_ip, res)
            return res

        # 3. Default Fallback Intelligence
        score = 0
        is_mal = False
        rep = "CLEAN"

        res = {
            "ip": clean_ip,
            "threat_score": score,
            "reputation": rep,
            "category": "Unlisted Public Host",
            "country": "Unknown",
            "isp": "Public Internet",
            "is_malicious": is_mal,
            "reports_count": 0,
            "source": "Heuristic Local Analysis"
        }
        self._cache_result(clean_ip, res)
        return res


    def _default_clean(self, category: str) -> Dict[str, Any]:
        return {
            "threat_score": 0,
            "reputation": "CLEAN",
            "category": category,
            "country": "Internal Lab",
            "isp": "Localhost",
            "is_malicious": False,
            "reports_count": 0,
            "source": "Localhost Rule"
        }

    def _cache_result(self, ip: str, data: Dict[str, Any]):
        self.cache[ip] = data
        self.cache_timestamps[ip] = time.time()


threat_intel_service = ThreatIntelService()
