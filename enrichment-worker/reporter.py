import logging
from datetime import datetime, timezone
from enricher import EnrichmentResult

logger = logging.getLogger(__name__)

RISK_CRITICAL = "CRITICAL"
RISK_HIGH     = "HIGH"
RISK_MEDIUM   = "MEDIUM"
RISK_LOW      = "LOW"
RISK_INFO     = "INFO"

_RISK_ORDER = [RISK_INFO, RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_CRITICAL]

WAZUH_URL = "https://15.207.7.85"

def _max_risk(a, b):
    return a if _RISK_ORDER.index(a) >= _RISK_ORDER.index(b) else b

def _score_result(result):
    risk = RISK_INFO
    if result.virustotal and "malicious_count" in result.virustotal:
        mal = result.virustotal["malicious_count"]
        if mal >= 10:   risk = _max_risk(risk, RISK_CRITICAL)
        elif mal >= 5:  risk = _max_risk(risk, RISK_HIGH)
        elif mal >= 2:  risk = _max_risk(risk, RISK_MEDIUM)
        elif mal >= 1:  risk = _max_risk(risk, RISK_LOW)
    if result.abuseipdb and "abuse_score" in result.abuseipdb:
        score = result.abuseipdb["abuse_score"]
        if score >= 90:   risk = _max_risk(risk, RISK_CRITICAL)
        elif score >= 70: risk = _max_risk(risk, RISK_HIGH)
        elif score >= 40: risk = _max_risk(risk, RISK_MEDIUM)
        elif score >= 10: risk = _max_risk(risk, RISK_LOW)
    if result.otx and "pulse_count" in result.otx:
        pulses = result.otx["pulse_count"]
        if pulses >= 10:  risk = _max_risk(risk, RISK_HIGH)
        elif pulses >= 3: risk = _max_risk(risk, RISK_MEDIUM)
        elif pulses >= 1: risk = _max_risk(risk, RISK_LOW)
    return risk

def compute_overall_risk(enrichment_results):
    if not enrichment_results:
        return RISK_INFO
    overall = RISK_INFO
    for r in enrichment_results:
        overall = _max_risk(overall, _score_result(r))
    return overall

_TACTIC_ACTIONS = {
    "initial access": {
        "phishing":          "Block sender domain, quarantine email, reset credentials for targeted user, enable MFA.",
        "brute force":       "Block source IP, enforce account lockout policy, enable MFA on affected service.",
        "exploit":           "Patch vulnerable service immediately, isolate affected host, review WAF rules.",
        "default":           "Block source IP, review access logs, check for successful logins from this IP.",
    },
    "execution": {
        "malware":           "Quarantine affected host, run full AV scan, check for persistence mechanisms in startup/registry.",
        "ransomware":        "IMMEDIATELY isolate host from network, disable SMB shares, restore from clean backup, do not pay ransom.",
        "script":            "Kill malicious process, review scheduled tasks and startup items, scan for lateral movement.",
        "default":           "Isolate affected host, collect forensic image, review running processes and network connections.",
    },
    "credential access": {
        "brute force":       "Block source IP at firewall, enforce strong password policy, enable MFA, check for successful logins.",
        "credential dump":   "Reset all credentials on affected host, rotate service account passwords, check for golden ticket attacks.",
        "default":           "Reset affected account credentials, enable MFA, review authentication logs for successful breaches.",
    },
    "lateral movement": {
        "default":           "Isolate affected segment, review SMB/RDP/SSH connections, check for pass-the-hash or pass-the-ticket.",
    },
    "command and control": {
        "dns":               "Block malicious domain at DNS level, check for DNS tunneling, review all hosts querying this domain.",
        "default":           "Block C2 IP/domain at perimeter, isolate communicating host, review beaconing patterns.",
    },
    "impact": {
        "ransomware":        "IMMEDIATELY isolate host, disable network shares, preserve encrypted files for recovery, restore from backup.",
        "ddos":              "Enable rate limiting and traffic scrubbing, contact upstream ISP for null routing, activate DDoS mitigation.",
        "default":           "Assess damage scope, isolate affected systems, begin incident response procedure.",
    },
    "collection": {
        "default":           "Review data access logs, check for large data transfers, identify and contain affected accounts.",
    },
    "exfiltration": {
        "default":           "Block outbound connections to suspicious IPs, review DLP alerts, identify data accessed and transferred.",
    },
    "discovery": {
        "default":           "Block source IP, review what was accessed, check for subsequent exploitation attempts.",
    },
    "persistence": {
        "default":           "Remove malicious startup entries, review scheduled tasks, reset compromised credentials, patch exploited vulnerability.",
    },
    "privilege escalation": {
        "default":           "Revoke elevated privileges, patch exploited vulnerability, review sudo/admin group membership.",
    },
    "defense evasion": {
        "default":           "Review log integrity, check for disabled security tools, restore security controls, investigate scope.",
    },
}

_RISK_ACTIONS_DEFAULT = {
    RISK_CRITICAL: "IMMEDIATE ACTION: Block all associated IPs/domains, isolate affected host, escalate to IR team.",
    RISK_HIGH:     "Block associated IPs/domains at perimeter, investigate affected host, notify security lead.",
    RISK_MEDIUM:   "Monitor traffic, review host logs, consider temporary block.",
    RISK_LOW:      "Log and monitor. No immediate action required.",
    RISK_INFO:     "Informational. No enrichment data. Manual review recommended.",
}

# Rule description keyword -> recommendation (checked first, most specific)
_DESCRIPTION_ACTIONS = {
    "sql injection":       "Block source IP at WAF, review database query logs, check for data exfiltration, sanitize and patch vulnerable input fields.",
    "xss":                 "Implement Content Security Policy headers, sanitize input fields, invalidate affected user sessions, check for stolen cookies.",
    "cross-site scripting":"Implement Content Security Policy headers, sanitize input fields, invalidate affected user sessions, check for stolen cookies.",
    "path traversal":      "Block source IP, restrict directory traversal at web server, audit file access logs, patch vulnerable application.",
    "url interpretation":  "Block source IP, restrict directory traversal at web server, audit file access logs, patch vulnerable application.",
    "dns spoofing":        "Flush DNS cache on all affected hosts, block spoofed DNS responses, verify DNS server integrity, enable DNSSEC.",
    "dns poison":          "Flush DNS cache on all affected hosts, block spoofed DNS responses, verify DNS server integrity, enable DNSSEC.",
    "session hijacking":   "Invalidate all active sessions, force re-authentication for all users, rotate session tokens, block source IP.",
    "cookie theft":        "Invalidate all active sessions, force re-authentication for all users, rotate session tokens, set HttpOnly and Secure cookie flags.",
    "brute force":         "Block source IP at firewall, enforce account lockout policy, enable MFA, review successful logins from this IP.",
    "ssh brute":           "Block source IP at firewall, enforce account lockout policy, enable MFA on SSH, consider key-based auth only.",
    "phishing":            "Block sender domain, quarantine email, reset credentials for targeted user, enable MFA.",
    "spear phishing":      "Block sender domain, quarantine email, reset credentials for targeted executive, escalate to security team.",
    "ransomware":          "IMMEDIATELY isolate host from network, disable SMB shares, preserve encrypted files, restore from clean backup - do not pay ransom.",
    "mass file encryption":"IMMEDIATELY isolate host from network, disable SMB shares, preserve encrypted files, restore from clean backup - do not pay ransom.",
    "ddos":                "Enable rate limiting and traffic scrubbing, contact upstream ISP for null routing, activate DDoS mitigation service.",
    "syn flood":           "Enable SYN cookies, apply rate limiting at firewall, contact ISP for upstream filtering.",
    "malware":             "Quarantine affected host, run full AV scan, check for persistence mechanisms in startup and registry.",
    "c2":                  "Block C2 IP/domain at perimeter, isolate communicating host, review all beaconing connections.",
    "lateral movement":    "Isolate affected network segment, review SMB/RDP/SSH connections, check for pass-the-hash attacks.",
    "privilege escalation":"Revoke elevated privileges immediately, patch exploited vulnerability, review sudo and admin group membership.",
    "data exfiltration":   "Block outbound connections to suspicious IPs, review DLP alerts, identify and contain exfiltrated data scope.",
}

def _get_recommendation(alert, overall):
    """Generate context-aware recommendation based on rule description, groups and MITRE tactic."""
    rule        = alert.get("rule", {})
    description = rule.get("description", "").lower()
    groups      = [g.lower() for g in rule.get("groups", [])]
    mitre       = rule.get("mitre", {})
    tactic      = (mitre.get("tactic") or [""])[0].lower() if mitre.get("tactic") else ""

    # 1. Match by rule description keywords (most specific)
    for keyword, action in _DESCRIPTION_ACTIONS.items():
        if keyword in description:
            return action

    # 2. Match by group keywords
    for keyword, action in _DESCRIPTION_ACTIONS.items():
        if any(keyword in g for g in groups):
            return action

    # 3. Match by tactic
    tactic_map = _TACTIC_ACTIONS.get(tactic, {})
    if "default" in tactic_map:
        return tactic_map["default"]

    # 4. Final fallback to risk-level default
    return _RISK_ACTIONS_DEFAULT.get(overall, _RISK_ACTIONS_DEFAULT[RISK_INFO])

def _fmt_ts(ts):
    if ts is None: return "N/A"
    if isinstance(ts, (int, float)):
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            return str(ts)
    return str(ts)

def _extract_geoip(enrichment_results):
    """Extract best available GeoIP data from existing API responses."""
    geo = {"country": "N/A", "city": "N/A", "asn": "N/A", "isp": "N/A"}
    for r in enrichment_results:
        if r.abuseipdb:
            if r.abuseipdb.get("country"):
                geo["country"] = r.abuseipdb["country"]
            if r.abuseipdb.get("isp"):
                geo["isp"] = r.abuseipdb["isp"]
        if r.otx:
            if r.otx.get("country") and geo["country"] == "N/A":
                geo["country"] = r.otx["country"]
            if r.otx.get("asn"):
                geo["asn"] = r.otx["asn"]
    return geo

def _extract_mitre(alert):
    """Extract MITRE ATT&CK info directly from Wazuh rule."""
    mitre = alert.get("rule", {}).get("mitre", {})
    techniques = mitre.get("technique", [])
    ids        = mitre.get("id", [])
    tactic     = mitre.get("tactic", [])
    if techniques and ids:
        combined = [f"{i} - {t}" for i, t in zip(ids, techniques)]
        return {
            "techniques": combined,
            "tactic":     tactic,
        }
    return {"techniques": [], "tactic": []}

def _extract_attack_tags(alert, enrichment_results):
    """Combine Wazuh rule groups + OTX tags as attack tags."""
    tags = set()
    for g in alert.get("rule", {}).get("groups", []):
        tags.add(g)
    for r in enrichment_results:
        if r.otx and r.otx.get("tags"):
            for t in r.otx["tags"][:5]:
                tags.add(t)
    return list(tags)

def _build_threat_intel_links(enrichment_results):
    """Build direct links to each IOC on threat intel platforms."""
    links = []
    for r in enrichment_results:
        v = r.ioc_value
        t = r.ioc_type
        if t == "ip":
            links.append(f"VirusTotal: https://www.virustotal.com/gui/ip-address/{v}")
            links.append(f"AbuseIPDB: https://www.abuseipdb.com/check/{v}")
            links.append(f"AlienVault OTX: https://otx.alienvault.com/indicator/ip/{v}")
        elif t == "domain":
            links.append(f"VirusTotal: https://www.virustotal.com/gui/domain/{v}")
            links.append(f"AlienVault OTX: https://otx.alienvault.com/indicator/domain/{v}")
        elif t in ("md5", "sha1", "sha256"):
            links.append(f"VirusTotal: https://www.virustotal.com/gui/file/{v}")
            links.append(f"AlienVault OTX: https://otx.alienvault.com/indicator/file/{v}")
        elif t == "url":
            links.append(f"VirusTotal: https://www.virustotal.com/gui/url/{v}")
    return links

def _build_wazuh_link(alert):
    """Build deep link to specific alert in Wazuh dashboard."""
    agent_id = alert.get("agent", {}).get("id", "")
    rule_id  = alert.get("rule", {}).get("id", "")
    ts       = alert.get("timestamp", "")
    base     = WAZUH_URL
    if agent_id and rule_id:
        return (
            f"{base}/app/discover#/?_g=(time:(from:now-1h,to:now))"
            f"&_a=(query:(language:kuery,query:'agent.id:{agent_id}"
            f" AND rule.id:{rule_id}'))"
        )
    return f"{base}/app/wazuh"

def _verdict_overall(enrichment_results):
    """Single line threat intelligence verdict."""
    malicious = []
    clean     = []
    for r in enrichment_results:
        is_mal = False
        if r.virustotal and r.virustotal.get("malicious_count", 0) > 0:
            is_mal = True
        if r.abuseipdb and r.abuseipdb.get("abuse_score", 0) >= 25:
            is_mal = True
        if r.otx and r.otx.get("pulse_count", 0) > 0:
            is_mal = True
        if is_mal:
            malicious.append(r.ioc_value)
        else:
            clean.append(r.ioc_value)
    if malicious:
        return f"MALICIOUS — {len(malicious)} IOC(s) flagged: {', '.join(malicious[:3])}"
    if clean:
        return "CLEAN / UNKNOWN — No threat intelligence matches found"
    return "NO IOCs EXTRACTED"

def build_report(alert, enrichment_results):
    rule   = alert.get("rule", {})
    agent  = alert.get("agent", {})
    data   = alert.get("data", {})
    src_ip = data.get("srcip", "") or data.get("src_ip", "")
    dst_ip = data.get("dstip", "") or data.get("dst_ip", "")
    ts     = alert.get("timestamp", datetime.now(timezone.utc).isoformat())
    overall = compute_overall_risk(enrichment_results)

    # Extract username from various Wazuh data fields
    username = (
        data.get("dstuser") or data.get("srcuser") or
        data.get("user") or alert.get("data", {}).get("win", {}).get("eventdata", {}).get("targetUserName", "") or
        "N/A"
    )

    # Extract log evidence (raw log)
    log_evidence = (
        alert.get("full_log") or
        data.get("message") or
        "N/A"
    )

    ioc_summaries = []
    for r in enrichment_results:
        ioc_risk = _score_result(r)
        summary  = {
            "type": r.ioc_type, "value": r.ioc_value,
            "risk": ioc_risk, "from_cache": r.from_cache, "errors": r.errors,
        }
        if r.virustotal:
            summary["virustotal"] = {
                "detection_ratio":  r.virustotal.get("detection_ratio", "N/A"),
                "malicious_count":  r.virustotal.get("malicious_count", 0),
                "total_engines":    r.virustotal.get("total_engines", 0),
                "reputation":       r.virustotal.get("reputation", "N/A"),
                "first_seen":       _fmt_ts(r.virustotal.get("first_seen")),
                "last_seen":        _fmt_ts(r.virustotal.get("last_seen")),
                "malware_families": r.virustotal.get("malware_families", []),
                "tags":             r.virustotal.get("tags", []),
            }
        if r.abuseipdb:
            summary["abuseipdb"] = {
                "abuse_score":   r.abuseipdb.get("abuse_score", 0),
                "total_reports": r.abuseipdb.get("total_reports", 0),
                "country":       r.abuseipdb.get("country", ""),
                "isp":           r.abuseipdb.get("isp", ""),
                "is_tor":        r.abuseipdb.get("is_tor", False),
                "last_reported": _fmt_ts(r.abuseipdb.get("last_reported")),
            }
        if r.otx:
            summary["otx"] = {
                "pulse_count":      r.otx.get("pulse_count", 0),
                "malware_families": r.otx.get("malware_families", []),
                "tags":             r.otx.get("tags", []),
                "country":          r.otx.get("country", ""),
                "asn":              r.otx.get("asn", ""),
                "first_seen":       _fmt_ts(r.otx.get("first_seen")),
                "last_seen":        _fmt_ts(r.otx.get("last_seen")),
            }
        ioc_summaries.append(summary)

    geoip        = _extract_geoip(enrichment_results)
    mitre        = _extract_mitre(alert)
    attack_tags  = _extract_attack_tags(alert, enrichment_results)
    intel_links  = _build_threat_intel_links(enrichment_results)
    wazuh_link   = _build_wazuh_link(alert)
    verdict      = _verdict_overall(enrichment_results)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "alert": {
            "id":        alert.get("id", "unknown"),
            "timestamp": ts,
            "rule_id":   rule.get("id", "unknown"),
            "rule_name": rule.get("description", "unknown"),
            "severity":  rule.get("level", 0),
            "groups":    rule.get("groups", []),
        },
        "host": {
            "name": agent.get("name", "unknown"),
            "ip":   agent.get("ip", "unknown"),
            "id":   agent.get("id", "unknown"),
        },
        "network": {
            "source_ip": src_ip,
            "dest_ip":   dst_ip,
            "username":  username,
        },
        "geoip":   geoip,
        "mitre":   mitre,
        "risk": {
            "overall":            overall,
            "recommended_action": _get_recommendation(alert, overall),
            "ioc_count":          len(enrichment_results),
            "verdict":            verdict,
        },
        "attack_tags":   attack_tags,
        "log_evidence":  log_evidence,
        "intel_links":   intel_links,
        "wazuh_link":    wazuh_link,
        "iocs":          ioc_summaries,
    }

def render_markdown(report):
    a    = report["alert"]
    h    = report["host"]
    net  = report["network"]
    risk = report["risk"]

    lines = [
        f"# Wazuh Alert Enrichment Report",
        f"**Generated:** {report['generated_at']}",
        "",
        "## Alert Details",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Rule ID | `{a['rule_id']}` |",
        f"| Rule Name | {a['rule_name']} |",
        f"| Timestamp | {a['timestamp']} |",
        f"| Severity | {a['severity']} |",
        f"| Groups | {', '.join(a['groups']) or 'N/A'} |",
        "",
        "## Affected Host",
        f"| Hostname | `{h['name']}` |",
        f"| Host IP | `{h['ip']}` |",
        f"| Agent ID | `{h['id']}` |",
        "",
        "## Network",
        f"| Source IP | `{net['source_ip'] or 'N/A'}` |",
        f"| Dest IP   | `{net['dest_ip'] or 'N/A'}` |",
        f"| Username  | `{net['username']}` |",
        "",
        f"## Risk Assessment",
        f"**Overall Risk: {risk['overall']}**",
        f"**Action:** {risk['recommended_action']}",
        f"**IOCs Processed:** {risk['ioc_count']}",
        "",
    ]
    lines.append("\n---\n*Generated by Wazuh Enrichment Pipeline*")
    return "\n".join(lines)
