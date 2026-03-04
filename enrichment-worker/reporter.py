import logging
from datetime import datetime, timezone
from typing import Optional
from enricher import EnrichmentResult

logger = logging.getLogger(__name__)

RISK_CRITICAL = "CRITICAL"
RISK_HIGH     = "HIGH"
RISK_MEDIUM   = "MEDIUM"
RISK_LOW      = "LOW"
RISK_INFO     = "INFO"

_RISK_ORDER = [RISK_INFO, RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_CRITICAL]

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

_RISK_ACTIONS = {
    RISK_CRITICAL: "IMMEDIATE ACTION: Block all associated IPs/domains, isolate affected host, escalate to IR team.",
    RISK_HIGH:     "Block associated IPs/domains at perimeter, investigate affected host, notify security lead.",
    RISK_MEDIUM:   "Monitor traffic, review host logs, consider temporary block.",
    RISK_LOW:      "Log and monitor. No immediate action required.",
    RISK_INFO:     "Informational. No enrichment data. Manual review recommended.",
}

def _fmt_ts(ts):
    if ts is None: return "N/A"
    if isinstance(ts, (int, float)):
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            return str(ts)
    return str(ts)

def build_report(alert, enrichment_results):
    rule     = alert.get("rule", {})
    agent    = alert.get("agent", {})
    data     = alert.get("data", {})
    src_ip   = data.get("srcip", "") or data.get("src_ip", "")
    dst_ip   = data.get("dstip", "") or data.get("dst_ip", "")
    ts       = alert.get("timestamp", datetime.now(timezone.utc).isoformat())
    overall  = compute_overall_risk(enrichment_results)

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
                "first_seen":       _fmt_ts(r.otx.get("first_seen")),
                "last_seen":        _fmt_ts(r.otx.get("last_seen")),
            }
        ioc_summaries.append(summary)

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
        "network": {"source_ip": src_ip, "dest_ip": dst_ip},
        "risk": {
            "overall":            overall,
            "recommended_action": _RISK_ACTIONS[overall],
            "ioc_count":          len(enrichment_results),
        },
        "iocs": ioc_summaries,
    }

def render_markdown(report):
    a    = report["alert"]
    h    = report["host"]
    net  = report["network"]
    risk = report["risk"]
    emoji = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","INFO":"⚪"}.get(risk["overall"],"⚪")

    lines = [
        f"# {emoji} Wazuh Alert Enrichment Report",
        f"**Generated:** {report['generated_at']}",
        "",
        "## 🔎 Alert Details",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Rule ID | `{a['rule_id']}` |",
        f"| Rule Name | {a['rule_name']} |",
        f"| Timestamp | {a['timestamp']} |",
        f"| Severity | {a['severity']} |",
        f"| Groups | {', '.join(a['groups']) or 'N/A'} |",
        "",
        "## 🖥️ Affected Host",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Hostname | `{h['name']}` |",
        f"| Host IP | `{h['ip']}` |",
        f"| Agent ID | `{h['id']}` |",
        "",
        "## 🌐 Network",
        f"| Source IP | `{net['source_ip'] or 'N/A'}` |",
        f"| Dest IP   | `{net['dest_ip'] or 'N/A'}` |",
        "",
        f"## ⚠️ Risk Assessment",
        f"**Overall Risk: {emoji} {risk['overall']}**",
        "",
        f"**Action:** {risk['recommended_action']}",
        f"**IOCs Processed:** {risk['ioc_count']}",
        "",
    ]

    if report["iocs"]:
        lines.append("## 🧾 IOC Enrichment Results")
        for ioc in report["iocs"]:
            ie = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","INFO":"⚪"}.get(ioc["risk"],"⚪")
            lines.append(f"\n### {ie} {ioc['type'].upper()}: `{ioc['value']}`")
            lines.append(f"**Risk:** {ioc['risk']}  |  **Cached:** {'Yes' if ioc['from_cache'] else 'No'}")
            if "virustotal" in ioc:
                vt = ioc["virustotal"]
                lines.append(f"\n**VirusTotal:** {vt['detection_ratio']} detections | First: {vt['first_seen']} | Last: {vt['last_seen']}")
                if vt["malware_families"]:
                    lines.append(f"- Malware: {vt['malware_families']}")
            if "abuseipdb" in ioc:
                ab = ioc["abuseipdb"]
                lines.append(f"\n**AbuseIPDB:** Score {ab['abuse_score']}/100 | Reports: {ab['total_reports']} | Country: {ab['country']} | TOR: {'Yes' if ab['is_tor'] else 'No'}")
            if "otx" in ioc:
                otx = ioc["otx"]
                lines.append(f"\n**OTX:** {otx['pulse_count']} pulses | {otx['malware_families']}")
            if ioc["errors"]:
                lines.append(f"\n⚠️ Errors: {';'.join(ioc['errors'])}")

    lines.append("\n---\n*Generated by Wazuh Enrichment Pipeline — internal use only*")
    return "\n".join(lines)
