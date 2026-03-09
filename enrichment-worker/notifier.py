import logging
import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from reporter import render_markdown, RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM, RISK_LOW

logger = logging.getLogger(__name__)

SMTP_HOST      = os.getenv("SMTP_HOST", "")
SMTP_PORT      = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER      = os.getenv("SMTP_USER", "")
SMTP_PASS      = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM      = os.getenv("SMTP_FROM", "wazuh@localhost")
SMTP_TO        = [a.strip() for a in os.getenv("SMTP_TO", "").split(",") if a.strip()]
TEAMS_WEBHOOK  = os.getenv("TEAMS_WEBHOOK_URL", "")
SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN", "")
SLACK_CHANNEL  = os.getenv("SLACK_CHANNEL", "wazuh-alerts")

_RISK_PRIORITY = {
    RISK_CRITICAL: "P1 - CRITICAL",
    RISK_HIGH:     "P2 - HIGH",
    RISK_MEDIUM:   "P3 - MEDIUM",
    RISK_LOW:      "P4 - LOW",
    "INFO":        "P5 - INFO",
}


def _subject(report):
    risk = report["risk"]["overall"]
    rule = report["alert"]["rule_name"]
    host = report["host"]["name"]
    return "[{}] Wazuh: {} | {}".format(risk, rule, host)


def _build_slack_blocks(report):
    a      = report["alert"]
    h      = report["host"]
    net    = report["network"]
    risk   = report["risk"]
    geo    = report.get("geoip", {})
    mitre  = report.get("mitre", {})
    r      = risk["overall"]
    blocks = []

    # ── Header ──────────────────────────────────────────────────────
    blocks.append({
        "type": "header",
        "text": {"type": "plain_text", "text": f"WAZUH SECURITY ALERT  |  {r}", "emoji": False}
    })

    blocks.append({"type": "divider"})

    # ── Section 1: Alert Info ────────────────────────────────────────
    blocks.append({
        "type": "section",
        "text": {"type": "mrkdwn", "text": "*ALERT INFORMATION*"}
    })
    blocks.append({
        "type": "section",
        "fields": [
            {"type": "mrkdwn", "text": f"*Severity*\n{a['severity']} — {_RISK_PRIORITY.get(r, r)}"},
            {"type": "mrkdwn", "text": f"*Rule Description*\n{a['rule_name']}"},
            {"type": "mrkdwn", "text": f"*Rule ID*\n{a['rule_id']}"},
            {"type": "mrkdwn", "text": f"*Timestamp*\n{a['timestamp']}"},
        ]
    })

    blocks.append({"type": "divider"})

    # ── Section 2: Host Info ─────────────────────────────────────────
    blocks.append({
        "type": "section",
        "text": {"type": "mrkdwn", "text": "*HOST INFORMATION*"}
    })
    blocks.append({
        "type": "section",
        "fields": [
            {"type": "mrkdwn", "text": f"*Hostname*\n{h['name']}"},
            {"type": "mrkdwn", "text": f"*Agent ID*\n{h['id']}"},
            {"type": "mrkdwn", "text": f"*Host IP*\n{h['ip']}"},
            {"type": "mrkdwn", "text": f"*Username*\n{net.get('username', 'N/A')}"},
        ]
    })

    blocks.append({"type": "divider"})

    # ── Section 3: Network Info ──────────────────────────────────────
    blocks.append({
        "type": "section",
        "text": {"type": "mrkdwn", "text": "*NETWORK INFORMATION*"}
    })
    blocks.append({
        "type": "section",
        "fields": [
            {"type": "mrkdwn", "text": f"*Source IP*\n{net.get('source_ip') or 'N/A'}"},
            {"type": "mrkdwn", "text": f"*Destination IP*\n{net.get('dest_ip') or 'N/A'}"},
        ]
    })

    blocks.append({"type": "divider"})

    # ── Section 4: GeoIP ─────────────────────────────────────────────
    blocks.append({
        "type": "section",
        "text": {"type": "mrkdwn", "text": "*GEOLOCATION*"}
    })
    blocks.append({
        "type": "section",
        "fields": [
            {"type": "mrkdwn", "text": f"*Country*\n{geo.get('country', 'N/A')}"},
            {"type": "mrkdwn", "text": f"*City*\n{geo.get('city', 'N/A')}"},
            {"type": "mrkdwn", "text": f"*ASN*\n{geo.get('asn', 'N/A')}"},
            {"type": "mrkdwn", "text": f"*ISP / Organization*\n{geo.get('isp', 'N/A')}"},
        ]
    })

    blocks.append({"type": "divider"})

    # ── Section 5: Attack Context ────────────────────────────────────
    blocks.append({
        "type": "section",
        "text": {"type": "mrkdwn", "text": "*ATTACK CONTEXT*"}
    })
    attack_tags = report.get("attack_tags", [])
    tag_str     = ", ".join(attack_tags[:10]) if attack_tags else "N/A"
    techniques  = mitre.get("techniques", [])
    tactic      = mitre.get("tactic", [])
    mitre_str   = "\n".join(techniques[:5]) if techniques else "N/A"
    tactic_str  = ", ".join(tactic) if tactic else "N/A"
    blocks.append({
        "type": "section",
        "fields": [
            {"type": "mrkdwn", "text": f"*Attack Tags*\n{tag_str}"},
            {"type": "mrkdwn", "text": f"*MITRE Tactic*\n{tactic_str}"},
            {"type": "mrkdwn", "text": f"*MITRE Technique*\n{mitre_str}"},
            {"type": "mrkdwn", "text": f"*IOC Count*\n{risk.get('ioc_count', 0)}"},
        ]
    })

    blocks.append({"type": "divider"})

    # ── Section 6: Threat Intelligence ──────────────────────────────
    blocks.append({
        "type": "section",
        "text": {"type": "mrkdwn", "text": "*THREAT INTELLIGENCE*"}
    })

    for ioc in report.get("iocs", []):
        vt_score   = "N/A"
        abuse_score = "N/A"
        abuse_reports = "N/A"
        otx_pulses = "N/A"

        if "virustotal" in ioc:
            vt = ioc["virustotal"]
            vt_score = f"{vt.get('malicious_count', 0)} / {vt.get('total_engines', 0)} engines"

        if "abuseipdb" in ioc:
            ab = ioc["abuseipdb"]
            abuse_score   = f"{ab.get('abuse_score', 0)} / 100"
            abuse_reports = str(ab.get("total_reports", 0))

        if "otx" in ioc:
            otx_pulses = str(ioc["otx"].get("pulse_count", 0))

        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*IOC:* `{ioc['type'].upper()}` — `{ioc['value']}`"}
        })
        blocks.append({
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*VirusTotal Score*\n{vt_score}"},
                {"type": "mrkdwn", "text": f"*AbuseIPDB Confidence*\n{abuse_score}"},
                {"type": "mrkdwn", "text": f"*AbuseIPDB Reports*\n{abuse_reports}"},
                {"type": "mrkdwn", "text": f"*AlienVault OTX Pulses*\n{otx_pulses}"},
            ]
        })

    blocks.append({
        "type": "section",
        "fields": [
            {"type": "mrkdwn", "text": f"*Threat Intelligence Verdict*\n{risk.get('verdict', 'N/A')}"},
            {"type": "mrkdwn", "text": f"*Recommended Action*\n{risk.get('recommended_action', 'N/A')}"},
        ]
    })

    blocks.append({"type": "divider"})

    # ── Section 7: Log Evidence ──────────────────────────────────────
    log_ev = report.get("log_evidence", "N/A")
    if log_ev and log_ev != "N/A":
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*LOG EVIDENCE*"}
        })
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"```{str(log_ev)[:500]}```"}
        })
        blocks.append({"type": "divider"})

    # ── Section 8: Links ─────────────────────────────────────────────
    blocks.append({
        "type": "section",
        "text": {"type": "mrkdwn", "text": "*INVESTIGATION LINKS*"}
    })

    intel_links = report.get("intel_links", [])
    wazuh_link  = report.get("wazuh_link", "")
    link_text   = ""
    for lnk in intel_links[:6]:
        link_text += f"{lnk}\n"
    if wazuh_link:
        link_text += f"Wazuh Dashboard: {wazuh_link}"

    if link_text:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": link_text.strip()}
        })

    blocks.append({"type": "divider"})

    # ── Footer ───────────────────────────────────────────────────────
    blocks.append({
        "type": "context",
        "elements": [{
            "type": "mrkdwn",
            "text": f"{report['generated_at'][:19].replace('T', ' ')} UTC"
        }]
    })

    return blocks


def send_slack(report):
    if not SLACK_BOT_TOKEN:
        logger.warning("Slack not configured - skipping")
        return False, None
    try:
        client   = WebClient(token=SLACK_BOT_TOKEN)
        blocks   = _build_slack_blocks(report)
        risk     = report["risk"]["overall"]
        fallback = "[{}] Wazuh: {} on {}".format(
            risk, report["alert"]["rule_name"], report["host"]["name"]
        )
        response = client.chat_postMessage(
            channel=SLACK_CHANNEL,
            text=fallback,
            blocks=blocks,
            unfurl_links=False,
            unfurl_media=False,
        )
        ts          = response["ts"]
        channel_id  = response["channel"]
        permalink_r = client.chat_getPermalink(channel=channel_id, message_ts=ts)
        permalink   = permalink_r.get("permalink", "")
        logger.info("Slack notification sent — permalink: %s", permalink)
        return True, permalink
    except SlackApiError as exc:
        logger.error("Slack API error: %s", exc.response["error"])
        return False, None
    except Exception as exc:
        logger.error("Slack error: %s", exc)
        return False, None


def send_email(report):
    if not SMTP_HOST or not SMTP_TO:
        logger.warning("Email not configured - skipping")
        return False
    body    = render_markdown(report)
    subject = _subject(report)
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = SMTP_FROM
    msg["To"]      = ", ".join(SMTP_TO)
    msg.attach(MIMEText(body, "plain", "utf-8"))
    try:
        ctx = ssl.create_default_context()
        if SMTP_PORT == 465:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx) as s:
                if SMTP_USER:
                    s.login(SMTP_USER, SMTP_PASS)
                s.sendmail(SMTP_FROM, SMTP_TO, msg.as_string())
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
                s.ehlo(); s.starttls(context=ctx); s.ehlo()
                if SMTP_USER:
                    s.login(SMTP_USER, SMTP_PASS)
                s.sendmail(SMTP_FROM, SMTP_TO, msg.as_string())
        logger.info("Email sent to %s", SMTP_TO)
        return True
    except Exception as exc:
        logger.error("Email error: %s", exc)
        return False


def send_teams(report):
    if not TEAMS_WEBHOOK:
        logger.warning("Teams not configured - skipping")
        return False
    a   = report["alert"]
    h   = report["host"]
    net = report["network"]
    ri  = report["risk"]
    r   = ri["overall"]
    color = {
        RISK_CRITICAL: "Attention", RISK_HIGH: "Attention",
        RISK_MEDIUM: "Warning", RISK_LOW: "Good", "INFO": "Default",
    }.get(r, "Default")
    card = {
        "type": "message",
        "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard", "version": "1.4",
            "body": [
                {"type": "TextBlock", "text": f"Wazuh Alert - {r}",
                 "size": "Large", "weight": "Bolder", "color": color},
                {"type": "FactSet", "facts": [
                    {"title": "Rule",      "value": f"{a['rule_name']} (ID: {a['rule_id']})"},
                    {"title": "Timestamp", "value": a["timestamp"]},
                    {"title": "Host",      "value": h["name"]},
                    {"title": "Source IP", "value": net["source_ip"] or "N/A"},
                ]},
                {"type": "TextBlock", "text": ri["recommended_action"], "wrap": True},
            ]
        }}]
    }
    try:
        resp = requests.post(TEAMS_WEBHOOK, json=card, timeout=10)
        resp.raise_for_status()
        logger.info("Teams notification sent")
        return True
    except Exception as exc:
        logger.error("Teams error: %s", exc)
        return False


def deliver(report):
    slack_ok, slack_permalink = send_slack(report)
    results = {
        "email":           send_email(report),
        "teams":           send_teams(report),
        "slack":           slack_ok,
        "slack_permalink": slack_permalink or "",
    }
    logger.info("Delivery results: %s", results)
    return results
