import logging
import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import requests
from reporter import render_markdown, RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM, RISK_LOW

logger = logging.getLogger(__name__)

SMTP_HOST     = os.getenv("SMTP_HOST", "")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER", "")
SMTP_PASS     = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM     = os.getenv("SMTP_FROM", "wazuh@localhost")
SMTP_TO       = [a.strip() for a in os.getenv("SMTP_TO", "").split(",") if a.strip()]
TEAMS_WEBHOOK = os.getenv("TEAMS_WEBHOOK_URL", "")
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL", "")

_RISK_EMOJI = {
    RISK_CRITICAL: ":red_circle:",
    RISK_HIGH:     ":large_orange_circle:",
    RISK_MEDIUM:   ":large_yellow_circle:",
    RISK_LOW:      ":large_green_circle:",
    "INFO":        ":white_circle:",
}


def _subject(report):
    risk  = report["risk"]["overall"]
    emoji = _RISK_EMOJI.get(risk, ":white_circle:")
    rule  = report["alert"]["rule_name"]
    host  = report["host"]["name"]
    return "{} [{}] Wazuh: {} | {}".format(emoji, risk, rule, host)


def _verdict_str(ioc):
    mal_vt = False
    mal_abuse = False
    mal_otx = False
    if "virustotal" in ioc:
        try:
            detected = int(ioc["virustotal"].get("detection_ratio", "0/0").split("/")[0])
            mal_vt = detected > 0
        except Exception:
            pass
    if "abuseipdb" in ioc:
        mal_abuse = ioc["abuseipdb"].get("abuse_score", 0) >= 25
    if "otx" in ioc:
        mal_otx = ioc["otx"].get("pulse_count", 0) > 0
    if mal_vt or mal_abuse or mal_otx:
        return ":biohazard_sign: *MALICIOUS*"
    return ":white_check_mark: *CLEAN / UNKNOWN*"


def _build_slack_blocks(report):
    a    = report["alert"]
    h    = report["host"]
    net  = report["network"]
    risk = report["risk"]
    r    = risk["overall"]
    emoji = _RISK_EMOJI.get(r, ":white_circle:")
    blocks = []

    blocks.append({
        "type": "header",
        "text": {"type": "plain_text", "text": "WAZUH ALERT - {}".format(r), "emoji": True}
    })

    blocks.append({"type": "divider"})

    groups = ", ".join(a.get("groups", [])) or "N/A"
    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": (
                "{} *{}*\n"
                ":clipboard: *Rule:* {} _(ID: {})_\n"
                ":warning: *Severity:* {} | *Groups:* {}\n"
                ":computer: *Host:* `{}` | *Agent IP:* `{}`\n"
                ":globe_with_meridians: *Source IP:* `{}` | *Dest IP:* `{}`"
            ).format(
                emoji, a["rule_name"],
                a["rule_name"], a["rule_id"],
                a["severity"], groups,
                h["name"], h["ip"],
                net["source_ip"] or "N/A",
                net["dest_ip"] or "N/A",
            )
        }
    })

    descriptions = {
        "5710": "Multiple failed SSH login attempts detected. Indicates a brute force or credential stuffing attack targeting SSH service.",
        "5712": "SSH login succeeded after multiple failures. Possible successful brute force compromise - investigate immediately.",
        "5503": "User authentication failure. An account may be under attack.",
        "31151": "Web attack detected. Possible SQL injection or XSS attempt against a web application.",
        "1002": "Unknown system problem detected. Review full logs for additional context.",
    }
    rule_desc = descriptions.get(
        str(a["rule_id"]),
        "Security event detected by Wazuh. Review the alert details and enrichment results below for context."
    )
    blocks.append({
        "type": "section",
        "text": {"type": "mrkdwn", "text": ":mag: *What this alert means:*\n{}".format(rule_desc)}
    })

    if report["iocs"]:
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": ":label: *IOC Enrichment Results*"}
        })

        for ioc in report["iocs"]:
            verdict = _verdict_str(ioc)
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*{} `{}`*\nOverall Verdict: {}".format(
                        ioc["type"].upper(), ioc["value"], verdict
                    )
                }
            })

            if "virustotal" in ioc:
                vt = ioc["virustotal"]
                try:
                    parts    = vt.get("detection_ratio", "0/0").split("/")
                    detected = int(parts[0])
                    total    = int(parts[1]) if len(parts) > 1 else 0
                    vt_v     = ":biohazard_sign: MALICIOUS" if detected > 0 else ":white_check_mark: CLEAN"
                except Exception:
                    detected, total, vt_v = 0, 0, ":question: UNKNOWN"
                families = vt.get("malware_families", [])
                fam_str  = ", ".join(str(f) for f in families[:3]) if families else "None identified"
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            ":vt: *VirusTotal*\n"
                            ">Verdict: *{}*\n"
                            ">Detection: *{}/{}* engines flagged this IOC\n"
                            ">Malware Family: {}\n"
                            ">First Seen: {} | Last Seen: {}"
                        ).format(
                            vt_v, detected, total, fam_str,
                            vt.get("first_seen", "N/A"),
                            vt.get("last_seen", "N/A"),
                        )
                    }
                })

            if "abuseipdb" in ioc:
                ab    = ioc["abuseipdb"]
                score = ab.get("abuse_score", 0)
                ab_v  = ":biohazard_sign: MALICIOUS" if score >= 25 else ":white_check_mark: CLEAN"
                tor   = ":warning: YES - TOR Exit Node" if ab.get("is_tor") else "No"
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            ":shield: *AbuseIPDB*\n"
                            ">Verdict: *{}*\n"
                            ">Abuse Confidence Score: *{}/100*\n"
                            ">Total Reports: {} | Last Reported: {}\n"
                            ">Country: {} | ISP: {}\n"
                            ">TOR Exit Node: {}"
                        ).format(
                            ab_v, score,
                            ab.get("total_reports", 0),
                            ab.get("last_reported", "N/A"),
                            ab.get("country", "N/A"),
                            ab.get("isp", "N/A"),
                            tor,
                        )
                    }
                })

            if "otx" in ioc:
                otx    = ioc["otx"]
                pulses = otx.get("pulse_count", 0)
                otx_v  = ":biohazard_sign: MALICIOUS" if pulses > 0 else ":white_check_mark: CLEAN"
                fams   = otx.get("malware_families", [])
                fam_str = ", ".join(fams[:3]) if fams else "None identified"
                tags    = otx.get("tags", [])
                tag_str = ", ".join(tags[:5]) if tags else "None"
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            ":alien: *AlienVault OTX*\n"
                            ">Verdict: *{}*\n"
                            ">Threat Pulses: *{}* intelligence reports reference this IOC\n"
                            ">Malware Family: {}\n"
                            ">Tags: {}\n"
                            ">Country: {} | First Seen: {}"
                        ).format(
                            otx_v, pulses, fam_str, tag_str,
                            otx.get("country", "N/A"),
                            otx.get("first_seen", "N/A"),
                        )
                    }
                })

            blocks.append({"type": "divider"})

    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": "{} *Risk: {}*\n:rotating_light: *Action:* {}".format(
                emoji, r, risk["recommended_action"]
            )
        }
    })

    blocks.append({"type": "divider"})
    blocks.append({
        "type": "context",
        "elements": [{
            "type": "mrkdwn",
            "text": ":lock: Wazuh Enrichment Pipeline | {} | ID: {} | Internal Use Only".format(
                report["generated_at"][:19].replace("T", " "),
                report["alert"]["id"]
            )
        }]
    })

    return blocks


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
                s.ehlo()
                s.starttls(context=ctx)
                s.ehlo()
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
    risk  = report["risk"]["overall"]
    emoji = _RISK_EMOJI.get(risk, ":white_circle:")
    a     = report["alert"]
    h     = report["host"]
    net   = report["network"]
    ri    = report["risk"]
    color = {
        RISK_CRITICAL: "Attention", RISK_HIGH: "Attention",
        RISK_MEDIUM: "Warning", RISK_LOW: "Good", "INFO": "Default",
    }.get(risk, "Default")
    card = {
        "type": "message",
        "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard", "version": "1.4",
            "body": [
                {"type": "TextBlock", "text": "{} Wazuh Alert - {}".format(emoji, risk),
                 "size": "Large", "weight": "Bolder", "color": color},
                {"type": "FactSet", "facts": [
                    {"title": "Rule",      "value": "{} (ID: {})".format(a["rule_name"], a["rule_id"])},
                    {"title": "Timestamp", "value": a["timestamp"]},
                    {"title": "Host",      "value": h["name"]},
                    {"title": "Source IP", "value": net["source_ip"] or "N/A"},
                    {"title": "Dest IP",   "value": net["dest_ip"]   or "N/A"},
                ]},
                {"type": "TextBlock",
                 "text": "{} - {}".format(risk, ri["recommended_action"]), "wrap": True},
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


def send_slack(report):
    if not SLACK_WEBHOOK:
        logger.warning("Slack not configured - skipping")
        return False
    try:
        blocks   = _build_slack_blocks(report)
        risk     = report["risk"]["overall"]
        fallback = "[{}] Wazuh: {} on {}".format(
            risk, report["alert"]["rule_name"], report["host"]["name"]
        )
        resp = requests.post(
            SLACK_WEBHOOK,
            json={"text": fallback, "blocks": blocks},
            timeout=10
        )
        resp.raise_for_status()
        logger.info("Slack notification sent")
        return True
    except Exception as exc:
        logger.error("Slack error: %s", exc)
        return False


def deliver(report):
    results = {
        "email": send_email(report),
        "teams": send_teams(report),
        "slack": send_slack(report),
    }
    logger.info("Delivery results: %s", results)
    return results
