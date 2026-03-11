import os
import logging
import requests
from requests.auth import HTTPBasicAuth
import threading
import time

logger = logging.getLogger("jira_client")

JIRA_URL       = os.getenv("JIRA_URL")
JIRA_EMAIL     = os.getenv("JIRA_EMAIL")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")
JIRA_PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY", "KAN")

if not JIRA_URL:
    raise ValueError("JIRA_URL environment variable not set")

JIRA_API = f"{JIRA_URL}/rest/api/3"

auth = HTTPBasicAuth(JIRA_EMAIL, JIRA_API_TOKEN)

headers = {
    "Accept": "application/json",
    "Content-Type": "application/json"
}

PRIORITY_MAP = {
    "CRITICAL": "Highest",
    "HIGH":     "High",
    "MEDIUM":   "Medium",
    "LOW":      "Low"
}

# Rules that always create a Jira ticket regardless of risk level
ALWAYS_TICKET_RULES = {"5715"}  # SSH authentication success

def create_ticket(alert, risk, slack_permalink=None):
    rule_id = alert.get("rule", {}).get("id", "")
    if risk == "INFO" and rule_id not in ALWAYS_TICKET_RULES:
        logger.info("Jira ticket skipped — risk=%s rule_id=%s", risk, rule_id)
        return None

    try:
        priority = PRIORITY_MAP.get(risk, "Medium")
        rule     = alert.get("rule", {})
        agent    = alert.get("agent", {})
        data     = alert.get("data", {})

        summary = f"[{risk}] {rule.get('description')} — {agent.get('name')}"

        description_text = (
            f"Risk Level: {risk}\n"
            f"Timestamp: {alert.get('timestamp')}\n"
            f"Rule: {rule.get('id')} — {rule.get('description')}\n"
            f"Agent: {agent.get('name')} ({agent.get('ip')})\n"
            f"Source IP: {data.get('srcip')}\n"
        )
        payload = {
            "fields": {
                "project":     {"key": JIRA_PROJECT_KEY},
                "summary":     summary,
                "description": {
                    "type": "doc", "version": 1,
                    "content": [{
                        "type": "paragraph",
                        "content": [{"type": "text", "text": description_text}]
                    }] + ([{
                        "type": "paragraph",
                        "content": [
                            {"type": "text", "text": "Slack Alert: "},
                            {"type": "text", "text": slack_permalink,
                             "marks": [{"type": "link", "attrs": {"href": slack_permalink}}]}
                        ]
                    }] if slack_permalink else [])
                },
                "issuetype": {"name": "Task"},
                "priority":  {"name": priority}
            }
        }

        resp = requests.post(
            f"{JIRA_API}/issue",
            headers=headers,
            json=payload,
            auth=auth,
            timeout=15
        )
        resp.raise_for_status()
        ticket_key = resp.json().get("key")
        logger.info("Jira ticket created: %s", ticket_key)
        return {"key": ticket_key, "url": f"{JIRA_URL}/browse/{ticket_key}"}

    except Exception as e:
        logger.error("Jira error: %s", e)
        return None


def poll_jira_status():
    try:
        resp = requests.get(
            f"{JIRA_API}/search/jql",
            headers=headers,
            auth=auth,
            params={
                "jql":       f"project={JIRA_PROJECT_KEY}",
                "fields":    "status",
                "maxResults": 1000
            },
            timeout=10
        )
        resp.raise_for_status()
        issues = resp.json().get("issues", [])

        todo = sum(1 for i in issues if i["fields"]["status"]["name"] == "To Do")
        in_progress = sum(1 for i in issues if i["fields"]["status"]["name"] == "In Progress")
        done = sum(1 for i in issues if i["fields"]["status"]["name"] == "Done")

        logger.info("Jira poll: todo=%s in_progress=%s done=%s", todo, in_progress, done)
        return {"todo": todo, "in_progress": in_progress, "done": done}

    except Exception as e:
        logger.error("Jira poll error: %s", e)
        return {"todo": 0, "in_progress": 0, "done": 0}


def start_status_poller(interval=60):
    def poll_loop():
        logger.info("Jira status poller started (%ss interval)", interval)
        while True:
            try:
                poll_jira_status()
            except Exception as e:
                logger.error("Jira poll loop error: %s", e)
            time.sleep(interval)

    thread = threading.Thread(target=poll_loop, daemon=True)
    thread.start()
