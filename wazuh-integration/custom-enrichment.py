#!/usr/bin/env python3
import json
import logging
import os
import sys
import time

LOG_FILE = os.getenv("INTEGRATION_LOG", "/var/ossec/logs/integrations.log")
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
    format="%(asctime)s [%(levelname)s] custom-enrichment — %(message)s")
logger = logging.getLogger(__name__)

REDIS_HOST     = os.getenv("REDIS_HOST", "127.0.0.1")
REDIS_PORT     = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
QUEUE_KEY      = os.getenv("QUEUE_KEY", "wazuh:alerts")
MAX_RETRIES    = 3

def push_to_queue(alert_json):
    try:
        import redis as redis_lib
    except ImportError:
        logger.error("redis-py not installed")
        return False
    attempt = 0
    while attempt < MAX_RETRIES:
        try:
            client = redis_lib.Redis(
                host=REDIS_HOST, port=REDIS_PORT,
                password=REDIS_PASSWORD or None,
                decode_responses=True,
                socket_connect_timeout=5, socket_timeout=5,
            )
            client.rpush(QUEUE_KEY, alert_json)
            return True
        except Exception as exc:
            attempt += 1
            logger.warning("Redis push failed (attempt %d/%d): %s", attempt, MAX_RETRIES, exc)
            if attempt < MAX_RETRIES:
                time.sleep(2 ** attempt)
    return False

def main():
    if len(sys.argv) < 2:
        logger.error("No alert file path provided")
        sys.exit(1)
    try:
        with open(sys.argv[1], "r", encoding="utf-8") as fh:
            raw = fh.read().strip()
    except OSError as exc:
        logger.error("Cannot read alert file: %s", exc)
        sys.exit(1)
    try:
        alert = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON: %s", exc)
        sys.exit(1)

    alert_id = alert.get("id", "unknown")
    logger.info("Received alert_id=%s rule=%s", alert_id, alert.get("rule", {}).get("id", "?"))

    if push_to_queue(raw):
        logger.info("alert_id=%s pushed to queue", alert_id)
        sys.exit(0)
    else:
        logger.error("alert_id=%s FAILED to push", alert_id)
        sys.exit(1)

if __name__ == "__main__":
    main()
