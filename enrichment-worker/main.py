import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone

import redis

import cache
import extractor
import enricher
import reporter
import notifier

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("worker.main")

REDIS_HOST     = os.getenv("REDIS_HOST", "redis")
REDIS_PORT     = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
QUEUE_KEY      = os.getenv("QUEUE_KEY", "wazuh:alerts")
DLQ_KEY        = f"{QUEUE_KEY}:dlq"
BLPOP_TIMEOUT  = 30

_running = True

def _handle_shutdown(signum, frame):
    global _running
    logger.info("Shutdown signal received — stopping")
    _running = False

signal.signal(signal.SIGTERM, _handle_shutdown)
signal.signal(signal.SIGINT,  _handle_shutdown)

def _connect_redis():
    attempt = 0
    while _running:
        try:
            client = redis.Redis(
                host=REDIS_HOST, port=REDIS_PORT,
                password=REDIS_PASSWORD or None,
                decode_responses=True,
                socket_connect_timeout=5, socket_timeout=35,
            )
            client.ping()
            logger.info("Connected to Redis at %s:%s", REDIS_HOST, REDIS_PORT)
            return client
        except redis.RedisError as exc:
            attempt += 1
            wait = min(2 ** attempt, 60)
            logger.warning("Redis connection failed (attempt %d): %s — retrying in %ds", attempt, exc, wait)
            time.sleep(wait)
    sys.exit(0)

def process_alert(raw_json):
    start = time.monotonic()
    try:
        alert = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse alert JSON: %s", exc)
        return False

    alert_id  = alert.get("id", "unknown")
    rule_id   = alert.get("rule", {}).get("id", "unknown")
    rule_name = alert.get("rule", {}).get("description", "unknown")
    logger.info("Processing alert_id=%s rule_id=%s rule=%s", alert_id, rule_id, rule_name)

    iocs = extractor.extract(alert)
    enrichment_results = enricher.enrich_all(iocs) if not iocs.is_empty() else []

    report       = reporter.build_report(alert, enrichment_results)
    overall_risk = report["risk"]["overall"]
    delivery     = notifier.deliver(report)
    elapsed      = time.monotonic() - start

    logger.info(
        "AUDIT | alert_id=%s rule_id=%s risk=%s ioc_count=%d email=%s teams=%s elapsed=%.2fs",
        alert_id, rule_id, overall_risk, len(enrichment_results),
        delivery.get("email"), delivery.get("teams"), elapsed,
    )
    return any(delivery.values())

def _push_dlq(client, raw_json, reason):
    try:
        client.rpush(DLQ_KEY, json.dumps({
            "failed_at": datetime.now(timezone.utc).isoformat(),
            "reason": reason, "raw": raw_json,
        }))
    except Exception as exc:
        logger.error("Failed to push to DLQ: %s", exc)

def run():
    logger.info("Enrichment worker starting | queue=%s", QUEUE_KEY)
    client = _connect_redis()
    while _running:
        try:
            result = client.blpop(QUEUE_KEY, timeout=BLPOP_TIMEOUT)
            if result is None:
                logger.debug("Queue empty — waiting...")
                continue
            _, raw_json = result
            try:
                success = process_alert(raw_json)
                if not success:
                    _push_dlq(client, raw_json, "processing_failed")
            except Exception as exc:
                logger.exception("Unhandled error: %s", exc)
                _push_dlq(client, raw_json, f"exception: {exc}")
        except redis.ConnectionError as exc:
            logger.error("Redis lost: %s — reconnecting", exc)
            time.sleep(5)
            client = _connect_redis()
        except redis.RedisError as exc:
            logger.error("Redis error: %s", exc)
            time.sleep(2)
    logger.info("Worker stopped.")

if __name__ == "__main__":
    run()
