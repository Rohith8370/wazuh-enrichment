"""
main.py (metrics-enabled) — drop-in replacement for enrichment-worker/main.py.
Adds Prometheus instrumentation without changing any pipeline logic.

New metrics exposed on :9090/metrics:
  enrichment_alerts_processed_total        counter  {risk_level}
  enrichment_alerts_failed_total           counter
  enrichment_queue_depth                   gauge
  enrichment_dlq_depth                     gauge
  enrichment_api_latency_seconds           summary  {provider}
  enrichment_api_errors_total              counter  {provider}
  enrichment_processing_duration_seconds   summary
"""

import json
import logging
import os
import signal
import sys
import time

import redis

from extractor  import extract_iocs
from cache      import get_cached, set_cached
from enricher   import enrich_ioc
from reporter   import build_report
from notifier   import send_notifications
from metrics    import init_metrics, inc, set_gauge, observe

# ── Config ───────────────────────────────────────────────────────────────────

REDIS_HOST   = os.getenv("REDIS_HOST",   "redis")
REDIS_PORT   = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASS   = os.getenv("REDIS_PASSWORD", "") or None
QUEUE_KEY    = os.getenv("QUEUE_KEY",    "wazuh:alerts")
DLQ_KEY      = QUEUE_KEY + ":dlq"
LOG_LEVEL    = os.getenv("LOG_LEVEL",   "INFO")
METRICS_PORT = int(os.getenv("METRICS_PORT", "9090"))
BLPOP_TIMEOUT = 30

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s  %(levelname)-8s %(name)-20s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("worker.main")

# ── Graceful shutdown ────────────────────────────────────────────────────────

_running = True

def _handle_signal(sig, frame):
    global _running
    log.info("Shutdown signal received")
    _running = False

signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT,  _handle_signal)

# ── Redis connection ─────────────────────────────────────────────────────────

def connect_redis() -> redis.Redis:
    while _running:
        try:
            r = redis.Redis(
                host=REDIS_HOST, port=REDIS_PORT,
                password=REDIS_PASS, decode_responses=True,
                socket_timeout=35, socket_connect_timeout=5,
            )
            r.ping()
            log.info(f"Connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
            return r
        except Exception as e:
            log.warning(f"Redis unavailable ({e}), retrying in 5s...")
            time.sleep(5)

# ── Queue depth updater ──────────────────────────────────────────────────────

def _update_queue_metrics(r: redis.Redis):
    """Refresh queue and DLQ depth gauges."""
    try:
        set_gauge("enrichment_queue_depth", r.llen(QUEUE_KEY))
        set_gauge("enrichment_dlq_depth",   r.llen(DLQ_KEY))
    except Exception:
        pass

# ── Alert processor ──────────────────────────────────────────────────────────

def process_alert(alert: dict, r: redis.Redis):
    alert_id = alert.get("id", "unknown")
    rule_id  = alert.get("rule", {}).get("id", "0")
    t_start  = time.time()

    log.info(f"Processing alert_id={alert_id} rule_id={rule_id}")

    # Extract IOCs
    iocs = extract_iocs(alert)
    if not iocs:
        log.info(f"No IOCs found in alert_id={alert_id}, skipping")
        inc("enrichment_alerts_processed_total", labels={"risk_level": "INFO"})
        return

    log.info(f"IOC extraction complete | ioc_count={len(iocs)}")

    # Enrich each IOC — measure per-provider latency
    enriched = []
    for ioc in iocs:
        cached = get_cached(r, ioc)
        if cached:
            enriched.append(cached)
            continue

        result = {}
        for provider in ["virustotal", "abuseipdb", "otx"]:
            t0 = time.time()
            try:
                data = enrich_ioc(ioc, provider)
                result[provider] = data
                observe("enrichment_api_latency_seconds", time.time() - t0,
                        labels={"provider": provider})
            except Exception as e:
                log.warning(f"Enrichment failed provider={provider} ioc={ioc}: {e}")
                inc("enrichment_api_errors_total", labels={"provider": provider})

        set_cached(r, ioc, result)
        enriched.append(result)

    # Build report and score risk
    report = build_report(alert, iocs, enriched)
    risk   = report.get("risk_level", "INFO")

    log.info(f"Risk scored | risk={risk} ioc_count={len(iocs)}")

    # Send notifications
    results = send_notifications(report)

    # Record metrics
    inc("enrichment_alerts_processed_total", labels={"risk_level": risk})
    observe("enrichment_processing_duration_seconds", time.time() - t_start)

    elapsed = round(time.time() - t_start, 2)
    log.info(
        f"AUDIT | alert_id={alert_id} risk={risk} "
        f"ioc_count={len(iocs)} slack={results.get('slack')} elapsed={elapsed}s"
    )

# ── Main loop ────────────────────────────────────────────────────────────────

def main():
    log.info("Enrichment worker starting...")
    init_metrics(port=METRICS_PORT)

    r = connect_redis()
    log.info(f"Listening on queue: {QUEUE_KEY}")

    depth_tick = 0

    while _running:
        try:
            # Update queue depth every 10 iterations
            depth_tick += 1
            if depth_tick >= 10:
                _update_queue_metrics(r)
                depth_tick = 0

            result = r.blpop(QUEUE_KEY, timeout=BLPOP_TIMEOUT)
            if result is None:
                continue

            _, raw = result
            try:
                alert = json.loads(raw)
            except json.JSONDecodeError as e:
                log.error(f"Invalid JSON in queue: {e}")
                inc("enrichment_alerts_failed_total")
                continue

            process_alert(alert, r)

        except redis.ConnectionError as e:
            log.error(f"Redis connection lost: {e}. Reconnecting...")
            inc("enrichment_alerts_failed_total")
            time.sleep(2)
            r = connect_redis()

        except Exception as e:
            log.exception(f"Unexpected error processing alert: {e}")
            inc("enrichment_alerts_failed_total")
            try:
                r.rpush(DLQ_KEY, raw)
                log.warning(f"Alert moved to DLQ")
            except Exception:
                pass

    log.info("Worker shut down cleanly")

if __name__ == "__main__":
    main()
