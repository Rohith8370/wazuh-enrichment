"""
main.py — metrics-enabled queue worker.
"""

import json
import logging
import os
import signal
import time

import redis

from extractor    import extract
from enricher     import enrich_all, _vt_query, _abuseipdb_query, _otx_query
from reporter     import build_report
from notifier     import deliver
from jira_client  import create_ticket, start_jira_poller
from cache        import get as cache_get, set as cache_set, exists as cache_exists
from metrics      import init_metrics, inc, set_gauge, observe

REDIS_HOST    = os.getenv("REDIS_HOST",    "redis")
REDIS_PORT    = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASS    = os.getenv("REDIS_PASSWORD", "") or None
QUEUE_KEY     = os.getenv("QUEUE_KEY",     "wazuh:alerts")
DLQ_KEY       = QUEUE_KEY + ":dlq"
LOG_LEVEL     = os.getenv("LOG_LEVEL",    "INFO")
METRICS_PORT  = int(os.getenv("METRICS_PORT", "9090"))
BLPOP_TIMEOUT = 30

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("worker.main")

_running = True

def _handle_signal(sig, frame):
    global _running
    log.info("Shutdown signal received")
    _running = False

signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT,  _handle_signal)


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


def _enrich_with_latency(iocs):
    """Enrich all IOCs and record per-provider latency metrics."""
    from enricher import enrich_ioc, _vt_query, _abuseipdb_query, _otx_query, EnrichmentResult
    from cache import get as cache_get
    results = []

    all_ioc_list = (
        [("ip", v) for v in iocs.ips] +
        [("sha256", v) for v in iocs.hashes["sha256"]] +
        [("sha1",   v) for v in iocs.hashes["sha1"]] +
        [("md5",    v) for v in iocs.hashes["md5"]] +
        [("domain", v) for v in iocs.domains] +
        [("url",    v) for v in iocs.urls]
    )

    for ioc_type, ioc_value in all_ioc_list:
        cached = cache_get(ioc_type, ioc_value)
        if cached:
            results.append(EnrichmentResult(
                ioc_type=ioc_type, ioc_value=ioc_value,
                virustotal=cached.get("virustotal"),
                abuseipdb=cached.get("abuseipdb"),
                otx=cached.get("otx"),
                from_cache=True,
            ))
            continue

        result = EnrichmentResult(ioc_type=ioc_type, ioc_value=ioc_value)

        # VirusTotal
        t0 = time.time()
        vt = _vt_query(ioc_type, ioc_value)
        observe("enrichment_api_latency_seconds", time.time() - t0,
                labels={"provider": "virustotal"})
        if "error" not in vt:
            result.virustotal = vt
        else:
            result.errors.append(f"VirusTotal: {vt['error']}")

        # AbuseIPDB (IP only)
        if ioc_type == "ip":
            t0 = time.time()
            abuse = _abuseipdb_query(ioc_value)
            observe("enrichment_api_latency_seconds", time.time() - t0,
                    labels={"provider": "abuseipdb"})
            if "error" not in abuse:
                result.abuseipdb = abuse
            else:
                result.errors.append(f"AbuseIPDB: {abuse['error']}")

        # AlienVault OTX
        t0 = time.time()
        from enricher import _otx_query
        otx = _otx_query(ioc_type, ioc_value)
        observe("enrichment_api_latency_seconds", time.time() - t0,
                labels={"provider": "otx"})
        if "error" not in otx:
            result.otx = otx
        else:
            result.errors.append(f"OTX: {otx['error']}")

        from cache import set as cache_set
        cache_set(ioc_type, ioc_value, {
            "virustotal": result.virustotal,
            "abuseipdb":  result.abuseipdb,
            "otx":        result.otx,
        })
        results.append(result)

    return results


def process_alert(alert: dict, r: redis.Redis):
    alert_id = alert.get("id", "unknown")
    rule_id  = alert.get("rule", {}).get("id", "0")
    rule     = alert.get("rule", {}).get("description", "")
    t_start  = time.time()

    log.info(f"Processing alert_id={alert_id} rule_id={rule_id} rule={rule}")

    # Extract IOCs
    iocs = extract(alert)
    ioc_count = sum([
        len(iocs.ips), len(iocs.domains), len(iocs.urls),
        len(iocs.hashes["md5"]), len(iocs.hashes["sha1"]), len(iocs.hashes["sha256"])
    ])

    log.info(f"IOC extraction complete | ioc_count={ioc_count}")

    if ioc_count == 0:
        inc("enrichment_alerts_processed_total", labels={"risk_level": "INFO"})
        report = build_report(alert, [])
        results = deliver(report)
        slack_permalink = results.get("slack_permalink", "")
        create_ticket(report, slack_permalink)
        return

    # Enrich with per-provider latency tracking
    enrichment_results = _enrich_with_latency(iocs)

    # Build report
    report = build_report(alert, enrichment_results)
    risk   = report.get("risk", {}).get("overall", "INFO")

    log.info(f"Risk scored | risk={risk} ioc_count={ioc_count}")

    # Deliver to Slack (returns permalink)
    results         = deliver(report)
    slack_permalink = results.get("slack_permalink", "")

    # Create Jira ticket
    ticket = create_ticket(report, slack_permalink)
    if ticket:
        log.info(f"Jira ticket: {ticket['key']} — {ticket['url']}")

    # Record metrics
    inc("enrichment_alerts_processed_total", labels={"risk_level": risk})
    observe("enrichment_processing_duration_seconds", time.time() - t_start)

    elapsed = round(time.time() - t_start, 2)
    log.info(
        f"AUDIT | alert_id={alert_id} rule_id={rule_id} risk={risk} "
        f"ioc_count={ioc_count} slack={results.get('slack')} "
        f"jira={ticket['key'] if ticket else 'skipped'} elapsed={elapsed}s"
    )


def main():
    log.info("Enrichment worker starting...")
    init_metrics(port=METRICS_PORT)
    start_jira_poller()

    r = connect_redis()
    log.info(f"Listening on queue: {QUEUE_KEY}")

    depth_tick = 0
    raw = None

    while _running:
        try:
            depth_tick += 1
            if depth_tick >= 10:
                set_gauge("enrichment_queue_depth", r.llen(QUEUE_KEY))
                set_gauge("enrichment_dlq_depth",   r.llen(DLQ_KEY))
                depth_tick = 0

            result = r.blpop(QUEUE_KEY, timeout=BLPOP_TIMEOUT)
            if result is None:
                continue

            _, raw = result
            try:
                alert = json.loads(raw)
            except json.JSONDecodeError as e:
                log.error(f"Invalid JSON: {e}")
                inc("enrichment_alerts_failed_total")
                continue

            process_alert(alert, r)

        except redis.ConnectionError as e:
            log.error(f"Redis connection lost: {e}. Reconnecting...")
            inc("enrichment_alerts_failed_total")
            time.sleep(2)
            r = connect_redis()

        except Exception as e:
            log.exception(f"Unexpected error: {e}")
            inc("enrichment_alerts_failed_total")
            try:
                if raw:
                    r.rpush(DLQ_KEY, raw)
                    log.warning("Alert moved to DLQ")
            except Exception:
                pass

    log.info("Worker shut down cleanly")


if __name__ == "__main__":
    main()
