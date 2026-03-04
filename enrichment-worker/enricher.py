import logging
import os
import time
import threading
from dataclasses import dataclass, field
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import cache
from extractor import ExtractedIOCs

logger = logging.getLogger(__name__)

VT_API_KEY    = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY   = os.getenv("OTX_API_KEY", "")

def _build_session():
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    return session

_SESSION = _build_session()
_REQUEST_TIMEOUT = 15

class RateLimiter:
    def __init__(self, calls, period):
        self._calls  = calls
        self._period = period
        self._lock   = threading.Lock()
        self._history = []

    def wait(self):
        with self._lock:
            now = time.monotonic()
            self._history = [t for t in self._history if now - t < self._period]
            if len(self._history) >= self._calls:
                sleep_for = self._period - (now - self._history[0])
                if sleep_for > 0:
                    time.sleep(sleep_for)
            self._history.append(time.monotonic())

_VT_LIMITER    = RateLimiter(calls=4,  period=60)
_ABUSE_LIMITER = RateLimiter(calls=30, period=60)
_OTX_LIMITER   = RateLimiter(calls=60, period=60)

@dataclass
class EnrichmentResult:
    ioc_type:   str
    ioc_value:  str
    virustotal: Optional[dict] = None
    abuseipdb:  Optional[dict] = None
    otx:        Optional[dict] = None
    errors:     list = field(default_factory=list)
    from_cache: bool = False

def _vt_query(ioc_type, ioc_value):
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not configured"}
    _VT_LIMITER.wait()
    headers = {"x-apikey": VT_API_KEY}
    type_map = {
        "ip":     f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}",
        "md5":    f"https://www.virustotal.com/api/v3/files/{ioc_value}",
        "sha1":   f"https://www.virustotal.com/api/v3/files/{ioc_value}",
        "sha256": f"https://www.virustotal.com/api/v3/files/{ioc_value}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{ioc_value}",
        "url":    f"https://www.virustotal.com/api/v3/urls/{ioc_value}",
    }
    url = type_map.get(ioc_type)
    if not url:
        return {"error": f"Unsupported IOC type: {ioc_type}"}
    try:
        resp = _SESSION.get(url, headers=headers, timeout=_REQUEST_TIMEOUT)
        resp.raise_for_status()
        data  = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        total = sum(stats.values()) if stats else 0
        mal   = stats.get("malicious", 0)
        return {
            "provider":         "virustotal",
            "reputation":       data.get("reputation"),
            "detection_ratio":  f"{mal}/{total}" if total else "N/A",
            "malicious_count":  mal,
            "total_engines":    total,
            "categories":       data.get("categories", {}),
            "first_seen":       data.get("first_submission_date"),
            "last_seen":        data.get("last_analysis_date"),
            "malware_families": data.get("popular_threat_classification", {}).get("popular_threat_name", []),
            "tags":             data.get("tags", []),
        }
    except Exception as exc:
        logger.warning("VT error for %s %s: %s", ioc_type, ioc_value, exc)
        return {"error": str(exc)}

def _abuseipdb_query(ip):
    if not ABUSEIPDB_KEY:
        return {"error": "ABUSEIPDB_API_KEY not configured"}
    _ABUSE_LIMITER.wait()
    try:
        resp = _SESSION.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=_REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        d = resp.json().get("data", {})
        return {
            "provider":      "abuseipdb",
            "abuse_score":   d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "last_reported": d.get("lastReportedAt"),
            "country":       d.get("countryCode", ""),
            "isp":           d.get("isp", ""),
            "is_tor":        d.get("isTor", False),
            "usage_type":    d.get("usageType", ""),
        }
    except Exception as exc:
        logger.warning("AbuseIPDB error for %s: %s", ip, exc)
        return {"error": str(exc)}

def _otx_query(ioc_type, ioc_value):
    if not OTX_API_KEY:
        return {"error": "OTX_API_KEY not configured"}
    _OTX_LIMITER.wait()
    type_map = {
        "ip":     f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc_value}/general",
        "md5":    f"https://otx.alienvault.com/api/v1/indicators/file/{ioc_value}/general",
        "sha1":   f"https://otx.alienvault.com/api/v1/indicators/file/{ioc_value}/general",
        "sha256": f"https://otx.alienvault.com/api/v1/indicators/file/{ioc_value}/general",
        "domain": f"https://otx.alienvault.com/api/v1/indicators/domain/{ioc_value}/general",
        "url":    f"https://otx.alienvault.com/api/v1/indicators/url/{ioc_value}/general",
    }
    url = type_map.get(ioc_type)
    if not url:
        return {"error": f"Unsupported IOC type: {ioc_type}"}
    try:
        resp = _SESSION.get(url, headers={"X-OTX-API-KEY": OTX_API_KEY}, timeout=_REQUEST_TIMEOUT)
        resp.raise_for_status()
        d = resp.json()
        pulse_info = d.get("pulse_info", {})
        pulses     = pulse_info.get("pulses", [])
        tags       = list({tag for p in pulses for tag in p.get("tags", [])})
        malware    = list({m.get("display_name", "") for p in pulses for m in p.get("malware_families", [])})
        return {
            "provider":         "otx",
            "pulse_count":      pulse_info.get("count", 0),
            "tags":             tags[:20],
            "malware_families": [m for m in malware if m][:10],
            "first_seen":       d.get("created"),
            "last_seen":        d.get("modified"),
            "reputation":       d.get("reputation"),
            "country":          d.get("country_name", ""),
            "asn":              d.get("asn", ""),
        }
    except Exception as exc:
        logger.warning("OTX error for %s %s: %s", ioc_type, ioc_value, exc)
        return {"error": str(exc)}

def enrich_ioc(ioc_type, ioc_value):
    cached = cache.get(ioc_type, ioc_value)
    if cached:
        return EnrichmentResult(
            ioc_type=ioc_type, ioc_value=ioc_value,
            virustotal=cached.get("virustotal"),
            abuseipdb=cached.get("abuseipdb"),
            otx=cached.get("otx"),
            from_cache=True,
        )
    logger.info("Enriching %s: %s", ioc_type, ioc_value)
    result = EnrichmentResult(ioc_type=ioc_type, ioc_value=ioc_value)

    vt = _vt_query(ioc_type, ioc_value)
    if "error" in vt:
        result.errors.append(f"VirusTotal: {vt['error']}")
    else:
        result.virustotal = vt

    if ioc_type == "ip":
        abuse = _abuseipdb_query(ioc_value)
        if "error" in abuse:
            result.errors.append(f"AbuseIPDB: {abuse['error']}")
        else:
            result.abuseipdb = abuse

    otx = _otx_query(ioc_type, ioc_value)
    if "error" in otx:
        result.errors.append(f"OTX: {otx['error']}")
    else:
        result.otx = otx

    cache.set(ioc_type, ioc_value, {
        "virustotal": result.virustotal,
        "abuseipdb":  result.abuseipdb,
        "otx":        result.otx,
    })
    return result

def enrich_all(iocs):
    results = []
    for ip in iocs.ips:
        results.append(enrich_ioc("ip", ip))
    for h in iocs.hashes["sha256"]:
        results.append(enrich_ioc("sha256", h))
    for h in iocs.hashes["sha1"]:
        results.append(enrich_ioc("sha1", h))
    for h in iocs.hashes["md5"]:
        results.append(enrich_ioc("md5", h))
    for domain in iocs.domains:
        results.append(enrich_ioc("domain", domain))
    for url in iocs.urls:
        results.append(enrich_ioc("url", url))
    return results
