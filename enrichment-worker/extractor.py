import re
import logging
import ipaddress
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_RE_MD5    = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_SHA1   = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
_RE_URL = re.compile(r"https?://[^\s<>]+")

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("255.255.255.255/32"),
]

@dataclass
class ExtractedIOCs:
    ips:     list = field(default_factory=list)
    hashes:  dict = field(default_factory=lambda: {"md5": [], "sha1": [], "sha256": []})
    domains: list = field(default_factory=list)
    urls:    list = field(default_factory=list)

    def is_empty(self):
        return (not self.ips and not any(self.hashes.values())
                and not self.domains and not self.urls)

    def summary(self):
        return {
            "ip_count": len(self.ips),
            "md5_count": len(self.hashes["md5"]),
            "sha1_count": len(self.hashes["sha1"]),
            "sha256_count": len(self.hashes["sha256"]),
            "domain_count": len(self.domains),
            "url_count": len(self.urls),
        }

def _is_public_ip(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return not any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False

def _flatten_alert(alert, prefix=""):
    parts = []
    for key, value in alert.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            parts.append(_flatten_alert(value, full_key))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    parts.append(_flatten_alert(item, full_key))
                else:
                    parts.append(str(item))
        else:
            parts.append(str(value))
    return " ".join(parts)

def _dedupe(lst):
    seen = set()
    result = []
    for item in lst:
        lower = item.lower()
        if lower not in seen:
            seen.add(lower)
            result.append(item)
    return result

_SKIP_DOMAINS = {
    "localhost", "local", "internal", "corp", "lan",
    # common file extensions mistaken for domains
    "exe", "dll", "bat", "ps1", "sh", "py", "txt", "log", "cfg", "conf",
    "zip", "tar", "gz", "rar", "pdf", "doc", "docx", "xls", "xlsx",
    "locked", "enc", "crypt",
    # common name suffixes mistaken for domains
    "doe", "com", "admin", "user", "test", "example",
}

# Valid public TLDs - domain must end in one of these
_VALID_TLDS = {
    "com", "net", "org", "io", "gov", "edu", "mil",
    "ru", "cn", "de", "uk", "fr", "jp", "br", "in", "au",
    "co", "info", "biz", "me", "tv", "cc", "tk", "pw",
    "xyz", "top", "site", "online", "tech", "live", "club",
    "su", "to", "ws", "us", "ca", "eu", "nl", "pl", "es",
}

def _is_valid_domain(domain):
    parts = domain.lower().split(".")
    if len(parts) < 2:
        return False
    tld = parts[-1]
    if tld not in _VALID_TLDS:
        return False
    if any(p in _SKIP_DOMAINS for p in parts):
        return False
    return all(len(p) > 0 for p in parts)

def extract(alert):
    agent_ip = alert.get("agent", {}).get("ip", "")
    alert_id = alert.get("id", "unknown")
    logger.info("Starting IOC extraction for alert_id=%s", alert_id)
    text = _flatten_alert(alert)
    iocs = ExtractedIOCs()

    raw_ips = _RE_IPV4.findall(text)
    iocs.ips = _dedupe([ip for ip in raw_ips if _is_public_ip(ip) and ip != agent_ip])

    remaining_text = text
    sha256_hits = _RE_SHA256.findall(remaining_text)
    iocs.hashes["sha256"] = _dedupe([h.lower() for h in sha256_hits])
    for h in sha256_hits:
        remaining_text = remaining_text.replace(h, "")

    sha1_hits = _RE_SHA1.findall(remaining_text)
    iocs.hashes["sha1"] = _dedupe([h.lower() for h in sha1_hits])
    for h in sha1_hits:
        remaining_text = remaining_text.replace(h, "")

    md5_hits = _RE_MD5.findall(remaining_text)
    iocs.hashes["md5"] = _dedupe([h.lower() for h in md5_hits])

    raw_urls = _RE_URL.findall(text)
    iocs.urls = _dedupe(raw_urls)

    url_hosts = set()
    for url in iocs.urls:
        try:
            host = url.split("/")[2]
            url_hosts.add(host.lower())
        except IndexError:
            pass

    raw_domains = _RE_DOMAIN.findall(text)
    iocs.domains = _dedupe([
        d for d in raw_domains
        if _is_valid_domain(d) and d.lower() not in url_hosts
    ])

    logger.info("IOC extraction complete for alert_id=%s | summary=%s", alert_id, iocs.summary())
    return iocs
