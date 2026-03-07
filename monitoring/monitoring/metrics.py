"""
metrics.py — Prometheus metrics exporter for the enrichment worker.
Exposes a /metrics HTTP endpoint on port 9090.
Import and call init_metrics() at worker startup.
"""

import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import defaultdict

# ── In-memory metric stores ─────────────────────────────────────────────────

_counters = defaultdict(float)   # monotonically increasing
_gauges   = defaultdict(float)   # current value (can go up/down)
_histograms = defaultdict(list)  # raw samples for summary stats

_lock = threading.Lock()

# ── Public API ───────────────────────────────────────────────────────────────

def inc(name: str, value: float = 1.0, labels: dict = None):
    """Increment a counter."""
    key = _make_key(name, labels)
    with _lock:
        _counters[key] += value

def set_gauge(name: str, value: float, labels: dict = None):
    """Set a gauge to an exact value."""
    key = _make_key(name, labels)
    with _lock:
        _gauges[key] = value

def observe(name: str, value: float, labels: dict = None):
    """Record a histogram observation (e.g. latency in seconds)."""
    key = _make_key(name, labels)
    with _lock:
        _histograms[key].append(value)
        # Keep last 1000 samples only
        if len(_histograms[key]) > 1000:
            _histograms[key] = _histograms[key][-1000:]

# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_key(name: str, labels: dict = None) -> str:
    if not labels:
        return name
    label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
    return f"{name}{{{label_str}}}"

def _render_metrics() -> str:
    lines = []
    with _lock:
        # Counters
        for key, val in sorted(_counters.items()):
            name = key.split("{")[0]
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{key} {val}")

        # Gauges
        for key, val in sorted(_gauges.items()):
            name = key.split("{")[0]
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{key} {val}")

        # Histograms — expose as summary (count, sum, p50, p90, p99)
        for key, samples in sorted(_histograms.items()):
            if not samples:
                continue
            name = key.split("{")[0]
            label_part = key[len(name):]
            sorted_s = sorted(samples)
            n = len(sorted_s)
            total = sum(sorted_s)
            p50 = sorted_s[int(n * 0.50)]
            p90 = sorted_s[int(n * 0.90)]
            p99 = sorted_s[int(n * 0.99)]

            lines.append(f"# TYPE {name} summary")
            lines.append(f'{name}{{quantile="0.5"{("," + label_part[1:]) if label_part else ""}}} {p50:.4f}')
            lines.append(f'{name}{{quantile="0.9"{("," + label_part[1:]) if label_part else ""}}} {p90:.4f}')
            lines.append(f'{name}{{quantile="0.99"{("," + label_part[1:]) if label_part else ""}}} {p99:.4f}')
            lines.append(f"{name}_count{label_part} {n}")
            lines.append(f"{name}_sum{label_part} {total:.4f}")

    return "\n".join(lines) + "\n"

# ── HTTP Handler ─────────────────────────────────────────────────────────────

class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            body = _render_metrics().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        pass  # suppress access logs


def init_metrics(port: int = 9090):
    """Start the metrics HTTP server in a background thread."""
    server = HTTPServer(("0.0.0.0", port), MetricsHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[metrics] Prometheus endpoint running on :{port}/metrics")
