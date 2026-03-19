"""In-memory metrics collector — no external dependencies.

Tracks request counts, latencies, error rates, and active connections.
Thread-safe for multi-worker use within a single process.
"""

import os
import time
from collections import deque
from threading import Lock


class MetricsCollector:
    """Lightweight in-memory metrics store."""

    def __init__(self):
        self._started_at: float = time.time()
        self._total_requests: int = 0
        self._total_errors: int = 0
        self._active_connections: int = 0
        self._latencies: deque[tuple[float, float]] = deque(maxlen=1000)  # (timestamp, latency_ms)
        self._lock = Lock()

    @property
    def started_at(self) -> float:
        return self._started_at

    @property
    def uptime_seconds(self) -> float:
        return round(time.time() - self._started_at, 1)

    def record_request(self, latency_ms: float, is_error: bool = False) -> None:
        """Record a completed request."""
        with self._lock:
            self._total_requests += 1
            if is_error:
                self._total_errors += 1
            self._latencies.append((time.time(), latency_ms))

    def inc_connections(self) -> None:
        with self._lock:
            self._active_connections += 1

    def dec_connections(self) -> None:
        with self._lock:
            self._active_connections = max(0, self._active_connections - 1)

    def snapshot(self) -> dict:
        """Return current metrics as a dict."""
        now = time.time()
        with self._lock:
            total = self._total_requests
            errors = self._total_errors
            active = self._active_connections

            # Requests in the last 60 seconds
            one_min_ago = now - 60
            recent = [lat for ts, lat in self._latencies if ts > one_min_ago]
            rpm = len(recent)

            # Average latency from last 100 requests
            last_100 = list(self._latencies)[-100:] if self._latencies else []
            avg_latency = round(sum(lat for _, lat in last_100) / len(last_100), 2) if last_100 else 0.0

            error_rate = round(errors / total, 4) if total > 0 else 0.0

        return {
            "uptime_seconds": self.uptime_seconds,
            "total_requests": total,
            "requests_per_minute": rpm,
            "error_rate": error_rate,
            "avg_latency_ms": avg_latency,
            "active_connections": active,
        }


# Singleton instance
metrics = MetricsCollector()


class MetricsMiddleware:
    """ASGI middleware that records metrics for every request.

    Implemented as raw ASGI middleware (not BaseHTTPMiddleware) to track
    active connections without double-counting from Starlette internals.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Skip in test mode
        if os.environ.get("TESTING"):
            await self.app(scope, receive, send)
            return

        metrics.inc_connections()
        start = time.monotonic()
        status_code = 500

        async def send_wrapper(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            latency_ms = round((time.monotonic() - start) * 1000, 2)
            metrics.dec_connections()
            metrics.record_request(latency_ms, is_error=(status_code >= 500))
