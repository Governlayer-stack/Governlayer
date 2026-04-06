"""Request body size limit middleware.

Rejects request bodies exceeding a configurable maximum size with a 413 status.
Implemented as raw ASGI middleware for minimal overhead.
"""

import json
import os

# Default 1MB limit, configurable via environment variable
MAX_BODY_BYTES = int(os.environ.get("MAX_REQUEST_BODY_BYTES", 1_048_576))


class BodySizeLimitMiddleware:
    """ASGI middleware that rejects request bodies larger than a configured limit.

    Returns 413 Payload Too Large with a JSON error body when the limit is exceeded.
    """

    def __init__(self, app, max_bytes: int = MAX_BODY_BYTES):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Check Content-Length header first (fast path)
        headers = dict(scope.get("headers", []))
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                if int(content_length) > self.max_bytes:
                    await self._send_413(send)
                    return
            except (ValueError, TypeError):
                pass

        # For chunked/streaming requests, wrap receive to count bytes
        total_received = 0
        exceeded = False

        async def limited_receive():
            nonlocal total_received, exceeded
            message = await receive()
            if message.get("type") == "http.request":
                body = message.get("body", b"")
                total_received += len(body)
                if total_received > self.max_bytes:
                    exceeded = True
                    raise _BodyTooLargeError()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _BodyTooLargeError:
            await self._send_413(send)

    async def _send_413(self, send):
        body = json.dumps({
            "error": "payload_too_large",
            "message": f"Request body exceeds {self.max_bytes / 1_048_576:.0f}MB limit",
            "max_bytes": self.max_bytes,
        }).encode("utf-8")

        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                [b"content-type", b"application/json"],
                [b"content-length", str(len(body)).encode()],
            ],
        })
        await send({
            "type": "http.response.body",
            "body": body,
        })


class _BodyTooLargeError(Exception):
    """Internal signal — not exposed to callers."""
    pass
