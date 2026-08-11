"""Shared httpx client plumbing: request/response debug logging (redacted)
and a small retry loop. Used by both keycloak_client.py and
authentik_client.py so neither has to reimplement it.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from kc2ak.redact import redact

logger = logging.getLogger("kc2ak.http")

_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_MAX_ATTEMPTS = 3
_BACKOFF_SECONDS = 0.5


def _log_request(request: httpx.Request) -> None:
    if not logger.isEnabledFor(logging.DEBUG):
        return
    headers = {
        key: ("[REDACTED]" if key.lower() == "authorization" else value)
        for key, value in request.headers.items()
    }
    body = redact(request.content.decode("utf-8", errors="replace")) if request.content else ""
    logger.debug("request: %s %s headers=%s body=%s", request.method, request.url, headers, body)


def _log_response(response: httpx.Response) -> None:
    if not logger.isEnabledFor(logging.DEBUG):
        return
    logger.debug("response: %s %s", response.status_code, response.request.url)


def build_client(
    base_url: str,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
    transport: httpx.BaseTransport | None = None,
) -> httpx.Client:
    return httpx.Client(
        base_url=base_url,
        headers=headers,
        timeout=timeout,
        transport=transport,
        event_hooks={"request": [_log_request], "response": [_log_response]},
    )


def request_with_retry(
    client: httpx.Client, method: str, url: str, **kwargs: Any
) -> httpx.Response:
    """Issue a request, retrying transient failures (connection errors and
    5xx/429 responses) a few times with a short backoff. Raises on exhaustion.
    """
    last_exc: Exception | None = None
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            response = client.request(method, url, **kwargs)
        except httpx.TransportError as exc:
            last_exc = exc
            if attempt == _MAX_ATTEMPTS:
                raise httpx.TransportError(redact(str(exc))) from None
            time.sleep(_BACKOFF_SECONDS * attempt)
            continue
        if response.status_code in _RETRYABLE_STATUS and attempt < _MAX_ATTEMPTS:
            time.sleep(_BACKOFF_SECONDS * attempt)
            continue
        return response
    assert last_exc is not None  # pragma: no cover - unreachable
    raise last_exc
