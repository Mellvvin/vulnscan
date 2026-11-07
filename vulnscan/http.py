"""Minimal HTTP client with retries (standard library only).

Honours the usual HTTP(S)_PROXY environment variables through urllib, and
identifies itself with a generic client name (no personal details).
"""

from __future__ import annotations

import http.client
import json
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, Optional

USER_AGENT = "vulnscan/1.1 (open-source security audit tool)"
RETRY_STATUS = {429, 500, 502, 503, 504}


class HttpError(Exception):
    def __init__(self, message: str, status: Optional[int] = None) -> None:
        super().__init__(message)
        self.status = status


class Http:
    def __init__(self, timeout: float = 30.0, retries: int = 3,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.timeout = timeout
        self.retries = retries
        self._sleep = sleep

    def request(self, method: str, url: str, data: Optional[bytes] = None,
                headers: Optional[Dict[str, str]] = None, max_bytes: int = 200_000_000) -> bytes:
        hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json, */*"}
        if data is not None:
            hdrs["Content-Type"] = "application/json"
        hdrs.update(headers or {})
        last: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            try:
                req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    body = resp.read(max_bytes + 1)
                if len(body) > max_bytes:
                    raise HttpError(f"response from {url} exceeds {max_bytes} bytes")
                return body
            except urllib.error.HTTPError as exc:
                if exc.code in RETRY_STATUS and attempt < self.retries:
                    wait = 2 ** attempt
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    if retry_after and retry_after.isdigit():
                        wait = min(int(retry_after), 30)
                    self._sleep(wait)
                    last = exc
                    continue
                raise HttpError(f"HTTP {exc.code} for {url}", exc.code) from exc
            except (urllib.error.URLError, socket.timeout, ConnectionError, TimeoutError,
                    http.client.HTTPException) as exc:
                last = exc
                if attempt < self.retries:
                    self._sleep(0.5 * 2 ** attempt)
                    continue
            except ValueError as exc:  # malformed URL
                raise HttpError(f"invalid request for {url}: {exc}") from exc
        raise HttpError(f"network error for {url}: {last}")

    def get_bytes(self, url: str) -> bytes:
        return self.request("GET", url)

    def get_text(self, url: str) -> str:
        return self.get_bytes(url).decode("utf-8", "replace")

    def get_json(self, url: str) -> Any:
        try:
            return json.loads(self.get_bytes(url))
        except ValueError as exc:
            raise HttpError(f"invalid JSON from {url}: {exc}") from exc

    def post_json(self, url: str, obj: Any) -> Any:
        try:
            body = self.request("POST", url, json.dumps(obj).encode())
            return json.loads(body)
        except ValueError as exc:
            raise HttpError(f"invalid JSON from {url}: {exc}") from exc
