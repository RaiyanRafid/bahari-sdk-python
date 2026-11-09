"""A tiny HTTP layer: a pluggable :class:`HttpClient` protocol and a stdlib implementation that never follows
redirects."""

from __future__ import annotations

import functools
import http.client
import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Any, Mapping, Optional

try:  # Python 3.8+
    from typing import Protocol
except ImportError:  # pragma: no cover
    from typing_extensions import Protocol  # type: ignore

from .errors import BahariError

__all__ = ["HttpClient", "Response", "UrllibHttpClient"]


class Response:
    """An HTTP response. Header names are lower-case."""

    __slots__ = ("status", "body", "headers")

    def __init__(self, status: int, body: str = "", headers: Optional[Mapping[str, str]] = None) -> None:
        self.status = int(status)
        self.body = body
        self.headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}

    def json(self, key: Optional[str] = None) -> Any:
        """The decoded JSON body (``None`` when it is not JSON), or one top-level key of it."""
        try:
            data = json.loads(self.body) if self.body else None
        except ValueError:
            data = None
        if key is None:
            return data
        return data.get(key) if isinstance(data, dict) else None

    def header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def __repr__(self) -> str:
        return f"Response(status={self.status})"


class HttpClient(Protocol):
    """Sends one request without following redirects. Raise :class:`BahariError` when Bahari cannot be reached."""

    def send(
        self, method: str, url: str, headers: Optional[Mapping[str, str]] = None, body: Optional[str] = None
    ) -> Response: ...


class _ConnectTimeout:
    """Uses a short timeout to connect (and for the TLS handshake), then the longer one for the exchange."""

    def __init__(self, *args: Any, connect_timeout: float = 3.0, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[call-arg]
        self._connect_timeout = connect_timeout

    def connect(self) -> None:
        total = self.timeout  # type: ignore[attr-defined]
        if isinstance(total, (int, float)):
            self.timeout = min(self._connect_timeout, total)  # type: ignore[attr-defined]
        try:
            super().connect()  # type: ignore[misc]
        finally:
            self.timeout = total  # type: ignore[attr-defined]
        if self.sock is not None and isinstance(total, (int, float)):  # type: ignore[attr-defined]
            self.sock.settimeout(total)  # type: ignore[attr-defined]


class _HTTPConnection(_ConnectTimeout, http.client.HTTPConnection):
    pass


class _HTTPSConnection(_ConnectTimeout, http.client.HTTPSConnection):
    pass


class _HTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, connect_timeout: float) -> None:
        super().__init__()
        self._connect_timeout = connect_timeout

    def http_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(functools.partial(_HTTPConnection, connect_timeout=self._connect_timeout), req)


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, connect_timeout: float, context: ssl.SSLContext) -> None:
        super().__init__(context=context)
        self._connect_timeout = connect_timeout
        self._ssl_context = context

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(
            functools.partial(_HTTPSConnection, connect_timeout=self._connect_timeout), req, context=self._ssl_context
        )


class UrllibHttpClient:
    """Default transport built on ``urllib.request``.

    Only http(s) is spoken, redirects are never followed (a 3xx is returned as is), non-2xx answers are returned
    rather than raised, connecting is limited to ``connect_timeout`` seconds and the whole request to roughly
    ``timeout`` seconds. Proxies from the environment (``https_proxy``/``no_proxy``) are honoured.
    """

    def __init__(
        self,
        connect_timeout: float = 3.0,
        timeout: float = 10.0,
        max_bytes: int = 5 * 1024 * 1024,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        self.connect_timeout = connect_timeout
        self.timeout = timeout
        self.max_bytes = max_bytes
        opener = urllib.request.OpenerDirector()
        # No HTTPErrorProcessor and no redirect handler: every status comes back as a response.
        for handler in (
            urllib.request.ProxyHandler(),
            _HTTPHandler(connect_timeout),
            _HTTPSHandler(connect_timeout, ssl_context or ssl.create_default_context()),
            urllib.request.UnknownHandler(),
        ):
            opener.add_handler(handler)
        self._opener = opener

    def send(
        self, method: str, url: str, headers: Optional[Mapping[str, str]] = None, body: Optional[str] = None
    ) -> Response:
        if not url.lower().startswith(("https://", "http://")):
            raise BahariError("Bahari Accounts URLs must use http or https.")
        data = body.encode("utf-8") if body is not None else None
        request = urllib.request.Request(url, data=data, headers=dict(headers or {}), method=method.upper())
        deadline = time.monotonic() + self.timeout
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                chunks = []
                size = 0
                while True:
                    if time.monotonic() > deadline:
                        raise BahariError("Bahari Accounts could not be reached: the request timed out.")
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > self.max_bytes:
                        raise BahariError("Bahari Accounts answered with an oversized response.")
                    chunks.append(chunk)
                status = getattr(response, "status", None) or response.getcode()
                received = {name.lower(): value for name, value in response.headers.items()}
        except BahariError:
            raise
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
            reason = getattr(exc, "reason", exc)
            raise BahariError(f"Bahari Accounts could not be reached: {reason}") from exc
        return Response(int(status), b"".join(chunks).decode("utf-8", errors="replace"), received)
