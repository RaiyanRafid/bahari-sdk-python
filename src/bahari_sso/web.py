"""Framework-independent sign-in flow shared by :mod:`bahari_sso.flask` and :mod:`bahari_sso.fastapi`.

The browser only ever holds an opaque, random browser id. Everything else (sign-in transactions, the pointer to the
signed-in session of each kind, the "expected admin user" of the auto flow) lives server-side in the cache, and the
Bahari sessions with their tokens live in a :class:`~bahari_sso.sessions.SessionStore`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets
import threading
import time
import weakref
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple
from urllib.parse import parse_qs, quote, unquote_to_bytes

try:
    from typing import Protocol
except ImportError:  # pragma: no cover
    from typing_extensions import Protocol  # type: ignore

from .cache import Cache
from .client import ADMIN_ROLES, KINDS, BahariClient
from .errors import AccessDeniedError, BahariError
from .sessions import MemorySessionStore, SessionStore, StoredSession

__all__ = ["WebAuth", "WebError", "Browser", "safe_return_path"]

logger = logging.getLogger("bahari_sso")

_HEX64 = re.compile(r"\A[a-f0-9]{64}\Z")
_UNSAFE = re.compile(rb"[\\\x00-\x20\x7f]")
TRANSACTION_TTL = 600
MAX_BACKCHANNEL_BYTES = 65536


def safe_return_path(prefix: str, value: Any) -> str:
    """A local return path inside ``prefix`` (the kind's area), or the area itself. Blocks external URLs and
    traversal. Same rules as ``BahariManager::safeReturnPath`` in the Laravel package."""
    prefix = "/" + str(prefix).strip("/")
    if not isinstance(value, str) or len(value.encode("utf-8")) > 2048:
        return prefix
    if not re.match(re.escape(prefix.rstrip("/")) + r"(?:[/?]|\Z)", value):
        return prefix
    decoded = unquote_to_bytes(value)
    if _UNSAFE.search(decoded) or b".." in decoded or value.startswith("//"):
        return prefix
    return value


class WebError(Exception):
    """An HTTP error the framework adapter turns into a plain-text response."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class Browser(Protocol):
    """Reads and replaces the opaque browser id kept in the framework's cookie."""

    def get(self) -> Optional[str]: ...

    def set(self, value: str) -> None: ...


class _Lock:
    __slots__ = ("lock", "__weakref__")

    def __init__(self) -> None:
        self.lock = threading.Lock()


def _hash(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


class WebAuth:
    """The sign-in flow of one app.

    :param client: the configured :class:`BahariClient`.
    :param store: where signed-in sessions are kept (default per-process :class:`MemorySessionStore`).
    :param prefix: route prefix of the helper routes (``/auth``).
    :param paths: the area of each kind, used as default return path and to pick the kind of a protected path.
    :param auto_admin: after an auto sign-in, continue to the admin sign-in when Bahari reports ``admin_access``.
    :param session_hours: lifetime of a local session.
    :param post_logout_redirect: where Bahari returns customers after logout (default: the app's root URL).
    :param public_url: the app's public base URL for callback URLs (default: derived from the request).
    :param state_cache: server-side cache for sign-in state (default: the client's cache).
    """

    def __init__(
        self,
        client: BahariClient,
        store: Optional[SessionStore] = None,
        *,
        prefix: str = "/auth",
        paths: Optional[Mapping[str, str]] = None,
        auto_admin: bool = True,
        session_hours: float = 8,
        post_logout_redirect: Optional[str] = None,
        public_url: Optional[str] = None,
        state_cache: Optional[Cache] = None,
    ) -> None:
        self.client = client
        self.store: SessionStore = store if store is not None else MemorySessionStore()
        self.prefix = ("/" + prefix.strip("/")) if prefix.strip("/") else ""
        self.paths: Dict[str, str] = {"client": "/dashboard", "admin": "/admin"}
        self.paths.update(paths or {})
        self.auto_admin = auto_admin
        self.session_seconds = max(60, int(session_hours * 3600))
        self.post_logout_redirect = post_logout_redirect
        self.public_url = public_url.rstrip("/") if public_url else None
        self.cache: Cache = state_cache if state_cache is not None else client.cache
        self._locks: "weakref.WeakValueDictionary[str, _Lock]" = weakref.WeakValueDictionary()
        self._locks_guard = threading.Lock()
        self._add_guard = threading.Lock()

    # ------------------------------------------------------------------ helpers

    def safe_return_path(self, kind: str, value: Any) -> str:
        return safe_return_path(self.paths.get(kind, "/"), value)

    def kind_for(self, path: str) -> str:
        """The kind ("client" or "admin") a request path belongs to (longest matching area wins)."""
        best, length = "client", -1
        for kind in KINDS:
            area = self.paths.get(kind, "").strip("/")
            if area and (path.strip("/") == area or path.lstrip("/").startswith(area + "/")) and len(area) > length:
                best, length = kind, len(area)
        return best

    def login_path(self, kind: Optional[str] = None, return_to: Optional[str] = None) -> str:
        path = self.prefix + ("/login" if kind is None else f"/{kind}/login")
        return path + ("?return_to=" + quote(return_to, safe="") if return_to else "")

    def callback_url(self, kind: str, request_base_url: str) -> str:
        return (self.public_url or request_base_url.rstrip("/")) + self.prefix + f"/{kind}/callback"

    def _check_kind(self, kind: Any) -> str:
        if kind not in KINDS:
            raise WebError(404, "Not found.")
        return kind

    def _browser_id(self, browser: Browser, create: bool = False) -> Optional[str]:
        value = browser.get()
        if isinstance(value, str) and _HEX64.match(value):
            return value
        if not create:
            return None
        value = secrets.token_hex(32)
        browser.set(value)
        return value

    def _tx_key(self, bid: str, state: str) -> str:
        return "bahari:web:tx:" + _hash(bid, state)

    def _pointer_key(self, bid: str, kind: str) -> str:
        return "bahari:web:session:" + _hash(bid, kind)

    def _expect_key(self, bid: str) -> str:
        return "bahari:web:expect-admin:" + _hash(bid)

    def _rotate(self, browser: Browser, old: Optional[str]) -> str:
        """A new browser id after sign-in (prevents session fixation); signed-in sessions of other kinds move along."""
        new = secrets.token_hex(32)
        if old:
            for kind in KINDS:
                pointer = self.cache.get(self._pointer_key(old, kind))
                if isinstance(pointer, str):
                    self.cache.set(self._pointer_key(new, kind), pointer, self.session_seconds)
                self.cache.delete(self._pointer_key(old, kind))
            self.cache.delete(self._expect_key(old))
        browser.set(new)
        return new

    def _admin_access(self, profile: Mapping[str, Any]) -> bool:
        access = profile.get("admin_access")
        platform = self.client.config.platform
        return (
            isinstance(access, dict)
            and platform is not None
            and access.get("platform", platform) == platform
            and access.get("role", "ADMIN") in ADMIN_ROLES
        )

    def _lock(self, session_id: str) -> _Lock:
        with self._locks_guard:
            lock = self._locks.get(session_id)
            if lock is None:
                lock = _Lock()
                self._locks[session_id] = lock
            return lock

    def _add(self, key: str, value: Any, ttl: int) -> bool:
        add = getattr(self.cache, "add", None)
        if callable(add):
            return bool(add(key, value, ttl))
        with self._add_guard:
            if self.cache.get(key) is not None:
                return False
            self.cache.set(key, value, ttl)
            return True

    # ------------------------------------------------------------------ routes

    def begin(
        self, browser: Browser, kind: Optional[str], return_to: Any, request_base_url: str, prompt: Optional[str] = None
    ) -> str:
        """``GET {prefix}/login`` (kind ``None``: auto), ``GET {prefix}/register`` (auto with ``prompt="create"``) and
        ``GET {prefix}/{kind}/login``. Returns the redirect URL."""
        auto = kind is None
        kind = self._check_kind("client" if auto else kind)
        if not self.client.config.configured:
            raise WebError(503, "Bahari sign-in is being configured.")
        login = self.client.begin_login(kind, self.callback_url(kind, request_base_url), prompt=prompt if auto else None)
        bid = self._browser_id(browser, create=True)
        assert bid is not None
        transaction: Dict[str, Any] = dict(login.transaction)
        transaction["return_to"] = self.safe_return_path(kind, return_to)
        if auto:
            transaction["auto"] = True
        if kind == "admin":
            expected = self.cache.get(self._expect_key(bid))
            if isinstance(expected, str) and expected:
                transaction["expected_user_id"] = expected
                self.cache.delete(self._expect_key(bid))
        self.cache.set(self._tx_key(bid, login.state), transaction, TRANSACTION_TTL)
        return login.url

    def complete(
        self, browser: Browser, kind: str, state: Any, code: Any, error: Any = None
    ) -> str:
        """``GET {prefix}/{kind}/callback``. Returns the local path to redirect to."""
        kind = self._check_kind(kind)
        if not isinstance(state, str) or not _HEX64.match(state):
            raise WebError(422, "The sign-in request is invalid.")
        if (code is not None and (not isinstance(code, str) or len(code) > 20000)) or (
            error is not None and (not isinstance(error, str) or len(error) > 100)
        ):
            raise WebError(422, "The sign-in request is invalid.")
        bid = self._browser_id(browser)
        transaction = None
        if bid:
            key = self._tx_key(bid, state)
            transaction = self.cache.get(key)
            self.cache.delete(key)
        created = transaction.get("created_at") if isinstance(transaction, dict) else None
        if (
            not isinstance(transaction, dict)
            or transaction.get("kind") != kind
            or not isinstance(created, int)
            or time.time() - created > TRANSACTION_TTL
        ):
            raise WebError(422, "Sign-in expired. Please start again.")
        if error or not code:
            raise WebError(422, "Sign-in was not approved.")
        try:
            identity = self.client.complete_login(transaction, code)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Bahari sign-in failed (%s): %s: %s", kind, type(exc).__name__, exc)
            raise WebError(503, "Sign-in could not be completed. Please start again or contact support.") from exc

        expected = transaction.get("expected_user_id")
        if kind == "admin" and expected and identity.profile.get("user_id") != expected:
            # The administrator who signed in is not linked to the customer who started the auto sign-in.
            logger.warning("Bahari admin sign-in rejected: the administrator is not linked to the signed-in customer.")
            try:
                self.client.revoke("admin", identity.tokens)
            except Exception as exc:  # noqa: BLE001
                logger.info("Bahari admin session revoke failed: %s", type(exc).__name__)
            return self.paths["client"]

        try:
            session = self.store.create(identity, self.session_seconds)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Bahari session could not be stored (%s): %s", kind, type(exc).__name__)
            raise WebError(503, "Sign-in could not be completed. Please start again or contact support.") from exc
        bid = self._rotate(browser, bid)
        self.cache.set(self._pointer_key(bid, kind), session.id, self.session_seconds)

        if kind == "client" and transaction.get("auto") and self.auto_admin and self._admin_access(identity.profile):
            self.cache.set(self._expect_key(bid), identity.subject, TRANSACTION_TTL)
            return self.login_path("admin", self.paths["admin"])
        return transaction.get("return_to") or self.safe_return_path(kind, None)

    def logout(self, browser: Browser, kind: str, request_base_url: str) -> str:
        """``POST {prefix}/{kind}/logout``. Returns the URL to redirect to (Bahari logout or the admin panel)."""
        kind = self._check_kind(kind)
        id_token: Optional[str] = None
        bid = self._browser_id(browser)
        if bid:
            pointer = self.cache.get(self._pointer_key(bid, kind))
            self.cache.delete(self._pointer_key(bid, kind))
            if kind == "client":
                self.cache.delete(self._expect_key(bid))
            session = self.store.find(kind, pointer) if isinstance(pointer, str) else None
            if session is not None:
                hint = session.tokens.get("id_token") if isinstance(session.tokens, dict) else None
                id_token = hint if isinstance(hint, str) else None
                self.store.revoke(session)
                try:
                    self.client.revoke(kind, session.tokens)
                except Exception as exc:  # noqa: BLE001
                    logger.info("Bahari session revoke failed; the local session is ended. (%s)", type(exc).__name__)
        return self.client.logout_url(
            kind, self.post_logout_redirect or request_base_url.rstrip("/") + "/", id_token
        )

    def current(self, browser: Browser, kind: str) -> Optional[StoredSession]:
        """The rechecked session of this kind, or ``None``. Any failure ends the local session (fail closed)."""
        kind = self._check_kind(kind)
        bid = self._browser_id(browser)
        if not bid:
            return None
        pointer = self.cache.get(self._pointer_key(bid, kind))
        if not isinstance(pointer, str):
            return None
        stored = self.store.find(kind, pointer)
        if stored is not None:
            try:
                return self.check(stored)
            except Exception as exc:  # noqa: BLE001
                logger.info("Bahari session ended (%s): %s", kind, type(exc).__name__)
                try:
                    self.store.revoke(stored)
                except Exception:  # noqa: BLE001
                    pass
        self.cache.delete(self._pointer_key(bid, kind))
        return None

    def check(self, session: StoredSession) -> StoredSession:
        """Rechecks a stored session with Bahari (rotating client tokens when needed) and saves the result.

        :raises AccessDeniedError: when the session must end.
        """
        holder = self._lock(session.id)
        if not holder.lock.acquire(timeout=15):
            raise BahariError("The session is busy.")
        try:
            fresh = self.store.find(session.kind, session.id)
            if fresh is None:
                raise AccessDeniedError("The session has ended.")
            identity = self.client.refresh(fresh.kind, fresh.tokens, fresh.subject, fresh.access_expires_in)
            return self.store.update(fresh, identity)
        finally:
            holder.lock.release()

    def session_info(self, browser: Browser, kinds: Optional[Iterable[str]] = None) -> Dict[str, Any]:
        """``GET {prefix}/session``: the rechecked sessions without any token."""
        sessions: Dict[str, Any] = {}
        for kind in kinds or KINDS:
            current = self.current(browser, kind)
            sessions[kind] = current.public() if current else None
        return {"authenticated": any(sessions.values()), "sessions": sessions}

    def backchannel(self, body: bytes, content_type: Optional[str]) -> Tuple[int, Dict[str, Any]]:
        """``POST {prefix}/backchannel-logout``: Bahari posts a signed logout_token when a customer signs out anywhere;
        every local customer session of that account ends (once per jti)."""
        if len(body) > MAX_BACKCHANNEL_BYTES:
            return 413, {"message": "The notification is too large."}
        token: Any = None
        try:
            if content_type and "json" in content_type.lower():
                data = json.loads(body.decode("utf-8"))
                token = data.get("logout_token") if isinstance(data, dict) else None
            else:
                values = parse_qs(body.decode("utf-8"), max_num_fields=20).get("logout_token")
                token = values[0] if values else None
        except (ValueError, UnicodeDecodeError):
            token = None
        if not isinstance(token, str) or not token or len(token) > 20000:
            return 422, {"message": "The logout_token field is required."}
        try:
            claims = self.client.verify_logout_token(token)
        except Exception:  # noqa: BLE001
            return 422, {"message": "Invalid logout notification."}
        key = "bahari-logout-jti:" + _hash(str(claims["jti"]))
        if self._add(key, True, 300):
            try:
                self.store.revoke_subject("client", claims["sub"])
                # Bahari also sends this when someone loses admin access to the app: end their admin sessions too.
                revoke_linked = getattr(self.store, "revoke_linked_user", None)
                if callable(revoke_linked):
                    revoke_linked(str(claims["sub"]))
            except Exception:
                self.cache.delete(key)
                raise
        return 200, {"received": True}
