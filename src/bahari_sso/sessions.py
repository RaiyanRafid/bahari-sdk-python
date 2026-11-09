"""Server-side storage of signed-in Bahari sessions for the framework helpers."""

from __future__ import annotations

import dataclasses
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

try:
    from typing import Protocol
except ImportError:  # pragma: no cover
    from typing_extensions import Protocol  # type: ignore

from .types import Identity

__all__ = ["StoredSession", "SessionStore", "MemorySessionStore", "TOKEN_KEYS"]

TOKEN_KEYS = ("access_token", "refresh_token", "id_token", "session_token")


@dataclass
class StoredSession:
    """A Bahari session kept by the app. ``tokens`` must be stored encrypted and never reach the browser."""

    id: str
    kind: str
    subject: str
    tokens: Dict[str, Any] = field(repr=False)
    profile: Dict[str, Any]
    expires_at: float
    access_expires_at: Optional[float] = None
    created_at: float = field(default_factory=time.time)

    @property
    def access_expires_in(self) -> Optional[int]:
        """Seconds until the stored client access token expires (``None`` for admin sessions)."""
        return None if self.access_expires_at is None else int(self.access_expires_at - time.time())

    def public(self) -> Dict[str, Any]:
        """What may be shown to the browser: never any token."""
        return {
            "kind": self.kind,
            "subject": self.subject,
            "profile": {k: v for k, v in self.profile.items() if k not in TOKEN_KEYS},
            "expires_at": int(self.expires_at),
        }


class SessionStore(Protocol):
    def create(self, identity: Identity, expires_in: int) -> StoredSession:
        """Saves a new session for this identity (lasting ``expires_in`` seconds) with an unguessable id."""

    def find(self, kind: str, session_id: str) -> Optional[StoredSession]:
        """The active (not revoked, not expired) session with this id and kind, or ``None``."""

    def update(self, session: StoredSession, identity: Identity) -> StoredSession:
        """Saves the rechecked profile, and the tokens when ``identity.tokens_changed``."""

    def revoke(self, session: StoredSession) -> None: ...

    def revoke_subject(self, kind: str, subject: str) -> None:
        """Ends every active session of this Bahari account (back-channel logout)."""


class MemorySessionStore:
    """Per-process, thread-safe store for development, tests and single-process apps.

    Use a database or Redis-backed store (with encrypted tokens) when running several workers.
    """

    def __init__(self) -> None:
        self._sessions: Dict[str, StoredSession] = {}
        self._revoked: Dict[str, bool] = {}
        self._lock = threading.Lock()

    def create(self, identity: Identity, expires_in: int) -> StoredSession:
        now = time.time()
        session = StoredSession(
            id=secrets.token_hex(32),
            kind=identity.kind,
            subject=identity.subject,
            tokens=dict(identity.tokens),
            profile=dict(identity.profile),
            expires_at=now + expires_in,
            access_expires_at=now + identity.access_expires_in if identity.access_expires_in else None,
            created_at=now,
        )
        with self._lock:
            for key in [k for k, v in self._sessions.items() if v.expires_at <= now]:
                del self._sessions[key]
                self._revoked.pop(key, None)
            self._sessions[session.id] = session
        return dataclasses.replace(session)

    def find(self, kind: str, session_id: str) -> Optional[StoredSession]:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.kind != kind or self._revoked.get(session_id) or session.expires_at <= time.time():
                return None
            return dataclasses.replace(session, tokens=dict(session.tokens), profile=dict(session.profile))

    def update(self, session: StoredSession, identity: Identity) -> StoredSession:
        with self._lock:
            stored = self._sessions.get(session.id)
            if stored is None:
                return session
            stored.profile = dict(identity.profile)
            if identity.tokens_changed:
                stored.tokens = dict(identity.tokens)
                stored.access_expires_at = time.time() + (identity.access_expires_in or 900)
            return dataclasses.replace(stored, tokens=dict(stored.tokens), profile=dict(stored.profile))

    def revoke(self, session: StoredSession) -> None:
        with self._lock:
            if session.id in self._sessions:
                self._revoked[session.id] = True

    def revoke_subject(self, kind: str, subject: str) -> None:
        with self._lock:
            for session in self._sessions.values():
                if session.kind == kind and session.subject == subject:
                    self._revoked[session.id] = True
