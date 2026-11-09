"""Value objects returned by :class:`bahari_sso.BahariClient`."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

__all__ = ["Identity", "LoginRequest"]


@dataclass(frozen=True)
class Identity:
    """A signed-in Bahari identity.

    ``kind`` is ``"client"`` (a customer) or ``"admin"`` (a platform administrator). ``tokens`` must be stored
    encrypted on the server and never sent to the browser. ``access_expires_in`` is in seconds (client sessions only).
    """

    kind: str
    subject: str
    tokens: Dict[str, Any] = field(repr=False)
    profile: Dict[str, Any]
    access_expires_in: Optional[int] = None
    tokens_changed: bool = False


@dataclass(frozen=True)
class LoginRequest:
    """Where to send the browser, and what to keep server-side until the callback.

    Store ``transaction`` in a server-side session under ``state`` (never in a cookie the browser can read) and pass it
    back to :meth:`BahariClient.complete_login`.
    """

    url: str
    state: str
    transaction: Dict[str, Any] = field(repr=False)
