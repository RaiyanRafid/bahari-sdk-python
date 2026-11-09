"""Bahari Accounts SSO for Python apps: customer sign-in (OIDC + PKCE), platform admin sign-in, back-channel logout.

Framework helpers live in :mod:`bahari_sso.flask` and :mod:`bahari_sso.fastapi` (optional extras).
"""

from ._version import PACKAGE, VERSION
from .cache import Cache, MemoryCache
from .client import BahariClient
from .config import DEFAULT_SCOPES, Config
from .discovery import Discovery
from .errors import AccessDeniedError, BahariError, HttpError, InvalidTokenError
from .http import HttpClient, Response, UrllibHttpClient
from .sessions import MemorySessionStore, SessionStore, StoredSession
from .tokens import TokenVerifier
from .types import Identity, LoginRequest
from .web import WebAuth, safe_return_path

__version__ = VERSION

__all__ = [
    "PACKAGE",
    "VERSION",
    "__version__",
    "AccessDeniedError",
    "BahariClient",
    "BahariError",
    "Cache",
    "Config",
    "DEFAULT_SCOPES",
    "Discovery",
    "HttpClient",
    "HttpError",
    "Identity",
    "InvalidTokenError",
    "LoginRequest",
    "MemoryCache",
    "MemorySessionStore",
    "Response",
    "SessionStore",
    "StoredSession",
    "TokenVerifier",
    "UrllibHttpClient",
    "WebAuth",
    "safe_return_path",
]
