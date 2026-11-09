"""SDK configuration: the issuer and this app's credentials. Everything else comes from discovery."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional
from urllib.parse import urlsplit

__all__ = ["Config", "DEFAULT_SCOPES"]

DEFAULT_SCOPES = "openid profile email phone profile:read identity:read wallet:read platform:read"

_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


def _origin(url: Any, name: str) -> str:
    error = ValueError(f"The Bahari {name} must be an https URL such as https://accounts.baharione.com.")
    if not isinstance(url, str):
        raise error
    url = url.strip().rstrip("/")
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        raise error from None
    scheme = parts.scheme.lower()
    if (
        not host
        or not (scheme == "https" or (scheme == "http" and host in _LOCAL_HOSTS))
        or "@" in parts.netloc
        or "?" in url
        or "#" in url
        or any(c.isspace() for c in url)
    ):
        raise error
    return url


@dataclass(frozen=True)
class Config:
    """The only settings an app needs.

    ``admin_issuer`` is only used when discovery cannot be reached and nothing is cached.
    """

    issuer: str
    client_id: str
    client_secret: str = field(repr=False)
    platform: Optional[str] = None
    scopes: str = DEFAULT_SCOPES
    admin_issuer: Optional[str] = None
    discovery_ttl: int = 300

    def __post_init__(self) -> None:
        object.__setattr__(self, "issuer", _origin(self.issuer, "issuer"))
        if self.admin_issuer:
            object.__setattr__(self, "admin_issuer", _origin(self.admin_issuer, "admin issuer"))
        else:
            object.__setattr__(self, "admin_issuer", None)
        object.__setattr__(self, "client_id", str(self.client_id or ""))
        object.__setattr__(self, "client_secret", str(self.client_secret or ""))
        object.__setattr__(self, "platform", str(self.platform) if self.platform else None)
        object.__setattr__(self, "scopes", str(self.scopes or DEFAULT_SCOPES))
        object.__setattr__(self, "discovery_ttl", int(self.discovery_ttl))

    @classmethod
    def from_dict(cls, config: Mapping[str, Any]) -> "Config":
        return cls(
            issuer=config.get("issuer") or "",
            client_id=config.get("client_id") or "",
            client_secret=config.get("client_secret") or "",
            platform=config.get("platform"),
            scopes=config.get("scopes") or DEFAULT_SCOPES,
            admin_issuer=config.get("admin_issuer"),
            discovery_ttl=int(config.get("discovery_ttl") or 300),
        )

    @classmethod
    def from_env(cls, environ: Optional[Mapping[str, str]] = None) -> "Config":
        """Reads BAHARI_ACCOUNTS_ISSUER, BAHARI_CLIENT_ID, BAHARI_CLIENT_SECRET, BAHARI_PLATFORM_KEY, BAHARI_SCOPES
        and BAHARI_ADMIN_ISSUER."""
        env = os.environ if environ is None else environ
        return cls.from_dict(
            {
                "issuer": env.get("BAHARI_ACCOUNTS_ISSUER", "https://accounts.baharione.com"),
                "client_id": env.get("BAHARI_CLIENT_ID"),
                "client_secret": env.get("BAHARI_CLIENT_SECRET"),
                "platform": env.get("BAHARI_PLATFORM_KEY"),
                "scopes": env.get("BAHARI_SCOPES"),
                "admin_issuer": env.get("BAHARI_ADMIN_ISSUER"),
            }
        )

    @property
    def configured(self) -> bool:
        return self.client_id != "" and self.client_secret != ""
