"""The Bahari discovery document (``/.well-known/bahari-configuration``)."""

from __future__ import annotations

import copy
import re
from typing import TYPE_CHECKING, Any, Dict

from .errors import BahariError

if TYPE_CHECKING:  # pragma: no cover
    from .config import Config

__all__ = ["Discovery"]

_URL = re.compile(r"^https?://")


class Discovery:
    """Read values with dot paths: ``discovery.get("admin.authorize_endpoint")``.

    ``from_server`` is ``False`` when the long-standing default endpoints are used because discovery was unavailable.
    """

    def __init__(self, data: Dict[str, Any], from_server: bool = True) -> None:
        self._data = data
        self.from_server = from_server

    @classmethod
    def fallback(cls, config: "Config") -> "Discovery":
        """Endpoints Bahari has always used, for when discovery cannot be reached and nothing is cached yet."""
        issuer = config.issuer
        admin = config.admin_issuer or issuer
        api = issuer + "/api/v1"
        return cls(
            {
                "issuer": issuer,
                "authorization_endpoint": issuer + "/oauth/authorize",
                "token_endpoint": issuer + "/oauth/token",
                "userinfo_endpoint": issuer + "/oauth/userinfo",
                "profile_endpoint": issuer + "/oauth/user",
                "jwks_uri": issuer + "/oauth/jwks",
                "revocation_endpoint": issuer + "/oauth/revoke",
                "end_session_endpoint": issuer + "/oauth/logout",
                "client": {
                    "dashboard_url": issuer + "/dashboard",
                    "profile_url": issuer + "/dashboard/personal-details",
                    "security_url": issuer + "/dashboard/security",
                    "identity_url": issuer + "/dashboard/identity-verification",
                    "wallet_url": issuer + "/dashboard/wallet",
                    "billing_url": issuer + "/dashboard/billing",
                    "applications_url": issuer + "/dashboard/applications",
                },
                "admin": {
                    "origin": admin,
                    "panel_url": admin + "/admin",
                    "billing_url": admin + "/admin/billing",
                    "profile_url": admin + "/admin/profile",
                    "authorize_endpoint": admin + "/admin-sso/authorize",
                    "exchange_endpoint": api + "/admin-sso/exchange",
                    "session_endpoint": api + "/admin-sso/session",
                    "revoke_endpoint": api + "/admin-sso/revoke",
                    "navigation_endpoint": api + "/admin-sso/navigation",
                },
                "api": {"base_url": api, "platform_navigation": api + "/platform-navigation", "platform_branding": api + "/platform-branding/{key}"},
                "sdk": {"packages": []},
            },
            from_server=False,
        )

    def get(self, path: str, default: Any = None) -> Any:
        value: Any = self._data
        for segment in path.split("."):
            if not isinstance(value, dict) or segment not in value:
                return default
            value = value[segment]
        return value

    def url(self, path: str) -> str:
        """A URL from the document. Raises when it is missing so a typo never sends a request to the wrong place."""
        url = self.get(path)
        if not isinstance(url, str) or not _URL.match(url):
            raise BahariError(f"Bahari discovery has no URL for '{path}'.")
        return url

    def to_dict(self) -> Dict[str, Any]:
        return copy.deepcopy(self._data)

    def __repr__(self) -> str:
        return f"Discovery(issuer={self._data.get('issuer')!r}, from_server={self.from_server})"
