"""Bahari Accounts for one app.

Only the issuer and the client credentials are configured; every endpoint, including the admin host, comes from
``/.well-known/bahari-configuration``, so Bahari can move domains without app changes.

Kinds: ``"client"`` signs in customers with OIDC authorization code + PKCE. ``"admin"`` signs in platform
administrators through Bahari's admin SSO and a server-to-server exchange.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets
import threading
import time
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Set, Tuple, Union
from urllib.parse import quote, urlencode

from ._version import PACKAGE, VERSION
from .cache import Cache, MemoryCache
from .config import Config
from .discovery import Discovery
from .errors import AccessDeniedError, BahariError, HttpError
from .http import HttpClient, Response, UrllibHttpClient
from .tokens import TokenVerifier, base64url, is_uuid
from .types import Identity, LoginRequest

__all__ = ["BahariClient", "KINDS", "ADMIN_ROLES"]

logger = logging.getLogger("bahari_sso")

KINDS = ("client", "admin")
ADMIN_ROLES = ("ADMIN", "SUPER_ADMIN")

_EMAIL = re.compile(
    r"\A[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\Z"
)

_warned: Set[Tuple[str, str]] = set()
_warned_lock = threading.Lock()


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _query(params: Mapping[str, Any]) -> str:
    return urlencode([(k, v) for k, v in params.items() if v is not None])


class BahariClient:
    """The Bahari SDK core.

    :param config: a :class:`Config` or a mapping accepted by :meth:`Config.from_dict`.
    :param http: transport (default :class:`UrllibHttpClient`).
    :param cache: shared cache for discovery, JWKS and machine tokens (default per-process :class:`MemoryCache`).
    :param sdk: sent as ``X-Bahari-SDK`` so Bahari can tell you when the package is outdated.
    :param seal: encrypts cached machine tokens (``str -> str``); ``unseal`` reverses it.
    """

    KINDS = KINDS

    def __init__(
        self,
        config: Union[Config, Mapping[str, Any]],
        http: Optional[HttpClient] = None,
        cache: Optional[Cache] = None,
        *,
        sdk: Optional[str] = None,
        seal: Optional[Callable[[str], str]] = None,
        unseal: Optional[Callable[[str], str]] = None,
    ) -> None:
        self._config = config if isinstance(config, Config) else Config.from_dict(config)
        self._http: HttpClient = http if http is not None else UrllibHttpClient()
        self._cache: Cache = cache if cache is not None else MemoryCache()
        self._sdk = sdk or f"{PACKAGE}/{VERSION}"
        self._seal = seal
        self._unseal = unseal
        self._sdk_status: Optional[str] = None
        self._discovery: Optional[Discovery] = None
        self._discovery_until = 0.0
        self._verifier = TokenVerifier(self)

    # ------------------------------------------------------------------ accessors

    @property
    def config(self) -> Config:
        return self._config

    @property
    def cache(self) -> Cache:
        return self._cache

    @property
    def verifier(self) -> TokenVerifier:
        return self._verifier

    @property
    def sdk_status(self) -> Optional[str]:
        """``"ok"``, ``"outdated"``, ``"unsupported"`` or ``"unknown"`` from the last Bahari response, or ``None``."""
        return self._sdk_status

    # ------------------------------------------------------------------ discovery

    def discovery(self) -> Discovery:
        """The discovery document: cached for ``discovery_ttl``, then the last good copy (up to a week) when Bahari is
        unreachable, and finally the long-standing default endpoints."""
        now = time.monotonic()
        if self._discovery is not None and now < self._discovery_until:
            return self._discovery
        issuer = self._config.issuer
        ttl = self._config.discovery_ttl
        key = "bahari:discovery:" + _sha256(issuer)
        cached = self._cache.get(key)
        if isinstance(cached, dict) and isinstance(cached.get("data"), dict):
            data = cached["data"]
            found = Discovery(data, bool(cached.get("from_server")) and data.get("issuer") == issuer)
            return self._remember(found, min(30, ttl))
        try:
            data = self._send("GET", issuer + "/.well-known/bahari-configuration").json()
            if isinstance(data, dict) and data.get("issuer") == issuer:
                self._cache.set(key, {"from_server": True, "data": data}, ttl)
                self._cache.set(key + ":last-good", data, 604800)
                return self._remember(Discovery(data), ttl)
        except Exception:  # noqa: BLE001 - fall through to the last good copy or the defaults
            pass
        last = self._cache.get(key + ":last-good")
        found = Discovery(last) if isinstance(last, dict) and last.get("issuer") == issuer else Discovery.fallback(self._config)
        self._cache.set(key, {"from_server": found.from_server, "data": found.to_dict()}, 60)
        return self._remember(found, 60)

    def _remember(self, discovery: Discovery, seconds: float) -> Discovery:
        self._discovery = discovery
        self._discovery_until = time.monotonic() + max(0, seconds)
        return discovery

    # ------------------------------------------------------------------ sign-in

    def begin_login(
        self, kind: str, redirect_uri: str, login_hint: Optional[str] = None, prompt: Optional[str] = None
    ) -> LoginRequest:
        """Starts a sign-in. Store ``request.transaction`` server-side under ``request.state``, then redirect the
        browser to ``request.url``. ``prompt="create"`` opens Bahari registration first (customer sign-in only)."""
        self._assert_kind(kind)
        if not self._config.configured:
            raise BahariError("Bahari sign-in is not configured: set the client ID and secret.")
        state = secrets.token_hex(32)
        nonce = secrets.token_hex(32)
        verifier = secrets.token_hex(32)
        parameters: Dict[str, Any] = {
            "client_id": self._config.client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": base64url(hashlib.sha256(verifier.encode("ascii")).digest()),
        }
        if kind == "client":
            parameters.update(
                {"response_type": "code", "scope": self._config.scopes, "nonce": nonce, "code_challenge_method": "S256"}
            )
            if prompt in ("create", "login"):
                parameters["prompt"] = prompt
        if isinstance(login_hint, str) and "@" in login_hint and len(login_hint) <= 255:
            parameters["login_hint"] = login_hint
        endpoint = self.discovery().url("admin.authorize_endpoint" if kind == "admin" else "authorization_endpoint")
        separator = "&" if "?" in endpoint else "?"
        transaction = {
            "kind": kind,
            "nonce": nonce,
            "verifier": verifier,
            "redirect_uri": redirect_uri,
            "created_at": int(time.time()),
        }
        return LoginRequest(endpoint + separator + _query(parameters), state, transaction)

    def complete_login(self, transaction: Mapping[str, Any], code: str) -> Identity:
        """Finishes a sign-in with the transaction saved by :meth:`begin_login` and the code from the callback."""
        kind = transaction.get("kind")
        self._assert_kind(kind)
        created = transaction.get("created_at")
        if not isinstance(created, int) or isinstance(created, bool) or time.time() - created > 600:
            raise BahariError("The sign-in expired. Start again.")
        exchange = {
            "code": code,
            "code_verifier": transaction.get("verifier"),
            "redirect_uri": transaction.get("redirect_uri"),
        }
        if kind == "admin":
            profile = self._machine("admin.exchange_endpoint", exchange)
            session_token = profile.pop("session_token", None)
            tokens = {"session_token": "" if session_token is None else str(session_token)}
            self._check_identity(profile)
            self._authorize_admin(profile)
            return Identity("admin", profile["id"], tokens, profile)
        nonce = transaction.get("nonce")
        if not isinstance(nonce, str) or not nonce:
            raise BahariError("The sign-in transaction is invalid. Start again.")
        tokens = self._token({**exchange, "grant_type": "authorization_code"})
        claims = self._verifier.verify(str(tokens.get("id_token") or ""), nonce)
        profile = self._profile(str(tokens["access_token"]), claims["sub"])
        self._check_identity(profile)
        return Identity("client", claims["sub"], tokens, profile, self._lifetime(tokens), True)

    def refresh(
        self, kind: str, tokens: Mapping[str, Any], subject: str, access_expires_in: Optional[int] = None
    ) -> Identity:
        """Re-checks a stored session with Bahari (call on each request or every few minutes).

        ``access_expires_in`` is the number of seconds until the stored client access token expires. Client access
        tokens are rotated when they expire within 30 seconds; store the returned tokens when ``tokens_changed``.

        :raises AccessDeniedError: when the session must end.
        """
        self._assert_kind(kind)
        tokens = dict(tokens)
        try:
            if kind == "admin":
                profile = self._machine("admin.session_endpoint", {"session_token": str(tokens.get("session_token") or "")})
                profile.pop("session_token", None)
                if profile.get("id") != subject:
                    raise AccessDeniedError("The admin session belongs to another account.")
                self._authorize_admin(profile)
                return Identity("admin", subject, tokens, profile)
            changed = False
            lifetime = access_expires_in
            if access_expires_in is not None and access_expires_in < 30:
                tokens = self._token({"grant_type": "refresh_token", "refresh_token": str(tokens.get("refresh_token") or "")})
                claims = self._verifier.verify(str(tokens.get("id_token") or ""))
                if claims["sub"] != subject:
                    raise AccessDeniedError("The identity changed during refresh.")
                changed = True
                lifetime = self._lifetime(tokens)
            profile = self._profile(str(tokens.get("access_token") or ""), subject)
            return Identity("client", subject, tokens, profile, lifetime, changed)
        except HttpError as exc:
            if exc.response.status in (400, 401, 403):
                raise AccessDeniedError("Bahari ended this session.") from exc
            raise

    def revoke(self, kind: str, tokens: Mapping[str, Any]) -> None:
        """Ends the session at Bahari (admin session or client tokens)."""
        self._assert_kind(kind)
        if kind == "admin":
            self._machine("admin.revoke_endpoint", {"session_token": str(tokens.get("session_token") or "")})
            return
        for token_type in ("refresh_token", "access_token"):
            if tokens.get(token_type) is not None:
                self._form(
                    self.discovery().url("revocation_endpoint"),
                    {
                        "token": tokens[token_type],
                        "token_type_hint": token_type,
                        "client_id": self._config.client_id,
                        "client_secret": self._config.client_secret,
                    },
                )

    def logout_url(self, kind: str, post_logout_redirect: str, id_token_hint: Optional[str] = None) -> str:
        """Where to send the browser after the local logout: Bahari's logout for customers, the admin panel for admins.
        With the customer's ``id_token`` as ``id_token_hint`` Bahari signs out at once and returns to the app."""
        self._assert_kind(kind)
        if kind == "admin":
            return self.discovery().url("admin.panel_url")
        parameters = {"client_id": self._config.client_id, "post_logout_redirect_uri": post_logout_redirect}
        if id_token_hint:
            parameters["id_token_hint"] = id_token_hint
        return self._append(self.discovery().url("end_session_endpoint"), parameters)

    def verify_logout_token(self, token: str) -> Dict[str, Any]:
        """Verifies a back-channel logout token. End every local customer session of ``claims["sub"]``, once per
        ``claims["jti"]``."""
        return self._verifier.verify(token, logout=True)

    # ------------------------------------------------------------------ roles, branding and maintenance

    def role(self, identity: Any) -> str:
        """The person's role in this app: ``SUPER_ADMIN``, ``ADMIN`` or ``USER``, as Bahari decides it from the platform's
        Access & RBAC settings. A customer session is ``USER`` unless Bahari reports admin access to this platform."""
        profile = getattr(identity, "profile", None) or {}
        if getattr(identity, "kind", None) == "admin":
            role = profile.get("role") or "ADMIN"
        else:
            access = profile.get("admin_access")
            role = (
                access.get("role")
                if isinstance(access, dict) and access.get("platform") == self._config.platform and access.get("role") in ("ADMIN", "SUPER_ADMIN")
                else "USER"
            )
        return role if role in ("SUPER_ADMIN", "ADMIN", "USER") else "USER"

    def is_admin(self, identity: Any) -> bool:
        """True for an administrator session of this app (not a customer who merely could become one)."""
        return getattr(identity, "kind", None) == "admin" and self.role(identity) != "USER"

    @staticmethod
    def linked_user_id(identity: Any) -> str:
        """The Bahari account a back-channel logout is about: the customer subject, or an admin session's user_id."""
        if getattr(identity, "kind", None) == "admin":
            return str((getattr(identity, "profile", None) or {}).get("user_id") or "")
        return str(getattr(identity, "subject", ""))

    def branding(self, platform: Optional[str] = None, ttl: int = 60) -> Dict[str, Any]:
        """The app's branding, access mode, maintenance state and support contact from Bahari. Public, cached for
        ``ttl`` seconds; the last good copy is used when Bahari cannot be reached."""
        key = platform or self._config.platform
        if not isinstance(key, str) or not re.fullmatch(r"[a-z0-9_-]{1,80}", key):
            raise BahariError("Set the platform key (BAHARI_PLATFORM_KEY) to read branding.")
        defaults: Dict[str, Any] = {
            "name": None, "access_mode": "hybrid", "logo_url": None, "logo_light_url": None, "logo_dark_url": None,
            "favicon_url": None, "brand_color": None, "maintenance": {"enabled": False, "message": None},
            "support": {"email": None, "phone": None, "url": None},
        }
        cache_key = "bahari:branding:" + _sha256(self._config.issuer + "|" + key)
        cached = self._cache.get(cache_key)
        if isinstance(cached, dict):
            return {**defaults, **cached}
        template = self.discovery().get("api.platform_branding") or self._config.issuer + "/api/v1/platform-branding/{key}"
        try:
            data = self._send("GET", str(template).replace("{key}", quote(key, safe="")), throw=True).json("data")
            if isinstance(data, dict):
                self._cache.set(cache_key, data, max(1, ttl))
                self._cache.set(cache_key + ":last-good", data, 604800)
                return {**defaults, **data}
        except Exception:  # noqa: BLE001 - fall back to the last good copy
            pass
        last = self._cache.get(cache_key + ":last-good")
        return {**defaults, **(last if isinstance(last, dict) else {})}

    def maintenance(self, platform: Optional[str] = None) -> Dict[str, Any]:
        """``{"enabled": bool, "message": str | None}``: show a banner when enabled. Bahari already stops new sign-ins."""
        maintenance = self.branding(platform).get("maintenance") or {}
        message = maintenance.get("message")
        return {"enabled": bool(maintenance.get("enabled")), "message": message if isinstance(message, str) else None}

    # ------------------------------------------------------------------ navigation and URLs

    def navigation(self, kind: str, tokens: Mapping[str, Any], wallet_return_to: Optional[str] = None) -> Any:
        """The platform switcher for the signed-in person. For customers the wallet link opens Bahari's wallet for this
        platform."""
        self._assert_kind(kind)
        if kind == "admin":
            return self._machine("admin.navigation_endpoint", {"session_token": str(tokens.get("session_token") or "")})
        navigation = self._send(
            "GET",
            self.discovery().url("api.platform_navigation"),
            {"Authorization": "Bearer " + str(tokens.get("access_token") or "")},
            throw=True,
        ).json("data")
        if isinstance(navigation, dict) and isinstance(navigation.get("wallet"), dict):
            navigation["wallet"]["url"] = self.wallet_url(wallet_return_to)
        return navigation if isinstance(navigation, (dict, list)) else {}

    def update_pinned(self, tokens: Mapping[str, Any], keys: Iterable[str]) -> Response:
        """Saves the customer's pinned platforms. Returns Bahari's response so validation errors (422) can be shown."""
        url = self.discovery().url("api.platform_navigation")
        response = self._send(
            "PUT",
            url,
            {"Authorization": "Bearer " + str(tokens.get("access_token") or ""), "Content-Type": "application/json"},
            json.dumps({"pinned_keys": list(keys)}),
        )
        if not response.ok and response.status != 422:
            raise HttpError(response, url)
        return response

    def url(self, name: str, query: Optional[Mapping[str, Any]] = None) -> str:
        """A URL from discovery, such as ``client.wallet_url``, ``client.profile_url``, ``admin.panel_url``."""
        url = self.discovery().url(name)
        return self._append(url, query) if query else url

    def wallet_url(self, return_to: Optional[str] = None, amount: Optional[str] = None) -> str:
        query = {k: v for k, v in {"platform": self._config.platform, "return_to": return_to, "amount": amount}.items() if v}
        return self.url("client.wallet_url", query)

    def checkout_options(self, external_user_id: str) -> Any:
        return self.api("GET", "platform-wallets/" + quote(external_user_id, safe="") + "/checkout-options", None, "wallet:read")

    def start_top_up(self, external_user_id: str, top_up: Mapping[str, Any]) -> Any:
        return self.api("POST", "platform-wallets/" + quote(external_user_id, safe="") + "/top-ups", top_up, "wallet:debit")

    def top_up(self, external_user_id: str, reference: str) -> Any:
        return self.api("GET", "platform-wallets/" + quote(external_user_id, safe="") + "/top-ups/" + quote(reference, safe=""), None, "wallet:read")

    # ------------------------------------------------------------ billing (features "Invoices" / "Subscriptions")
    # The app sets its prices; Bahari invoices, takes payment and renews. ``reference`` is your own UUID (idempotent).
    # Answers are {"data": ..., "payment": ...}; send the customer to data["checkout_url"] (or
    # data["open_invoice"]["checkout_url"]) unless you paid with pay="wallet" ("Charge without confirmation").

    def create_invoice(self, invoice: Mapping[str, Any]) -> Any:
        return self.api("POST", "platform-billing/invoices", invoice, "billing")

    def invoice(self, reference: str) -> Any:
        return self.api("GET", "platform-billing/invoices/" + quote(reference, safe=""), None, "billing")

    def void_invoice(self, reference: str) -> Any:
        return self.api("POST", "platform-billing/invoices/" + quote(reference, safe="") + "/void", None, "billing")

    def create_subscription(self, subscription: Mapping[str, Any]) -> Any:
        return self.api("POST", "platform-billing/subscriptions", subscription, "billing")

    def subscription(self, reference: str) -> Any:
        return self.api("GET", "platform-billing/subscriptions/" + quote(reference, safe=""), None, "billing")

    def update_subscription(self, reference: str, changes: Mapping[str, Any]) -> Any:
        """Changes plan_name, amount or cycle from the next renewal invoice."""
        return self.api("PATCH", "platform-billing/subscriptions/" + quote(reference, safe=""), changes, "billing")

    def cancel_subscription(self, reference: str, when: str = "period_end") -> Any:
        return self.api("POST", "platform-billing/subscriptions/" + quote(reference, safe="") + "/cancel", {"when": when}, "billing")

    def resume_subscription(self, reference: str) -> Any:
        return self.api("POST", "platform-billing/subscriptions/" + quote(reference, safe="") + "/resume", None, "billing")

    def customer_subscriptions(self, user_id: str) -> Any:
        return self.api("GET", "platform-billing/customers/" + quote(user_id, safe="") + "/subscriptions", None, "billing")

    def api(self, method: str, path: str, data: Optional[Mapping[str, Any]] = None, scope: str = "identity:lookup") -> Any:
        """Calls a platform API endpoint with this app's machine token (client credentials).

        ``path`` is relative to the API base URL, for example ``"platform-wallets/123/debits"``.
        """
        method = method.upper()
        data = dict(data or {})
        url = self.discovery().url("api.base_url").rstrip("/") + "/" + path.lstrip("/")
        body = None if method == "GET" else json.dumps(data)
        if method == "GET" and data:
            url = self._append(url, data)

        def call() -> Response:
            return self._send(
                method,
                url,
                {"Authorization": "Bearer " + self._machine_token(scope), "Content-Type": "application/json"},
                body,
            )

        response = call()
        if response.status == 401:
            self._cache.delete(self._machine_key(scope))
            response = call()
        if not response.ok:
            raise HttpError(response, url)
        result = response.json()
        return result if isinstance(result, (dict, list)) else {}

    def jwks(self, fresh: bool = False) -> Dict[str, Any]:
        url = self.discovery().url("jwks_uri")
        key = "bahari:jwks:" + _sha256(url)
        jwks = None if fresh else self._cache.get(key)
        if not isinstance(jwks, dict):
            jwks = self._send("GET", url, throw=True).json()
            jwks = jwks if isinstance(jwks, dict) else {}
            self._cache.set(key, jwks, 300)
        return jwks

    # ------------------------------------------------------------------ internals

    def _token(self, data: Mapping[str, Any]) -> Dict[str, Any]:
        response = self._form(
            self.discovery().url("token_endpoint"),
            {**data, "client_id": self._config.client_id, "client_secret": self._config.client_secret},
        )
        tokens = response.json()
        if not isinstance(tokens, dict) or not isinstance(tokens.get("access_token"), str):
            raise BahariError("Bahari returned no access token.")
        return tokens

    def _profile(self, access_token: str, subject: str) -> Dict[str, Any]:
        profile = self._send(
            "GET", self.discovery().url("profile_endpoint"), {"Authorization": "Bearer " + access_token}, throw=True
        ).json("data")
        customer = profile.get("customer") if isinstance(profile, dict) else None
        if (
            not isinstance(profile, dict)
            or profile.get("id") != subject
            or profile.get("status") != "active"
            or not isinstance(customer, dict)
            or not is_uuid(customer.get("id"))
        ):
            raise AccessDeniedError("The Bahari account is unavailable.")
        return profile

    def _machine(self, endpoint: str, data: Mapping[str, Any]) -> Dict[str, Any]:
        url = self.discovery().url(endpoint)
        body = json.dumps(dict(data))

        def call() -> Response:
            return self._send(
                "POST",
                url,
                {"Authorization": "Bearer " + self._machine_token("identity:lookup"), "Content-Type": "application/json"},
                body,
            )

        response = call()
        if response.status == 401:
            self._cache.delete(self._machine_key("identity:lookup"))
            response = call()
        if not response.ok:
            raise HttpError(response, url)
        result = response.json("data")
        return result if isinstance(result, dict) else {}

    def _machine_token(self, scope: str) -> str:
        key = self._machine_key(scope)
        sealed = self._cache.get(key)
        if isinstance(sealed, str):
            return self._unseal(sealed) if self._unseal else sealed
        tokens = self._token({"grant_type": "client_credentials", "scope": scope})
        token = tokens["access_token"]
        try:
            expires_in = int(tokens.get("expires_in") or 600)
        except (TypeError, ValueError):
            expires_in = 600
        self._cache.set(key, self._seal(token) if self._seal else token, max(30, min(600, expires_in - 60)))
        return token

    def _machine_key(self, scope: str) -> str:
        return "bahari:machine:" + _sha256(self._config.client_id + "\0" + self._config.client_secret + "\0" + scope)

    def _form(self, url: str, data: Mapping[str, Any]) -> Response:
        return self._send(
            "POST", url, {"Content-Type": "application/x-www-form-urlencoded"}, _query(data), throw=True
        )

    def _send(
        self,
        method: str,
        url: str,
        headers: Optional[Mapping[str, str]] = None,
        body: Optional[str] = None,
        throw: bool = False,
    ) -> Response:
        merged = dict(headers or {})
        merged.setdefault("Accept", "application/json")
        merged.setdefault("X-Bahari-SDK", self._sdk)
        response = self._http.send(method, url, merged, body)
        status = response.header("X-Bahari-SDK-Status")
        if status:
            self._sdk_status = status
            self._warn_outdated(status)
        if throw and not response.ok:
            raise HttpError(response, url)
        return response

    def _warn_outdated(self, status: str) -> None:
        if status not in ("outdated", "unsupported"):
            return
        with _warned_lock:
            if (self._sdk, status) in _warned:
                return
            _warned.add((self._sdk, status))
        logger.warning("Bahari reports %s as %s. Run: pip install --upgrade %s", self._sdk, status, PACKAGE)

    def _check_identity(self, profile: Mapping[str, Any]) -> None:
        email = profile.get("email")
        if not is_uuid(profile.get("id")) or not isinstance(email, str) or not _EMAIL.match(email) or not isinstance(profile.get("name"), str):
            raise BahariError("Bahari returned an invalid identity.")

    def _authorize_admin(self, profile: Mapping[str, Any]) -> None:
        if (
            self._config.platform is None
            or profile.get("platform") != self._config.platform
            or profile.get("role") not in ADMIN_ROLES
        ):
            raise AccessDeniedError("Administration of this platform is not authorized.")

    @staticmethod
    def _assert_kind(kind: Any) -> None:
        if kind not in KINDS:
            raise ValueError('Kind must be "client" or "admin".')

    @staticmethod
    def _lifetime(tokens: Mapping[str, Any]) -> int:
        try:
            expires_in = int(tokens.get("expires_in") if tokens.get("expires_in") is not None else 900)
        except (TypeError, ValueError):
            expires_in = 900
        return min(900, max(1, expires_in))

    @staticmethod
    def _append(url: str, query: Mapping[str, Any]) -> str:
        encoded = _query(query)
        if not encoded:
            return url
        return url + ("&" if "?" in url else "?") + encoded
