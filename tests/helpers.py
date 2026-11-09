"""Shared test fixtures: real RS256 keys, a fake HTTP transport and a fake Bahari server."""

from __future__ import annotations

import json
import time
from typing import Any, Callable, Dict, List, Mapping, Optional, Union
from urllib.parse import parse_qs, urlsplit

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from bahari_sso import BahariClient, BahariError, Config, MemoryCache, Response
from bahari_sso.tokens import base64url

ISSUER = "https://accounts.example.test"
ADMIN = "https://admin.example.test"
SUBJECT = "0198a6c1-1111-7000-8000-000000000001"
OTHER = "0198a6c1-3333-7000-8000-000000000003"
CUSTOMER = "0198a6c1-2222-7000-8000-000000000002"
ADMIN_ID = "0198a6c1-4444-7000-8000-000000000004"
LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"
SDK = "bahari-sso/0.1.0"

Route = Union[Response, Callable[[Optional[str], Dict[str, str]], Response]]


class Keys:
    def __init__(self, kid: str = "k1") -> None:
        self.kid = kid
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pem = self.private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        numbers = self.private.public_key().public_numbers()
        self.jwk = {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": base64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
            "e": base64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
        }

    def token(self, claims: Optional[Mapping[str, Any]] = None, headers: Optional[Mapping[str, Any]] = None) -> str:
        now = int(time.time())
        payload = {"iss": ISSUER, "aud": ["client-1"], "sub": SUBJECT, "iat": now, "exp": now + 900}
        payload.update(claims or {})
        return jwt.encode(payload, self.pem, algorithm="RS256", headers={"kid": self.kid, **(headers or {})})

    def logout_token(self, jti: str = "j1", **claims: Any) -> str:
        return self.token({"jti": jti, "events": {LOGOUT_EVENT: {}}, **claims})


def json_response(data: Any, status: int = 200, headers: Optional[Mapping[str, str]] = None) -> Response:
    return Response(status, json.dumps(data), headers or {})


class FakeHttp:
    """Routes are keyed "METHOD url-without-query"; a callable route receives (body, headers)."""

    def __init__(self, routes: Optional[Dict[str, Route]] = None) -> None:
        self.routes: Dict[str, Route] = dict(routes or {})
        self.sent: List[Dict[str, Any]] = []

    def send(self, method: str, url: str, headers: Optional[Mapping[str, str]] = None, body: Optional[str] = None) -> Response:
        headers = dict(headers or {})
        self.sent.append({"method": method, "url": url, "headers": headers, "body": body})
        route = self.routes.get(method + " " + url.split("?", 1)[0])
        if route is None:
            raise BahariError("Unexpected request " + method + " " + url)
        return route(body, headers) if callable(route) else route

    def calls(self, method: str, url: str) -> List[Dict[str, Any]]:
        return [s for s in self.sent if s["method"] == method and s["url"].split("?", 1)[0] == url]


def discovery(admin: str = ADMIN) -> Dict[str, Any]:
    return {
        "issuer": ISSUER,
        "authorization_endpoint": ISSUER + "/oauth/authorize",
        "token_endpoint": ISSUER + "/oauth/token",
        "profile_endpoint": ISSUER + "/oauth/user",
        "jwks_uri": ISSUER + "/oauth/jwks",
        "revocation_endpoint": ISSUER + "/oauth/revoke",
        "end_session_endpoint": ISSUER + "/oauth/logout",
        "client": {"wallet_url": ISSUER + "/dashboard/wallet"},
        "admin": {
            "panel_url": admin + "/admin",
            "authorize_endpoint": admin + "/admin-sso/authorize",
            "exchange_endpoint": ISSUER + "/api/v1/admin-sso/exchange",
            "session_endpoint": ISSUER + "/api/v1/admin-sso/session",
            "revoke_endpoint": ISSUER + "/api/v1/admin-sso/revoke",
            "navigation_endpoint": ISSUER + "/api/v1/admin-sso/navigation",
        },
        "api": {"base_url": ISSUER + "/api/v1", "platform_navigation": ISSUER + "/api/v1/platform-navigation"},
    }


def profile(**overrides: Any) -> Dict[str, Any]:
    data = {"id": SUBJECT, "name": "Rafi", "email": "rafi@example.test", "status": "active", "customer": {"id": CUSTOMER}}
    data.update(overrides)
    return data


def make_client(http: FakeHttp, cache: Optional[MemoryCache] = None, **config: Any) -> BahariClient:
    settings = {"issuer": ISSUER, "client_id": "client-1", "client_secret": "secret-1", "platform": "reseller"}
    settings.update(config)
    return BahariClient(Config.from_dict(settings), http, cache if cache is not None else MemoryCache(), sdk=SDK)


def form(body: Optional[str]) -> Dict[str, str]:
    return {k: v[0] for k, v in parse_qs(body or "").items()}


def query(url: str) -> Dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


class FakeBahari:
    """A fake Bahari Accounts server behind FakeHttp, for the framework helper tests."""

    def __init__(self, keys: Keys) -> None:
        self.keys = keys
        self.http = FakeHttp()
        self.codes: Dict[str, Optional[str]] = {}
        self.customer = profile(admin_access=None)
        self.customer_status = 200
        self.admin = profile(id=ADMIN_ID, name="Admin", email="admin@example.test", platform="reseller", role="ADMIN", user_id=SUBJECT)
        self.admin_session_status = 200
        self.revoked: List[Dict[str, str]] = []
        self.admin_revoked: List[str] = []
        self.counter = 0
        r = self.http.routes
        r["GET " + ISSUER + "/.well-known/bahari-configuration"] = json_response(discovery())
        r["GET " + ISSUER + "/oauth/jwks"] = lambda b, h: json_response({"keys": [self.keys.jwk]})
        r["POST " + ISSUER + "/oauth/token"] = self._token
        r["GET " + ISSUER + "/oauth/user"] = lambda b, h: json_response({"data": self.customer}, self.customer_status) if self.customer_status == 200 else json_response({"message": "no"}, self.customer_status)
        r["POST " + ISSUER + "/oauth/revoke"] = self._revoke
        r["POST " + ISSUER + "/api/v1/admin-sso/exchange"] = self._exchange
        r["POST " + ISSUER + "/api/v1/admin-sso/session"] = self._admin_session
        r["POST " + ISSUER + "/api/v1/admin-sso/revoke"] = self._admin_revoke

    def authorize(self, url: str) -> Dict[str, str]:
        """Plays the authorize page: returns {"state", "code"} for the callback."""
        params = query(url)
        assert params["client_id"] == "client-1"
        self.counter += 1
        code = f"code-{self.counter}"
        self.codes[code] = params.get("nonce")
        return {"state": params["state"], "code": code}

    def _token(self, body: Optional[str], headers: Dict[str, str]) -> Response:
        data = form(body)
        assert data["client_id"] == "client-1" and data["client_secret"] == "secret-1"
        if data["grant_type"] == "client_credentials":
            return json_response({"access_token": "machine", "expires_in": 3600})
        if data["grant_type"] == "refresh_token":
            return json_response({"access_token": "a2", "refresh_token": "r2", "expires_in": 600, "id_token": self.keys.token()})
        nonce = self.codes.pop(data["code"])
        return json_response(
            {"access_token": "access-secret", "refresh_token": "refresh-secret", "expires_in": 3600, "id_token": self.keys.token({"nonce": nonce})}
        )

    def _revoke(self, body: Optional[str], headers: Dict[str, str]) -> Response:
        self.revoked.append(form(body))
        return json_response({})

    def _exchange(self, body: Optional[str], headers: Dict[str, str]) -> Response:
        assert headers["Authorization"] == "Bearer machine"
        assert json.loads(body or "{}")["code"] in self.codes
        self.codes.pop(json.loads(body or "{}")["code"])
        return json_response({"data": dict(self.admin, session_token="admin-session-secret")})

    def _admin_session(self, body: Optional[str], headers: Dict[str, str]) -> Response:
        if self.admin_session_status != 200:
            return json_response({"message": "revoked"}, self.admin_session_status)
        return json_response({"data": dict(self.admin)})

    def _admin_revoke(self, body: Optional[str], headers: Dict[str, str]) -> Response:
        self.admin_revoked.append(json.loads(body or "{}").get("session_token"))
        return json_response({"data": {}})

    def client(self, **config: Any) -> BahariClient:
        return make_client(self.http, **config)


SECRETS = ("access-secret", "refresh-secret", "admin-session-secret", "access_token", "refresh_token", "session_token", "id_token")
