from urllib.parse import parse_qs, urlsplit
"""Mirrors php/tests/ClientTest.php, plus extra protocol checks."""

import hashlib
import json
import logging
import time

import pytest

import bahari_sso.client as client_module
from bahari_sso import AccessDeniedError, BahariError, Config, HttpError, InvalidTokenError, MemoryCache
from bahari_sso.tokens import base64url
from helpers import (
    ADMIN,
    ISSUER,
    LOGOUT_EVENT,
    OTHER,
    SDK,
    SUBJECT,
    FakeHttp,
    Keys,
    discovery,
    form,
    json_response,
    make_client,
    profile,
    query,
)

WELL_KNOWN = "GET " + ISSUER + "/.well-known/bahari-configuration"
JWKS = "GET " + ISSUER + "/oauth/jwks"
TOKEN = "POST " + ISSUER + "/oauth/token"
USER = "GET " + ISSUER + "/oauth/user"


# ---------------------------------------------------------------- ClientTest.php


def test_admin_login_uses_the_admin_host_from_discovery_and_sends_the_sdk_header(caplog):
    client_module._warned.clear()
    http = FakeHttp({WELL_KNOWN: json_response(discovery("https://new-admin.example.test"), headers={"x-bahari-sdk-status": "outdated"})})
    client = make_client(http)
    with caplog.at_level(logging.WARNING, logger="bahari_sso"):
        login = client.begin_login("admin", "https://app.example.test/auth/admin/callback")

    assert login.url.startswith("https://new-admin.example.test/admin-sso/authorize?")
    params = query(login.url)
    assert params["state"] == login.state
    assert params["code_challenge"] == base64url(hashlib.sha256(login.transaction["verifier"].encode()).digest())
    assert set(params) == {"client_id", "redirect_uri", "state", "code_challenge"}  # no response_type/scope/nonce
    assert http.sent[0]["headers"]["X-Bahari-SDK"] == SDK
    assert http.sent[0]["headers"]["Accept"] == "application/json"
    assert client.sdk_status == "outdated"
    assert [r.message for r in caplog.records].count(f"Bahari reports {SDK} as outdated. Run: pip install --upgrade bahari-sso") == 1

    # Warned at most once per process.
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="bahari_sso"):
        make_client(http).discovery()
    assert not caplog.records


def test_discovery_falls_back_to_defaults_and_rejects_a_document_for_another_issuer():
    doc = dict(discovery("https://evil.example.test"), issuer="https://evil.example.test")
    http = FakeHttp({WELL_KNOWN: json_response(doc)})
    client = make_client(http, admin_issuer="https://admin-fallback.example.test")

    assert client.discovery().from_server is False
    assert client.discovery().url("admin.authorize_endpoint") == "https://admin-fallback.example.test/admin-sso/authorize"
    assert client.discovery().url("token_endpoint") == ISSUER + "/oauth/token"
    assert client.url("admin.profile_url") == "https://admin-fallback.example.test/admin/profile"
    assert client.url("client.applications_url") == ISSUER + "/dashboard/applications"


def test_last_good_discovery_is_used_when_bahari_is_unreachable():
    cache = MemoryCache()
    make_client(FakeHttp({WELL_KNOWN: json_response(discovery("https://moved-admin.example.test"))}), cache).discovery()
    cache.delete("bahari:discovery:" + hashlib.sha256(ISSUER.encode()).hexdigest())

    client = make_client(FakeHttp(), cache)

    assert client.url("admin.panel_url") == "https://moved-admin.example.test/admin"


def test_client_login_verifies_the_id_token_nonce_and_profile(keys):
    http = FakeHttp({WELL_KNOWN: json_response(discovery()), JWKS: json_response({"keys": [keys.jwk]}), USER: json_response({"data": profile()})})
    client = make_client(http)
    login = client.begin_login("client", "https://app.example.test/cb")
    params = query(login.url)
    assert params["response_type"] == "code" and params["code_challenge_method"] == "S256"
    assert params["nonce"] == login.transaction["nonce"]
    assert params["scope"] == "openid profile email phone profile:read identity:read wallet:read platform:read"
    http.routes[TOKEN] = json_response(
        {"access_token": "a", "refresh_token": "r", "expires_in": 3600, "id_token": keys.token({"nonce": login.transaction["nonce"]})}
    )

    identity = client.complete_login(login.transaction, "code-1")

    assert identity.subject == SUBJECT
    assert identity.access_expires_in == 900
    assert identity.profile["email"] == "rafi@example.test"
    sent = form(http.calls("POST", ISSUER + "/oauth/token")[0]["body"])
    assert sent["code_verifier"] == login.transaction["verifier"] and sent["grant_type"] == "authorization_code"

    http.routes[TOKEN] = json_response({"access_token": "a", "id_token": keys.token({"nonce": "wrong"})})
    with pytest.raises(InvalidTokenError):
        client.complete_login(login.transaction, "code-2")


def test_admin_exchange_requires_an_admin_role_for_this_platform():
    admin_profile = profile(platform="reseller", role="ADMIN", session_token="s" * 64)
    http = FakeHttp(
        {
            WELL_KNOWN: json_response(discovery()),
            TOKEN: json_response({"access_token": "machine", "expires_in": 3600}),
            "POST " + ISSUER + "/api/v1/admin-sso/exchange": lambda body, headers: json_response({"data": admin_profile}),
        }
    )
    client = make_client(http)
    login = client.begin_login("admin", "https://app.example.test/cb")

    identity = client.complete_login(login.transaction, "code")
    assert identity.tokens == {"session_token": "s" * 64}
    assert "session_token" not in identity.profile
    exchange = http.calls("POST", ISSUER + "/api/v1/admin-sso/exchange")[0]
    assert exchange["headers"]["Authorization"] == "Bearer machine"
    assert json.loads(exchange["body"]) == {"code": "code", "code_verifier": login.transaction["verifier"], "redirect_uri": "https://app.example.test/cb"}
    assert form(http.calls("POST", ISSUER + "/oauth/token")[0]["body"])["scope"] == "identity:lookup"

    admin_profile["platform"] = "sms"
    with pytest.raises(AccessDeniedError):
        client.complete_login(login.transaction, "code")


def test_refresh_rotates_expiring_tokens_and_rejects_another_subject(keys):
    subject = {"value": SUBJECT}
    http = FakeHttp(
        {
            WELL_KNOWN: json_response(discovery()),
            JWKS: json_response({"keys": [keys.jwk]}),
            USER: json_response({"data": profile()}),
            TOKEN: lambda body, headers: json_response(
                {"access_token": "new-a", "refresh_token": "new-r", "expires_in": 600, "id_token": keys.token({"sub": subject["value"]})}
            ),
        }
    )
    client = make_client(http)

    fresh = client.refresh("client", {"access_token": "a", "refresh_token": "r"}, SUBJECT, 300)
    assert fresh.tokens_changed is False

    rotated = client.refresh("client", {"access_token": "a", "refresh_token": "r"}, SUBJECT, 10)
    assert rotated.tokens_changed is True
    assert rotated.tokens["refresh_token"] == "new-r"
    assert rotated.access_expires_in == 600

    subject["value"] = OTHER
    with pytest.raises(AccessDeniedError):
        client.refresh("client", {"access_token": "a", "refresh_token": "r"}, SUBJECT, 10)


def test_revoked_admin_session_is_access_denied():
    http = FakeHttp(
        {
            WELL_KNOWN: json_response(discovery()),
            TOKEN: json_response({"access_token": "machine"}),
            "POST " + ISSUER + "/api/v1/admin-sso/session": json_response({"message": "revoked"}, 403),
        }
    )
    with pytest.raises(AccessDeniedError):
        make_client(http).refresh("admin", {"session_token": "x"}, SUBJECT)


def test_logout_token_and_urls(keys):
    http = FakeHttp({WELL_KNOWN: json_response(discovery()), JWKS: json_response({"keys": [keys.jwk]})})
    client = make_client(http)

    claims = client.verify_logout_token(keys.token({"jti": "j1", "events": {LOGOUT_EVENT: {}}}))
    assert claims["sub"] == SUBJECT
    assert client.logout_url("client", "https://app.example.test/") == ISSUER + "/oauth/logout?client_id=client-1&post_logout_redirect_uri=https%3A%2F%2Fapp.example.test%2F"
    assert client.logout_url("admin", "https://app.example.test/") == ADMIN + "/admin"
    assert client.wallet_url("/dashboard") == ISSUER + "/dashboard/wallet?platform=reseller&return_to=%2Fdashboard"

    with pytest.raises(InvalidTokenError):
        client.verify_logout_token(keys.token({"jti": "j2"}))


def test_issuer_must_be_https():
    with pytest.raises(ValueError):
        Config.from_dict({"issuer": "http://accounts.example.test", "client_id": "a", "client_secret": "b"})


# ---------------------------------------------------------------- extra coverage


@pytest.mark.parametrize(
    "issuer",
    ["https://user:pw@accounts.example.test", "https://accounts.example.test/?x=1", "https://accounts.example.test/#f", "ftp://accounts.example.test", "accounts.example.test", ""],
)
def test_invalid_issuers_are_rejected(issuer):
    with pytest.raises(ValueError):
        Config(issuer, "a", "b")


def test_localhost_may_use_http_and_trailing_slash_is_removed():
    assert Config("http://localhost:8000/", "a", "b").issuer == "http://localhost:8000"
    assert Config("http://127.0.0.1", "a", "b").issuer == "http://127.0.0.1"
    config = Config.from_dict({"issuer": "https://accounts.example.test/", "client_id": "a", "client_secret": "b"})
    assert config.discovery_ttl == 300 and config.configured
    assert "super-secret" not in repr(Config("https://x.test", "a", "super-secret"))


def test_begin_login_requires_credentials():
    with pytest.raises(BahariError):
        make_client(FakeHttp({WELL_KNOWN: json_response(discovery())}), client_secret="").begin_login("client", "https://app/cb")
    with pytest.raises(ValueError):
        make_client(FakeHttp()).begin_login("staff", "https://app/cb")


def test_expired_transaction_is_rejected():
    client = make_client(FakeHttp({WELL_KNOWN: json_response(discovery())}))
    login = client.begin_login("client", "https://app/cb")
    with pytest.raises(BahariError, match="expired"):
        client.complete_login(dict(login.transaction, created_at=int(time.time()) - 601), "code")


def test_tokens_with_bad_algorithm_kid_issuer_audience_or_subject_are_rejected(keys):
    http = FakeHttp({WELL_KNOWN: json_response(discovery()), JWKS: json_response({"keys": [keys.jwk]})})
    client = make_client(http)
    verify = client.verifier.verify
    assert verify(keys.token())["sub"] == SUBJECT
    import jwt as pyjwt

    unsigned = pyjwt.encode({"sub": SUBJECT}, "secret-key-of-sufficient-length-32b", algorithm="HS256", headers={"kid": "k1"})
    for bad in (
        unsigned,
        "not-a-token",
        keys.token({"iss": "https://evil.example.test"}),
        keys.token({"aud": ["someone-else"]}),
        keys.token({"sub": "not-a-uuid"}),
        keys.token({"exp": int(time.time()) - 120}),
        keys.token({"iat": int(time.time()) + 600, "exp": int(time.time()) + 1200}),
    ):
        with pytest.raises(InvalidTokenError):
            verify(bad)
    assert verify(keys.token({"aud": "client-1"}))["sub"] == SUBJECT
    assert verify(keys.token({"exp": int(time.time()) - 10}))["sub"] == SUBJECT  # 30 s leeway
    with pytest.raises(InvalidTokenError, match="algorithm"):
        verify(pyjwt.encode({"sub": SUBJECT}, keys.pem, algorithm="RS256"))  # no kid


def test_jwks_is_cached_and_refetched_once_for_an_unknown_kid(keys):
    rotated = Keys("k2")
    jwks = {"keys": [keys.jwk]}
    http = FakeHttp({WELL_KNOWN: json_response(discovery()), JWKS: lambda b, h: json_response(jwks)})
    client = make_client(http)
    client.verifier.verify(keys.token())
    client.verifier.verify(keys.token())
    assert len(http.calls("GET", ISSUER + "/oauth/jwks")) == 1

    jwks["keys"] = [keys.jwk, rotated.jwk]
    assert client.verifier.verify(rotated.token())["sub"] == SUBJECT
    assert len(http.calls("GET", ISSUER + "/oauth/jwks")) == 2

    with pytest.raises(InvalidTokenError, match="signature"):
        client.verifier.verify(Keys("k3").token())
    assert len(http.calls("GET", ISSUER + "/oauth/jwks")) == 3

    forged = Keys("k1")  # same kid, different key: bad signature, refetched once, still rejected
    with pytest.raises(InvalidTokenError):
        client.verifier.verify(forged.token())


def test_logout_token_rules(keys):
    client = make_client(FakeHttp({WELL_KNOWN: json_response(discovery()), JWKS: json_response({"keys": [keys.jwk]})}))
    now = int(time.time())
    for bad in (
        keys.token({"events": {LOGOUT_EVENT: {}}}),  # no jti
        keys.logout_token(nonce="n"),
        keys.token({"jti": "x", "events": {"other": {}}}),
        keys.logout_token(iat=now - 400, exp=now + 900),
    ):
        with pytest.raises(InvalidTokenError):
            client.verify_logout_token(bad)


def test_profile_must_be_active_and_match_the_subject(keys):
    user = {"data": profile(status="suspended")}
    http = FakeHttp({WELL_KNOWN: json_response(discovery()), USER: lambda b, h: json_response(user)})
    client = make_client(http)
    for data in (profile(status="suspended"), profile(id=OTHER), profile(customer={"id": "nope"}), None):
        user["data"] = data
        with pytest.raises(AccessDeniedError):
            client.refresh("client", {"access_token": "a"}, SUBJECT, 300)
    user["data"] = profile(admin_access={"platform": "reseller", "role": "ADMIN", "two_factor_ready": True})
    identity = client.refresh("client", {"access_token": "a"}, SUBJECT, None)
    assert identity.profile["admin_access"]["role"] == "ADMIN"
    assert http.sent[-1]["headers"]["Authorization"] == "Bearer a"


@pytest.mark.parametrize("status", [400, 401, 403])
def test_refresh_http_rejections_are_access_denied(status):
    http = FakeHttp({WELL_KNOWN: json_response(discovery()), USER: json_response({"message": "no"}, status)})
    with pytest.raises(AccessDeniedError):
        make_client(http).refresh("client", {"access_token": "a"}, SUBJECT, 300)


def test_refresh_server_errors_stay_http_errors():
    http = FakeHttp({WELL_KNOWN: json_response(discovery()), USER: json_response({"message": "down"}, 500)})
    with pytest.raises(HttpError) as info:
        make_client(http).refresh("client", {"access_token": "a"}, SUBJECT, 300)
    assert info.value.status == 500 and "/oauth/user" in str(info.value)


def test_admin_refresh_checks_subject_role_and_passes_user_id():
    data = profile(platform="reseller", role="SUPER_ADMIN", user_id=OTHER)
    http = FakeHttp(
        {
            WELL_KNOWN: json_response(discovery()),
            TOKEN: json_response({"access_token": "machine", "expires_in": 3600}),
            "POST " + ISSUER + "/api/v1/admin-sso/session": lambda b, h: json_response({"data": dict(data)}),
        }
    )
    client = make_client(http)
    identity = client.refresh("admin", {"session_token": "t"}, SUBJECT)
    assert identity.profile["user_id"] == OTHER and identity.tokens == {"session_token": "t"}
    data["role"] = "SUPPORT"
    with pytest.raises(AccessDeniedError):
        client.refresh("admin", {"session_token": "t"}, SUBJECT)
    data["role"] = "ADMIN"
    with pytest.raises(AccessDeniedError):
        client.refresh("admin", {"session_token": "t"}, OTHER)


def test_machine_token_is_cached_sealed_and_retried_once_on_401():
    tokens = {"n": 0}
    statuses = [401, 200]

    def token(body, headers):
        tokens["n"] += 1
        return json_response({"access_token": f"machine-{tokens['n']}", "expires_in": 3600})

    http = FakeHttp(
        {
            WELL_KNOWN: json_response(discovery()),
            TOKEN: token,
            "POST " + ISSUER + "/api/v1/admin-sso/navigation": lambda b, h: json_response({"data": {"items": [h["Authorization"]]}}, statuses.pop(0) if statuses else 200),
        }
    )
    cache = MemoryCache()
    client = make_client(http, cache)
    client._seal = lambda value: "sealed:" + value
    client._unseal = lambda value: value[len("sealed:"):]

    assert client.navigation("admin", {"session_token": "s"}) == {"items": ["Bearer machine-2"]}
    assert client.navigation("admin", {"session_token": "s"}) == {"items": ["Bearer machine-2"]}
    assert tokens["n"] == 2
    key = "bahari:machine:" + hashlib.sha256(b"client-1\0secret-1\0identity:lookup").hexdigest()
    assert cache.get(key) == "sealed:machine-2"


def test_navigation_rewrites_the_wallet_url_and_update_pinned_passes_422():
    http = FakeHttp(
        {
            WELL_KNOWN: json_response(discovery()),
            "GET " + ISSUER + "/api/v1/platform-navigation": json_response({"data": {"wallet": {"url": "https://elsewhere"}, "platforms": []}}),
            "PUT " + ISSUER + "/api/v1/platform-navigation": lambda b, h: json_response({"errors": {"pinned_keys": ["bad"]}}, 422 if "bad" in b else 200),
        }
    )
    client = make_client(http)
    nav = client.navigation("client", {"access_token": "a"}, "/dashboard")
    assert nav["wallet"]["url"] == ISSUER + "/dashboard/wallet?platform=reseller&return_to=%2Fdashboard"
    assert client.update_pinned({"access_token": "a"}, ["bad"]).status == 422
    assert client.update_pinned({"access_token": "a"}, ["sms"]).ok
    assert json.loads(http.sent[-1]["body"]) == {"pinned_keys": ["sms"]}
    http.routes["PUT " + ISSUER + "/api/v1/platform-navigation"] = json_response({}, 500)
    with pytest.raises(HttpError):
        client.update_pinned({"access_token": "a"}, ["sms"])


def test_revoke_and_api_calls():
    http = FakeHttp(
        {
            WELL_KNOWN: json_response(discovery()),
            TOKEN: json_response({"access_token": "machine", "expires_in": 3600}),
            "POST " + ISSUER + "/oauth/revoke": json_response({}),
            "POST " + ISSUER + "/api/v1/admin-sso/revoke": json_response({"data": {}}),
            "GET " + ISSUER + "/api/v1/platform-wallet-balances": json_response({"data": [1]}),
            "POST " + ISSUER + "/api/v1/platform-wallets/u1/debits": lambda b, h: json_response({"ok": json.loads(b)}),
        }
    )
    client = make_client(http)
    client.revoke("client", {"access_token": "a", "refresh_token": "r"})
    revoked = [form(c["body"]) for c in http.calls("POST", ISSUER + "/oauth/revoke")]
    assert [(r["token"], r["token_type_hint"]) for r in revoked] == [("r", "refresh_token"), ("a", "access_token")]
    client.revoke("admin", {"session_token": "s"})
    assert json.loads(http.calls("POST", ISSUER + "/api/v1/admin-sso/revoke")[0]["body"]) == {"session_token": "s"}

    assert client.api("GET", "/platform-wallet-balances", {"page": 2}) == {"data": [1]}
    assert http.sent[-1]["url"] == ISSUER + "/api/v1/platform-wallet-balances?page=2"
    assert http.sent[-1]["body"] is None
    assert client.api("post", "platform-wallets/u1/debits", {"amount": 5}) == {"ok": {"amount": 5}}
    assert client.url("client.wallet_url", {"a": "1", "b": None}) == ISSUER + "/dashboard/wallet?a=1"
    with pytest.raises(BahariError):
        client.url("client.nope")


def test_discovery_is_cached_for_the_ttl():
    http = FakeHttp({WELL_KNOWN: json_response(discovery())})
    cache = MemoryCache()
    make_client(http, cache).discovery()
    make_client(http, cache).discovery()
    assert len(http.sent) == 1


def test_registration_prompt_login_hint_and_logout_hint(bahari):
    client = bahari.client()
    url = client.begin_login("client", "https://app.example.test/cb", prompt="create").url
    assert parse_qs(urlsplit(url).query)["prompt"] == ["create"]
    assert "prompt" not in parse_qs(urlsplit(client.begin_login("client", "https://app.example.test/cb", prompt="consent").url).query)
    assert parse_qs(urlsplit(client.begin_login("admin", "https://app.example.test/cb", login_hint="a@example.test").url).query)["login_hint"] == ["a@example.test"]
    assert parse_qs(urlsplit(client.logout_url("client", "https://app.example.test/", "a.b.c")).query)["id_token_hint"] == ["a.b.c"]


def test_billing_helpers_call_the_billing_api_with_a_billing_machine_token():
    def token(body, headers):
        return json_response({"access_token": "machine-" + parse_qs(body)["scope"][0], "expires_in": 3600})

    http = FakeHttp(
        {
            WELL_KNOWN: json_response(discovery()),
            TOKEN: token,
            "POST " + ISSUER + "/api/v1/platform-billing/subscriptions": lambda b, h: json_response({"data": {"status": "pending", "auth": h["Authorization"]}, "payment": None}, 201),
            "POST " + ISSUER + "/api/v1/platform-billing/subscriptions/ref%2F1/cancel": lambda b, h: json_response({"data": {"when": json.loads(b)["when"]}}),
        }
    )
    client = make_client(http)
    created = client.create_subscription({"user_id": SUBJECT, "reference": "r1", "plan_name": "Starter", "cycle": "monthly", "amount": "999.00"})
    assert created["data"] == {"status": "pending", "auth": "Bearer machine-billing"}
    assert client.cancel_subscription("ref/1", when="now")["data"]["when"] == "now"


def test_branding_and_maintenance_are_cached_and_fall_back_to_the_last_good_copy():
    cache = MemoryCache()
    data = {"name": "Bahari Reseller", "access_mode": "hybrid", "brand_color": "#0EA5E9",
            "maintenance": {"enabled": True, "message": "Back by 3 PM."}, "support": {"email": "help@reseller.test", "phone": None, "url": None}}
    http = FakeHttp({"GET " + ISSUER + "/.well-known/bahari-configuration": json_response(discovery()),
                     "GET " + ISSUER + "/api/v1/platform-branding/reseller": json_response({"data": data})})
    client = make_client(http, cache)

    assert client.branding()["name"] == "Bahari Reseller"
    assert client.maintenance() == {"enabled": True, "message": "Back by 3 PM."}
    assert client.branding()["support"]["email"] == "help@reseller.test"
    assert len(http.sent) == 2  # cached

    cache.delete("bahari:branding:" + hashlib.sha256((ISSUER + "|reseller").encode()).hexdigest())
    offline = make_client(FakeHttp({"GET " + ISSUER + "/.well-known/bahari-configuration": json_response(discovery())}), cache)
    assert offline.maintenance()["enabled"] is True  # last good copy
    fresh = make_client(FakeHttp({"GET " + ISSUER + "/.well-known/bahari-configuration": json_response(discovery())}))
    assert fresh.maintenance() == {"enabled": False, "message": None}


def test_role_reports_admin_rights_from_bahari():
    from bahari_sso import BahariClient, Identity

    client = make_client(FakeHttp())
    customer = Identity("client", SUBJECT, {}, profile())
    would_be_admin = Identity("client", SUBJECT, {}, profile(admin_access={"platform": "reseller", "role": "ADMIN", "two_factor_ready": True}))
    other_platform = Identity("client", SUBJECT, {}, profile(admin_access={"platform": "sms", "role": "SUPER_ADMIN", "two_factor_ready": True}))
    admin = Identity("admin", "admin-1", {}, {"id": "admin-1", "user_id": SUBJECT, "role": "SUPER_ADMIN"})

    assert [client.role(i) for i in (customer, would_be_admin, other_platform, admin)] == ["USER", "ADMIN", "USER", "SUPER_ADMIN"]
    assert [client.is_admin(i) for i in (customer, would_be_admin, admin)] == [False, False, True]
    assert [BahariClient.linked_user_id(customer), BahariClient.linked_user_id(admin)] == [SUBJECT, SUBJECT]


def test_memory_store_ends_admin_sessions_linked_to_the_account():
    from bahari_sso import Identity
    from bahari_sso.sessions import MemorySessionStore

    store = MemorySessionStore()
    linked = store.create(Identity("admin", "admin-1", {"session_token": "s" * 64}, {"id": "admin-1", "user_id": SUBJECT}), 3600)
    other = store.create(Identity("admin", "admin-2", {"session_token": "t" * 64}, {"id": "admin-2", "user_id": OTHER}), 3600)
    store.revoke_linked_user(SUBJECT)
    assert store.find("admin", linked.id) is None
    assert store.find("admin", other.id) is not None
