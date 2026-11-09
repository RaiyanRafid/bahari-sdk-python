import json
from urllib.parse import parse_qs, urlsplit

import pytest

flask = pytest.importorskip("flask")

from bahari_sso import MemorySessionStore  # noqa: E402
from bahari_sso.flask import create_blueprint, current_session, login_required  # noqa: E402
from helpers import ADMIN, ADMIN_ID, ISSUER, OTHER, SECRETS, SUBJECT, query  # noqa: E402


class CountingStore(MemorySessionStore):
    def __init__(self):
        super().__init__()
        self.revoke_subject_calls = []

    def revoke_subject(self, kind, subject):
        self.revoke_subject_calls.append((kind, subject))
        super().revoke_subject(kind, subject)


def make_app(bahari, **options):
    app = flask.Flask(__name__)
    app.secret_key = "test-secret"
    store = CountingStore()
    app.register_blueprint(create_blueprint(bahari.client(), store, **options))

    @app.get("/dashboard")
    @login_required()
    def dashboard():
        return {"subject": current_session().subject}

    @app.get("/dashboard/settings")
    @login_required
    def settings():
        return "ok"

    @app.get("/admin")
    @login_required("admin")
    def admin():
        return {"subject": current_session("admin").subject, "user_id": current_session().profile.get("user_id")}

    return app, store


def sign_in(web, bahari, start="/auth/client/login"):
    response = web.get(start)
    assert response.status_code == 302
    location = response.headers["Location"]
    params = bahari.authorize(location)
    kind = "admin" if location.startswith(ADMIN) else "client"
    return web.get(f"/auth/{kind}/callback", query_string=params), location


def test_client_sign_in_creates_a_server_side_session(bahari):
    app, store = make_app(bahari)
    web = app.test_client()

    response = web.get("/dashboard?x=1")
    assert response.status_code == 302 and response.headers["Location"] == "/auth/client/login?return_to=%2Fdashboard%3Fx%3D1"

    start = web.get("/auth/client/login?return_to=/dashboard/settings")
    assert start.headers["Cache-Control"] == "private, no-store"
    params = query(start.headers["Location"])
    assert start.headers["Location"].startswith(ISSUER + "/oauth/authorize?")
    assert params["redirect_uri"] == "http://localhost/auth/client/callback"
    with web.session_transaction() as cookie:
        assert set(cookie.keys()) == {"bahari_bid"}
        first_bid = cookie["bahari_bid"]

    callback = web.get("/auth/client/callback", query_string=bahari.authorize(start.headers["Location"]))
    assert callback.status_code == 302 and callback.headers["Location"] == "/dashboard/settings"
    assert callback.headers["Referrer-Policy"] == "no-referrer"
    with web.session_transaction() as cookie:
        assert set(cookie.keys()) == {"bahari_bid"} and cookie["bahari_bid"] != first_bid  # rotated

    assert web.get("/dashboard").get_json() == {"subject": SUBJECT}
    assert web.get("/dashboard/settings").data == b"ok"


def test_unknown_or_foreign_state_is_rejected(bahari):
    app, _ = make_app(bahari)
    web = app.test_client()
    start = web.get("/auth/client/login")
    params = bahari.authorize(start.headers["Location"])

    other_browser = app.test_client()
    other_browser.get("/auth/client/login")
    assert other_browser.get("/auth/client/callback", query_string=params).status_code == 422  # bound to the browser
    assert web.get("/auth/client/callback", query_string={"state": "x", "code": "c"}).status_code == 422
    assert web.get("/auth/admin/callback", query_string=params).status_code == 422  # wrong kind
    assert web.get("/auth/staff/login").status_code == 404

    start = web.get("/auth/client/login")
    denied = dict(bahari.authorize(start.headers["Location"]), error="access_denied")
    assert web.get("/auth/client/callback", query_string=denied).status_code == 422
    # A state is single-use.
    start = web.get("/auth/client/login")
    params = bahari.authorize(start.headers["Location"])
    assert web.get("/auth/client/callback", query_string=params).status_code == 302
    assert web.get("/auth/client/callback", query_string=params).status_code == 422


def test_auto_sign_in_continues_to_admin_when_bahari_reports_admin_access(bahari):
    bahari.customer["admin_access"] = {"platform": "reseller", "role": "ADMIN", "two_factor_ready": True}
    app, store = make_app(bahari)
    web = app.test_client()

    callback, location = sign_in(web, bahari, "/auth/login?return_to=/dashboard")
    assert location.startswith(ISSUER + "/oauth/authorize?")
    assert callback.headers["Location"] == "/auth/admin/login?return_to=%2Fadmin"

    admin_start = web.get(callback.headers["Location"])
    assert admin_start.headers["Location"].startswith(ADMIN + "/admin-sso/authorize?")
    admin_callback = web.get("/auth/admin/callback", query_string=bahari.authorize(admin_start.headers["Location"]))
    assert admin_callback.headers["Location"] == "/admin"

    assert web.get("/admin").get_json() == {"subject": ADMIN_ID, "user_id": SUBJECT}
    info = web.get("/auth/session").get_json()
    assert info["authenticated"] is True
    assert info["sessions"]["client"]["subject"] == SUBJECT
    assert info["sessions"]["admin"]["subject"] == ADMIN_ID


def test_auto_admin_with_another_linked_user_creates_no_admin_session(bahari):
    bahari.customer["admin_access"] = {"platform": "reseller", "role": "SUPER_ADMIN", "two_factor_ready": False}
    bahari.admin["user_id"] = OTHER
    app, _ = make_app(bahari)
    web = app.test_client()

    callback, _ = sign_in(web, bahari, "/auth/login")
    admin_start = web.get(callback.headers["Location"])
    admin_callback = web.get("/auth/admin/callback", query_string=bahari.authorize(admin_start.headers["Location"]))

    assert admin_callback.headers["Location"] == "/dashboard"
    assert bahari.admin_revoked == ["admin-session-secret"]
    assert web.get("/admin").status_code == 302
    info = web.get("/auth/session").get_json()
    assert info["sessions"]["admin"] is None and info["sessions"]["client"]["subject"] == SUBJECT


def test_auto_sign_in_without_admin_access_or_when_disabled_stays_in_the_client_area(bahari):
    app, _ = make_app(bahari)
    callback, _ = sign_in(app.test_client(), bahari, "/auth/login?return_to=/dashboard/settings")
    assert callback.headers["Location"] == "/dashboard/settings"

    bahari.customer["admin_access"] = {"platform": "reseller", "role": "ADMIN", "two_factor_ready": True}
    app, _ = make_app(bahari, auto_admin=False)
    callback, _ = sign_in(app.test_client(), bahari, "/auth/login")
    assert callback.headers["Location"] == "/dashboard"

    app, _ = make_app(bahari)
    callback, _ = sign_in(app.test_client(), bahari, "/auth/client/login")  # explicit client sign-in: no auto
    assert callback.headers["Location"] == "/dashboard"


def test_direct_admin_sign_in_has_no_expected_user(bahari):
    bahari.admin["user_id"] = None
    app, _ = make_app(bahari)
    web = app.test_client()
    callback, _ = sign_in(web, bahari, "/auth/admin/login?return_to=/admin")
    assert callback.headers["Location"] == "/admin"
    assert web.get("/admin").status_code == 200


def test_recheck_fails_closed(bahari):
    app, store = make_app(bahari)
    web = app.test_client()
    sign_in(web, bahari)
    assert web.get("/dashboard").status_code == 200

    bahari.customer_status = 401
    response = web.get("/dashboard")
    assert response.status_code == 302 and response.headers["Location"].startswith("/auth/client/login")
    assert web.get("/dashboard", headers={"Accept": "application/json"}).status_code == 401
    bahari.customer_status = 200
    assert web.get("/dashboard").status_code == 302  # the local session stays ended

    sign_in(web, bahari)
    bahari.http.routes.pop("GET " + ISSUER + "/oauth/user")  # Bahari unreachable
    assert web.get("/dashboard").status_code == 302


def test_admin_recheck_fails_closed_when_bahari_revokes(bahari):
    app, _ = make_app(bahari)
    web = app.test_client()
    sign_in(web, bahari, "/auth/admin/login")
    assert web.get("/admin").status_code == 200
    bahari.admin_session_status = 403
    assert web.get("/admin").status_code == 302


def test_session_json_never_contains_tokens(bahari):
    bahari.customer["admin_access"] = {"platform": "reseller", "role": "ADMIN", "two_factor_ready": True}
    app, _ = make_app(bahari)
    web = app.test_client()
    callback, _ = sign_in(web, bahari, "/auth/login")
    admin_start = web.get(callback.headers["Location"])
    web.get("/auth/admin/callback", query_string=bahari.authorize(admin_start.headers["Location"]))

    response = web.get("/auth/session")
    body = response.get_data(as_text=True)
    assert response.headers["Cache-Control"] == "private, no-store"
    assert json.loads(body)["sessions"]["admin"]["profile"]["user_id"] == SUBJECT
    for secret in SECRETS:
        assert secret not in body
    import base64

    cookie = web.get_cookie("session")
    payload = cookie.value.lstrip(".").split(".")[0]
    decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    if cookie.value.startswith("."):
        import zlib

        decoded = zlib.decompress(decoded)
    assert json.loads(decoded).keys() == {"bahari_bid"}
    for secret in SECRETS:
        assert secret not in decoded.decode()
    assert web.get("/auth/session?kind=client").get_json()["sessions"].keys() == {"client"}


def test_logout_revokes_locally_and_at_bahari(bahari):
    app, store = make_app(bahari)
    web = app.test_client()
    sign_in(web, bahari)
    response = web.post("/auth/client/logout")
    assert response.status_code == 302
    location = urlsplit(response.headers["Location"])
    assert location.path == "/oauth/logout"
    logout = parse_qs(location.query)
    assert logout["client_id"] == ["client-1"] and logout["post_logout_redirect_uri"] == ["http://localhost/"]
    # The ID token lets Bahari sign out at once and come straight back (no confirmation page).
    assert logout["id_token_hint"][0].count(".") == 2
    assert [r["token_type_hint"] for r in bahari.revoked] == ["refresh_token", "access_token"]
    assert web.get("/dashboard").status_code == 302

    sign_in(web, bahari, "/auth/admin/login")
    response = web.post("/auth/admin/logout")
    assert response.headers["Location"] == ADMIN + "/admin"
    assert bahari.admin_revoked == ["admin-session-secret"]
    assert web.get("/admin").status_code == 302


def test_backchannel_logout_revokes_once_per_jti(bahari, keys):
    app, store = make_app(bahari)
    web = app.test_client()
    other = app.test_client()
    sign_in(web, bahari)
    sign_in(other, bahari)

    response = web.post("/auth/backchannel-logout", data={"logout_token": keys.logout_token("jti-1")})
    assert response.status_code == 200 and response.get_json() == {"received": True}
    assert web.get("/dashboard").status_code == 302
    assert other.get("/dashboard").status_code == 302
    assert store.revoke_subject_calls == [("client", SUBJECT)]

    sign_in(web, bahari)
    replay = web.post("/auth/backchannel-logout", data={"logout_token": keys.logout_token("jti-1")})
    assert replay.status_code == 200
    assert store.revoke_subject_calls == [("client", SUBJECT)]  # de-duplicated
    assert web.get("/dashboard").status_code == 200

    as_json = web.post("/auth/backchannel-logout", json={"logout_token": keys.logout_token("jti-2")})
    assert as_json.status_code == 200 and len(store.revoke_subject_calls) == 2

    assert web.post("/auth/backchannel-logout", data={"logout_token": keys.token({"jti": "x"})}).status_code == 422
    assert web.post("/auth/backchannel-logout", data={}).status_code == 422
    assert web.post("/auth/backchannel-logout", data={"logout_token": "x" * 70000}).status_code == 413


def test_not_configured_is_503(bahari):
    app = flask.Flask(__name__)
    app.secret_key = "k"
    app.register_blueprint(create_blueprint(bahari.client(client_secret="")))
    assert app.test_client().get("/auth/client/login").status_code == 503


def test_public_url_and_custom_prefix(bahari):
    app, _ = make_app(bahari, url_prefix="/sso", public_url="https://app.example.test/")
    web = app.test_client()
    start = web.get("/sso/login")
    assert query(start.headers["Location"])["redirect_uri"] == "https://app.example.test/sso/client/callback"
    bahari.customer["admin_access"] = {"platform": "reseller", "role": "ADMIN"}
    callback = web.get("/sso/client/callback", query_string=bahari.authorize(start.headers["Location"]))
    assert callback.headers["Location"] == "/sso/admin/login?return_to=%2Fadmin"


def test_create_account_opens_bahari_registration(bahari):
    app, _ = make_app(bahari)
    response = app.test_client().get("/auth/register?return_to=/dashboard/settings")
    assert response.status_code == 302
    location = urlsplit(response.headers["Location"])
    assert location.path == "/oauth/authorize"
    params = parse_qs(location.query)
    assert params["prompt"] == ["create"] and params["response_type"] == ["code"]
