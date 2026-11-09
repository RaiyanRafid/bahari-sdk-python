from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from bahari_sso import MemorySessionStore, StoredSession  # noqa: E402
from bahari_sso.fastapi import create_router  # noqa: E402
from helpers import ADMIN, ADMIN_ID, ISSUER, OTHER, SECRETS, SUBJECT, query  # noqa: E402


class CountingStore(MemorySessionStore):
    def __init__(self):
        super().__init__()
        self.revoke_subject_calls = []

    def revoke_subject(self, kind, subject):
        self.revoke_subject_calls.append((kind, subject))
        super().revoke_subject(kind, subject)


def make_app(bahari, **options):
    store = CountingStore()
    router = create_router(bahari.client(), store, **options)
    app = FastAPI()
    app.include_router(router)

    @app.get("/dashboard")
    def dashboard(session: StoredSession = Depends(router.login_required())):
        return {"subject": session.subject}

    @app.get("/admin")
    def admin(session: StoredSession = Depends(router.login_required("admin"))):
        return {"subject": session.subject, "user_id": session.profile.get("user_id")}

    web = TestClient(app, base_url="https://testserver", follow_redirects=False)
    return web, store


def sign_in(web, bahari, start="/auth/client/login"):
    response = web.get(start)
    assert response.status_code == 302
    location = response.headers["location"]
    kind = "admin" if location.startswith(ADMIN) else "client"
    return web.get(f"/auth/{kind}/callback", params=bahari.authorize(location))


def test_cookie_is_opaque_http_only_secure_lax_and_rotated(bahari):
    web, _ = make_app(bahari)
    start = web.get("/auth/client/login")
    cookie = start.headers["set-cookie"]
    assert "HttpOnly" in cookie and "Secure" in cookie and "samesite=lax" in cookie.lower() and "Path=/" in cookie
    assert query(start.headers["location"])["redirect_uri"] == "https://testserver/auth/client/callback"
    first = web.cookies.get("bahari_session")
    callback = web.get("/auth/client/callback", params=bahari.authorize(start.headers["location"]))
    assert callback.status_code == 302 and callback.headers["location"] == "/dashboard"
    assert callback.headers["referrer-policy"] == "no-referrer"
    assert web.cookies.get("bahari_session") not in (None, first)
    for secret in SECRETS:
        assert secret not in callback.headers.get("set-cookie", "")
    assert web.get("/dashboard").json() == {"subject": SUBJECT}


def test_auto_flow_and_session_json(bahari):
    bahari.customer["admin_access"] = {"platform": "reseller", "role": "ADMIN", "two_factor_ready": True}
    web, _ = make_app(bahari)
    callback = sign_in(web, bahari, "/auth/login")
    assert callback.headers["location"] == "/auth/admin/login?return_to=%2Fadmin"
    admin_start = web.get(callback.headers["location"])
    assert admin_start.headers["location"].startswith(ADMIN + "/admin-sso/authorize?")
    admin_callback = web.get("/auth/admin/callback", params=bahari.authorize(admin_start.headers["location"]))
    assert admin_callback.headers["location"] == "/admin"
    assert web.get("/admin").json() == {"subject": ADMIN_ID, "user_id": SUBJECT}

    response = web.get("/auth/session")
    data = response.json()
    assert data["authenticated"] is True and data["sessions"]["admin"]["subject"] == ADMIN_ID
    for secret in SECRETS:
        assert secret not in response.text


def test_auto_flow_rejects_admin_linked_to_another_user(bahari):
    bahari.customer["admin_access"] = {"platform": "reseller", "role": "ADMIN", "two_factor_ready": True}
    bahari.admin["user_id"] = OTHER
    web, _ = make_app(bahari)
    callback = sign_in(web, bahari, "/auth/login")
    admin_start = web.get(callback.headers["location"])
    admin_callback = web.get("/auth/admin/callback", params=bahari.authorize(admin_start.headers["location"]))
    assert admin_callback.headers["location"] == "/dashboard"
    assert web.get("/admin").status_code == 303
    assert web.get("/auth/session").json()["sessions"]["admin"] is None
    assert bahari.admin_revoked == ["admin-session-secret"]


def test_dependency_fails_closed(bahari):
    web, _ = make_app(bahari)
    unauthenticated = web.get("/dashboard?x=1")
    assert unauthenticated.status_code == 303
    assert unauthenticated.headers["location"] == "/auth/client/login?return_to=%2Fdashboard%3Fx%3D1"
    assert web.get("/dashboard", headers={"accept": "application/json"}).status_code == 401

    sign_in(web, bahari)
    assert web.get("/dashboard").status_code == 200
    bahari.customer = dict(bahari.customer, status="suspended")
    assert web.get("/dashboard").status_code == 303
    bahari.customer = dict(bahari.customer, status="active")
    assert web.get("/dashboard").status_code == 303  # stays ended


def test_backchannel_dedup_and_logout(bahari, keys):
    web, store = make_app(bahari)
    sign_in(web, bahari)
    token = keys.logout_token("jti-9")
    first = web.post("/auth/backchannel-logout", content="logout_token=" + token, headers={"content-type": "application/x-www-form-urlencoded"})
    assert first.status_code == 200 and first.json() == {"received": True}
    assert web.get("/dashboard").status_code == 303
    second = web.post("/auth/backchannel-logout", content="logout_token=" + token, headers={"content-type": "application/x-www-form-urlencoded"})
    assert second.status_code == 200
    assert store.revoke_subject_calls == [("client", SUBJECT)]
    assert web.post("/auth/backchannel-logout", json={"logout_token": "nope"}).status_code == 422
    assert web.post("/auth/backchannel-logout", content="x" * 70000).status_code == 413

    sign_in(web, bahari)
    response = web.post("/auth/client/logout")
    location = urlsplit(response.headers["location"])
    assert location.path == "/oauth/logout"
    assert parse_qs(location.query)["post_logout_redirect_uri"] == ["https://testserver/"]
    assert web.get("/dashboard").status_code == 303
    assert web.get("/auth/staff/login").status_code == 404
