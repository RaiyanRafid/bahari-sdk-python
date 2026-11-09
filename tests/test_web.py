import pytest

from bahari_sso import MemoryCache, MemorySessionStore, WebAuth, safe_return_path
from helpers import FakeHttp, make_client


@pytest.mark.parametrize(
    "value, expected",
    [
        (None, "/dashboard"),
        (123, "/dashboard"),
        ("", "/dashboard"),
        ("/dashboard", "/dashboard"),
        ("/dashboard/", "/dashboard/"),
        ("/dashboard/billing?tab=2", "/dashboard/billing?tab=2"),
        ("/dashboard?tab=2", "/dashboard?tab=2"),
        ("/dashboard/caf%C3%A9", "/dashboard/caf%C3%A9"),
        ("/dashboardevil", "/dashboard"),
        ("/admin", "/dashboard"),
        ("https://evil.example/dashboard", "/dashboard"),
        ("//evil.example/dashboard", "/dashboard"),
        ("/dashboard/../admin", "/dashboard"),
        ("/dashboard/%2e%2e/admin", "/dashboard"),
        ("/dashboard/%2E%2E/admin", "/dashboard"),
        ("/dashboard/\\evil", "/dashboard"),
        ("/dashboard/%5cevil", "/dashboard"),
        ("/dashboard/x%0d%0aSet-Cookie:a", "/dashboard"),
        ("/dashboard/a b", "/dashboard"),
        ("/dashboard/a%20b", "/dashboard"),
        ("/dashboard/a%00", "/dashboard"),
        ("/dashboard/a%7f", "/dashboard"),
        ("/dashboard/" + "a" * 2050, "/dashboard"),
    ],
)
def test_safe_return_path(value, expected):
    assert safe_return_path("/dashboard", value) == expected
    assert safe_return_path("dashboard/", value) == expected


def test_safe_return_path_with_root_area():
    assert safe_return_path("/", "/anything?x=1") == "/anything?x=1"
    assert safe_return_path("/", "//evil.example") == "/"
    assert safe_return_path("/", "https://evil.example") == "/"
    assert safe_return_path("/", "/a/../b") == "/"


def test_kind_for_and_login_path():
    auth = WebAuth(make_client(FakeHttp()), MemorySessionStore(), paths={"client": "/app", "admin": "/app/admin"}, state_cache=MemoryCache())
    assert auth.kind_for("/app/admin/users") == "admin"
    assert auth.kind_for("/app/admin") == "admin"
    assert auth.kind_for("/app/settings") == "client"
    assert auth.kind_for("/elsewhere") == "client"
    assert auth.login_path("admin", "/app/admin?x=1") == "/auth/admin/login?return_to=%2Fapp%2Fadmin%3Fx%3D1"
    assert auth.login_path() == "/auth/login"
