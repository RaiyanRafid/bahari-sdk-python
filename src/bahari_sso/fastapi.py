"""FastAPI helpers: ``create_router()`` and its ``login_required()`` dependency.

Install with ``pip install "bahari-sso[fastapi]"``. The browser keeps only an opaque session id in an httpOnly,
Secure, SameSite=Lax cookie; sign-in state and sessions stay on the server. Bahari calls are blocking, so routes and
the dependency are synchronous and run in FastAPI's thread pool.
"""

# No "from __future__ import annotations": FastAPI reads these annotations at runtime.

import functools
from typing import Any, Callable, Optional

try:
    from fastapi import APIRouter, HTTPException, Request
    from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
    from starlette.concurrency import run_in_threadpool
except ImportError as exc:  # pragma: no cover
    raise ImportError('bahari_sso.fastapi needs FastAPI: pip install "bahari-sso[fastapi]"') from exc

from .client import BahariClient
from .sessions import SessionStore, StoredSession
from .web import MAX_BACKCHANNEL_BYTES, WebAuth, WebError

__all__ = ["create_router", "BahariRouter"]

_NO_STORE = "private, no-store"


class _CookieBrowser:
    def __init__(self, request: Request, cookie_name: str) -> None:
        self._value = request.cookies.get(cookie_name)
        self.changed: Optional[str] = None

    def get(self) -> Optional[str]:
        return self.changed or self._value

    def set(self, value: str) -> None:
        self.changed = value


def _wants_json(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return request.headers.get("x-requested-with") == "XMLHttpRequest" or (
        "json" in accept and "html" not in accept.split(",")[0]
    )


def _local(request: Request, location: str) -> str:
    if location.startswith("/") and not location.startswith("//"):
        return request.scope.get("root_path", "").rstrip("/") + location
    return location


def _base_url(request: Request) -> str:
    return str(request.base_url)


class BahariRouter(APIRouter):
    """An ``APIRouter`` with the Bahari routes. ``router.bahari`` is the :class:`~bahari_sso.web.WebAuth` flow."""

    bahari: WebAuth
    cookie_name: str

    def login_required(self, kind: Optional[str] = None) -> Callable[..., StoredSession]:
        """A dependency returning the rechecked :class:`StoredSession` (fail closed on any error).

        Unauthenticated JSON requests get 401; others are redirected (303) to the sign-in.
        """
        auth = self.bahari
        cookie_name = self.cookie_name

        def dependency(request: Request) -> StoredSession:
            path = request.url.path
            root = request.scope.get("root_path", "").rstrip("/")
            if root and path.startswith(root):
                path = path[len(root):] or "/"
            chosen = kind or auth.kind_for(path)
            stored = auth.current(_CookieBrowser(request, cookie_name), chosen)
            if stored is None:
                if _wants_json(request):
                    raise HTTPException(status_code=401, detail="Bahari sign-in is required.")
                return_to = path + ("?" + request.url.query if request.url.query else "")
                raise HTTPException(
                    status_code=303,
                    detail="Bahari sign-in is required.",
                    headers={"Location": _local(request, auth.login_path(chosen, return_to)), "Cache-Control": _NO_STORE},
                )
            request.state.bahari_session = stored
            return stored

        return dependency


def create_router(
    client: BahariClient,
    store: Optional[SessionStore] = None,
    *,
    prefix: str = "/auth",
    name: str = "bahari",
    cookie_name: str = "bahari_session",
    cookie_secure: bool = True,
    cookie_domain: Optional[str] = None,
    **options: Any,
) -> BahariRouter:
    """Routes ``{prefix}/login`` (auto), ``/{kind}/login``, ``/{kind}/callback``, ``POST /{kind}/logout``,
    ``POST /backchannel-logout`` and ``GET /session``. Include it without an extra prefix:
    ``app.include_router(router)``. ``options`` go to :class:`~bahari_sso.web.WebAuth`.
    """
    auth = WebAuth(client, store, prefix=prefix, **options)
    router = BahariRouter(prefix=auth.prefix)
    router.bahari = auth
    router.cookie_name = cookie_name

    def finish(response: Response, browser: _CookieBrowser) -> Response:
        response.headers["Cache-Control"] = _NO_STORE
        if browser.changed:
            response.set_cookie(
                cookie_name,
                browser.changed,
                max_age=auth.session_seconds,
                path="/",
                domain=cookie_domain,
                secure=cookie_secure,
                httponly=True,
                samesite="lax",
            )
        return response

    def error(problem: WebError) -> Response:
        return PlainTextResponse(problem.message, status_code=problem.status, headers={"Cache-Control": _NO_STORE})

    def begin(request: Request, kind: Optional[str], return_to: Optional[str], prompt: Optional[str] = None) -> Response:
        browser = _CookieBrowser(request, cookie_name)
        try:
            location = auth.begin(browser, kind, return_to, _base_url(request), prompt=prompt)
        except WebError as problem:
            return error(problem)
        return finish(RedirectResponse(location, status_code=302), browser)

    @router.get("/login", name=f"{name}_auto_login", include_in_schema=False)
    def auto_login(request: Request, return_to: Optional[str] = None) -> Response:
        return begin(request, None, return_to)

    @router.get("/register", name=f"{name}_register", include_in_schema=False)
    def register(request: Request, return_to: Optional[str] = None) -> Response:
        return begin(request, None, return_to, prompt="create")

    @router.get("/{kind}/login", name=f"{name}_login", include_in_schema=False)
    def login(request: Request, kind: str, return_to: Optional[str] = None) -> Response:
        return begin(request, kind, return_to)

    @router.get("/{kind}/callback", name=f"{name}_callback", include_in_schema=False)
    def callback(request: Request, kind: str, state: Optional[str] = None, code: Optional[str] = None) -> Response:
        browser = _CookieBrowser(request, cookie_name)
        try:
            location = auth.complete(browser, kind, state, code, request.query_params.get("error"))
        except WebError as problem:
            return error(problem)
        response = finish(RedirectResponse(_local(request, location), status_code=302), browser)
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @router.post("/{kind}/logout", name=f"{name}_logout", include_in_schema=False)
    def logout(request: Request, kind: str) -> Response:
        browser = _CookieBrowser(request, cookie_name)
        try:
            location = auth.logout(browser, kind, _base_url(request))
        except WebError as problem:
            return error(problem)
        return finish(RedirectResponse(location, status_code=302), browser)

    @router.post("/backchannel-logout", name=f"{name}_backchannel", include_in_schema=False)
    async def backchannel(request: Request) -> Response:
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_BACKCHANNEL_BYTES:
            status, payload = 413, {"message": "The notification is too large."}
        else:
            body = b""
            async for chunk in request.stream():
                body += chunk
                if len(body) > MAX_BACKCHANNEL_BYTES:
                    break
            status, payload = await run_in_threadpool(
                functools.partial(auth.backchannel, body, request.headers.get("content-type"))
            )
        return JSONResponse(payload, status_code=status, headers={"Cache-Control": "no-store"})

    @router.get("/session", name=f"{name}_session")
    def session_info(request: Request, kind: Optional[str] = None) -> Response:
        if kind is not None and kind not in ("client", "admin"):
            return error(WebError(404, "Not found."))
        browser = _CookieBrowser(request, cookie_name)
        return JSONResponse(auth.session_info(browser, [kind] if kind else None), headers={"Cache-Control": _NO_STORE})

    return router
