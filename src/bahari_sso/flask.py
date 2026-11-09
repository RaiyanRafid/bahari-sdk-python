"""Flask helpers: ``create_blueprint()`` and ``login_required()``. Install with ``pip install "bahari-sso[flask]"``.

The browser keeps only an opaque server-side session id inside Flask's signed session cookie (set
``app.secret_key``). Sign-in state and sessions stay on the server.
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Optional

try:
    from flask import Blueprint, Response, current_app, g, jsonify, redirect, request, session
except ImportError as exc:  # pragma: no cover
    raise ImportError('bahari_sso.flask needs Flask: pip install "bahari-sso[flask]"') from exc

from .client import BahariClient
from .sessions import SessionStore, StoredSession
from .web import WebAuth, WebError

__all__ = ["create_blueprint", "login_required", "current_session", "SESSION_KEY", "EXTENSION_KEY"]

SESSION_KEY = "bahari_bid"
EXTENSION_KEY = "bahari_sso"
_NO_STORE = "private, no-store"


class _FlaskBrowser:
    def get(self) -> Optional[str]:
        value = session.get(SESSION_KEY)
        return value if isinstance(value, str) else None

    def set(self, value: str) -> None:
        session[SESSION_KEY] = value


def _local(location: str) -> str:
    """Prefixes app-local paths with the script root when the app is mounted below a path."""
    if location.startswith("/") and not location.startswith("//"):
        return request.script_root + location
    return location


def _redirect(location: str, referrer: bool = True) -> Response:
    response = redirect(location, 302)
    response.headers["Cache-Control"] = _NO_STORE
    if not referrer:
        response.headers["Referrer-Policy"] = "no-referrer"
    return response


def _error(error: WebError) -> Response:
    response = Response(error.message, error.status, mimetype="text/plain")
    response.headers["Cache-Control"] = _NO_STORE
    return response


def _wants_json() -> bool:
    best = request.accept_mimetypes.best or ""
    return (
        request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or "json" in best
        or (request.is_json and "html" not in best)
    )


def _auth() -> WebAuth:
    auth = current_app.extensions.get(EXTENSION_KEY)
    if not isinstance(auth, WebAuth):
        raise RuntimeError("Register the Bahari blueprint first: app.register_blueprint(create_blueprint(client)).")
    return auth


def create_blueprint(
    client: BahariClient,
    store: Optional[SessionStore] = None,
    *,
    url_prefix: str = "/auth",
    name: str = "bahari",
    **options: Any,
) -> Blueprint:
    """Routes ``{url_prefix}/login`` (auto), ``/<kind>/login``, ``/<kind>/callback``, ``POST /<kind>/logout``,
    ``POST /backchannel-logout`` and ``GET /session``. ``options`` are passed to :class:`~bahari_sso.web.WebAuth`
    (``paths``, ``auto_admin``, ``session_hours``, ``post_logout_redirect``, ``public_url``, ``state_cache``).

    The flow object is available as ``blueprint.bahari`` and ``app.extensions["bahari_sso"]``.
    """
    auth = WebAuth(client, store, prefix=url_prefix, **options)
    blueprint = Blueprint(name, __name__, url_prefix=auth.prefix or None)
    blueprint.bahari = auth  # type: ignore[attr-defined]
    browser = _FlaskBrowser()

    @blueprint.record_once
    def _register(state: Any) -> None:
        state.app.extensions[EXTENSION_KEY] = auth

    def _base_url() -> str:
        return request.url_root

    @blueprint.get("/login")
    def auto_login() -> Response:
        try:
            return _redirect(auth.begin(browser, None, request.args.get("return_to"), _base_url()))
        except WebError as error:
            return _error(error)

    @blueprint.get("/register")
    def register() -> Response:
        try:
            return _redirect(auth.begin(browser, None, request.args.get("return_to"), _base_url(), prompt="create"))
        except WebError as error:
            return _error(error)

    @blueprint.get("/<any(client, admin):kind>/login")
    def login(kind: str) -> Response:
        try:
            return _redirect(auth.begin(browser, kind, request.args.get("return_to"), _base_url()))
        except WebError as error:
            return _error(error)

    @blueprint.get("/<any(client, admin):kind>/callback")
    def callback(kind: str) -> Response:
        try:
            location = auth.complete(
                browser, kind, request.args.get("state"), request.args.get("code"), request.args.get("error")
            )
        except WebError as error:
            return _error(error)
        return _redirect(_local(location), referrer=False)

    @blueprint.post("/<any(client, admin):kind>/logout")
    def logout(kind: str) -> Response:
        try:
            return _redirect(auth.logout(browser, kind, _base_url()))
        except WebError as error:
            return _error(error)

    @blueprint.post("/backchannel-logout")
    def backchannel() -> Response:
        if (request.content_length or 0) > 65536:
            status, payload = 413, {"message": "The notification is too large."}
        else:
            status, payload = auth.backchannel(request.get_data(cache=False), request.content_type)
        response = jsonify(payload)
        response.status_code = status
        response.headers["Cache-Control"] = "no-store"
        return response

    @blueprint.get("/session")
    def session_info() -> Response:
        kind = request.args.get("kind")
        if kind is not None and kind not in ("client", "admin"):
            return _error(WebError(404, "Not found."))
        response = jsonify(auth.session_info(browser, [kind] if kind else None))
        response.headers["Cache-Control"] = _NO_STORE
        return response

    return blueprint


def login_required(kind: Any = None) -> Callable[..., Any]:
    """Requires a live Bahari session, rechecked with Bahari on every request (fail closed).

    Use ``@login_required()``, ``@login_required("admin")`` or bare ``@login_required``. Without a kind it is picked
    from the request path (``paths``). The session is available as ``g.bahari_session`` / :func:`current_session`.
    Unauthenticated JSON requests get 401; others are redirected to the sign-in.
    """
    if callable(kind):
        return login_required(None)(kind)

    def decorator(view: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(view)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            auth = _auth()
            chosen = kind or auth.kind_for(request.path)
            stored = auth.current(_FlaskBrowser(), chosen)
            if stored is None:
                if _wants_json():
                    response = jsonify(message="Bahari sign-in is required.")
                    response.status_code = 401
                    return response
                query = request.query_string.decode("latin-1")
                return_to = request.path + ("?" + query if query else "")
                return _redirect(_local(auth.login_path(chosen, return_to)))
            g.bahari_session = stored
            sessions = dict(getattr(g, "bahari_sessions", {}) or {})
            sessions[chosen] = stored
            g.bahari_sessions = sessions
            return view(*args, **kwargs)

        return wrapper

    return decorator


def current_session(kind: Optional[str] = None) -> Optional[StoredSession]:
    """The session checked by :func:`login_required` for this request."""
    if kind is None:
        return getattr(g, "bahari_session", None)
    return (getattr(g, "bahari_sessions", None) or {}).get(kind)
