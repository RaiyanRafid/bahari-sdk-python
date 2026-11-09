# bahari-sso

Sign customers and platform administrators in to your Python app with **Bahari Accounts**, the central SSO /
OIDC identity provider. This is the Python port of `bahari/sso-php` and `bahari/laravel`, and it speaks the same
protocol.

- Customers (`client`) sign in with OIDC authorization code + PKCE (S256) + nonce.
- Platform administrators (`admin`) sign in through Bahari's admin SSO and a server-to-server exchange.
- Every endpoint, including the admin host, comes from `{issuer}/.well-known/bahari-configuration`. It is cached,
  a last good copy is kept for a week, and built-in defaults are used when there is no copy.
- ID and logout tokens are verified as RS256 only, against the issuer's JWKS.
- Each request can be rechecked with Bahari, so suspended accounts, removed admin roles and revoked sessions end
  straight away (fail closed).
- Back-channel logout de-duplicates notifications by `jti`.
- Optional helpers for **Flask** and **FastAPI**. They include an "auto" sign-in that detects administrators.

```bash
pip install bahari-sso              # core only (PyJWT[crypto])
pip install "bahari-sso[flask]"     # + Flask blueprint
pip install "bahari-sso[fastapi]"   # + FastAPI router
```

Requires Python 3.9 or newer.

## Configuration

You only configure the issuer and this app's credentials:

```python
from bahari_sso import BahariClient, Config

client = BahariClient(Config(
    issuer="https://accounts.baharione.com",   # https only (http allowed for localhost)
    client_id="...",
    client_secret="...",
    platform="reseller",                        # this app's platform key: required for admin sign-in
    # scopes="openid profile email phone profile:read identity:read wallet:read platform:read",
    # admin_issuer=None,                        # used only when discovery is unreachable and nothing is cached
    # discovery_ttl=300,
))
# or Config.from_dict({...}) / Config.from_env()  (BAHARI_ACCOUNTS_ISSUER, BAHARI_CLIENT_ID, BAHARI_CLIENT_SECRET,
#                                                  BAHARI_PLATFORM_KEY, BAHARI_SCOPES, BAHARI_ADMIN_ISSUER)
```

`BahariClient(config, http=None, cache=None, *, sdk=None, seal=None, unseal=None)`

- `http` is any object with `send(method, url, headers, body) -> Response`. The default `UrllibHttpClient` uses the
  standard library and never follows redirects. Its timeouts are 3 s to connect and about 10 s per request.
- `cache` is any object with `get(key)`, `set(key, value, ttl)` and `delete(key)`. It can also have
  `add(key, value, ttl) -> bool`, which is used for `jti` de-duplication. The default is a per-process
  `MemoryCache`. **Use a shared cache such as Redis when you run several workers.**
- `seal` and `unseal` are `str -> str` callables, for example Fernet encrypt/decrypt. They encrypt the machine
  tokens that are kept in the cache.

Every request sends `Accept: application/json` and `X-Bahari-SDK: bahari-sso/0.1.0`. Bahari answers with
`X-Bahari-SDK-Status` (`ok|outdated|unsupported|unknown`), which you can read as `client.sdk_status`. When the
status is `outdated` or `unsupported`, the `bahari_sso` logger writes one warning per process.

## Core API

```python
login = client.begin_login("client", "https://app.example.com/auth/client/callback")
# Store login.transaction server-side under login.state (never in a browser-readable cookie), then redirect to login.url.

identity = client.complete_login(transaction, code)        # -> Identity(kind, subject, tokens, profile, access_expires_in, tokens_changed)
identity = client.refresh(kind, tokens, subject, access_expires_in)   # recheck; rotates client tokens < 30 s before expiry
client.revoke(kind, tokens)
client.logout_url(kind, post_logout_redirect)              # client: end_session_endpoint; admin: admin.panel_url
claims = client.verify_logout_token(token)                 # back-channel logout
client.navigation(kind, tokens, wallet_return_to=None)     # platform switcher
client.update_pinned(tokens, ["sms", "hosting"])           # returns the Response; a 422 is passed through
client.url("client.profile_url", {"tab": "x"}); client.wallet_url("/dashboard")
client.api("POST", "platform-wallets/123/debits", {...}, scope="wallet:debit")   # with the machine token
client.discovery().get("admin.panel_url")
```

Errors (from `bahari_sso`):

- `BahariError` is the base class.
- `HttpError` has `.response` and `.status`.
- `InvalidTokenError` means a token is invalid.
- `AccessDeniedError` means the session must end. You get it for HTTP 400, 401 or 403 during a refresh, for an
  inactive account, for a missing admin role, or when the identity changed.

### Identity checks

- **Client.** The ID token must be RS256 and have a `kid`. Its `iss` must be the issuer, its `aud` must contain
  your `client_id`, and its `sub` must be a UUID. `exp` and `iat` must be present, with 30 s leeway, and the nonce
  must match. The profile from `profile_endpoint` must have `data.id == sub`, `status == "active"` and a UUID
  `customer.id`. The access lifetime is capped at 900 s.
- **Admin.** The exchanged profile must have `platform == config.platform` and `role` set to `ADMIN` or
  `SUPER_ADMIN`. `session_token` moves from the profile into `tokens`.

## Flask

```python
from flask import Flask
from bahari_sso import BahariClient, Config
from bahari_sso.flask import create_blueprint, login_required, current_session

app = Flask(__name__)
app.secret_key = "..."                      # the signed cookie keeps only an opaque server-side session id
client = BahariClient(Config.from_env())
app.register_blueprint(create_blueprint(client, paths={"client": "/dashboard", "admin": "/admin"}))

@app.get("/dashboard")
@login_required()                           # kind is taken from the path; or login_required("admin")
def dashboard():
    return {"email": current_session().profile["email"]}
```

## FastAPI

```python
from fastapi import Depends, FastAPI
from bahari_sso.fastapi import create_router

router = create_router(client)              # cookie "bahari_session": httpOnly, Secure, SameSite=Lax
app = FastAPI()
app.include_router(router)                  # do not add another prefix here; pass prefix= to create_router

@app.get("/admin")
def admin(session=Depends(router.login_required("admin"))):
    return {"admin": session.profile["email"]}
```

### Routes (both helpers, default prefix `/auth`)

| Route | Purpose |
| --- | --- |
| `GET /auth/login?return_to=` | Auto sign-in: starts a customer sign-in and continues to the admin sign-in when Bahari reports `admin_access`. |
| `GET /auth/{client,admin}/login?return_to=` | Starts a sign-in of one kind. |
| `GET /auth/{kind}/callback` | Completes the sign-in. |
| `POST /auth/{kind}/logout` | Ends the local session, revokes it at Bahari and redirects to Bahari's logout or the admin panel. |
| `POST /auth/backchannel-logout` | Bahari's signed `logout_token`. Ends every local customer session of that account, once per `jti`. |
| `GET /auth/session[?kind=]` | JSON of the rechecked sessions (`kind`, `subject`, `profile`, `expires_at`). Never includes tokens. |

Options (keyword arguments to `create_blueprint` and `create_router`):

- `paths` sets the area of each kind. The defaults are `/dashboard` and `/admin`.
- `auto_admin` defaults to `True`.
- `session_hours` defaults to `8`.
- `post_logout_redirect` sets where customers land after logging out.
- `public_url` sets the base URL for callbacks when you run behind a proxy.
- `state_cache` sets where sign-in state is kept. The default is the client's cache.

Pass `store=` to keep sessions in your own store.

`return_to` is sanitised the same way as in the Laravel package. It must stay inside the area of its kind. URLs
that start with `//`, backslashes, control characters, spaces and `..` are rejected (`..` also when encoded).
Values longer than 2048 bytes are rejected.

### Auto admin detection

1. `GET /auth/login` starts a customer sign-in and marks the transaction with `auto=True`.
2. After the client callback creates the customer session, the profile may contain
   `admin_access: {"platform", "role", "two_factor_ready"}`. If it does, and `auto_admin` is on, the customer's
   subject is stored server-side as the expected admin user. The browser is then redirected to
   `/auth/admin/login?return_to=/admin`.
3. The admin sign-in copies the expected user into its transaction. Bahari asks for the admin password and 2FA on
   its admin host.
4. On the admin callback, if the exchanged profile's `user_id` is not the expected customer, **no admin session is
   created**. The Bahari admin session is revoked and the browser goes back to the client area.

### Sessions

The browser holds only a random, opaque id. Sign-in transactions (PKCE verifier and nonce), the pointer to each
kind's session and the expected admin user are all kept in the server-side cache. Sessions themselves, tokens
included, are kept in a `SessionStore`, which has `create`, `find`, `update`, `revoke` and `revoke_subject`. The
default `MemorySessionStore` works per process. In production, implement a store backed by a database or Redis
that **encrypts tokens**, and use a shared cache.

The browser id is replaced after every sign-in, which prevents session fixation. Every protected request rechecks
the session with Bahari while holding a per-session lock. If the check fails for any reason, the local session ends.

## Development

```bash
python3 -m venv .venv && .venv/bin/python -m pip install -e ".[test]"
.venv/bin/python -m pytest
```

## License

MIT. See `LICENSE`.


## No local authentication

The app has no sign-in of its own. Bahari Accounts does sign-in, registration, passwords, password reset,
verification, 2FA and administrator sign-in. Remove any login or registration forms, password fields and local admin
logins, and store no passwords: local users keep only the Bahari ID and copies of name and email.

| Button | Route |
| --- | --- |
| Sign in | `GET /auth/login` |
| Create account | `GET /auth/register` |
| Administrator sign-in (optional) | `GET /auth/admin/login` |
| Sign out | `POST /auth/{client\|admin}/logout` |

Clicking Sign in opens Bahari ("Sign in to continue to *your app*"). After sign-in or registration Bahari sends the
person straight back to the page they wanted in your app; connected apps see no consent screen. Sign out ends the app
session and Bahari's, then returns to your home page without a confirmation page (the package sends the ID token as
`id_token_hint`).
