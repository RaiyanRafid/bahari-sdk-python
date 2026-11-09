"""RS256 verification of ID tokens and back-channel logout tokens against the issuer's JWKS."""

from __future__ import annotations

import base64
import hmac
import json
import re
import time
from typing import TYPE_CHECKING, Any, Dict, Mapping, Optional

import jwt

from .errors import BahariError, InvalidTokenError

if TYPE_CHECKING:  # pragma: no cover
    from .client import BahariClient

__all__ = ["TokenVerifier", "LOGOUT_EVENT", "is_uuid", "base64url"]

LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"
LEEWAY = 30

_UUID = re.compile(r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")


def is_uuid(value: Any) -> bool:
    return isinstance(value, str) and _UUID.match(value) is not None


def base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


class _UnknownKey(Exception):
    pass


class TokenVerifier:
    """Verifies RS256 tokens. The JWKS is cached by the client and refetched once on an unknown key or bad signature."""

    def __init__(self, client: "BahariClient") -> None:
        self._client = client

    def verify(self, token: str, nonce: Optional[str] = None, logout: bool = False) -> Dict[str, Any]:
        kid = self._kid(token)
        try:
            claims = self._decode(token, self._client.jwks(), kid)
        except InvalidTokenError:
            raise
        except (_UnknownKey, jwt.InvalidSignatureError, jwt.InvalidKeyError, jwt.PyJWKError, BahariError):
            # The key may have rotated: fetch the key set once more.
            try:
                claims = self._decode(token, self._client.jwks(fresh=True), kid)
            except InvalidTokenError:
                raise
            except Exception as exc:
                raise InvalidTokenError("Invalid token signature.") from exc

        config = self._client.config
        audience = claims.get("aud")
        audiences = audience if isinstance(audience, list) else [audience] if audience is not None else []
        iat = claims.get("iat")
        if (
            claims.get("iss") != config.issuer
            or config.client_id not in audiences
            or not is_uuid(claims.get("sub"))
            or not _number(claims.get("exp"))
            or not _number(iat)
            or iat > time.time() + LEEWAY
        ):
            raise InvalidTokenError("Invalid token claims.")
        if nonce is not None:
            claimed = claims.get("nonce")
            if not isinstance(claimed, str) or not hmac.compare_digest(nonce.encode(), claimed.encode()):
                raise InvalidTokenError("Invalid token nonce.")
        if logout:
            events = claims.get("events")
            if (
                claims.get("jti") in (None, "")
                or "nonce" in claims
                or not isinstance(events, dict)
                or LOGOUT_EVENT not in events
                or abs(time.time() - iat) > 300
            ):
                raise InvalidTokenError("Invalid logout token.")
        return claims

    @staticmethod
    def _kid(token: Any) -> str:
        parts = token.split(".") if isinstance(token, str) else []
        header: Any = None
        if len(parts) == 3:
            try:
                header = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
            except (ValueError, TypeError):
                header = None
        if not isinstance(header, dict) or header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
            raise InvalidTokenError("Invalid token algorithm.")
        return header["kid"]

    @staticmethod
    def _decode(token: str, jwks: Mapping[str, Any], kid: str) -> Dict[str, Any]:
        key = None
        keys = jwks.get("keys") if isinstance(jwks, Mapping) else None
        for candidate in keys if isinstance(keys, list) else []:
            if (
                isinstance(candidate, dict)
                and candidate.get("kid") == kid
                and candidate.get("kty") == "RSA"
                and candidate.get("alg", "RS256") == "RS256"
                and candidate.get("use", "sig") == "sig"
            ):
                key = jwt.PyJWK(candidate, algorithm="RS256").key
                break
        if key is None:
            raise _UnknownKey("Unknown signing key.")
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                leeway=LEEWAY,
                options={"verify_aud": False, "verify_iss": False, "require": ["exp", "iat"]},
            )
        except jwt.InvalidSignatureError:
            raise
        except jwt.PyJWTError as exc:
            raise InvalidTokenError("Invalid token.") from exc
        if not isinstance(claims, dict):
            raise InvalidTokenError("Invalid token.")
        return claims
