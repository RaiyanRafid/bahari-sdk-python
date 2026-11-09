"""Exceptions raised by the Bahari SDK."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:  # pragma: no cover
    from .http import Response

__all__ = ["BahariError", "HttpError", "InvalidTokenError", "AccessDeniedError"]


class BahariError(Exception):
    """Base error: Bahari could not be reached or answered unexpectedly."""


class HttpError(BahariError):
    """Bahari answered with an unexpected HTTP status. ``response`` holds the answer."""

    def __init__(self, response: "Response", url: str) -> None:
        self.response = response
        self.url = url
        super().__init__(f"Bahari Accounts answered {response.status} for {urlsplit(url).path}.")

    @property
    def status(self) -> int:
        return self.response.status


class InvalidTokenError(BahariError):
    """A token failed signature, issuer, audience, nonce or lifetime checks."""


class AccessDeniedError(BahariError):
    """The account or admin session is no longer allowed (revoked, suspended, role removed, identity changed).

    End the local session.
    """
