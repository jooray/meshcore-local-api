"""Errors raised by the client. Every one carries a `code`: the server's error code for an answer
with `ok: false`, or one of the client-side codes below."""
from __future__ import annotations


class LocalApiError(Exception):
    """An error answer from the server, or a client-side failure with a code of its own.

    `code` is the server's code (`unknown_channel`, `rate_limited`, `budget`, ...) or one of
    `timeout`, `closed`, `unsupported`, `pairing`, `refused`. `maybe_sent` is True when the server
    says the command reached the radio but was not confirmed, so it may have been transmitted.
    """

    def __init__(self, code: str, message: str | None = None, *, maybe_sent: bool = False,
                 method: str | None = None, details: dict | None = None):
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code
        self.message = message or code
        self.maybe_sent = maybe_sent
        self.method = method
        self.details = details or {}

    @classmethod
    def from_answer(cls, error, method: str | None = None) -> "LocalApiError":
        """Builds the error from the `error` object of an answer (or of a pre-pairing `error` frame)."""
        if not isinstance(error, dict):
            return cls("error", "malformed error answer", method=method)
        code = error.get("code") if isinstance(error.get("code"), str) else "error"
        message = error.get("message") if isinstance(error.get("message"), str) else None
        return cls(code, message, maybe_sent=error.get("maybeSent") is True, method=method, details=error)


class RequestTimeout(LocalApiError):
    """No answer within the request's timeout."""

    def __init__(self, method: str, timeout: float):
        super().__init__("timeout", f"{method} got no answer in {timeout:g} s", method=method)


class ConnectionClosed(LocalApiError):
    """The connection is not open, or closed while the request waited."""

    def __init__(self, message: str = "the connection is not open", method: str | None = None):
        super().__init__("closed", message, method=method)


class MissingCapability(LocalApiError):
    """The request needs an optional feature the server did not list in `hello.capabilities`."""

    def __init__(self, capability: str, method: str | None = None):
        super().__init__("unsupported", f"the server does not advertise {capability}", method=method)
        self.capability = capability


class PairingError(LocalApiError):
    """The pairing challenge was malformed or asked to sign something other than the pairing string."""

    def __init__(self, message: str):
        super().__init__("pairing", message)
