"""Shared test fixtures / fakes for WebSecAnalyzer."""

from __future__ import annotations


class _FakeRaw:
    """Mimics urllib3 raw response exposing Set-Cookie via getlist."""

    def __init__(self, set_cookies: list[str]):
        self.headers = _FakeRawHeaders(set_cookies)


class _FakeRawHeaders:
    def __init__(self, set_cookies: list[str]):
        self._set_cookies = set_cookies

    def getlist(self, name: str) -> list[str]:
        if name.lower() == "set-cookie":
            return list(self._set_cookies)
        return []


class FakeResponse:
    """Minimal stand-in for requests.Response for the passive checks.

    Only implements the attributes the check functions actually use:
    .headers (dict), .text (str), .raw.headers.getlist("Set-Cookie").
    """

    def __init__(
        self,
        headers: dict[str, str] | None = None,
        text: str = "",
        set_cookies: list[str] | None = None,
    ):
        self.headers = headers or {}
        self.text = text
        self.raw = _FakeRaw(set_cookies or [])
