"""Egress containment for http_fetch (Invariant 2).

A URL is allowed only when its (scheme, host, port) EXACTLY matches an allowlist entry — not
when its raw string starts with an allowlisted prefix. Prefix matching is brittle: it depends
on a trailing slash and does not parse the URL the way an HTTP client (or a redirect target)
would, so it can diverge from where a real request would actually go. These tests pin the
robust containment predicate.
"""

from aitw.tools import http_fetch
from aitw.tools.registry import ToolContext

ALLOW_SLASH = ["http://localhost:8099/"]
ALLOW_NO_SLASH = ["http://localhost:8099"]  # same host:port, no trailing slash


def _fetch(url, allowlist, tmp_path):
    ctx = ToolContext(tenant_id="t", workspace=tmp_path, egress_allowlist=list(allowlist))
    return http_fetch._run({"url": url}, ctx), ctx


def test_allowlisted_host_any_path_is_allowed(tmp_path):
    out, ctx = _fetch("http://localhost:8099/mock/email", ALLOW_SLASH, tmp_path)
    assert out.startswith("MOCK 200 OK")
    assert ctx.fetched == [{"url": "http://localhost:8099/mock/email"}]


def test_offhost_is_blocked(tmp_path):
    out, ctx = _fetch("http://evil.com/", ALLOW_SLASH, tmp_path)
    assert out.startswith("ERROR: egress blocked")
    assert ctx.fetched == []


def test_lookalike_host_blocked_regardless_of_trailing_slash(tmp_path):
    # The key regression: a `startswith` check against the no-trailing-slash entry ALLOWS this
    # (the real host is `localhost:8099.evil.com`). Exact host/port matching blocks it for BOTH
    # allowlist forms — the predicate must not depend on a trailing slash.
    for allowlist in (ALLOW_SLASH, ALLOW_NO_SLASH):
        out, ctx = _fetch("http://localhost:8099.evil.com/steal", allowlist, tmp_path)
        assert out.startswith("ERROR: egress blocked"), allowlist
        assert ctx.fetched == []


def test_userinfo_confusion_host_is_blocked(tmp_path):
    # urlsplit resolves the real host to evil.com; must be blocked.
    out, ctx = _fetch("http://localhost:8099@evil.com/", ALLOW_SLASH, tmp_path)
    assert out.startswith("ERROR: egress blocked")
    assert ctx.fetched == []


def test_different_port_is_blocked(tmp_path):
    out, _ = _fetch("http://localhost:9000/", ALLOW_SLASH, tmp_path)
    assert out.startswith("ERROR: egress blocked")


def test_non_http_scheme_is_blocked(tmp_path):
    out, _ = _fetch("file:///etc/passwd", ALLOW_SLASH, tmp_path)
    assert out.startswith("ERROR: egress blocked")


def test_scheme_and_host_case_are_normalized(tmp_path):
    # A real client treats HTTP://LOCALHOST:8099 as the same host; exact matching normalizes.
    out, _ = _fetch("HTTP://LOCALHOST:8099/x", ALLOW_SLASH, tmp_path)
    assert out.startswith("MOCK 200 OK")


def test_malformed_url_is_blocked(tmp_path):
    out, _ = _fetch("::::not-a-url", ALLOW_SLASH, tmp_path)
    assert out.startswith("ERROR: egress blocked")
