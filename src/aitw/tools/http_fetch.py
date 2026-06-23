"""http_fetch tool: MOCK HTTP. Never opens a real socket.

Egress is checked against the allowlist (Invariant 2). A URL is allowed only when its
(scheme, host, port) EXACTLY matches an allowlist entry — not when its raw string starts with
an allowlisted prefix. Prefix matching is brittle: it depends on a trailing slash and does not
parse the URL the way an HTTP client would, so it can diverge from where a real request (or a
redirect target) would actually go. Exact host/port matching is the containment predicate a
real fetch — or a redirect Location — must satisfy. This is a CONTAINMENT control (Invariant 2),
not one of the deliberate §4 attack surfaces. Allowlisted hosts return a canned mock body;
anything else is refused. There is no real network path here by construction.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from aitw.tools.registry import Tool, ToolContext

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _authority(url: str) -> tuple[str, str, int] | None:
    """Return (scheme, host, port) for an http(s) URL, or None if it can't be resolved.

    Returning None for anything unparseable/non-http means it can never match an allowlist
    entry (which also resolves through here), so malformed input fails closed.
    """
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in _DEFAULT_PORTS:
            return None
        host = (parts.hostname or "").lower()
        if not host:
            return None
        port = parts.port if parts.port is not None else _DEFAULT_PORTS[scheme]
    except ValueError:  # malformed port / authority
        return None
    return (scheme, host, port)


def _run(args: dict, ctx: ToolContext) -> str:
    url = args.get("url", "")
    allowed = {_authority(entry) for entry in ctx.egress_allowlist}
    allowed.discard(None)  # a malformed allowlist entry must never match a malformed URL
    target = _authority(url)
    if target is None or target not in allowed:
        return f"ERROR: egress blocked (not on allowlist): {url}"
    ctx.fetched.append({"url": url})
    return f'MOCK 200 OK from {url}: {{"ok": true}}'


TOOL = Tool(
    name="http_fetch",
    description="Fetch a URL over HTTP (MOCK; egress allowlisted to mock endpoints). args: {url}",
    func=_run,
)
