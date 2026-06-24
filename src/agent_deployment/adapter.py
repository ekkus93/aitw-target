"""Intake adapter exposing the defended layer as a minimal deployment object.

The host runtime loads a root ``provider.py`` and reads a ``DEPLOYMENT`` object from it. This module
defines that object. It reuses the existing, separately-tested policy modules — tool allow-list,
external-effect validation, tenant-scoped memory, and the central scanner — and adds no new security
logic; it only re-shapes them to the contract the host calls:

    name
    wrap_store(raw_store, tenant_id)
    task_registry(ctx, *, scanner=None, credential_guard=None)
    posture_registry(ctx)            # same defended registry
    make_scanner()                   # host-contract scanner: register(*values) + scan(text).redacted
    make_broker(...)                 # real credential broker (issue_tool_credential / is_valid)

``Deployment`` is a plain class — it deliberately does NOT subclass any host base (the stock host
does not require it). The submitted artifact imports only stock ``aitw`` symbols and its own
``agent_deployment`` modules; it never depends on fork-only additions.
"""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass
from typing import Optional

from agent_deployment.external_effects import EffectPolicy
from agent_deployment.policy import ToolPolicy
from agent_deployment.registered_secrets import RegisteredSecretScanner, SecretScanResult
from agent_deployment.registry import PolicyRegistry
from agent_deployment.scanner import Finding, RedactionResult, Scanner

# Method names a host-provided scanner / credential guard might expose for redaction, in preference
# order. Each is tried by duck typing; an incompatible object is skipped, never fatal.
_HOST_REDACT_METHODS = ("redact_text", "redact", "guard", "scan")

# Fail-closed sentinel returned when a scan/redaction path raises: degraded content, never a raw
# value. Surfaced alongside a synthetic ``scanner_error`` finding so the failure stays visible.
_SCANNER_ERROR_MARKER = "[redacted:scanner_error]"

# Fail-closed sentinel for a payload shape we cannot safely introspect/redact (an arbitrary object
# that is not a str / known container / scalar). We never return such an object unchanged, since it
# could carry or later stringify into raw sensitive content.
_UNSUPPORTED_PAYLOAD_MARKER = "[redacted:unsupported_payload]"

# Scalar types that cannot carry nested string content and are safe to preserve as-is.
_SAFE_SCALARS = (bool, int, float, type(None))

# Faults a scanner/redactor (ours or a host-provided one) can plausibly raise. We catch this
# explicit set — not a blind ``except Exception`` — so a scan/redact failure FAILS CLOSED (safe
# marker / ``scanner_error`` finding) while a genuinely unexpected error type still propagates (fail
# loud) instead of being silently swallowed.
_SCANNER_FAULTS = (
    ArithmeticError,
    AttributeError,
    LookupError,
    TypeError,
    ValueError,
    RuntimeError,
    re.error,
)


def _first_present(mapping, *names, default=None):
    """Return the first present, non-None value among ``names`` in ``mapping``, else ``default``.

    Used for broker kwargs so a meaningful falsy value (e.g. ``ttl_seconds=0`` or an explicit empty
    token list) is honored rather than swallowed by an ``or`` chain.
    """
    for name in names:
        if name in mapping and mapping[name] is not None:
            return mapping[name]
    return default


# --------------------------------------------------------------------------------------------------
# Tenant-scoped store wrapper
# --------------------------------------------------------------------------------------------------


class ScopedStore:
    """Tenant-scoped wrapper over the host's raw shared store.

    The raw store has no concept of caller identity — cross-tenant reads, lists, searches, writes,
    and deletes are all possible. This wrapper binds one tenant and confines every operation to that
    tenant's key prefix. A cross-tenant request returns a controlled empty/``None``/``False`` result
    rather than raising: the host may treat an exception as a run failure, so denial must be quiet.

    Only the known store methods are wrapped explicitly. There is deliberately NO ``__getattr__``
    passthrough — an unaudited raw-store method must never be able to silently reintroduce
    cross-tenant access. If the host calls a method we did not wrap, that surfaces as a loud
    ``AttributeError`` in validation (to be given its own scoped wrapper) instead of a hidden leak.
    """

    def __init__(self, raw_store, tenant_id: str):
        self._raw = raw_store
        self._tenant_id = tenant_id
        self._prefix = f"{tenant_id}:"

    def _owned(self, key) -> bool:
        return isinstance(key, str) and key.startswith(self._prefix)

    @staticmethod
    def key_for(tenant_id: str, kind: str, name: str) -> str:
        return f"{tenant_id}:{kind}:{name}"

    def put(self, tenant_id: str, kind: str, name: str, content: str):
        # Never write under another tenant. None is the clearest denied/no-op sentinel for a method
        # that otherwise returns the stored key string.
        if tenant_id != self._tenant_id:
            return None
        return self._raw.put(tenant_id, kind, name, content)

    def get(self, key: str):
        if not self._owned(key):
            return None
        return self._raw.get(key)

    def get_value(self, tenant_id: str, kind: str, name: str):
        if tenant_id != self._tenant_id:
            return None
        return self._raw.get_value(tenant_id, kind, name)

    def list_keys(self, prefix: str = "") -> list:
        prefix = prefix or ""
        # An explicit prefix that cannot overlap our own tenant prefix is a cross-tenant request.
        if prefix and not (prefix.startswith(self._prefix) or self._prefix.startswith(prefix)):
            return []
        owned = self._raw.list_keys(self._prefix)  # only this tenant's keys
        if prefix:
            owned = [k for k in owned if k.startswith(prefix)]
        return owned

    def search(self, substring: str) -> list:
        hits = self._raw.search(substring or "")  # base search is unscoped across all tenants
        return [r for r in hits if self._owned(getattr(r, "key", None))]

    def delete(self, key: str) -> bool:
        if not self._owned(key):
            return False
        return self._raw.delete(key)

    def all_records(self) -> list:
        # A tenant-facing object by definition: only this tenant's records. A caller that genuinely
        # needs the whole store must use the raw, unwrapped store.
        return [r for r in self._raw.all_records() if self._owned(getattr(r, "key", None))]

    def close(self) -> None:
        close = getattr(self._raw, "close", None)
        if callable(close):
            close()


# --------------------------------------------------------------------------------------------------
# Host-contract scanner
# --------------------------------------------------------------------------------------------------


class HostScanner:
    """Scanner returned by :meth:`Deployment.make_scanner`.

    Host contract (text-centric):
      * ``register(*values)`` — record exact run secrets (the broker calls this);
      * ``scan(text)`` -> :class:`SecretScanResult` with a ``.redacted`` string.

    It composes two redactors: the exact-value :class:`RegisteredSecretScanner` (registered secrets
    plus base64/hex encodings) runs FIRST, then the pattern-based central :class:`Scanner`
    (prompt-injection / lure / credential-shape / configured private patterns) runs as the net.

    It ALSO presents the internal scanner contract the policy facade / registry depend on
    (``scan_text(...) -> list[Finding]`` and ``redact_text(...) -> RedactionResult``), so the SAME
    shared instance can back both the host's surfaces and the registry's tool-output/effect scanning
    — that way broker-registered secrets are redacted everywhere, not only on host-driven surfaces.

    Every method FAILS CLOSED: a scan/redact failure yields a ``scanner_error`` finding / the
    ``[redacted:scanner_error]`` marker, never the raw input.
    """

    def __init__(self, scanner: Optional[Scanner] = None):
        self._registered = RegisteredSecretScanner()
        self._scanner = scanner or Scanner()

    # --- host contract ---------------------------------------------------------------------------

    def register(self, *values) -> None:
        self._registered.register(*values)

    def scan(self, text, surface: str = "unknown") -> SecretScanResult:
        first = self._registered.scan(text)
        try:
            second = self._scanner.redact_text(first.redacted, surface=surface)
        except _SCANNER_FAULTS:
            return SecretScanResult(
                redacted=_SCANNER_ERROR_MARKER,
                redaction_count=first.redaction_count,
                findings=tuple(first.findings) + ("scanner_error",),
            )
        return SecretScanResult(
            redacted=second.text,
            redaction_count=first.redaction_count + second.redaction_count,
            findings=tuple(first.findings) + tuple(f.kind for f in second.findings),
        )

    # --- internal contract (policy facade / registry) -------------------------------------------

    def scan_text(self, text, *, surface: str = "unknown") -> list:
        first = self._registered.scan(text)
        findings: list = []
        if first.redaction_count:
            findings.append(Finding("registered_secret", surface, first.redaction_count))
        try:
            findings.extend(self._scanner.scan_text(first.redacted, surface=surface))
        except _SCANNER_FAULTS:
            findings.append(Finding("scanner_error", surface, 1))
        return findings

    def redact_text(self, text, *, surface: str = "unknown") -> RedactionResult:
        first = self._registered.scan(text)
        try:
            second = self._scanner.redact_text(first.redacted, surface=surface)
        except _SCANNER_FAULTS:
            return RedactionResult(_SCANNER_ERROR_MARKER, [Finding("scanner_error", surface, 1)])
        findings: list = []
        if first.redaction_count:
            findings.append(Finding("registered_secret", surface, first.redaction_count))
        findings.extend(second.findings)
        return RedactionResult(second.text, findings)

    # --- structured / generic helpers ------------------------------------------------------------

    def redact(self, payload, surface: str = "unknown"):
        if isinstance(payload, str):
            return self.scan(payload, surface).redacted
        if isinstance(payload, _SAFE_SCALARS):
            return payload
        try:
            if isinstance(payload, dict):
                return {k: self.redact(v, surface) for k, v in payload.items()}
            if isinstance(payload, list):
                return [self.redact(v, surface) for v in payload]
            if isinstance(payload, tuple):
                return tuple(self.redact(v, surface) for v in payload)
            if isinstance(payload, frozenset):
                return frozenset(self.redact(v, surface) for v in payload)
            if isinstance(payload, set):
                return {self.redact(v, surface) for v in payload}
        except _SCANNER_FAULTS:
            return _SCANNER_ERROR_MARKER
        return _UNSUPPORTED_PAYLOAD_MARKER

    def guard(self, payload, surface: str = "unknown"):
        return self.redact(payload, surface=surface)

    def check(self, payload, surface: str = "unknown") -> bool:
        if isinstance(payload, str):
            return self.scan(payload, surface).redaction_count > 0
        if isinstance(payload, _SAFE_SCALARS):
            return False
        if isinstance(payload, dict):
            return any(self.check(v, surface) for v in payload.values())
        if isinstance(payload, (list, tuple, set, frozenset)):
            return any(self.check(v, surface) for v in payload)
        return True  # un-introspectable object: fail closed (treat as suspicious)


# Back-compat alias: earlier code/tests referred to the host-facing scanner as ``ScannerAdapter``.
ScannerAdapter = HostScanner


def _host_redactors(obj) -> list:
    """Compatible ``(text, surface) -> str`` redactors duck-typed off a host scanner/guard object.

    Tries the known method names in preference order; normalizes a returned result object/tuple to
    its text (preferring ``.redacted`` then ``.text``). A ``TypeError`` is treated as a signature
    mismatch and retried positionally; ANY OTHER exception PROPAGATES so the composite can record a
    ``scanner_error`` and fall back to our own scanner. Used only to PRE-apply host redaction before
    our own scanner runs as the final net.
    """
    if obj is None:
        return []
    callables = []
    for meth in _HOST_REDACT_METHODS:
        fn = getattr(obj, meth, None)
        if not callable(fn):
            continue

        def _wrapped(text, surface, _fn=fn):
            try:
                out = _fn(text, surface=surface)
            except TypeError:
                out = _fn(text)  # signature mismatch only; other exceptions propagate to caller
            if isinstance(out, str):
                return out
            # Normalize a result object/tuple conservatively; if unclear, keep the input (our own
            # scanner still runs afterwards as the safety net).
            for attr in ("redacted", "text"):
                val = getattr(out, attr, None)
                if isinstance(val, str):
                    return val
            if isinstance(out, (tuple, list)) and out and isinstance(out[0], str):
                return out[0]
            return text

        callables.append(_wrapped)
    return callables


class _CompositeScanner:
    """Wraps a local final-net scanner, optionally pre-applying host-provided redactors.

    Presents the internal scanner contract (``scan_text -> list[Finding]``,
    ``redact_text -> RedactionResult``) that the policy facade / registry depend on. The
    ``local_scanner`` is the Deployment's shared :class:`HostScanner`, so registered run-secrets stay
    visible. Host redactors are an OPTIONAL pre-pass: one that raises is skipped and surfaced as a
    ``scanner_error`` finding, and the local net still runs; if the local net ALSO raises, fail
    closed (the marker, never raw text).
    """

    def __init__(self, *, local_scanner, host_scanner=None, host_guard=None):
        self._local = local_scanner
        self._host = _host_redactors(host_scanner) + _host_redactors(host_guard)

    def scan_text(self, text, *, surface: str = "unknown") -> list:
        return self._local.scan_text(text, surface=surface)

    def redact_text(self, text, *, surface: str = "unknown") -> RedactionResult:
        host_errors = 0
        if isinstance(text, str):
            for fn in self._host:
                try:
                    text = fn(text, surface)
                except _SCANNER_FAULTS:  # optional host pre-pass failed; rely on the local net
                    host_errors += 1
        try:
            result = self._local.redact_text(text, surface=surface)
        except _SCANNER_FAULTS:  # local net failed too: fail closed, never echo raw text
            return RedactionResult(_SCANNER_ERROR_MARKER, [Finding("scanner_error", surface, 1)])
        if host_errors:
            result = RedactionResult(
                result.text, list(result.findings) + [Finding("scanner_error", surface, host_errors)]
            )
        return result


def _compose_scanner(*, shared_scanner, host_scanner=None, credential_guard=None):
    """Resolve the scanner the registry/policy path uses.

    Always keeps ``shared_scanner`` (the Deployment's :class:`HostScanner`) as the final net so
    broker-registered run-secrets are redacted in tool output and effect args even when the host does
    not thread a scanner through ``task_registry``. A host-provided scanner/guard is composed as an
    optional pre-pass — it never REPLACES the shared scanner.
    """
    if host_scanner is None and credential_guard is None:
        return shared_scanner
    if host_scanner is shared_scanner and credential_guard is None:
        return shared_scanner
    return _CompositeScanner(
        local_scanner=shared_scanner, host_scanner=host_scanner, host_guard=credential_guard
    )


# --------------------------------------------------------------------------------------------------
# Credential broker
# --------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolCredential:
    tenant_id: str
    token: str
    issued_at: float
    ttl_seconds: int


def _normalize_token_entries(value):
    """Normalize host-supplied issued-token input to a tuple of entries.

    A single ``str``/``bytes`` token is ONE token, not an iterable of characters (iterating a bare
    string would register each character as a separate secret — including letters that appear inside
    the ``[REDACTED]`` marker). Other iterables are expanded; a non-iterable is a single entry.
    """
    if value is None:
        return ()
    if isinstance(value, bytes):
        return (value.decode("utf-8", errors="ignore"),)
    if isinstance(value, str):
        return (value,)
    try:
        return tuple(value)
    except TypeError:
        return (value,)


class CredentialBroker:
    """Issues and validates short-lived tool credentials, and teaches the scanner the run's secrets.

    Construction registers the model key, the tool backing secret, and any preexisting issued tokens
    with the scanner (this is how the scanner learns the run's exact secret values). Each freshly
    issued token is registered immediately too. Validation keys on token membership + TTL + tenant —
    NOT object identity or dataclass equality — because the host may round-trip or reconstruct
    credential objects.
    """

    def __init__(
        self,
        scanner,
        *,
        model_key=None,
        tool_backing_secret=None,
        issued_tokens=(),
        ttl_seconds: int = 300,
    ):
        self._scanner = scanner
        self._ttl_seconds = int(ttl_seconds)
        self._issued: dict = {}

        self._scanner.register(model_key, tool_backing_secret)
        for entry in _normalize_token_entries(issued_tokens):
            token = getattr(entry, "token", None)
            if isinstance(token, str) and token:
                self._scanner.register(token)
                self._issued[token] = ToolCredential(
                    tenant_id=str(getattr(entry, "tenant_id", "")),
                    token=token,
                    issued_at=float(getattr(entry, "issued_at", time.time())),
                    ttl_seconds=int(getattr(entry, "ttl_seconds", self._ttl_seconds)),
                )
            elif entry is not None:
                self._scanner.register(entry)

    def issue_tool_credential(self, tenant_id: str) -> ToolCredential:
        token = "tool-" + secrets.token_urlsafe(24)
        cred = ToolCredential(
            tenant_id=str(tenant_id),
            token=token,
            issued_at=time.time(),
            ttl_seconds=self._ttl_seconds,
        )
        self._issued[token] = cred
        self._scanner.register(token)
        return cred

    def is_valid(self, cred) -> bool:
        token = getattr(cred, "token", None)
        if not isinstance(token, str) or not token:
            return False
        issued = self._issued.get(token)
        if issued is None:
            return False
        # Trust only our stored issued_at/ttl/tenant, not values carried on the passed-in object.
        tenant_id = getattr(cred, "tenant_id", issued.tenant_id)
        if tenant_id != issued.tenant_id:
            return False
        return (time.time() - issued.issued_at) <= issued.ttl_seconds


# --------------------------------------------------------------------------------------------------
# Recipient derivation
# --------------------------------------------------------------------------------------------------


def _scenario_hint(ctx) -> Optional[str]:
    for attr in ("scenario_name", "scenario", "task_name"):
        val = getattr(ctx, attr, None)
        if isinstance(val, str) and val:
            return val
    return None


def _ctx_seeded_recipients(ctx):
    """Explicit seeded recipient/ticket data carried on ctx, if the host provides any."""
    tickets = getattr(ctx, "tickets", None)
    if isinstance(tickets, (list, tuple)):
        return {t.get("from") for t in tickets if isinstance(t, dict) and t.get("from")}
    return set()


def _allowed_recipients_for_ctx(ctx) -> frozenset:
    """Best-effort, fail-closed safe-recipient set for ``send_email``.

    Preference order (precise sources first):
      1. explicit seeded recipients/tickets carried on ``ctx`` (the operator-provided source);
      2. ``ctx`` scenario/task identity indicating support triage -> seeded support recipients from
         the host fixtures;
      3. a NARROW compatibility fallback (scenario identity missing): the exact seeded support
         recipients from the host fixtures, and nothing else.

    Every branch resolves to either the exact seeded fixture addresses or the empty set. The
    fallback in (3) NEVER admits an arbitrary/external recipient — there is no domain or wildcard
    fallback. A non-support scenario, or any failure to read the fixtures (e.g. the stock host has no
    ``aitw.scenarios.fixtures``), fails closed to empty, and the effect policy then denies all email.
    """
    seeded = _ctx_seeded_recipients(ctx)
    if seeded:
        return frozenset(seeded)

    scenario = _scenario_hint(ctx)
    # scenario is None -> bounded compatibility fallback; "support" in scenario -> support triage.
    if scenario is None or "support" in scenario.lower():
        try:
            from aitw.scenarios.fixtures import load_tickets

            return frozenset(t["from"] for t in load_tickets() if t.get("from"))
        except (ImportError, OSError, ValueError, KeyError, TypeError):
            # No fixture module/file, malformed fixture JSON, or unexpected shape: fail closed.
            return frozenset()
    return frozenset()


# --------------------------------------------------------------------------------------------------
# Deployment object
# --------------------------------------------------------------------------------------------------


class Deployment:
    """Minimal deployment object the host instantiates via ``provider:DEPLOYMENT``.

    A plain class — no host/fork base. It owns ONE shared :class:`HostScanner` so that secrets the
    broker registers are visible to every scan surface (host-driven and registry-driven alike).
    """

    name = "defense"

    def __init__(self):
        self._scanner = HostScanner(Scanner())

    def make_scanner(self) -> HostScanner:
        return self._scanner

    def wrap_store(self, raw_store, tenant_id: str) -> ScopedStore:
        return ScopedStore(raw_store, tenant_id)

    def task_registry(self, ctx, *, scanner=None, credential_guard=None) -> PolicyRegistry:
        registry_scanner = _compose_scanner(
            shared_scanner=self._scanner, host_scanner=scanner, credential_guard=credential_guard
        )
        return PolicyRegistry(
            ctx,
            tool_policy=ToolPolicy(),
            effect_policy=EffectPolicy(allowed_recipients=_allowed_recipients_for_ctx(ctx)),
            scanner=registry_scanner,
        )

    def posture_registry(self, ctx) -> PolicyRegistry:
        # Posture is telemetry/label only; the same defended registry is returned.
        return self.task_registry(ctx)

    def make_broker(self, *args, **kwargs) -> CredentialBroker:
        scanner = kwargs.get("scanner")
        if not isinstance(scanner, HostScanner):
            scanner = self._scanner  # never lose registrations in a detached scanner
        issued_tokens = _first_present(kwargs, "issued_tokens", "tokens", "credentials", default=())
        if issued_tokens is None:
            issued_tokens = ()
        return CredentialBroker(
            scanner,
            model_key=_first_present(kwargs, "model_key", "api_key", "model_api_key"),
            tool_backing_secret=_first_present(
                kwargs, "tool_backing_secret", "backing_secret", "tool_secret"
            ),
            issued_tokens=issued_tokens,
            ttl_seconds=int(_first_present(kwargs, "ttl_seconds", "credential_ttl_seconds", default=300)),
        )


DEPLOYMENT = Deployment()

__all__ = [
    "Deployment",
    "DEPLOYMENT",
    "ScopedStore",
    "HostScanner",
    "ScannerAdapter",
    "CredentialBroker",
    "ToolCredential",
]
