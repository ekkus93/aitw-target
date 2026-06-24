"""Intake adapter exposing the defended layer as a minimal deployment object.

The host runtime loads a root ``provider.py`` and reads a ``DEPLOYMENT`` object from it. This module
defines that object. It reuses the existing, separately-tested policy modules — tool allow-list,
external-effect validation, tenant-scoped memory, and the central scanner — and adds no new security
logic; it only re-shapes them to the contract the host calls:

    name
    wrap_store(raw_store, tenant_id)
    task_registry(ctx, *, scanner=None, credential_guard=None)
    posture_registry(ctx)            # same defended registry
    make_scanner()                   # a broad-compatibility scanner the host may apply itself
    make_broker(...)                 # pass-through unless the host contract documents wrapping

The host provides the deployment base class; this development tree does not, so the import is soft
and falls back to a plain base purely so the adapter's shape can be unit-tested locally. The
submitted artifact does not bundle a runtime.
"""

from __future__ import annotations

import re
from typing import Optional

try:  # provided by the host runtime; absent in this development fork.
    from aitw.orchestrator.deployments import V2Deployment
except ImportError:  # only a genuinely-absent module falls back; a broken host module fails loud.
    V2Deployment = object

from agent_deployment.external_effects import EffectPolicy
from agent_deployment.policy import ToolPolicy
from agent_deployment.registry import PolicyRegistry
from agent_deployment.scanner import Finding, RedactionResult, Scanner

# Method names a host-provided scanner / credential guard might expose for redaction, in preference
# order. Each is tried by duck typing; an incompatible object is skipped, never fatal.
_HOST_REDACT_METHODS = ("redact_text", "redact", "guard")

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
# Scanner adaptation
# --------------------------------------------------------------------------------------------------


class ScannerAdapter:
    """Broad-compatibility wrapper around the central :class:`Scanner`.

    Returned by :meth:`Deployment.make_scanner` so the host can call whatever simple scan/redact
    method name it expects, on either a plain string or a structured payload. Every method is
    non-crashing and FAILS CLOSED:

      * ``scan``/``redact`` recurse over ``str``/``dict``/``list``/``tuple``/``set``/``frozenset``;
      * safe scalars (``None``/``bool``/``int``/``float``) are preserved unchanged;
      * an un-introspectable object yields an ``unsupported_payload`` finding (scan) or the
        ``[redacted:unsupported_payload]`` marker (redact) — never passed through unchanged;
      * a scan that raises yields a synthetic ``scanner_error`` finding (never an empty all-clear);
        a redaction that raises yields ``[redacted:scanner_error]`` (never the raw input).

    It never returns or prints a raw detected value.
    """

    def __init__(self, scanner: Optional[Scanner] = None):
        self._scanner = scanner or Scanner()

    def scan_text(self, text, *, surface: str = "unknown") -> list:
        try:
            return self._scanner.scan_text(text, surface=surface)
        except _SCANNER_FAULTS:  # fail closed: a scan failure is not an all-clear
            return [Finding("scanner_error", surface, 1)]

    def redact_text(self, text, *, surface: str = "unknown") -> str:
        try:
            return self._scanner.redact_text(text, surface=surface).text
        except _SCANNER_FAULTS:  # fail closed: never echo the raw input on failure
            return _SCANNER_ERROR_MARKER

    # Generic aliases the host might use instead. ``surface`` is positional-or-keyword so a host may
    # call ``redact(payload, "telemetry")`` or ``redact(payload, surface="telemetry")``. Structured
    # payloads are scanned/redacted RECURSIVELY and FAIL CLOSED: a container is never returned with a
    # raw sensitive string still inside, and an un-introspectable object is replaced with a marker
    # rather than passed through.
    def scan(self, payload, surface: str = "unknown") -> list:
        if isinstance(payload, str):
            return self.scan_text(payload, surface=surface)
        if isinstance(payload, _SAFE_SCALARS):
            return []
        if isinstance(payload, dict):
            return self._scan_iter(payload.values(), surface)
        if isinstance(payload, (list, tuple, set, frozenset)):
            return self._scan_iter(payload, surface)
        # Unknown object: fail closed (a missing finding would be a false all-clear).
        return [Finding("unsupported_payload", surface, 1)]

    def redact(self, payload, surface: str = "unknown"):
        if isinstance(payload, str):
            return self.redact_text(payload, surface=surface)
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
            # Rebuilding this branch failed: fail closed rather than return raw data.
            return _SCANNER_ERROR_MARKER
        # Unknown object we cannot safely introspect/redact: never pass it through unchanged.
        return _UNSUPPORTED_PAYLOAD_MARKER

    def guard(self, payload, surface: str = "unknown"):
        return self.redact(payload, surface=surface)

    def check(self, payload, surface: str = "unknown") -> bool:
        return bool(self.scan(payload, surface=surface))

    def _scan_iter(self, values, surface: str) -> list:
        findings: list = []
        for value in values:
            findings.extend(self.scan(value, surface))
        return findings


def _host_redactors(obj) -> list:
    """Compatible ``(text, surface) -> str`` redactors duck-typed off a host scanner/guard object.

    Tries the known method names in preference order; normalizes a returned tuple/result object to
    its text where recognizable. A ``TypeError`` is treated as a signature mismatch and retried
    positionally; ANY OTHER exception PROPAGATES so the composite can record a ``scanner_error`` and
    fall back to our own scanner (a failed host redactor must not look like a successful one). Used
    only to PRE-apply host redaction before our own scanner runs as the final net.
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
            for attr in ("text", "redacted"):
                val = getattr(out, attr, None)
                if isinstance(val, str):
                    return val
            if isinstance(out, (tuple, list)) and out and isinstance(out[0], str):
                return out[0]
            return text

        callables.append(_wrapped)
    return callables


class _CompositeScanner(Scanner):
    """Our :class:`Scanner` as the final safety net, optionally pre-applying host redactors.

    A subclass so it remains a real ``Scanner`` (the registry/policy facade depends on the
    ``scan_text``/``redact_text`` contract). ``scan_text`` decisions come from our patterns; for
    ``redact_text`` we first run any compatible host redactor, then always run our own redaction.

    Fail-closed posture: a host redactor that raises is SKIPPED (it is an optional pre-pass) but the
    failure is surfaced as a synthetic ``scanner_error`` finding, and our own scanner still runs as
    the net. If our own scanner ALSO raises, we fail closed entirely — the marker, never raw text.
    """

    def __init__(self, *, host_scanner=None, host_guard=None, **scanner_kwargs):
        super().__init__(**scanner_kwargs)
        self._host = _host_redactors(host_scanner) + _host_redactors(host_guard)

    def redact_text(self, text: str, *, surface: str) -> RedactionResult:
        host_errors = 0
        if isinstance(text, str):
            for fn in self._host:
                try:
                    text = fn(text, surface)
                except _SCANNER_FAULTS:  # optional host pre-pass failed; rely on our net
                    host_errors += 1
        try:
            result = super().redact_text(text, surface=surface)
        except _SCANNER_FAULTS:  # our net failed too: fail closed, never echo raw text
            return RedactionResult(_SCANNER_ERROR_MARKER, [Finding("scanner_error", surface, 1)])
        if host_errors:
            result.findings = list(result.findings) + [Finding("scanner_error", surface, host_errors)]
        return result


def _compose_scanner(scanner=None, credential_guard=None) -> Scanner:
    """Resolve the internal scanner for the registry path.

    No host objects -> a fresh local :class:`Scanner`. A host object that is already our ``Scanner``
    is used directly. Any other host scanner/guard is consulted (duck-typed) as a pre-pass while our
    scanner remains the final net. Never crashes on an unexpected host shape.
    """
    if scanner is None and credential_guard is None:
        return Scanner()

    base_kwargs = {}
    host_scanner = scanner
    if isinstance(scanner, Scanner):
        # Carry the host Scanner's configured detection forward; no separate pre-pass needed.
        base_kwargs = {"extra_patterns": scanner.extra_patterns, "extra_literals": scanner.extra_literals}
        host_scanner = None

    if host_scanner is None and credential_guard is None:
        return Scanner(**base_kwargs)
    return _CompositeScanner(host_scanner=host_scanner, host_guard=credential_guard, **base_kwargs)


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
    fallback. A non-support scenario, or any failure to read the fixtures, fails closed to empty, and
    the effect policy then denies all email. (Future tightening: once the operator ctx shape is
    known, require explicit scenario/ticket identity and drop the scenario-missing fallback.)
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


class Deployment(V2Deployment):
    """Minimal deployment object the host instantiates via ``provider:DEPLOYMENT``."""

    name = "defense"

    def make_scanner(self) -> ScannerAdapter:
        return ScannerAdapter(Scanner())

    def wrap_store(self, raw_store, tenant_id: str) -> ScopedStore:
        return ScopedStore(raw_store, tenant_id)

    def task_registry(self, ctx, *, scanner=None, credential_guard=None) -> PolicyRegistry:
        return PolicyRegistry(
            ctx,
            tool_policy=ToolPolicy(),
            effect_policy=EffectPolicy(allowed_recipients=_allowed_recipients_for_ctx(ctx)),
            scanner=_compose_scanner(scanner, credential_guard),
        )

    def posture_registry(self, ctx) -> PolicyRegistry:
        # Posture is telemetry/label only; the same defended registry is returned.
        return self.task_registry(ctx)

    def make_broker(self, *args, **kwargs):
        # Pass-through unless the host contract later documents broker wrapping. External-effect
        # validation lives in the task registry's call path, not here.
        if args:
            return args[0]
        return kwargs.get("broker")


DEPLOYMENT = Deployment()

__all__ = ["Deployment", "DEPLOYMENT", "ScopedStore", "ScannerAdapter"]
