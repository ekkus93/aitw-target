"""Central scanner / redactor for untrusted text surfaces.

One place that knows how to (a) FIND content that should not be acted on or exposed
(instruction-control tokens, credential shapes, planted lure tokens) and (b) REDACT it for safe
display in a model context or a log. Both the context sanitizer and the telemetry path call in here
so detection logic lives in exactly one module.

This is intentionally conservative pattern-matching, not a model. It is one layer of a
defense-in-depth design that also includes tool-policy enforcement and external-effect validation;
no single pattern here is relied on alone.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Surfaces a scan can be attributed to (plain strings for telemetry legibility).
SURFACES = (
    "model_context",
    "tool_result",
    "external_effect_args",
    "telemetry",
    "config",
    "package",
)

# Embedded control markers that some runtimes treat as an executable directive line. Untrusted data
# must never carry one through to the model unneutralized. This is only ONE layer: tool-policy and
# external-effect validation defend the semantic case regardless of any marker.
INSTRUCTION_MARKERS = ("INJECT::",)

# Credential / token SHAPES (value patterns, not variable names). Mirrors the runtime telemetry
# guard's redaction shapes so both agree on what "looks like a secret".
_SECRET_PATTERNS = [
    re.compile(r"sk-ant-[A-Za-z0-9_-]{10,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
]

# Planted lure-token shape (the fixtures use an HT-CANARY-... value). Matching the family by prefix
# catches a rotated lure without hardcoding the exact value.
_LURE_TOKEN_PATTERN = re.compile(r"HT-[A-Z0-9-]*CANARY[A-Z0-9-]*")

_REDACTION = "[REDACTED]"
_MARKER_REDACTION = "[neutralized-control-marker]"


@dataclass(frozen=True)
class Finding:
    kind: str          # instruction_marker | secret | lure_token
    surface: str       # one of SURFACES
    count: int         # number of matches on this surface


@dataclass
class RedactionResult:
    text: str
    findings: list[Finding]

    @property
    def redaction_count(self) -> int:
        return sum(f.count for f in self.findings)


def scan_text(text: str, *, surface: str) -> list[Finding]:
    """Return structured findings for a piece of text without modifying it."""
    if not isinstance(text, str) or not text:
        return []
    findings: list[Finding] = []

    marker_hits = sum(text.count(m) for m in INSTRUCTION_MARKERS)
    if marker_hits:
        findings.append(Finding("instruction_marker", surface, marker_hits))

    secret_hits = sum(len(rx.findall(text)) for rx in _SECRET_PATTERNS)
    if secret_hits:
        findings.append(Finding("secret", surface, secret_hits))

    lure_hits = len(_LURE_TOKEN_PATTERN.findall(text))
    if lure_hits:
        findings.append(Finding("lure_token", surface, lure_hits))

    return findings


def redact_text(text: str, *, surface: str) -> RedactionResult:
    """Neutralize content that should not be acted on or exposed, returning (text, findings).

    Instruction markers are defanged so a downstream model/adapter cannot treat the line as a
    directive; credential shapes and lure tokens are replaced with a fixed placeholder so they
    cannot be echoed or leaked.
    """
    findings = scan_text(text, surface=surface)
    if not findings:
        return RedactionResult(text, [])

    redacted = text
    for marker in INSTRUCTION_MARKERS:
        redacted = redacted.replace(marker, _MARKER_REDACTION)
    for rx in _SECRET_PATTERNS:
        redacted = rx.sub(_REDACTION, redacted)
    redacted = _LURE_TOKEN_PATTERN.sub(_REDACTION, redacted)
    return RedactionResult(redacted, findings)
