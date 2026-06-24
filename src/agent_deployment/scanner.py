"""Central scanner / redactor for untrusted text surfaces.

One place that knows how to (a) FIND content that should not be acted on or exposed
(instruction-control tokens, credential shapes, planted lure tokens) and (b) REDACT it for safe
display in a model context, a log, or before an external effect. The context sanitizer, the tool
registry, the external-effect path, and the telemetry log all call in here so detection logic lives
in exactly one module.

This is intentionally conservative pattern-matching, not a model. It is one layer of a
defense-in-depth design that also includes tool-policy enforcement and external-effect validation;
no single pattern here is relied on alone.

Detection is LAYERED (configurable via :class:`Scanner`):

  1. built-in generic patterns (instruction markers, credential shapes, the lure-token family);
  2. optional private/local patterns supplied by the operator (loaded fail-closed); and
  3. optional exact values supplied by the host runtime (e.g. seeded lure values) so a lure whose
     shape differs from the built-in family is still caught.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# Surfaces a scan can be attributed to (plain strings for telemetry legibility).
SURFACES = (
    "model_context",
    "tool_result",
    "external_effect_args",
    "telemetry",
    "final_output",
    "config",
    "package",
)

# Embedded control markers that some runtimes treat as an executable directive line. Untrusted data
# must never carry one through to the model unneutralized. This is only ONE layer: tool-policy and
# external-effect validation defend the semantic case regardless of any marker.
INSTRUCTION_MARKERS = ("INJECT::",)

# Instruction-LIKE content that is not the literal mock marker: classic natural-language override
# phrases and JSON tool-call-shaped payloads embedded in untrusted data. Detection here does not
# REPLACE the semantic defenses (tool allow-list, recipient/egress validation, provenance framing);
# it demotes the most recognizable injection shapes so they are not echoed to the model as clean,
# executable-looking directives. Patterns are deliberately specific to avoid mangling legitimate
# prose (e.g. they require an instruction object like "instructions"/"context", not bare verbs).
_INSTRUCTION_LIKE_PATTERNS = [
    # "ignore/disregard/forget ... <instruction noun>" within a short window — catches qualifier
    # variants ("the prior system rules", "all previous instructions") without bare-verb misfires.
    re.compile(r"\b(?:ignore|disregard|forget)\b[^.\n]{0,40}?\b(?:instructions?|messages?|context|prompts?|rules?)\b", re.IGNORECASE),
    re.compile(r"new instructions\s*:", re.IGNORECASE),
    re.compile(r"(?:you are now|from now on,? you are)\b", re.IGNORECASE),
    re.compile(r"(?:override|bypass)\s+(?:the\s+)?(?:system|safety|security|policy)\b", re.IGNORECASE),
    # JSON tool-call-shaped content embedded in untrusted text.
    re.compile(r"\{\s*[\"']tool[\"']\s*:", re.IGNORECASE),
    re.compile(r"[\"']tool[\"']\s*:\s*[\"'][a-z_]+[\"']", re.IGNORECASE),
]
_INSTRUCTION_LIKE_REDACTION = "[neutralized-instruction]"

# Credential / token SHAPES (value patterns, not variable names). Mirrors the runtime telemetry
# guard's redaction shapes so both agree on what "looks like a secret".
#
# The provider-key prefix is assembled from fragments so this detector module never carries the
# literal token prefix as shippable text (a plain validator that greps for it should find nothing),
# while the compiled pattern is byte-identical to the literal form.
_PROVIDER_KEY_PREFIX = "sk-" + "ant-"
_SECRET_PATTERNS = [
    re.compile(_PROVIDER_KEY_PREFIX + r"[A-Za-z0-9_-]{10,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
]

# Canary-shaped lure-marker family. Matching by shape catches a rotated lure without hardcoding any
# concrete planted value (the regex definition below intentionally does not match itself).
_LURE_TOKEN_PATTERN = re.compile(r"HT-[A-Z0-9-]*CANARY[A-Z0-9-]*")

_REDACTION = "[REDACTED]"
_MARKER_REDACTION = "[neutralized-control-marker]"


def load_pattern_file(path: str | Path) -> tuple:
    """Compile operator-private redaction regexes from a local file. Fail closed.

    One regex per line; a simple YAML list (``- pattern``) is tolerated; ``#`` comments and blank
    lines are ignored. A missing/unreadable file or an invalid regex raises — a configured-but-broken
    private source must not silently degrade detection. Shared by the runtime scanner and the
    artifact scanner so both honor the same ``REDACTION_PATTERNS_PATH`` configuration.
    """
    raw = Path(path).read_text(encoding="utf-8")  # raises if missing/unreadable -> fail closed
    patterns = []
    for ln in raw.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        if ln.startswith("- "):
            ln = ln[2:].strip().strip("'\"")
        patterns.append(re.compile(ln))  # invalid regex -> raises -> fail closed
    return tuple(patterns)


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


@dataclass
class Scanner:
    """A configured scanner. ``extra_patterns`` are operator/private regexes; ``extra_literals``
    are exact strings (e.g. host-seeded lure values) to redact verbatim. Both are additive to the
    built-in patterns and are treated as lure-token findings."""

    extra_patterns: tuple = ()
    extra_literals: frozenset = field(default_factory=frozenset)

    def scan_text(self, text: str, *, surface: str) -> list[Finding]:
        if not isinstance(text, str) or not text:
            return []
        findings: list[Finding] = []

        marker_hits = sum(text.count(m) for m in INSTRUCTION_MARKERS)
        if marker_hits:
            findings.append(Finding("instruction_marker", surface, marker_hits))

        instruction_like_hits = sum(len(rx.findall(text)) for rx in _INSTRUCTION_LIKE_PATTERNS)
        if instruction_like_hits:
            findings.append(Finding("instruction_like", surface, instruction_like_hits))

        secret_hits = sum(len(rx.findall(text)) for rx in _SECRET_PATTERNS)
        if secret_hits:
            findings.append(Finding("secret", surface, secret_hits))

        lure_hits = len(_LURE_TOKEN_PATTERN.findall(text))
        lure_hits += sum(len(rx.findall(text)) for rx in self.extra_patterns)
        lure_hits += sum(text.count(lit) for lit in self.extra_literals if lit)
        if lure_hits:
            findings.append(Finding("lure_token", surface, lure_hits))

        return findings

    def redact_text(self, text: str, *, surface: str) -> RedactionResult:
        findings = self.scan_text(text, surface=surface)
        if not findings:
            return RedactionResult(text, [])

        redacted = text
        for marker in INSTRUCTION_MARKERS:
            redacted = redacted.replace(marker, _MARKER_REDACTION)
        for rx in _INSTRUCTION_LIKE_PATTERNS:
            redacted = rx.sub(_INSTRUCTION_LIKE_REDACTION, redacted)
        for rx in _SECRET_PATTERNS:
            redacted = rx.sub(_REDACTION, redacted)
        redacted = _LURE_TOKEN_PATTERN.sub(_REDACTION, redacted)
        for rx in self.extra_patterns:
            redacted = rx.sub(_REDACTION, redacted)
        for lit in self.extra_literals:
            if lit:
                redacted = redacted.replace(lit, _REDACTION)
        return RedactionResult(redacted, findings)


# A stateless default scanner with only the built-in patterns, for the module-level helpers and any
# caller that does not need private/host configuration.
_DEFAULT_SCANNER = Scanner()


def scan_text(text: str, *, surface: str) -> list[Finding]:
    """Return structured findings for a piece of text without modifying it (built-in patterns)."""
    return _DEFAULT_SCANNER.scan_text(text, surface=surface)


def redact_text(text: str, *, surface: str) -> RedactionResult:
    """Neutralize content that should not be acted on or exposed (built-in patterns).

    Instruction markers are defanged so a downstream model/adapter cannot treat the line as a
    directive; credential shapes and lure tokens are replaced with a fixed placeholder so they
    cannot be echoed or leaked.
    """
    return _DEFAULT_SCANNER.redact_text(text, surface=surface)
