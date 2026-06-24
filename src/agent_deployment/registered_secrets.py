"""Registered-secret redactor for the host scanner contract.

The host runtime tells the provider the run's exact secret values (model key, tool backing secret,
issued tool tokens) by registering them with the scanner returned by ``DEPLOYMENT.make_scanner()``.
This module redacts each registered value AND its common encodings (base64, lowercase hex, uppercase
hex) so a secret cannot slip through re-encoded. It is intentionally exact-value matching, separate
from the pattern-based central :class:`agent_deployment.scanner.Scanner` (prompt-injection / lure /
credential-shape detection); the two compose.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

REDACTED = "[REDACTED]"


@dataclass(frozen=True)
class SecretScanResult:
    redacted: str
    redaction_count: int = 0
    findings: tuple = field(default_factory=tuple)


class RegisteredSecretScanner:
    """Exact-value redactor. ``register(*values)`` records each value plus its base64/hex encodings;
    ``scan(text)`` replaces every registered form with ``[REDACTED]`` (longest match first, so an
    encoding that contains a shorter registered value is redacted as a whole)."""

    def __init__(self):
        self._values: set = set()

    def register(self, *values) -> None:
        for value in values:
            if value is None:
                continue
            text = str(value)
            if not text:
                continue
            self._values.add(text)
            raw = text.encode("utf-8")
            self._values.add(base64.b64encode(raw).decode("ascii"))
            hx = raw.hex()
            self._values.add(hx)
            self._values.add(hx.upper())

    def scan(self, text) -> SecretScanResult:
        redacted = str(text)
        count = 0
        findings: list = []
        # Longest-first so a longer registered form is redacted before a shorter substring of it.
        for value in sorted(self._values, key=len, reverse=True):
            if value and value in redacted:
                occurrences = redacted.count(value)
                redacted = redacted.replace(value, REDACTED)
                count += occurrences
                findings.append("registered_secret")
        return SecretScanResult(redacted=redacted, redaction_count=count, findings=tuple(findings))
