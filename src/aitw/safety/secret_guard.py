"""
CI secret + leak guard. Fails the build if disallowed patterns appear in tracked files.

secret-guard:allow-pattern-literals
  ^ This marker tells the guard NOT to scan THIS file for pattern literals. Files that
    legitimately contain the patterns themselves (this ruleset, its .example, the design
    spec that documents it) carry this marker so the guard does not flag its own rules.

Two non-standard behaviours, both intentional:
  1. The LLM provider key is the ONE allowed real secret (loaded from env at runtime,
     never committed). The guard WHITELISTS env-ACCESS forms (os.environ / getenv / ${...})
     so `os.environ["ANTHROPIC_API_KEY"]` passes, while a hardcoded key VALUE fails.
  2. Beyond normal secret patterns, the guard also fails on PATENT / APPLICATION-NUMBER
     leak patterns. This repo is operated under a strict separation from the maintainer's
     IP-bearing repositories; stray patent annotations have leaked into adjacent codebases
     before, so the guard catches them structurally rather than relying on memory.

Specific proprietary tells (codenames, schema names) are NOT in this committed file —
this repo goes public, and hardcoding a tell here would publish it. They live in a
gitignored `secret_guard_local.yaml` (see `secret_guard_local.example.yaml`), loaded if
present. When that file is ABSENT (CI / fresh clone), the guard still runs all generic
patterns and prints a LOUD stderr notice — it never silently passes for lack of the file:

    secret_guard_local.yaml not found — IP-codename checks skipped, generic patterns only

If a check fires, do NOT just delete the pattern from this guard. Remove the offending
content from the source file. The guard is the backstop, not the problem.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

try:  # pyyaml is a project dependency; degrade loudly rather than crash if missing.
    import yaml
except Exception:  # pragma: no cover - exercised only without pyyaml installed
    yaml = None

REPO_ROOT = Path(__file__).resolve().parents[3]
LOCAL_PATTERN_FILE = REPO_ROOT / "secret_guard_local.yaml"

# Files containing this marker are skipped by the pattern scan (see module docstring).
ALLOW_MARKER = "secret-guard:allow-pattern-literals"

# ── Conventional secret material (mock-service / third-party key shapes) ──
# These match secret VALUES, never env-var names, so legitimate env references pass.
VALUE_PATTERNS = [
    ("aws-access-key-id", r"AKIA[0-9A-Z]{16}"),
    ("anthropic-key-literal", r"sk-ant-[A-Za-z0-9_-]{20,}"),
    ("generic-provider-secret-key", r"sk-[a-zA-Z0-9]{20,}"),
    ("google-api-key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("private-key-block", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    ("slack-token", r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
]

# ── IP-separation leak class — GENERIC shapes only (see module docstring) ──
# Specific codenames/schema-name tells are loaded from secret_guard_local.yaml (gitignored).
IP_LEAK_PATTERNS = [
    ("patent-label", r"(?i)\bPatent\s*(?:Family|Claim|No\.?|:)"),
    ("provisional-app-number", r"\b6[0-9]/[0-9]{3},?[0-9]{3}\b"),
    ("uspto-reference", r"(?i)\bUSPTO\b"),
]

# Hardcoded "<credential-ish name> = '<literal>'" assignments. Exempt when the line is
# an env ACCESS (os.environ / getenv / ${...}) — that's a reference, not a hardcoded value.
HARDCODED_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(api[_-]?key|secret|token|password|passwd|credential)\b   # credential-ish lvalue
    \s*[:=]\s*                                                  # = or :
    ["'][^"'\s]{8,}["']                                         # quoted literal, 8+ chars
    """
)

# Bare var NAME does NOT exempt; only genuine env-ACCESS forms do.
ENV_ACCESS_TOKENS = ("os.environ", "os.getenv", "getenv(", "environ[", "environ.get", "${")


def _compile(pairs):
    return [(label, re.compile(rx)) for label, rx in pairs]


def compiled_default():
    """Generic value + IP-leak patterns, compiled. Local extras are added in scan_repo()."""
    return _compile(VALUE_PATTERNS) + _compile(IP_LEAK_PATTERNS)


def scan_text(text, extra_compiled=()):
    """Return a list of (line_no, label, snippet) violations for one file's text."""
    patterns = compiled_default() + list(extra_compiled)
    violations = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for label, rx in patterns:
            if rx.search(line):
                violations.append((lineno, label, line.strip()[:120]))
        if HARDCODED_ASSIGNMENT.search(line) and not any(tok in line for tok in ENV_ACCESS_TOKENS):
            violations.append((lineno, "hardcoded-credential-assignment", line.strip()[:120]))
    return violations


def load_local_patterns():
    """Load extra IP-tell regexes from the gitignored local file. LOUD if absent."""
    if not LOCAL_PATTERN_FILE.exists():
        print(
            f"{LOCAL_PATTERN_FILE.name} not found — IP-codename checks skipped, "
            "generic patterns only",
            file=sys.stderr,
        )
        return []
    if yaml is None:  # pragma: no cover
        print("pyyaml not installed — cannot load secret_guard_local.yaml", file=sys.stderr)
        return []
    data = yaml.safe_load(LOCAL_PATTERN_FILE.read_text(encoding="utf-8")) or {}
    return list(data.get("extra_disallowed_patterns", []))


def _tracked_files():
    """Tracked + untracked-but-not-gitignored files (i.e. what would go public)."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-co", "--exclude-standard"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        return [REPO_ROOT / line for line in out.splitlines() if line.strip()]
    except Exception:  # pragma: no cover - fallback when not a git repo
        return [p for p in REPO_ROOT.rglob("*") if p.is_file() and ".git" not in p.parts]


def _read(path):
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def scan_repo():
    """Scan the repo. Returns {relpath: [violations]} (empty dict == clean)."""
    extra = load_local_patterns()
    extra_compiled = [(f"local-pattern[{i}]", re.compile(p)) for i, p in enumerate(extra)]
    findings = {}
    scanned = 0
    for path in _tracked_files():
        text = _read(path)
        if text is None or ALLOW_MARKER in text:
            continue
        scanned += 1
        violations = scan_text(text, extra_compiled)
        if violations:
            findings[str(path.relative_to(REPO_ROOT))] = violations
    return findings, scanned


def main(argv=None):
    findings, scanned = scan_repo()
    if findings:
        print("\n❌ secret guard FAILED — disallowed patterns in tracked files:\n", file=sys.stderr)
        for relpath, violations in sorted(findings.items()):
            for lineno, label, snippet in violations:
                print(f"  {relpath}:{lineno}  [{label}]  {snippet}", file=sys.stderr)
        print(
            "\nRemove the offending content from the SOURCE file — do not delete the guard "
            "pattern.\n",
            file=sys.stderr,
        )
        return 1
    print(f"✅ secret guard: clean ({scanned} files scanned)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
