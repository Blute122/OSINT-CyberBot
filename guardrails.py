"""
Input guardrails for the API.

A defensive sanitation layer that inspects user-supplied query text and rejects
inputs that look malicious before they reach the engine. The current API is
read-only and does not pass input to the LLM or a SQL engine, so these are
defense-in-depth — but they also future-proof the path (if search ever feeds
the agent/orchestrator) and mirror how a commercial intel feed screens input.

Pure functions, no dependencies — easy to unit test.
"""
import re

MAX_QUERY_LEN = 200

# (pattern, label) — case-insensitive. Covers prompt-injection, code/script
# injection, SQL-ish payloads, and path traversal.
_PATTERNS = [
    (re.compile(r"ignore\s+(all\s+)?(the\s+)?previous", re.I), "prompt-injection"),
    (re.compile(r"disregard\s+(the\s+)?above", re.I),          "prompt-injection"),
    (re.compile(r"you\s+are\s+now\b", re.I),                   "prompt-injection"),
    (re.compile(r"system\s+prompt", re.I),                     "prompt-injection"),
    (re.compile(r"\bjailbreak\b", re.I),                       "prompt-injection"),
    (re.compile(r"```"),                                       "code-block"),
    (re.compile(r"</?script", re.I),                           "script-tag"),
    (re.compile(r"javascript:", re.I),                         "script-uri"),
    (re.compile(r"\b(eval|exec|system|popen)\s*\(", re.I),     "code-exec"),
    (re.compile(r"\bunion\s+select\b", re.I),                  "sql"),
    (re.compile(r"\bdrop\s+table\b", re.I),                    "sql"),
    (re.compile(r"\bor\s+1\s*=\s*1\b", re.I),                  "sql"),
    (re.compile(r"(;--|';|--\s)"),                             "sql-comment"),
    (re.compile(r"\.\.[\\/]"),                                 "path-traversal"),
]

# Disallowed control characters (everything non-printable except normal space).
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def check_query(q: str) -> list:
    """Return a list of guardrail violation labels for `q` ([] means clean)."""
    if not q:
        return ["empty"]
    reasons = []
    if len(q) > MAX_QUERY_LEN:
        reasons.append("too-long")
    if _CONTROL_RE.search(q):
        reasons.append("control-chars")
    for pattern, label in _PATTERNS:
        if pattern.search(q) and label not in reasons:
            reasons.append(label)
    return reasons


def is_safe(q: str) -> bool:
    return not check_query(q)
