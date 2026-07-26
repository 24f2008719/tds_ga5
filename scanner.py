"""
Q4 — Skill Safety Audit — Scanner API

Detects up to 4 vulnerability categories in an agent "skill" markdown file
(YAML frontmatter + instructions). Grading is F-beta (beta=0.5) — precision
weighted more than recall — so every rule here is written to avoid false
positives on clean files, even at some cost to recall on subtle cases.
"""

import re
from typing import List


# ------------------------------------------------------------------------
# hardcoded_secret
# ------------------------------------------------------------------------
# Known-shape credentials (near-zero false-positive risk: these formats are
# essentially never anything else).
_SECRET_PATTERNS = [
    r"hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}",
    r"discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]{20,}",
    r"AKIA[0-9A-Z]{16}",                        # AWS access key id
    r"sk-live-[A-Za-z0-9]{10,}",                 # Stripe-style live secret
    r"sk-[A-Za-z0-9]{32,}",                      # OpenAI-style secret key
    r"ghp_[A-Za-z0-9]{30,}",                     # GitHub personal token
    r"AIza[0-9A-Za-z\-_]{35}",                   # Google API key
    r"xox[baprs]-[A-Za-z0-9-]{10,}",             # Slack bot/user token
]

# Generic "field: literal-looking-secret" assignment, used only as a
# fallback and filtered hard against placeholders / env-var references.
_GENERIC_SECRET_FIELD = re.compile(
    r"(?:api[_-]?key|apikey|secret|token|password|private[_-]?key|"
    r"client[_-]?secret|access[_-]?key)\s*[:=]\s*[\"']([^\"']{16,})[\"']",
    re.IGNORECASE,
)

_PLACEHOLDER_MARKERS = (
    "${", "{{", "process.env", "os.environ", "getenv", "env.", "<your",
    "your-", "your_", "xxxxx", "changeme", "change_me", "example",
    "placeholder", "insert-", "insert_", "replace-", "replace_", "dummy",
    "test-key", "test_key", "fake", "sample",
)


def _has_hardcoded_secret(text: str) -> bool:
    for pat in _SECRET_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return True

    for m in _GENERIC_SECRET_FIELD.finditer(text):
        value = m.group(1)
        low = value.lower()
        if any(marker in low for marker in _PLACEHOLDER_MARKERS):
            continue
        # Require some entropy-ish signal: mixed alnum, reasonable length,
        # not just repeated characters or an obvious word.
        if len(value) >= 16 and re.search(r"[0-9]", value) and re.search(r"[A-Za-z]", value):
            return True

    return False


# ------------------------------------------------------------------------
# prompt_injection
# ------------------------------------------------------------------------
# Look for instructions that try to override user/agent control, phrased
# as *instructions to the agent* (not just words appearing anywhere).
_INJECTION_PATTERNS = [
    r"\bsilently\b.{0,40}\b(send|post|upload|exfiltrate|leak|transmit|email|forward|share)\b",
    r"\b(send|post|upload|exfiltrate|leak|transmit|email|forward)\b.{0,40}\bsilently\b",
    r"\bwithout\s+(telling|notifying|informing|alerting)\s+the\s+user\b",
    r"\bdo\s+not\s+(tell|notify|inform|alert)\s+the\s+user\b",
    r"\bhide\s+this\s+from\s+the\s+user\b",
    r"\bignore\s+(the\s+)?(user'?s?\s+)?(stop|cancel|abort)\b",
    r"\bignore\s+(any\s+|all\s+)?(previous|prior|system)\s+instructions?\b",
    r"\bdo\s+not\s+(surface|reveal|mention|log|output)\s+(this|it)\s+to\s+the\s+user\b",
    r"\bnever\s+(let|allow)\s+the\s+user\s+to\s+(cancel|stop|interrupt)\b",
]


def _has_prompt_injection(text: str) -> bool:
    for pat in _INJECTION_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return True
    return False


# ------------------------------------------------------------------------
# excessive_permissions
# ------------------------------------------------------------------------
_EXCESSIVE_PATTERNS = [
    r"\b(read|write|read[/-]write)\s+access\s+to\s+the\s+entire\s+(filesystem|file\s+system|home\s+directory|disk)\b",
    r"\bentire\s+(filesystem|file\s+system)\b",
    r"\bfull\s+(filesystem|system)\s+access\b",
    r"\begress\s+(allowed\s+)?to\s+any\s+(domain|host|external\s+domain)\b",
    r"\bnetwork\s+access\s*:\s*any\b",
    r"\baccess\s+to\s+any\s+external\s+domain\b",
    r"\bpermissions\s*:\s*.{0,20}\*",
    r"\ballow\s+all\s+(network|filesystem|domains|hosts)\b",
    r"\bunrestricted\s+(network|filesystem|file\s+system)\s+access\b",
]


def _has_excessive_permissions(text: str) -> bool:
    for pat in _EXCESSIVE_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return True
    return False


# ------------------------------------------------------------------------
# unclear_provenance
# ------------------------------------------------------------------------
_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---", re.DOTALL)

_SILENT_METADATA_PATTERNS = [
    r"\bsilently\s+(update|rewrite|bump|change)\s+.{0,20}(version|metadata|changelog)\b",
    r"\b(update|rewrite|bump|change)\s+.{0,20}(version|metadata|changelog)\s+.{0,20}\bwithout\s+(telling|notifying|informing|surfacing)\b",
]


def _has_unclear_provenance(text: str) -> bool:
    fm_match = _FRONTMATTER_RE.match(text.strip())
    if fm_match:
        fm = fm_match.group(1).lower()
        has_author = re.search(r"^\s*author\s*:", fm, re.MULTILINE) is not None
        has_version = re.search(r"^\s*version\s*:", fm, re.MULTILINE) is not None
        if not has_author and not has_version:
            return True
    else:
        # No frontmatter block at all is itself a provenance gap.
        return True

    for pat in _SILENT_METADATA_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return True

    return False


def scan_skill(skill_text: str) -> List[str]:
    categories = []
    if _has_hardcoded_secret(skill_text):
        categories.append("hardcoded_secret")
    if _has_prompt_injection(skill_text):
        categories.append("prompt_injection")
    if _has_excessive_permissions(skill_text):
        categories.append("excessive_permissions")
    if _has_unclear_provenance(skill_text):
        categories.append("unclear_provenance")
    return categories
