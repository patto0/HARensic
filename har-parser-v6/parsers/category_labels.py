"""
category_labels.py — Canonical section identifiers, display labels,
and backward-compatibility normalization for the HAR Parser forensic
evidence report categories.

Category naming convention (v2):
  A. Identity          (was: 2A)
  B. Prompt            (was: 2B)
  C. Security          (was: 2C)
  D. Autonomous        (was: 2D)
  E. URLs / Domains    (was: 2F)

Internal dict keys (unchanged for stability):
  "A_identity", "B_prompt", "C_security", "D_autonomous",
  "E_ai_urls",  "E_urls"
"""

from __future__ import annotations
import re
from typing import Dict, Any

# ── Canonical internal key → display label ────────────────────────────────────

SECTION_LABELS: Dict[str, str] = {
    "A_identity":   "A. Identity",
    "B_prompt":     "B. Prompt",
    "C_security":   "C. Security",
    "D_autonomous": "D. Autonomous",
    "E_ai_urls":    "E. URLs / Domains Visited",
    "E_urls":       "[DEBUG] Platform Infrastructure URL Attribution",
}

# Long-form descriptions used in reports / export headers
SECTION_DESCRIPTIONS: Dict[str, str] = {
    "A_identity":   "A. Identity — Identity & Session Artifacts",
    "B_prompt":     "B. Prompt — Prompt & Response Artifacts",
    "C_security":   "C. Security — Security & Authentication",
    "D_autonomous": "D. Autonomous — Autonomous & Background Actions",
    "E_ai_urls":    "E. URLs / Domains Visited — AI Browsing Evidence — Tool Retrieval",
    "E_urls":       "[DEBUG] Platform Infrastructure URL Attribution",
}

# Ordered list of canonical section keys (defines output ordering)
SECTION_ORDER = [
    "A_identity",
    "B_prompt",
    "C_security",
    "D_autonomous",
    "E_ai_urls",
    "E_urls",
]

# ── Legacy key → canonical key mapping ───────────────────────────────────────
# Maps old "2x_*" internal dict keys to the new "x_*" keys.

LEGACY_KEY_MAP: Dict[str, str] = {
    # Old internal keys (2A-style)
    "2A_identity":   "A_identity",
    "2B_prompt":     "B_prompt",
    "2C_security":   "C_security",
    "2D_autonomous": "D_autonomous",
    "2F_ai_urls":    "E_ai_urls",
    "2E_urls":       "E_urls",
    # Short prefix aliases
    "2A": "A_identity",
    "2B": "B_prompt",
    "2C": "C_security",
    "2D": "D_autonomous",
    "2F": "E_ai_urls",
    "2E": "E_urls",
}

# ── Prefix-level normalization (for "section" string fields) ──────────────────
# Maps the short legacy prefix (e.g. "2A") to the new prefix (e.g. "A").

LEGACY_PREFIX_MAP: Dict[str, str] = {
    "2A": "A",
    "2B": "B",
    "2C": "C",
    "2D": "D",
    "2F": "E",
    "2E": "E",
}

# Compiled regex that matches any legacy prefix (at word boundaries)
_LEGACY_PREFIX_RE = re.compile(
    r"(?<![A-Za-z0-9])(2[ABCDEF])(?=[._\s\-/]|$)",
    re.IGNORECASE,
)


# ── Public helpers ────────────────────────────────────────────────────────────

def normalize_key(key: str) -> str:
    """
    Return the canonical internal key for *key*, mapping any legacy
    "2x_*" key transparently.

    Examples
    --------
    >>> normalize_key("2A_identity")
    'A_identity'
    >>> normalize_key("A_identity")
    'A_identity'
    >>> normalize_key("2F_ai_urls")
    'E_ai_urls'
    """
    return LEGACY_KEY_MAP.get(key, key)


def normalize_results(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Accept a results dict that may use legacy keys ("2A_identity", …)
    and return an equivalent dict using canonical keys ("A_identity", …).

    Duplicate canonical keys are merged (lists concatenated); the
    canonical key wins if both old and new are present.
    """
    out: Dict[str, Any] = {}
    for k, v in results.items():
        canonical = normalize_key(k)
        if canonical in out:
            # merge — both should be lists
            if isinstance(out[canonical], list) and isinstance(v, list):
                out[canonical] = out[canonical] + v
        else:
            out[canonical] = v
    return out


def normalize_prefix(text: str) -> str:
    """
    Replace legacy section prefixes (e.g. "2A", "2F") wherever they appear
    in *text* as a word-boundary token, mapping to the new lettered scheme.

    Examples
    --------
    >>> normalize_prefix("2A — Identity")
    'A. — Identity'
    >>> normalize_prefix("Section 2F")
    'Section E.'
    >>> normalize_prefix("2C_security")
    'C._security'
    >>> normalize_prefix("AI BROWSING EVIDENCE REPORT — Section 2F")
    'AI BROWSING EVIDENCE REPORT — Section E.'
    """
    def _replace(m: re.Match) -> str:
        old_token = m.group(1).upper()
        new_letter = LEGACY_PREFIX_MAP.get(old_token, old_token)
        return new_letter + "."
    return _LEGACY_PREFIX_RE.sub(_replace, text)


def section_label(key: str) -> str:
    """
    Return the display label for a section key (canonical or legacy).

    Falls back gracefully to the key itself if unknown.
    """
    return SECTION_LABELS.get(normalize_key(key), key)


def section_description(key: str) -> str:
    """
    Return the long-form description for a section key (canonical or legacy).
    """
    return SECTION_DESCRIPTIONS.get(normalize_key(key), key)


def ordered_results(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return *results* (with canonical keys) in the canonical section order,
    with any extra keys appended at the end.
    """
    norm = normalize_results(results)
    ordered: Dict[str, Any] = {}
    for k in SECTION_ORDER:
        if k in norm:
            ordered[k] = norm[k]
    for k, v in norm.items():
        if k not in ordered:
            ordered[k] = v
    return ordered
