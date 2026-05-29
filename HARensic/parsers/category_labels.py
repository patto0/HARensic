"""
category_labels.py — Canonical section identifiers, display labels,
and backward-compatibility normalization for the HAR Parser forensic
evidence report categories.

Category naming convention (v2):
  A. Identity          (was: 2A)
  B. Prompt            (was: 2B)
  C. Security          (was: 2C)
  D. Autonomous        (was: 2D)
  E. URLs / Domains Visited (was: 2F / E_ai_urls)

Internal dict keys (stable):
  "A_identity", "B_prompt", "C_security", "D_autonomous", "E_urls"

  NOTE: "E_ai_urls" is a legacy alias — it maps to "E_urls" transparently.
        The unified E section contains ONLY AI-attributed URLs.
"""

from __future__ import annotations
import re
from typing import Dict, Any

# ── Canonical internal key → display label ─────────────────────────────────

SECTION_LABELS: Dict[str, str] = {
    "A_identity":   "A. Identity",
    "B_prompt":     "B. Prompt",
    "C_security":   "C. Security",
    "D_autonomous": "D. Autonomous",
    "E_urls":       "E. URLs / Domains Visited",
}

# Long-form descriptions used in reports / export headers
SECTION_DESCRIPTIONS: Dict[str, str] = {
    "A_identity":   "A. Identity — Identity & Session Artifacts",
    "B_prompt":     "B. Prompt — Prompt & Response Artifacts",
    "C_security":   "C. Security — Security & Authentication",
    "D_autonomous": "D. Autonomous — Autonomous & Background Actions",
    "E_urls":       "E. URLs / Domains Visited — AI Browsing Evidence — Tool Retrieval",
}

# Canonical section order (defines output ordering in all exports)
SECTION_ORDER = [
    "A_identity",
    "B_prompt",
    "C_security",
    "D_autonomous",
    "E_urls",
]

# ── Legacy key → canonical key mapping ──────────────────────────────────────
# Maps old "2x_*" internal dict keys AND the former "E_ai_urls" split key.

LEGACY_KEY_MAP: Dict[str, str] = {
    # Old 2x-style keys
    "2A_identity":   "A_identity",
    "2B_prompt":     "B_prompt",
    "2C_security":   "C_security",
    "2D_autonomous": "D_autonomous",
    "2F_ai_urls":    "E_urls",
    "2E_urls":       "E_urls",
    # Short prefix aliases
    "2A": "A_identity",
    "2B": "B_prompt",
    "2C": "C_security",
    "2D": "D_autonomous",
    "2F": "E_urls",
    "2E": "E_urls",
    # Former split-section alias — E_ai_urls merges into E_urls
    "E_ai_urls": "E_urls",
}

# Prefix-level normalization map
LEGACY_PREFIX_MAP: Dict[str, str] = {
    "2A": "A",
    "2B": "B",
    "2C": "C",
    "2D": "D",
    "2F": "E",
    "2E": "E",
}

_LEGACY_PREFIX_RE = re.compile(
    r"(?<![A-Za-z0-9])(2[ABCDEF])(?=[._\s\-/]|$)",
    re.IGNORECASE,
)


# ── Public helpers ────────────────────────────────────────────────────────────

def normalize_key(key: str) -> str:
    """
    Return the canonical internal key for *key*, mapping any legacy key.

    >>> normalize_key("E_ai_urls")
    'E_urls'
    >>> normalize_key("2F_ai_urls")
    'E_urls'
    >>> normalize_key("E_urls")
    'E_urls'
    """
    return LEGACY_KEY_MAP.get(key, key)


def normalize_results(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Accept a results dict that may use legacy keys and return an equivalent
    dict using canonical keys. Duplicate canonical keys are merged (lists
    concatenated); the canonical key wins if both are present.

    E_ai_urls rows are merged into E_urls (already AI-filtered at source).
    """
    out: Dict[str, Any] = {}
    for k, v in results.items():
        canonical = normalize_key(k)
        if canonical in out:
            if isinstance(out[canonical], list) and isinstance(v, list):
                out[canonical] = out[canonical] + v
        else:
            out[canonical] = v
    return out


def normalize_prefix(text: str) -> str:
    """Replace legacy section prefixes in *text*."""
    def _replace(m: re.Match) -> str:
        old_token = m.group(1).upper()
        new_letter = LEGACY_PREFIX_MAP.get(old_token, old_token)
        return new_letter + "."
    return _LEGACY_PREFIX_RE.sub(_replace, text)


def section_label(key: str) -> str:
    """Return the display label for a section key (canonical or legacy)."""
    return SECTION_LABELS.get(normalize_key(key), key)


def section_description(key: str) -> str:
    """Return the long-form description for a section key."""
    return SECTION_DESCRIPTIONS.get(normalize_key(key), key)


def ordered_results(results: Dict[str, Any]) -> Dict[str, Any]:
    """Return *results* (with canonical keys) in canonical section order."""
    norm = normalize_results(results)
    ordered: Dict[str, Any] = {}
    for k in SECTION_ORDER:
        if k in norm:
            ordered[k] = norm[k]
    for k, v in norm.items():
        if k not in ordered:
            ordered[k] = v
    return ordered
