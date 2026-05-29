"""
Analysis router — maps detected platform to the correct parser.
Supports sections A–E. E (URLs / Domains Visited) injected for all platforms.

Category naming (v2):
  A. Identity  |  B. Prompt  |  C. Security  |  D. Autonomous
  E. URLs / Domains Visited  (AI-attributed URLs ONLY)

Section E filtering
-------------------
The E. URLs / Domains Visited section contains ONLY URLs where:
  attribution.ai == True

Platform infrastructure, telemetry, CDN, auth, and human-originated
URLs are EXCLUDED. Filtering is attribution-driven (not regex-only).
See parsers/ai_url_filter.py for the authoritative filter rules.

Backward compatibility: legacy "2x_*" and "E_ai_urls" keys are
normalized transparently via parsers.category_labels.normalize_results().
"""

from __future__ import annotations
from typing import Dict, List
from .chatgpt import parse_chatgpt
from .gemini  import parse_gemini
from .claude  import parse_claude
from .generic_parser import parse_generic
from .detection_engine import _PLATFORM_CONFIGS
from .loader import get_entries
from .category_labels import normalize_results, SECTION_ORDER
from .ai_url_filter import (
    filter_ai_urls,
    network_row_to_unified,
    deduplicate_e_rows,
)

_EMPTY = {k: [] for k in SECTION_ORDER}
_PLATFORM_NAMES = {cfg["id"]: cfg["name"] for cfg in _PLATFORM_CONFIGS}
_LEGACY_ALIASES = {
    "anthropic_console": "claude",
    "openai_playground": "chatgpt",
    "google_ai_studio":  "gemini",
}


def _inject_E_urls_visited(results: Dict, har: Dict, platform: str = "") -> Dict:
    """
    Inject Section E. URLs / Domains Visited.

    This is the SINGLE E-section injection function. It:
      1. Extracts AI URLs from the SSE stream (richest provenance — primary).
      2. Extracts ALL network URLs, filters to attribution=="AI" only.
      3. Converts any network AI URLs to the unified ai_url_* schema.
      4. Merges both sources and deduplicates by normalised URL.
      5. Writes the result to results["E_urls"] (the canonical key).

    Any existing "E_ai_urls" or "E_urls" in results is merged and replaced
    so the final output is a single clean AI-only section.

    EXCLUDES:
      - PLATFORM URLs (CDN, telemetry, auth, sentinel, conversation API, etc.)
      - HUMAN URLs (user navigation unrelated to AI tool use)
      - Any URL role in AI_URL_ROLES_EXCLUDE

    INCLUDES:
      - SSE search_result_groups (AI raw search results)
      - SSE content_references (retrieved / cited pages)
      - SSE sources_footnote (final AI citations)
      - SSE url_moderation events (AI-safety-checked URLs)
      - Network URLs with attribution=="AI" and a qualifying role
    """
    sse_rows: List[Dict] = []
    network_ai_rows: List[Dict] = []

    # ── 1. Merge any existing parser-provided E rows ──────────────────────
    # parsers (chatgpt.py, claude.py, etc.) may already have populated
    # E_ai_urls with SSE-extracted rows — collect them first.
    for key in ("E_ai_urls", "E_urls"):
        existing = results.pop(key, []) or []
        if existing:
            # Filter to AI=True just in case any platform rows slipped in
            sse_rows.extend(filter_ai_urls(existing))

    # ── 2. SSE AI URL extraction (platform-specific) ──────────────────────
    if not sse_rows:
        try:
            entries = get_entries(har)
            if platform == "claude":
                from .claude_ai_urls import extract_claude_ai_urls
                report = extract_claude_ai_urls(entries)
                raw_rows = [u.to_row() for u in report.urls]
                if report.chain:
                    raw_rows.append({
                        "artifact":     "claude_ai_url_retrieval_chain",
                        "value":        f"{len(report.chain)} chain steps",
                        "har_location": "SSE + conversation citations",
                        "json_path":    "SSE tool_result + citations[]",
                        "attribution":  "AI",
                        "reason":       "AI: Claude retrieval chain from SSE tool_result blocks.",
                        "ai_url": "", "ai_url_raw": "", "ai_url_domain": "",
                        "ai_url_title": "", "ai_url_snippet": "",
                        "ai_url_pub_date": "", "ai_url_confidence": 99,
                        "ai_url_role": "retrieval_chain_summary",
                        "ai_url_sse_source": "SSE content_block tool_result",
                        "ai_url_sse_seq": -1,
                        "ai_url_after_search_start": True,
                        "ai_url_in_url_moderation": False,
                        "ai_url_search_query": report.user_prompt[:100],
                        "ai_url_tool_name": "web_search + web_fetch",
                    })
                sse_rows = filter_ai_urls(raw_rows)

            elif platform == "gemini":
                from .gemini_ai_urls import extract_gemini_ai_urls
                report = extract_gemini_ai_urls(entries)
                sse_rows = filter_ai_urls([u.to_row() for u in report.urls])

            else:
                # ChatGPT-style (default)
                import json as _j
                from .ai_urls import extract_ai_urls
                report = extract_ai_urls(entries)
                raw_rows = [u.to_row() for u in report.urls]
                if report.chain:
                    raw_rows.append({
                        "artifact":     "ai_url_retrieval_chain",
                        "value":        _j.dumps([
                            {"layer": c["layer"], "url": c["value"][:80]}
                            for c in report.chain
                        ])[:600],
                        "har_location": "SSE stream — retrieval chain",
                        "json_path":    "SSE search_model_queries → content_references",
                        "attribution":  "AI",
                        "reason": (
                            f"AI: {len(report.urls)} AI URLs extracted. "
                            f"Query: \"{report.search_queries[0] if report.search_queries else ''}\". "
                            f"Tool: {report.tool_name}."
                        ),
                        "ai_url": "", "ai_url_raw": "", "ai_url_domain": "",
                        "ai_url_title": "", "ai_url_snippet": "",
                        "ai_url_pub_date": "", "ai_url_confidence": 99,
                        "ai_url_role": "retrieval_chain_summary",
                        "ai_url_sse_source": "derived", "ai_url_sse_seq": -1,
                        "ai_url_after_search_start": True,
                        "ai_url_in_url_moderation": False,
                        "ai_url_search_query": report.search_queries[0] if report.search_queries else "",
                        "ai_url_tool_name": report.tool_name,
                    })
                sse_rows = filter_ai_urls(raw_rows)

        except Exception as exc:
            import logging
            logging.getLogger(__name__).error("E_urls SSE extraction: %s", exc)

    # ── 3. Network URL attribution — filter to AI=True only ───────────────
    try:
        entries = get_entries(har)
        from .url_attribution import run_url_attribution
        artifacts, _timeline, _chain = run_url_attribution(entries)
        for a in artifacts:
            row = a.to_row()
            # Attribution-driven filter: AI=True AND not excluded role
            from .ai_url_filter import is_ai_url_row
            if is_ai_url_row(row):
                # Normalise url_* fields → ai_url_* unified schema
                network_ai_rows.append(network_row_to_unified(row))
    except Exception as exc:
        import logging
        logging.getLogger(__name__).error("E_urls network attribution: %s", exc)

    # ── 4. Merge, deduplicate, sort ────────────────────────────────────────
    all_rows = sse_rows + network_ai_rows
    results["E_urls"] = deduplicate_e_rows(all_rows)
    return results


def run_analysis(har: Dict, platform: str) -> Dict[str, List[Dict]]:
    resolved = _LEGACY_ALIASES.get(platform, platform)
    try:
        if   resolved == "chatgpt": raw = parse_chatgpt(har)["results"]
        elif resolved == "gemini":  raw = parse_gemini(har)["results"]
        elif resolved == "claude":  raw = parse_claude(har)["results"]
        elif resolved == "unknown": raw = parse_generic(har, "Unknown AI Platform")["results"]
        else:
            dn = _PLATFORM_NAMES.get(resolved, resolved.replace("_", " ").title())
            raw = parse_generic(har, dn)["results"]
    except Exception as exc:
        import logging
        logging.getLogger(__name__).error("Parser error '%s': %s", platform, exc)
        return _EMPTY.copy()

    # Normalize any legacy "2x_*" or "E_ai_urls" keys
    results = normalize_results(raw)

    # Inject unified E. URLs / Domains Visited (AI-attributed only)
    results = _inject_E_urls_visited(results, har, platform=resolved)
    return results
