"""
ai_url_filter.py — Attribution-driven AI URL filter
====================================================

Single authoritative module that decides which URLs belong in the
"E. URLs / Domains Visited" section.

Rule: a URL is included ONLY when attribution.ai == True.
Secondary rule: the url_role must not be in the infrastructure exclusion set.

This module also provides the converter that normalises network-attributed
AI URL rows (produced by url_attribution.py with url_* fields) into the
unified ai_url_* schema used by the E section.
"""

from __future__ import annotations
from typing import Dict, List, Set

# ─────────────────────────────────────────────────────────────────────────────
#  ROLE CLASSIFICATION
# ─────────────────────────────────────────────────────────────────────────────

# URL roles that represent genuine AI-generated/AI-accessed content
AI_URL_ROLES_INCLUDE: Set[str] = {
    "search_result",
    "cited_source",
    "retrieved_content",
    "supporting_source",
    "citation_patch_url",
    "browsing_result",
    "tool_call_url",
    "user_navigation",           # only when attribution == AI
    "retrieval_chain_summary",   # AI chain summary row
}

# Infrastructure roles: ALWAYS excluded regardless of attribution
AI_URL_ROLES_EXCLUDE: Set[str] = {
    "telemetry",
    "analytics",
    "auth_endpoint",
    "cdn_asset",
    "platform_api",
    "conversation_api",
    "sentinel_endpoint",
    "favicon_cdn",
    "platform_background",
    "keepalive",
    "polling",
    "streaming_transport",
    "moderation_transport",
    "infrastructure",
}


# ─────────────────────────────────────────────────────────────────────────────
#  ATTRIBUTION FILTER
# ─────────────────────────────────────────────────────────────────────────────

def is_ai_url_row(row: Dict) -> bool:
    """
    Return True if *row* qualifies for the E. URLs / Domains Visited section.

    Criteria (both must pass):
      1. attribution == "AI"           (primary: attribution engine decision)
      2. url_role not in EXCLUDE set   (secondary: role sanity filter)
    """
    attribution = str(row.get("attribution", "")).upper()
    if attribution != "AI":
        return False

    # Check ai_url_role first (SSE records), then url_role (network records)
    role = row.get("ai_url_role") or row.get("url_role") or ""
    if role in AI_URL_ROLES_EXCLUDE:
        return False

    return True


def filter_ai_urls(rows: List[Dict]) -> List[Dict]:
    """
    Filter a list of URL rows to only those qualifying as AI-attributed.
    Always keep retrieval_chain_summary rows (summary metadata).
    """
    return [r for r in rows if is_ai_url_row(r)]


# ─────────────────────────────────────────────────────────────────────────────
#  SCHEMA NORMALISER
#  Convert network-attributed AI URL rows (url_* fields) into the unified
#  ai_url_* schema used by the E section.
# ─────────────────────────────────────────────────────────────────────────────

def network_row_to_unified(row: Dict) -> Dict:
    """
    Convert a url_attribution.py row that passed the AI filter into the
    unified ai_url_* schema.

    Network AI rows have url_* fields; this maps them to ai_url_* fields
    so the E section has a single consistent schema.
    """
    url = row.get("value", row.get("url_raw", ""))
    role = row.get("url_role", "ai_navigation")
    # Map network role names to canonical ai_url roles where different
    role_map = {
        "user_navigation":      "ai_navigation",
        "search_result":        "search_result",
        "retrieval_chain_summary": "retrieval_chain_summary",
    }
    mapped_role = role_map.get(role, role)

    return {
        "artifact":     f"ai_url_{mapped_role}",
        "har_location": row.get("har_location", ""),
        "json_path":    row.get("json_path", ""),
        "value":        url,
        "attribution":  "AI",
        "reason":       row.get("reason", ""),
        "ai_url":               url,
        "ai_url_domain":        row.get("url_domain", ""),
        "ai_url_title":         "",
        "ai_url_snippet":       row.get("url_snippet", ""),
        "ai_url_pub_date":      row.get("url_pub_date", ""),
        "ai_url_confidence":    row.get("url_confidence", 0),
        "ai_url_role":          mapped_role,
        "ai_url_sse_source":    row.get("url_source_type", "network_request"),
        "ai_url_after_search_start": row.get("url_trigger") == "search_start",
        "ai_url_in_url_moderation": False,
        "ai_url_search_query":  "",
        "ai_url_tool_name":     "",
    }


# ─────────────────────────────────────────────────────────────────────────────
#  DEDUPLICATOR
# ─────────────────────────────────────────────────────────────────────────────

def deduplicate_e_rows(rows: List[Dict]) -> List[Dict]:
    """
    Deduplicate rows by normalised URL value.
    SSE-sourced records win over network-sourced records (richer provenance).
    retrieval_chain_summary rows are always kept (they have no URL to dedup on).
    """
    seen: Dict[str, Dict] = {}
    summaries: List[Dict] = []

    for row in rows:
        role = row.get("ai_url_role", "")
        if role == "retrieval_chain_summary":
            summaries.append(row)
            continue

        url = row.get("ai_url") or row.get("value", "")
        if not url:
            continue

        if url not in seen:
            seen[url] = row
        else:
            existing = seen[url]
            # Prefer SSE-sourced records (higher confidence, richer fields)
            new_conf = row.get("ai_url_confidence", 0)
            old_conf = existing.get("ai_url_confidence", 0)
            new_has_title = bool(row.get("ai_url_title"))
            old_has_title = bool(existing.get("ai_url_title"))
            if new_conf > old_conf or (new_has_title and not old_has_title):
                seen[url] = row

    # Sort: cited/retrieved first, then search results, then other
    priority = {
        "cited_source": 0,
        "retrieved_content": 1,
        "supporting_source": 2,
        "search_result": 3,
        "browsing_result": 4,
        "tool_call_url": 5,
        "citation_patch_url": 6,
        "ai_navigation": 7,
        "user_navigation": 8,
    }
    deduped = sorted(
        seen.values(),
        key=lambda r: (
            priority.get(r.get("ai_url_role", ""), 99),
            -(r.get("ai_url_confidence", 0)),
        ),
    )
    return deduped + summaries
