"""
schemas.py — Section-Bound Typed Schemas & Centralized Attribution Engine
=========================================================================

AUTHORITATIVE source for:
  1. Per-section field whitelists (SECTION_SCHEMAS)
  2. Attribution rules (ATTRIBUTION_RULES)
  3. Schema validation (validate_section_record)
  4. Isolated section record builders

Section isolation guarantee
---------------------------
URL-enrichment fields (url_*, ai_url_*) are ONLY valid in E_urls / E_ai_urls.
They MUST NEVER appear in A_identity, B_prompt, C_security, or D_autonomous.

Attribution guarantee
---------------------
model_used:  AI=True  |  HUMAN=False  |  PLATFORM=True
The `attribution` column stores the *primary* attribution label per the PDF rules.
For model_used the primary label is "AI".

Usage
-----
    from parsers.schemas import (
        SECTION_SCHEMAS,
        build_record,
        validate_section_record,
        resolve_attribution,
    )
"""

from __future__ import annotations

import logging
from copy import deepcopy
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
#  ATTRIBUTION RULES  (authoritative — from PDF rules document)
# ─────────────────────────────────────────────────────────────────────────────

ATTRIBUTION_RULES: Dict[str, Dict[str, bool]] = {
    # ── AI-primary artifacts ──────────────────────────────────────────────
    "model_used":                   {"ai": True,  "human": False, "platform": True},
    "model_version":                {"ai": True,  "human": False, "platform": True},
    "ai_generated_response":        {"ai": True,  "human": False, "platform": False},
    "ai_response":                  {"ai": True,  "human": False, "platform": False},
    "ai_auto_title":                {"ai": True,  "human": False, "platform": False},
    "auto_title_generation":        {"ai": True,  "human": False, "platform": True},
    "conversation_title":           {"ai": True,  "human": True,  "platform": False},
    "ai_token_count":               {"ai": True,  "human": False, "platform": True},
    "token_timing_telemetry":       {"ai": True,  "human": False, "platform": True},
    "generation_timing":            {"ai": True,  "human": False, "platform": True},
    "hidden_system_prompt":         {"ai": True,  "human": False, "platform": True},
    "hidden_system_prompt_injections": {"ai": True, "human": False, "platform": True},
    "ai_generation_streams":        {"ai": True,  "human": False, "platform": True},
    "stop_reason":                  {"ai": True,  "human": False, "platform": True},
    "sse_events_total":             {"ai": True,  "human": False, "platform": True},
    # ── Human-primary artifacts ───────────────────────────────────────────
    "user_prompt":                  {"ai": False, "human": True,  "platform": False},
    "user_id":                      {"ai": False, "human": True,  "platform": True},
    "session_id":                   {"ai": False, "human": True,  "platform": True},
    "session_start_time":           {"ai": False, "human": True,  "platform": True},
    "session_end_time":             {"ai": False, "human": True,  "platform": True},
    "conversation_id":              {"ai": False, "human": True,  "platform": True},
    "device_id":                    {"ai": False, "human": True,  "platform": True},
    "oai_language":                 {"ai": False, "human": True,  "platform": True},
    "timezone":                     {"ai": False, "human": True,  "platform": True},
    "timezone_offset_min":          {"ai": False, "human": True,  "platform": True},
    "user_behaviour_analytics":     {"ai": False, "human": True,  "platform": True},
    "analytics_event":              {"ai": False, "human": True,  "platform": True},
    "keystroke_capture_before_send": {"ai": False, "human": True, "platform": True},
    "partial_keystroke":            {"ai": False, "human": True,  "platform": True},
    "opentelemetry_rum_telemetry":  {"ai": False, "human": True,  "platform": True},
    "datadog_rum_telemetry":        {"ai": False, "human": True,  "platform": True},
    "client_event_logging":         {"ai": False, "human": True,  "platform": True},
    "geolocation_enabled":          {"ai": False, "human": True,  "platform": True},
    "message_id":                   {"ai": False, "human": True,  "platform": True},
    "message_uuid":                 {"ai": False, "human": True,  "platform": True},
    "conversation_created_at":      {"ai": False, "human": True,  "platform": True},
    "conversation_updated_at":      {"ai": False, "human": True,  "platform": True},
    "connected_integrations":       {"ai": False, "human": True,  "platform": True},
    "organization_id":              {"ai": False, "human": True,  "platform": False},
    "account_id":                   {"ai": False, "human": True,  "platform": True},
    # ── Platform-only artifacts ───────────────────────────────────────────
    "user_agent":                   {"ai": False, "human": False, "platform": True},
    "anonymous_id":                 {"ai": False, "human": False, "platform": True},
    "browser_fingerprint_blob":     {"ai": False, "human": False, "platform": True},
    "account_privilege_flag":       {"ai": False, "human": False, "platform": True},
    "server_ip_address":            {"ai": False, "human": False, "platform": True},
    "server_ip":                    {"ai": False, "human": False, "platform": True},
    "conduit_jwt_cluster":          {"ai": False, "human": False, "platform": True},
    "conduit_jwt_conduit_location": {"ai": False, "human": False, "platform": True},
    "conduit_jwt_conduit_uuid":     {"ai": False, "human": False, "platform": True},
    "conduit_jwt_exp":              {"ai": False, "human": False, "platform": True},
    "conduit_jwt_iat":              {"ai": False, "human": False, "platform": True},
    "conduit_token_jwt":            {"ai": False, "human": False, "platform": True},
    "connector_state_polling":      {"ai": False, "human": False, "platform": True},
    "distributed_trace_ids":        {"ai": False, "human": False, "platform": True},
    "trace_id_count":               {"ai": False, "human": False, "platform": True},
    "sentinel_chat_requirements_token": {"ai": False, "human": False, "platform": True},
    "sentinel_extra_data":          {"ai": False, "human": False, "platform": True},
    "sentinel_finalize_token":      {"ai": False, "human": False, "platform": True},
    "sentinel_ping_keepalive":      {"ai": False, "human": False, "platform": True},
    "sentinel_prepare_token":       {"ai": False, "human": False, "platform": True},
    "sentinel_proof_token":         {"ai": False, "human": False, "platform": True},
    "stream_status_polling":        {"ai": False, "human": False, "platform": True},
    "session_cookies":              {"ai": False, "human": False, "platform": True},
    "user_prompt_server_confirmed": {"ai": False, "human": False, "platform": True},
    "backend_trace_id":             {"ai": False, "human": False, "platform": True},
    "anthropic_client_version":     {"ai": False, "human": False, "platform": True},
    "anthropic_telemetry":          {"ai": False, "human": False, "platform": True},
    "bootstrap_polling":            {"ai": False, "human": False, "platform": True},
    "conversation_state_polling":   {"ai": False, "human": False, "platform": True},
    "enabled_features":             {"ai": False, "human": False, "platform": True},
    "turn_chain_link":              {"ai": False, "human": False, "platform": True},
}


def resolve_attribution(artifact_name: str) -> Tuple[str, Dict[str, bool]]:
    """
    Resolve the primary attribution label and full tri-attribution dict for an artifact.

    Returns
    -------
    (primary_label, tri_dict)
        primary_label : "AI" | "HUMAN" | "PLATFORM"
        tri_dict      : {"ai": bool, "human": bool, "platform": bool}

    The primary label is the highest-priority TRUE flag: AI > HUMAN > PLATFORM.
    Falls back to "PLATFORM" for unknown artifacts (conservative).
    """
    tri = ATTRIBUTION_RULES.get(artifact_name)
    if tri is None:
        # Unknown artifact — conservative fallback
        return "PLATFORM", {"ai": False, "human": False, "platform": True}

    if tri["ai"]:
        return "AI", tri
    if tri["human"]:
        return "HUMAN", tri
    return "PLATFORM", tri


# ─────────────────────────────────────────────────────────────────────────────
#  BASE FIELDS — present in every section
# ─────────────────────────────────────────────────────────────────────────────

_BASE_FIELDS: List[str] = [
    "artifact",
    "har_location",
    "json_path",
    "value",
    "attribution",
    "reason",
]

# ─────────────────────────────────────────────────────────────────────────────
#  URL-ENRICHMENT FIELDS — ONLY valid in E_urls / E_ai_urls
# ─────────────────────────────────────────────────────────────────────────────

_URL_ONLY_FIELDS: Set[str] = {
    # Legacy URL attribution fields (url_attribution.py — not in any export schema now)
    "url_domain",
    "url_role",
    "url_confidence",
    "url_trigger",
    "url_snippet",
    "url_pub_date",
    "url_timeline",
    "url_source_type",
    "url_raw",
    # AI URL enrichment fields (the unified E_urls schema)
    "ai_url",
    "ai_url_domain",
    "ai_url_title",
    "ai_url_snippet",
    "ai_url_pub_date",
    "ai_url_confidence",
    "ai_url_role",
    "ai_url_sse_source",
    "ai_url_after_search_start",
    "ai_url_in_url_moderation",
    "ai_url_search_query",
    "ai_url_tool_name",
    "ai_url_raw",
    "ai_url_sse_seq",
    "ai_url_chain",
}

# ─────────────────────────────────────────────────────────────────────────────
#  SECTION SCHEMAS  (whitelist approach — only listed fields exported)
# ─────────────────────────────────────────────────────────────────────────────

SECTION_SCHEMAS: Dict[str, List[str]] = {
    "A_identity":   _BASE_FIELDS[:],
    "B_prompt":     _BASE_FIELDS[:],
    "C_security":   _BASE_FIELDS[:],
    "D_autonomous": _BASE_FIELDS[:],
    # E. URLs / Domains Visited — UNIFIED AI-only schema.
    # Contains ONLY URLs where attribution.ai == True.
    # Both SSE-extracted and network-attributed AI URLs use ai_url_* fields.
    # Legacy "E_ai_urls" key maps here transparently (see category_labels.py).
    "E_urls": _BASE_FIELDS + [
        "ai_url",
        "ai_url_domain",
        "ai_url_title",
        "ai_url_snippet",
        "ai_url_pub_date",
        "ai_url_confidence",
        "ai_url_role",
        "ai_url_sse_source",
        "ai_url_after_search_start",
        "ai_url_in_url_moderation",
        "ai_url_search_query",
        "ai_url_tool_name",
    ],
    # Legacy alias — treated identically to E_urls
    "E_ai_urls": _BASE_FIELDS + [
        "ai_url",
        "ai_url_domain",
        "ai_url_title",
        "ai_url_snippet",
        "ai_url_pub_date",
        "ai_url_confidence",
        "ai_url_role",
        "ai_url_sse_source",
        "ai_url_after_search_start",
        "ai_url_in_url_moderation",
        "ai_url_search_query",
        "ai_url_tool_name",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
#  SCHEMA VALIDATOR
# ─────────────────────────────────────────────────────────────────────────────

# Strict mode: raise on violation. Set to True via --debug-schema CLI flag.
_STRICT_MODE: bool = False


def set_strict_mode(enabled: bool) -> None:
    global _STRICT_MODE
    _STRICT_MODE = enabled


def validate_section_record(
    section_name: str,
    record: Dict[str, Any],
    debug: bool = False,
) -> Tuple[bool, List[str]]:
    """
    Validate that *record* contains no fields outside the section's whitelist.

    Parameters
    ----------
    section_name : canonical section key, e.g. "A_identity"
    record       : the artifact dict to validate
    debug        : if True, print violation details to stdout

    Returns
    -------
    (is_valid, list_of_unexpected_field_names)
    """
    allowed: Set[str] = set(SECTION_SCHEMAS.get(section_name, _BASE_FIELDS))
    unexpected = [k for k in record if k not in allowed]

    if unexpected:
        msg_lines = [
            f"[SCHEMA ERROR]",
            f"  Section: {section_name}",
            f"  Artifact: {record.get('artifact', '<unknown>')}",
            f"  Unexpected fields:",
        ]
        for f in unexpected:
            msg_lines.append(f"    - {f}")

        full_msg = "\n".join(msg_lines)

        if debug or _STRICT_MODE:
            print(full_msg)

        logger.debug(full_msg)

        if _STRICT_MODE:
            raise ValueError(full_msg)

        return False, unexpected

    return True, []


# ─────────────────────────────────────────────────────────────────────────────
#  RECORD BUILDER  — safe, schema-bound dict construction
# ─────────────────────────────────────────────────────────────────────────────

def build_record(
    section_name: str,
    artifact: str,
    value: Any,
    har_location: str = "",
    json_path: str = "",
    attribution: Optional[str] = None,
    reason: str = "",
    extra: Optional[Dict[str, Any]] = None,
    debug: bool = False,
) -> Dict[str, Any]:
    """
    Build a schema-validated artifact record for *section_name*.

    - attribution is resolved centrally if not explicitly provided.
    - URL-enrichment fields in *extra* are silently dropped for non-URL sections.
    - Any other unexpected fields are dropped and logged.

    Parameters
    ----------
    section_name : one of the SECTION_SCHEMAS keys
    artifact     : artifact_name string
    value        : the extracted value
    har_location : where in the HAR this was found
    json_path    : precise JSON path
    attribution  : override — if None, resolved from ATTRIBUTION_RULES
    reason       : forensic rationale string
    extra        : additional fields (only E_urls / E_ai_urls fields allowed there)
    debug        : print schema violations

    Returns
    -------
    A clean dict with only allowed fields for the section.
    """
    if attribution is None:
        attribution, _ = resolve_attribution(artifact)

    record: Dict[str, Any] = {
        "artifact":     artifact,
        "har_location": har_location,
        "json_path":    json_path,
        "value":        value,
        "attribution":  attribution,
        "reason":       reason,
    }

    if extra:
        allowed: Set[str] = set(SECTION_SCHEMAS.get(section_name, _BASE_FIELDS))
        for k, v in extra.items():
            if k in allowed:
                record[k] = v
            else:
                if k in _URL_ONLY_FIELDS:
                    # Silent drop — URL fields don't belong here
                    pass
                else:
                    logger.debug(
                        "[SCHEMA] Section %s: dropping unknown extra field '%s'",
                        section_name, k,
                    )

    # Final validation pass
    validate_section_record(section_name, record, debug=debug)
    return record


# ─────────────────────────────────────────────────────────────────────────────
#  SECTION STRIPPER  — strip foreign fields from existing records
# ─────────────────────────────────────────────────────────────────────────────

def strip_to_schema(section_name: str, record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a copy of *record* with only the fields allowed for *section_name*.
    Used by the exporter to enforce schema isolation at export time.
    """
    allowed: Set[str] = set(SECTION_SCHEMAS.get(section_name, _BASE_FIELDS))
    return {k: v for k, v in record.items() if k in allowed}


def strip_section_rows(
    section_name: str,
    rows: List[Dict[str, Any]],
    debug: bool = False,
) -> List[Dict[str, Any]]:
    """
    Strip all rows in a section to only allowed fields.
    Logs violations when debug=True or _STRICT_MODE is active.
    """
    cleaned = []
    for row in rows:
        validate_section_record(section_name, row, debug=debug)
        cleaned.append(strip_to_schema(section_name, row))
    return cleaned


# ─────────────────────────────────────────────────────────────────────────────
#  DEBUG SCHEMA REPORTER
# ─────────────────────────────────────────────────────────────────────────────

def print_schema_report(section_name: Optional[str] = None) -> None:
    """
    Print a human-readable schema report.
    If section_name is None, prints all sections.
    """
    sections = [section_name] if section_name else list(SECTION_SCHEMAS.keys())
    for sec in sections:
        fields = SECTION_SCHEMAS.get(sec, [])
        print(f"\n{'='*60}")
        print(f"  Section: {sec}")
        print(f"  Fields ({len(fields)}):")
        for f in fields:
            is_url = f in _URL_ONLY_FIELDS
            tag = " [URL-ONLY]" if is_url else ""
            print(f"    - {f}{tag}")
        url_fields_in_section = [f for f in fields if f in _URL_ONLY_FIELDS]
        non_url_section = sec not in ("E_urls", "E_ai_urls")
        if non_url_section and url_fields_in_section:
            print(f"  *** SCHEMA VIOLATION: URL fields in non-URL section! ***")
        print(f"{'='*60}")
