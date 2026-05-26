"""
Analysis router — maps detected platform to the correct parser.
Supports sections A–E. E (AI URLs / Domains Visited) injected for all platforms.

Category naming (v2):
  A. Identity  |  B. Prompt  |  C. Security  |  D. Autonomous  |  E. URLs / Domains Visited

Backward compatibility: legacy "2x_*" keys are normalized transparently via
parsers.category_labels.normalize_results().
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

_EMPTY = {k: [] for k in SECTION_ORDER}
_PLATFORM_NAMES = {cfg["id"]: cfg["name"] for cfg in _PLATFORM_CONFIGS}
_LEGACY_ALIASES = {
    "anthropic_console": "claude",
    "openai_playground": "chatgpt",
    "google_ai_studio":  "gemini",
}


def _inject_E_urls(results: Dict, har: Dict) -> Dict:
    """Inject section E_urls (platform infrastructure URL attribution, debug)."""
    if "E_urls" not in results or not results["E_urls"]:
        try:
            from .url_attribution import run_url_attribution
            import json as _j
            entries = get_entries(har)
            artifacts, timeline, chain = run_url_attribution(entries)
            url_rows = [a.to_row() for a in artifacts]
            if chain:
                url_rows.append({
                    "artifact":    "url_retrieval_chain",
                    "value":       _j.dumps([{"layer": c["layer_name"], "url": c["value"]} for c in chain])[:500],
                    "har_location": "SSE metadata",
                    "json_path":    "SSE search_result_groups → sources_footnote",
                    "attribution":  "AI",
                    "reason":       "AI: URL retrieval chain reconstructed from SSE metadata.",
                    "url_raw": "", "url_domain": "", "url_confidence": 99,
                    "url_trigger": "search_start", "url_role": "retrieval_chain_summary",
                    "url_snippet": "", "url_pub_date": "", "url_timeline": "",
                    "url_source_type": "derived",
                })
            results["E_urls"] = url_rows
        except Exception as exc:
            import logging; logging.getLogger(__name__).error("E_urls inject: %s", exc)
            results["E_urls"] = []
    return results


def _inject_E_ai_urls(results: Dict, har: Dict, platform: str = "") -> Dict:
    """Inject section E. URLs / Domains Visited (primary AI browsing evidence)."""
    if "E_ai_urls" not in results or not results["E_ai_urls"]:
        try:
            entries = get_entries(har)
            # Use provider-specific extractor
            if platform == "claude":
                from .claude_ai_urls import extract_claude_ai_urls
                report = extract_claude_ai_urls(entries)
                rows = [u.to_row() for u in report.urls]
                if report.chain:
                    rows.append({
                        "artifact": "claude_ai_url_retrieval_chain",
                        "value": str(len(report.chain)) + " chain steps",
                        "har_location": "SSE + conversation citations",
                        "json_path": "SSE tool_result + citations[]",
                        "attribution": "AI",
                        "reason": "AI: Claude retrieval from SSE tool_result blocks.",
                        "ai_url": "", "ai_url_raw": "", "ai_url_domain": "",
                        "ai_url_title": "", "ai_url_snippet": "", "ai_url_pub_date": "",
                        "ai_url_confidence": 99, "ai_url_role": "retrieval_chain_summary",
                        "ai_url_sse_source": "SSE content_block tool_result", "ai_url_sse_seq": -1,
                        "ai_url_after_search_start": True, "ai_url_in_url_moderation": False,
                        "ai_url_search_query": report.user_prompt[:100],
                        "ai_url_tool_name": "web_search + web_fetch",
                        "ai_url_chain": report.chain,
                    })
                results["E_ai_urls"] = rows
                return results
            elif platform == "gemini":
                from .gemini_ai_urls import extract_gemini_ai_urls
                report = extract_gemini_ai_urls(entries)
                results["E_ai_urls"] = [u.to_row() for u in report.urls]
                return results
            # Default: ChatGPT-style
            import json as _j
            from .ai_urls import extract_ai_urls
            report = extract_ai_urls(entries)
            rows = [u.to_row() for u in report.urls]
            if report.chain:
                rows.append({
                    "artifact": "ai_url_retrieval_chain",
                    "value":    _j.dumps([{"layer": c["layer"], "url": c["value"][:80]} for c in report.chain])[:600],
                    "har_location": "SSE stream — retrieval chain",
                    "json_path": "SSE search_model_queries → content_references",
                    "attribution": "AI",
                    "reason": f"AI: {len(report.urls)} AI URLs extracted. Query: \"{report.search_queries[0] if report.search_queries else ''}\". Tool: {report.tool_name}.",
                    "ai_url": "", "ai_url_raw": "", "ai_url_domain": "",
                    "ai_url_title": "", "ai_url_snippet": "", "ai_url_pub_date": "",
                    "ai_url_confidence": 99, "ai_url_role": "retrieval_chain_summary",
                    "ai_url_sse_source": "derived", "ai_url_sse_seq": -1,
                    "ai_url_after_search_start": True, "ai_url_in_url_moderation": False,
                    "ai_url_search_query": report.search_queries[0] if report.search_queries else "",
                    "ai_url_tool_name": report.tool_name,
                })
            results["E_ai_urls"] = rows
        except Exception as exc:
            import logging; logging.getLogger(__name__).error("E_ai_urls inject: %s", exc)
            results["E_ai_urls"] = []
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
        import logging; logging.getLogger(__name__).error("Parser error '%s': %s", platform, exc)
        return _EMPTY.copy()

    # Normalize any legacy "2x_*" keys from parsers to new "x_*" canonical keys
    results = normalize_results(raw)

    results = _inject_E_urls(results, har)
    results = _inject_E_ai_urls(results, har, platform=resolved)
    return results
