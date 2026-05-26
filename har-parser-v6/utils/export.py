"""
Multi-format export engine.
Supports: JSON, CSV, Markdown, TXT forensic reports.

Category naming (v2):
  A. Identity  |  B. Prompt  |  C. Security  |  D. Autonomous  |  E. URLs / Domains Visited

Legacy "2x_*" keys are normalized transparently via
parsers.category_labels.normalize_results().
"""

import csv
import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from parsers.category_labels import (
    SECTION_LABELS,
    SECTION_ORDER,
    normalize_results,
    section_label,
)

EXPORTS_DIR = "exports"
REPORTS_DIR = "reports"

# Base columns present in all sections
_COLUMNS = [
    "artifact", "har_location", "json_path", "value", "attribution", "reason",
    # E_urls infrastructure columns
    "url_domain", "url_role", "url_confidence", "url_trigger",
    "url_snippet", "url_pub_date", "url_timeline", "url_source_type",
    # E_ai_urls AI retrieval columns
    "ai_url", "ai_url_domain", "ai_url_title", "ai_url_snippet",
    "ai_url_pub_date", "ai_url_confidence", "ai_url_role", "ai_url_sse_source",
    "ai_url_after_search_start", "ai_url_in_url_moderation",
    "ai_url_search_query", "ai_url_tool_name",
]

# Focused columns for section E. URLs / Domains Visited CSV export
_AI_URL_COLUMNS = [
    "ai_url", "ai_url_domain", "ai_url_role", "ai_url_title",
    "ai_url_confidence", "ai_url_in_url_moderation", "ai_url_after_search_start",
    "ai_url_pub_date", "ai_url_search_query", "ai_url_tool_name",
    "ai_url_sse_source", "ai_url_snippet", "reason",
]


def _ensure_dirs(output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)


def _base_name(har_path: str) -> str:
    return os.path.splitext(os.path.basename(har_path))[0]


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def export_json(results: Dict[str, List[Dict]], platform: str,
                har_path: str, output_dir: str,
                cg: int = 0, gm: int = 0, cl: int = 0) -> str:
    """Export results as a structured JSON forensic report."""
    _ensure_dirs(output_dir)
    fname = f"{_base_name(har_path)}_{platform}_{_timestamp()}.json"
    fpath = os.path.join(output_dir, fname)

    # Normalize any legacy keys before export
    results = normalize_results(results)

    export_data = {
        "tool": "HAR Parser For Conversational AI",
        "platform": platform,
        "analysis_timestamp": datetime.now().isoformat(),
        "source_file": os.path.basename(har_path),
        "detection_scores": {"chatgpt": cg, "gemini": gm, "claude": cl},
        "section_labels": SECTION_LABELS,
        "results": results,
    }
    with open(fpath, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)
    return fpath


def export_csv(results: Dict[str, List[Dict]], platform: str,
               har_path: str, output_dir: str) -> List[str]:
    """Export each result section as a separate CSV file."""
    _ensure_dirs(output_dir)
    results = normalize_results(results)
    written = []
    base = _base_name(har_path)
    ts   = _timestamp()
    for section, rows in results.items():
        if not rows:
            continue
        fname = f"{base}_{platform}_{section}_{ts}.csv"
        fpath = os.path.join(output_dir, fname)
        # Use focused AI URL columns for E_ai_urls; standard columns for everything else
        col_set = _AI_URL_COLUMNS if section == "E_ai_urls" else _COLUMNS
        with open(fpath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=col_set, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        written.append(fpath)
    return written


def export_markdown(results: Dict[str, List[Dict]], platform: str,
                    har_path: str, output_dir: str,
                    cg: int = 0, gm: int = 0, cl: int = 0) -> str:
    """Export results as a Markdown forensic report."""
    _ensure_dirs(output_dir)
    fname = f"{_base_name(har_path)}_{platform}_{_timestamp()}.md"
    fpath = os.path.join(output_dir, fname)

    results = normalize_results(results)

    all_rows = [r for s in results.values() for r in s]
    ai_count = sum(1 for r in all_rows if r.get("attribution","").upper() == "AI")
    hu_count = sum(1 for r in all_rows if r.get("attribution","").upper() == "HUMAN")
    pl_count = len(all_rows) - ai_count - hu_count

    lines = [
        "# HAR Parser For Conversational AI — Forensic Report",
        "",
        f"**Tool:** HAR Parser For Conversational AI  ",
        f"**Platform:** {platform.upper()}  ",
        f"**Source File:** `{os.path.basename(har_path)}`  ",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        "",
        "---",
        "",
        "## Forensic Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total Artifacts | {len(all_rows)} |",
        f"| 🧑 Human Attribution | {hu_count} |",
        f"| 🤖 AI Attribution | {ai_count} |",
        f"| 🏛 Platform Attribution | {pl_count} |",
        f"| Detection Scores | ChatGPT={cg} / Gemini={gm} / Claude={cl} |",
        "",
        "## Table of Contents",
        "",
    ]

    # Build TOC
    for k in SECTION_ORDER:
        rows = results.get(k, [])
        if not rows:
            continue
        lbl = section_label(k)
        anchor = lbl.lower().replace(" ", "-").replace(".", "").replace("/", "")
        lines.append(f"- [{lbl}](#{anchor}) ({len(rows)} artifacts)")
    lines += ["", "---", ""]

    # Sections in canonical order
    ordered = {k: results.get(k, []) for k in SECTION_ORDER}
    ordered.update({k: v for k, v in results.items() if k not in ordered})

    for section, rows in ordered.items():
        if not rows:
            continue
        lbl = section_label(section)
        is_debug = section == "E_urls"
        if is_debug:
            lines += ["", "---", "", f"## 🔧 {lbl}  *(debug — platform infrastructure)*", ""]
        else:
            lines += ["", f"## {lbl}", ""]
        lines += [
            "| Artifact | Attribution | Value | HAR Location | Forensic Rationale |",
            "|----------|-------------|-------|-------------|-------------------|",
        ]
        for row in rows:
            artifact    = row.get("artifact","").replace("|","\\|")
            attribution = row.get("attribution","")
            value       = str(row.get("value",""))[:120].replace("|","\\|").replace("\n"," ")
            har_loc     = row.get("har_location","").replace("|","\\|")
            reason      = row.get("reason","")[:120].replace("|","\\|").replace("\n"," ")
            lines.append(f"| `{artifact}` | {attribution} | {value} | {har_loc} | {reason} |")
        lines.append("")

    with open(fpath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return fpath


def export_txt(results: Dict[str, List[Dict]], platform: str,
               har_path: str, output_dir: str,
               cg: int = 0, gm: int = 0, cl: int = 0) -> str:
    """Export results as a plain-text forensic report."""
    _ensure_dirs(output_dir)
    fname = f"{_base_name(har_path)}_{platform}_{_timestamp()}.txt"
    fpath = os.path.join(output_dir, fname)

    results = normalize_results(results)

    all_rows = [r for s in results.values() for r in s]
    ai_count = sum(1 for r in all_rows if r.get("attribution","").upper() == "AI")
    hu_count = sum(1 for r in all_rows if r.get("attribution","").upper() == "HUMAN")
    pl_count = len(all_rows) - ai_count - hu_count
    sep      = "═" * 72

    lines = [
        sep,
        "HAR PARSER FOR CONVERSATIONAL AI — FORENSIC REPORT",
        sep,
        f"Platform    : {platform.upper()}",
        f"Source File : {os.path.basename(har_path)}",
        f"Generated   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        sep,
        "FORENSIC SUMMARY",
        "-" * 40,
        f"  Total Artifacts    : {len(all_rows)}",
        f"  Human Attribution  : {hu_count}",
        f"  AI Attribution     : {ai_count}",
        f"  Platform Attrib.   : {pl_count}",
        f"  Detection Scores   : ChatGPT={cg}  Gemini={gm}  Claude={cl}",
        sep,
        "",
        "TABLE OF CONTENTS",
        "-" * 40,
    ]
    for k in SECTION_ORDER:
        rows = results.get(k, [])
        if not rows:
            continue
        lbl = section_label(k)
        lines.append(f"  {lbl}  ({len(rows)} artifacts)")
    lines += [sep, ""]

    for section, rows in results.items():
        if not rows:
            continue
        lbl = section_label(section)
        lines += [
            f"[{section}]  {lbl.upper()}",
            "-" * 72,
        ]
        for row in rows:
            lines += [
                f"  Artifact    : {row.get('artifact','')}",
                f"  Attribution : {row.get('attribution','')}",
                f"  Value       : {str(row.get('value',''))[:200]}",
                f"  HAR Loc     : {row.get('har_location','')}",
                f"  JSON Path   : {row.get('json_path','')}",
                f"  Rationale   : {row.get('reason','')[:200]}",
                "",
            ]
        lines.append("")

    with open(fpath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return fpath


def export_all(results: Dict[str, List[Dict]], platform: str,
               har_path: str, output_dir: str,
               cg: int = 0, gm: int = 0, cl: int = 0) -> Dict[str, object]:
    """Export all formats."""
    return {
        "json": export_json(results, platform, har_path, output_dir, cg, gm, cl),
        "csv":  export_csv(results, platform, har_path, output_dir),
        "md":   export_markdown(results, platform, har_path, output_dir, cg, gm, cl),
        "txt":  export_txt(results, platform, har_path, output_dir, cg, gm, cl),
    }


# ─── v2.0 extended export — includes multi-platform detection metadata ────────

def export_json_v2(
    results: Dict[str, List[Dict]],
    platform: str,
    har_path: str,
    output_dir: str,
    cg: int = 0,
    gm: int = 0,
    cl: int = 0,
    detection_data: Optional[Dict] = None,
) -> str:
    """
    Export v2 JSON report that includes:
      - all detected platforms with confidence scores and evidence
      - detected AI models
      - SDK fingerprints
      - streaming artifacts
      - session/correlation IDs
      - forensic artifact sections (A–E)

    Backward-compatible: accepts legacy "2x_*" keys in results.
    """
    _ensure_dirs(output_dir)
    fname = f"{_base_name(har_path)}_{platform}_{_timestamp()}_v2.json"
    fpath = os.path.join(output_dir, fname)

    results = normalize_results(results)
    detection_data = detection_data or {}

    export_data = {
        "tool":                "HAR Parser For Conversational AI",
        "version":             "2.0",
        "platform":            platform,
        "analysis_timestamp":  datetime.now().isoformat(),
        "source_file":         os.path.basename(har_path),
        # Legacy scores (backward compat)
        "detection_scores":    {"chatgpt": cg, "gemini": gm, "claude": cl},
        # Section metadata
        "section_labels":      SECTION_LABELS,
        "section_order":       SECTION_ORDER,
        # New: multi-platform results
        "detected_platforms":  detection_data.get("platforms_raw", []),
        "detected_models":     detection_data.get("models_raw", []),
        "detected_sdks":       detection_data.get("sdks_raw", []),
        "streaming_artifacts": detection_data.get("streaming", {}),
        "session_artifacts":   detection_data.get("sessions", {}),
        # Forensic results (canonical keys)
        "results":             results,
    }

    with open(fpath, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)
    return fpath
