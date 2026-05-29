"""
Multi-format export engine — v7 (schema-isolated).
Supports: JSON, CSV, Markdown, TXT forensic reports.

Category naming:
  A. Identity  |  B. Prompt  |  C. Security  |  D. Autonomous  |  E. URLs

CRITICAL: Each section exports ONLY its whitelisted fields.
URL-enrichment fields (url_*, ai_url_*) are STRICTLY isolated to E_urls / E_ai_urls.
No section widening. No union-of-all-fields. No NaN pollution.
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
from parsers.schemas import (
    SECTION_SCHEMAS,
    strip_section_rows,
    print_schema_report,
)
from utils.export_excel import export_excel  # noqa: E402 (circular-safe — no back-import)

EXPORTS_DIR = "exports"
REPORTS_DIR = "reports"


def _ensure_dirs(output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)


def _base_name(har_path: str) -> str:
    return os.path.splitext(os.path.basename(har_path))[0]


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


# ─────────────────────────────────────────────────────────────────────────────
#  CORE: Section-isolated CSV exporter
# ─────────────────────────────────────────────────────────────────────────────

def export_csv(
    results: Dict[str, List[Dict]],
    platform: str,
    har_path: str,
    output_dir: str,
    debug: bool = False,
) -> List[str]:
    """
    Export each result section as a separate CSV file.

    SCHEMA ISOLATION: Each section uses its own field whitelist from
    SECTION_SCHEMAS. Foreign fields are stripped, not exported.
    No URL-enrichment fields appear in A/B/C/D sections.
    """
    _ensure_dirs(output_dir)
    results = normalize_results(results)
    written = []
    base = _base_name(har_path)
    ts = _timestamp()

    for section, rows in results.items():
        if not rows:
            continue

        # Resolve schema for this section
        schema_fields = SECTION_SCHEMAS.get(section)
        if schema_fields is None:
            # Unknown section — use base fields only
            schema_fields = SECTION_SCHEMAS.get("A_identity", [])

        if debug:
            print(f"\n[DEBUG-SCHEMA] Section: {section}")
            print(f"  Fields ({len(schema_fields)}): {schema_fields}")
            print(f"  Enrichment pipeline: {'URL' if section.startswith('E') else 'NONE'}")
            print(f"  Attribution source: parsers.schemas.ATTRIBUTION_RULES")

        # Strip rows to section schema — enforces isolation
        clean_rows = strip_section_rows(section, rows, debug=debug)

        fname = f"{base}_{platform}_{section}_{ts}.csv"
        fpath = os.path.join(output_dir, fname)

        with open(fpath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=schema_fields,
                extrasaction="ignore",     # belt-and-suspenders: still ignore strays
                restval="",               # no NaN — empty string for missing fields
            )
            writer.writeheader()
            writer.writerows(clean_rows)

        written.append(fpath)

    return written


# ─────────────────────────────────────────────────────────────────────────────
#  JSON export
# ─────────────────────────────────────────────────────────────────────────────

def export_json(
    results: Dict[str, List[Dict]],
    platform: str,
    har_path: str,
    output_dir: str,
    cg: int = 0,
    gm: int = 0,
    cl: int = 0,
) -> str:
    """Export results as a structured JSON forensic report."""
    _ensure_dirs(output_dir)
    fname = f"{_base_name(har_path)}_{platform}_{_timestamp()}.json"
    fpath = os.path.join(output_dir, fname)

    results = normalize_results(results)

    export_data = {
        "tool": "HARensic",
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


# ─────────────────────────────────────────────────────────────────────────────
#  Markdown export
# ─────────────────────────────────────────────────────────────────────────────

def export_markdown(
    results: Dict[str, List[Dict]],
    platform: str,
    har_path: str,
    output_dir: str,
    cg: int = 0,
    gm: int = 0,
    cl: int = 0,
) -> str:
    """Export results as a Markdown forensic report."""
    _ensure_dirs(output_dir)
    fname = f"{_base_name(har_path)}_{platform}_{_timestamp()}.md"
    fpath = os.path.join(output_dir, fname)

    results = normalize_results(results)

    all_rows = [r for s in results.values() for r in s]
    ai_count = sum(1 for r in all_rows if r.get("attribution", "").upper() == "AI")
    hu_count = sum(1 for r in all_rows if r.get("attribution", "").upper() == "HUMAN")
    pl_count = len(all_rows) - ai_count - hu_count

    lines = [
        "# HARensic — Forensic Report",
        "",
        f"**Tool:** HARensic  ",
        f"**Platform:** {platform.upper()}  ",
        f"**Source File:** `{os.path.basename(har_path)}`  ",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        "",
        "---",
        "",
        "## Forensic Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total Artifacts | {len(all_rows)} |",
        f"| 🧑 Human Attribution | {hu_count} |",
        f"| 🤖 AI Attribution | {ai_count} |",
        f"| 🏛 Platform Attribution | {pl_count} |",
        f"| Detection Scores | ChatGPT={cg} / Gemini={gm} / Claude={cl} |",
        "",
        "## Table of Contents",
        "",
    ]

    for k in SECTION_ORDER:
        rows = results.get(k, [])
        if not rows:
            continue
        lbl = section_label(k)
        anchor = lbl.lower().replace(" ", "-").replace(".", "").replace("/", "")
        lines.append(f"- [{lbl}](#{anchor}) ({len(rows)} artifacts)")
    lines += ["", "---", ""]

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
            artifact    = row.get("artifact", "").replace("|", "\\|")
            attribution = row.get("attribution", "")
            value       = str(row.get("value", ""))[:120].replace("|", "\\|").replace("\n", " ")
            har_loc     = row.get("har_location", "").replace("|", "\\|")
            reason      = row.get("reason", "")[:120].replace("|", "\\|").replace("\n", " ")
            lines.append(f"| `{artifact}` | {attribution} | {value} | {har_loc} | {reason} |")
        lines.append("")

    with open(fpath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return fpath


# ─────────────────────────────────────────────────────────────────────────────
#  TXT export
# ─────────────────────────────────────────────────────────────────────────────

def export_txt(
    results: Dict[str, List[Dict]],
    platform: str,
    har_path: str,
    output_dir: str,
    cg: int = 0,
    gm: int = 0,
    cl: int = 0,
) -> str:
    """Export results as a plain-text forensic report."""
    _ensure_dirs(output_dir)
    fname = f"{_base_name(har_path)}_{platform}_{_timestamp()}.txt"
    fpath = os.path.join(output_dir, fname)

    results = normalize_results(results)

    all_rows = [r for s in results.values() for r in s]
    ai_count = sum(1 for r in all_rows if r.get("attribution", "").upper() == "AI")
    hu_count = sum(1 for r in all_rows if r.get("attribution", "").upper() == "HUMAN")
    pl_count = len(all_rows) - ai_count - hu_count
    sep = "═" * 72

    lines = [
        sep,
        "HARensic — FORENSIC REPORT",
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
                f"  Artifact    : {row.get('artifact', '')}",
                f"  Attribution : {row.get('attribution', '')}",
                f"  Value       : {str(row.get('value', ''))[:200]}",
                f"  HAR Loc     : {row.get('har_location', '')}",
                f"  JSON Path   : {row.get('json_path', '')}",
                f"  Rationale   : {row.get('reason', '')[:200]}",
                "",
            ]
        lines.append("")

    with open(fpath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return fpath


# ─────────────────────────────────────────────────────────────────────────────
#  Combined export
# ─────────────────────────────────────────────────────────────────────────────

def export_all(
    results: Dict[str, List[Dict]],
    platform: str,
    har_path: str,
    output_dir: str,
    cg: int = 0,
    gm: int = 0,
    cl: int = 0,
    debug: bool = False,
) -> Dict[str, object]:
    """Export all formats with schema isolation enforced."""
    return {
        "json":  export_json(results, platform, har_path, output_dir, cg, gm, cl),
        "csv":   export_csv(results, platform, har_path, output_dir, debug=debug),
        "xlsx":  export_excel(results, platform, har_path, output_dir, cg, gm, cl, debug=debug),
        "md":    export_markdown(results, platform, har_path, output_dir, cg, gm, cl),
        "txt":   export_txt(results, platform, har_path, output_dir, cg, gm, cl),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  v2.0 extended export (backward-compat)
# ─────────────────────────────────────────────────────────────────────────────

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
    Export v2 JSON report — multi-platform detection metadata included.
    Backward-compatible with legacy "2x_*" keys.
    """
    _ensure_dirs(output_dir)
    fname = f"{_base_name(har_path)}_{platform}_{_timestamp()}_v2.json"
    fpath = os.path.join(output_dir, fname)

    results = normalize_results(results)
    detection_data = detection_data or {}

    export_data = {
        "tool":                "HARensic",
        "version":             "2.0",
        "platform":            platform,
        "analysis_timestamp":  datetime.now().isoformat(),
        "source_file":         os.path.basename(har_path),
        "detection_scores":    {"chatgpt": cg, "gemini": gm, "claude": cl},
        "section_labels":      SECTION_LABELS,
        "section_order":       SECTION_ORDER,
        "detected_platforms":  detection_data.get("platforms_raw", []),
        "detected_models":     detection_data.get("models_raw", []),
        "detected_sdks":       detection_data.get("sdks_raw", []),
        "streaming_artifacts": detection_data.get("streaming", {}),
        "session_artifacts":   detection_data.get("sessions", {}),
        "results":             results,
    }

    with open(fpath, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)
    return fpath
