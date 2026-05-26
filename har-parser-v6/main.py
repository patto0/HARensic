#!/usr/bin/env python3
"""
HAR Parser For Conversational AI
=================================
Professional CLI-based forensic tool for analyzing HAR files captured
during interactions with conversational AI platforms.

Supported platforms : ChatGPT · Claude · Gemini
Forensic sections   : A. Identity · B. Prompt · C. Security · D. Autonomous

Usage
-----
    python main.py analyze sample.har
    python main.py analyze sample.har --verbose
    python main.py analyze sample.har --export json --output exports/
    python main.py analyze sample.har --export all
    python main.py batch ./har_files/
    python main.py stats sample.har
    python main.py validate sample.har
"""

import argparse
import os
import sys
import time
import glob
from typing import List, Optional

from cli.banner import print_banner
from cli.display import (
    print_stage, print_detection_scores,
    print_section_results, print_forensic_summary,
    print_stats_report, print_batch_summary,
    print_multi_platform_detection, print_streaming_artifacts, print_session_artifacts,
    cyan, green, red, yellow, bold, dim,
)
from core.logger import get_logger
from parsers.loader import load_har, get_entries
from parsers.detection import (
    detect_platform_with_scores,
    detect_all_platforms,
    detect_sdks,
    extract_models,
    detect_streaming_artifacts,
    extract_session_artifacts,
    full_detection,
)
from parsers.router import run_analysis
from utils.export import (
    export_json, export_csv, export_markdown, export_txt, export_all,
    EXPORTS_DIR, REPORTS_DIR,
)

logger = get_logger()


# ─────────────────────────────────────────────────────────────────────────────
#  CORE ANALYSIS WORKFLOW
# ─────────────────────────────────────────────────────────────────────────────

def run_analyze(har_path: str, verbose: bool = False, debug: bool = False,
                export_fmt: Optional[str] = None, output_dir: str = EXPORTS_DIR,
                quiet: bool = False) -> dict:
    """
    Full forensic analysis pipeline for a single HAR file.

    Parameters
    ----------
    har_path   : Path to the .har file
    verbose    : Show forensic rationale for each artifact
    debug      : Enable debug-level output
    export_fmt : One of 'json', 'csv', 'md', 'txt', 'all', or None
    output_dir : Directory for exported files
    quiet      : Suppress stage output (used in batch mode)

    Returns
    -------
    dict with keys: platform, results, cg, gm, cl, elapsed
    """
    t_start = time.perf_counter()

    def stage(msg: str, kind: str = "info") -> None:
        if not quiet:
            print_stage(msg, kind)
        logger.info(msg)

    stage(f"Loading HAR file: {har_path}")

    # ── Load ──────────────────────────────────────────────────────────────
    try:
        har = load_har(har_path)
    except RuntimeError as e:
        print_stage(f"Failed to load HAR: {e}", "error")
        logger.error(f"Load failure: {e}")
        raise

    entries = get_entries(har)
    stage(f"HAR loaded — {len(entries)} network entries found", "success")

    # ── Validate ──────────────────────────────────────────────────────────
    stage("Validating HAR structure...")
    if len(entries) == 0:
        raise RuntimeError("HAR file contains zero entries — nothing to analyze.")
    stage("HAR structure valid", "success")

    # ── Platform detection (v2 — multi-platform) ──────────────────────────
    stage("Running multi-platform AI detection engine...")

    detection = full_detection(entries, har_path=har_path, output_dir=output_dir)
    all_matches  = detection["platforms"]
    sdks         = detection["sdks"]
    models       = detection["models"]
    streaming    = detection["streaming"]
    sessions     = detection["session_artifacts"]

    # Legacy scores for backward-compatible downstream display
    platform, cg, gm, cl = detect_platform_with_scores(entries)

    if all_matches:
        primary = all_matches[0]
        stage(
            f"Primary platform: {primary.platform_name} ({primary.confidence}% confidence) "
            f"— {len(all_matches)} platform(s) detected total",
            "detect",
        )
        platform = primary.platform_id
    else:
        stage("Platform could not be identified — proceeding with generic extraction", "warn")
        logger.warning("Platform unknown — using generic parser")
        platform = "unknown"

    logger.info(
        "Detection: primary=%s  all=%s  sdks=%s  models=%s",
        platform,
        [m.platform_id for m in all_matches],
        [s.sdk_id for s in sdks],
        [m.model for m in models],
    )

    if not quiet:
        print_multi_platform_detection(all_matches, sdks, models)
        if cg or gm or cl:
            _leg_plat = platform if platform in ("chatgpt", "gemini", "claude") else "unknown"
            print_detection_scores(_leg_plat, cg, gm, cl)

    # ── Parsing ───────────────────────────────────────────────────────────
    stage("Extracting SSE streams and network artifacts...")
    stage("Building forensic artifact inventory...")
    stage("Running attribution analysis (Human / AI / Platform)...")

    try:
        results = run_analysis(har, platform)
    except Exception as e:
        logger.error(f"Parser error: {e}")
        raise RuntimeError(f"Parser failed: {e}") from e

    total = sum(len(v) for v in results.values())
    stage(f"Forensic artifacts extracted: {total}", "success")
    logger.info(f"Artifacts extracted: {total}")

    # ── Display results — unified section renderer for all categories (A–E) ──
    if not quiet:
        for section in ["A_identity", "B_prompt", "C_security", "D_autonomous", "E_ai_urls"]:
            print_section_results(section, results.get(section, results.get(
                # legacy key fallback
                {"A_identity":"2A_identity","B_prompt":"2B_prompt",
                 "C_security":"2C_security","D_autonomous":"2D_autonomous",
                 "E_ai_urls":"2F_ai_urls"}.get(section, section), []
            )), verbose=verbose)
        # 2E — Platform infrastructure detail (only shown when --infra flag set)
        if debug:
            from cli.display import print_url_attribution_section
            print_url_attribution_section(results.get("2E_urls", []), verbose=verbose)
        print_streaming_artifacts(streaming)
        print_session_artifacts(sessions)

    elapsed = time.perf_counter() - t_start

    if not quiet:
        print_forensic_summary(
            platform, results, os.path.basename(har_path), elapsed, cg, gm, cl
        )

    # ── Export ────────────────────────────────────────────────────────────
    if export_fmt:
        stage(f"Exporting results as: {export_fmt.upper()}")
        os.makedirs(output_dir, exist_ok=True)
        exported = []

        if export_fmt == "json":
            p = export_json(results, platform, har_path, output_dir, cg, gm, cl)
            exported = [p]
        elif export_fmt == "csv":
            exported = export_csv(results, platform, har_path, output_dir)
        elif export_fmt in ("md", "markdown"):
            p = export_markdown(results, platform, har_path, output_dir, cg, gm, cl)
            exported = [p]
        elif export_fmt in ("txt", "text"):
            p = export_txt(results, platform, har_path, output_dir, cg, gm, cl)
            exported = [p]
        elif export_fmt == "all":
            all_exports = export_all(results, platform, har_path, output_dir, cg, gm, cl)
            for key, val in all_exports.items():
                if isinstance(val, list):
                    exported.extend(val)
                else:
                    exported.append(val)
        else:
            stage(f"Unknown export format: {export_fmt}", "warn")

        for p in exported:
            stage(f"Exported → {p}", "success")
            logger.info(f"Export: {p}")

    logger.info(f"Analysis complete in {elapsed:.2f}s — platform={platform} artifacts={total}")
    return {"platform": platform, "results": results,
            "cg": cg, "gm": gm, "cl": cl, "elapsed": elapsed}


# ─────────────────────────────────────────────────────────────────────────────
#  SUBCOMMAND HANDLERS
# ─────────────────────────────────────────────────────────────────────────────

def cmd_analyze(args: argparse.Namespace) -> None:
    """Handle: python main.py analyze <file>"""
    har_path = args.har_file
    if not os.path.isfile(har_path):
        print_stage(f"File not found: {har_path}", "error")
        sys.exit(1)

    print_banner()

    try:
        run_analyze(
            har_path=har_path,
            verbose=args.verbose,
            debug=getattr(args, "debug", False),
            export_fmt=args.export,
            output_dir=args.output,
        )
    except Exception as e:
        print_stage(f"Analysis failed: {e}", "error")
        logger.error(f"cmd_analyze failed: {e}", exc_info=True)
        sys.exit(1)


def cmd_validate(args: argparse.Namespace) -> None:
    """Handle: python main.py validate <file>"""
    har_path = args.har_file
    print_banner()
    print_stage(f"Validating: {har_path}")

    try:
        har     = load_har(har_path)
        entries = get_entries(har)
        platform, cg, gm, cl = detect_platform_with_scores(entries)

        print_stage(f"File is valid HAR format", "success")
        print_stage(f"Entries: {len(entries)}", "info")
        print_stage(f"Detected platform: {platform.upper()}", "detect")
        print_detection_scores(platform, cg, gm, cl)
        print()
        print(green("  [OK]  HAR file is valid and ready for analysis."))
    except Exception as e:
        print_stage(f"Validation failed: {e}", "error")
        logger.error(f"Validation failed for {har_path}: {e}")
        sys.exit(1)


def cmd_stats(args: argparse.Namespace) -> None:
    """Handle: python main.py stats <file>"""
    har_path = args.har_file
    print_banner()

    try:
        har     = load_har(har_path)
        entries = get_entries(har)
        platform, cg, gm, cl = detect_platform_with_scores(entries)
        results = run_analysis(har, platform)

        print_stats_report(
            har_path=har_path,
            platform=platform,
            entries_count=len(entries),
            results=results,
            cg=cg, gm=gm, cl=cl,
        )
    except Exception as e:
        print_stage(f"Stats failed: {e}", "error")
        logger.error(f"cmd_stats failed: {e}", exc_info=True)
        sys.exit(1)


def cmd_batch(args: argparse.Namespace) -> None:
    """Handle: python main.py batch <folder>"""
    folder = args.folder
    print_banner()

    if not os.path.isdir(folder):
        print_stage(f"Directory not found: {folder}", "error")
        sys.exit(1)

    # Recursively find all .har files
    pattern = os.path.join(folder, "**", "*.har")
    har_files = glob.glob(pattern, recursive=True)

    if not har_files:
        print_stage(f"No .har files found in: {folder}", "warn")
        sys.exit(0)

    print_stage(f"Found {len(har_files)} HAR file(s) for batch processing", "info")
    logger.info(f"Batch: {len(har_files)} files in {folder}")

    batch_results = []
    output_dir = args.output or EXPORTS_DIR

    for idx, har_path in enumerate(har_files, 1):
        fname = os.path.basename(har_path)
        print()
        print(cyan(f"-- [{idx}/{len(har_files)}]  {fname}"))

        try:
            result = run_analyze(
                har_path=har_path,
                verbose=False,
                export_fmt=args.export,
                output_dir=os.path.join(output_dir, "batch"),
                quiet=True,
            )
            batch_results.append({
                "file": fname,
                "platform": result["platform"],
                "results": result["results"],
                "status": "OK",
            })
            all_rows = [r for s in result["results"].values() for r in s]
            print_stage(f"{fname} → {result['platform'].upper()}  "
                        f"({len(all_rows)} artifacts)", "success")
        except Exception as e:
            print_stage(f"{fname} → FAILED: {e}", "error")
            logger.error(f"Batch item failed: {har_path}: {e}")
            batch_results.append({
                "file": fname, "platform": "unknown",
                "results": {}, "status": f"ERROR: {e}",
            })

    print_batch_summary(batch_results)

    # Write combined JSON summary
    import json
    os.makedirs(output_dir, exist_ok=True)
    summary_path = os.path.join(output_dir, "batch_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(batch_results, f, indent=2, ensure_ascii=False, default=str)
    print_stage(f"Batch summary exported → {summary_path}", "success")


# ─────────────────────────────────────────────────────────────────────────────
#  ARGUMENT PARSER
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description=(
            "HAR Parser For Conversational AI\n"
            "Digital forensics tool for ChatGPT · Claude · Gemini HAR files.\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py analyze session.har
  python main.py analyze session.har --verbose
  python main.py analyze session.har --export json
  python main.py analyze session.har --export all --output /tmp/results/
  python main.py batch ./har_files/
  python main.py stats session.har
  python main.py validate session.har
        """,
    )

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    subparsers.required = True

    # ── analyze ────────────────────────────────────────────────────────────
    analyze_p = subparsers.add_parser(
        "analyze",
        help="Perform full forensic analysis on a single HAR file",
        description="Run the complete forensic analysis pipeline on a HAR file.",
    )
    analyze_p.add_argument("har_file", metavar="FILE", help="Path to .har file")
    analyze_p.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show full forensic rationale for each artifact",
    )
    analyze_p.add_argument(
        "--debug", "-d", action="store_true",
        help="Enable debug-level logging output",
    )
    analyze_p.add_argument(
        "--infra", action="store_true",
        dest="debug",
        help="Show platform infrastructure section (2E) — suppressed by default",
    )
    analyze_p.add_argument(
        "--export", "-e", metavar="FORMAT",
        choices=["json", "csv", "md", "markdown", "txt", "text", "all"],
        help="Export format: json, csv, md, txt, or all",
    )
    analyze_p.add_argument(
        "--output", "-o", metavar="DIR", default=EXPORTS_DIR,
        help=f"Output directory for exports (default: {EXPORTS_DIR}/)",
    )
    analyze_p.set_defaults(func=cmd_analyze)

    # ── validate ───────────────────────────────────────────────────────────
    validate_p = subparsers.add_parser(
        "validate",
        help="Validate a HAR file without full analysis",
        description="Check HAR file validity and detect the AI platform.",
    )
    validate_p.add_argument("har_file", metavar="FILE", help="Path to .har file")
    validate_p.set_defaults(func=cmd_validate)

    # ── stats ──────────────────────────────────────────────────────────────
    stats_p = subparsers.add_parser(
        "stats",
        help="Show forensic statistics for a HAR file",
        description="Display artifact counts, platform scores, and attribution breakdown.",
    )
    stats_p.add_argument("har_file", metavar="FILE", help="Path to .har file")
    stats_p.set_defaults(func=cmd_stats)

    # ── batch ──────────────────────────────────────────────────────────────
    batch_p = subparsers.add_parser(
        "batch",
        help="Recursively process all HAR files in a directory",
        description="Batch-analyze every .har file found recursively in a folder.",
    )
    batch_p.add_argument("folder", metavar="DIR", help="Directory containing .har files")
    batch_p.add_argument(
        "--export", "-e", metavar="FORMAT",
        choices=["json", "csv", "md", "txt", "all"],
        help="Export format for each file",
    )
    batch_p.add_argument(
        "--output", "-o", metavar="DIR", default=EXPORTS_DIR,
        help=f"Output directory for exports (default: {EXPORTS_DIR}/)",
    )
    batch_p.set_defaults(func=cmd_batch)

    return parser


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    try:
        args.func(args)
    except KeyboardInterrupt:
        print()
        print(yellow("  [!]  Analysis interrupted by user."))
        logger.warning("Session interrupted by user (KeyboardInterrupt)")
        sys.exit(130)
    except Exception as e:
        print(red(f"  [X]  Unhandled error: {e}"))
        logger.critical(f"Unhandled exception: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
