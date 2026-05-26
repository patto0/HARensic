"""
Terminal display utilities — stdlib-only implementation.
Uses ANSI escape codes; no external dependencies required.
"""

import os
import re
import sys
from typing import Dict, List
from datetime import datetime

# ─── ANSI codes ──────────────────────────────────────────────────────────────
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"

BRIGHT_RED     = "\033[91m"
BRIGHT_GREEN   = "\033[92m"
BRIGHT_YELLOW  = "\033[93m"
BRIGHT_BLUE    = "\033[94m"
BRIGHT_MAGENTA = "\033[95m"
BRIGHT_CYAN    = "\033[96m"
BRIGHT_WHITE   = "\033[97m"


def _no_color() -> bool:
    return (not sys.stdout.isatty() or bool(os.environ.get("NO_COLOR"))
            or os.environ.get("TERM") == "dumb")


def _c(code: str, text: str) -> str:
    return text if _no_color() else f"{code}{text}{RESET}"


def bold(t):    return _c(BOLD, t)
def dim(t):     return _c(DIM, t)
def cyan(t):    return _c(BRIGHT_CYAN, t)
def green(t):   return _c(BRIGHT_GREEN, t)
def red(t):     return _c(BRIGHT_RED, t)
def yellow(t):  return _c(BRIGHT_YELLOW, t)
def magenta(t): return _c(BRIGHT_MAGENTA, t)
def blue(t):    return _c(BRIGHT_BLUE, t)
def white(t):   return _c(BRIGHT_WHITE, t)


ATTR_META = {
    "HUMAN":    (green,   "H"),
    "AI":       (red,     "A"),
    "PLATFORM": (magenta, "P"),
}

SECTION_META = {
    # Canonical keys (v2)
    "A_identity":   (">>", "A. IDENTITY",               "A. Identity — Identity & Session Artifacts",                         cyan),
    "B_prompt":     (">>", "B. PROMPTS",                "B. Prompt — Prompt & Response Artifacts",                            green),
    "C_security":   (">>", "C. SECURITY",               "C. Security — Security & Authentication",                            yellow),
    "D_autonomous": (">>", "D. AUTONOMOUS",             "D. Autonomous — Autonomous & Background Actions",                    magenta),
    "E_ai_urls":    (">>", "E. URLS / DOMAINS VISITED", "E. URLs / Domains Visited — AI Visited URLs & External Navigation Artifacts", red),
    # Legacy aliases for backward compatibility
    "2A_identity":   (">>", "A. IDENTITY",               "A. Identity — Identity & Session Artifacts",                         cyan),
    "2B_prompt":     (">>", "B. PROMPTS",                "B. Prompt — Prompt & Response Artifacts",                            green),
    "2C_security":   (">>", "C. SECURITY",               "C. Security — Security & Authentication",                            yellow),
    "2D_autonomous": (">>", "D. AUTONOMOUS",             "D. Autonomous — Autonomous & Background Actions",                    magenta),
    "2F_ai_urls":    (">>", "E. URLS / DOMAINS VISITED", "E. URLs / Domains Visited — AI Visited URLs & External Navigation Artifacts", red),
}

_ANSI_RE = re.compile(r'\033\[[0-9;]*m')


def _visible_len(s: str) -> int:
    return len(_ANSI_RE.sub('', s))


def _rule(text: str = "", char: str = "-", width: int = 72, color_fn=cyan) -> None:
    if text:
        pad = max(0, width - len(text) - 2)
        left = char * (pad // 2)
        right = char * (pad - pad // 2)
        print(color_fn(f"{left} {text} {right}"))
    else:
        print(color_fn(char * width))


def _truncate(text: str, max_len: int) -> str:
    text = str(text).replace("\n", " ")
    if len(text) > max_len:
        return text[:max_len - 1] + "."
    return text


def print_stage(msg: str, stage: str = "info") -> None:
    prefixes = {
        "info":    cyan("[+]"),
        "success": green("[OK]"),
        "warn":    yellow("[!]"),
        "error":   red("[X]"),
        "detect":  magenta("[>>]"),
    }
    prefix = prefixes.get(stage, cyan("[+]"))
    print(f"  {prefix}  {msg}")


def print_detection_scores(platform: str, cg: int, gm: int, cl: int) -> None:
    total = max(cg + gm + cl, 1)

    def bar(score: int, color_fn) -> str:
        filled = int((score / total) * 20)
        return color_fn("#" * filled) + dim("." * (20 - filled)) + f"  {score}pts"

    platform_display = {
        "chatgpt": green("ChatGPT"),
        "gemini":  blue("Gemini"),
        "claude":  yellow("Claude"),
        "unknown": red("UNKNOWN"),
    }.get(platform, platform.upper())

    print()
    print(cyan("+" + "-" * 56 + "+"))
    title = f"  Platform Detection  ->  {platform_display}"
    print(cyan("|") + title + " " * max(0, 56 - _visible_len(title)) + cyan("|"))
    print(cyan("|") + " " * 56 + cyan("|"))
    for name, score, color_fn in [("ChatGPT", cg, green), ("Gemini ", gm, blue), ("Claude ", cl, yellow)]:
        row = f"  {bold(name)}  {bar(score, color_fn)}"
        print(cyan("|") + row + " " * max(0, 56 - _visible_len(row)) + cyan("|"))
    print(cyan("+" + "-" * 56 + "+"))
    print()


def print_section_results(section: str, rows: List[Dict], verbose: bool = False) -> None:
    """Unified section renderer for all five forensic categories (A–E).

    For E_ai_urls rows the value column shows the AI-extracted URL and the
    sub-role is appended to the artifact name, keeping the layout identical
    to all other categories while preserving all URL/SSE evidence detail.
    """
    if not rows:
        return

    # Normalise canonical key: treat legacy 2F_ai_urls same as E_ai_urls
    is_url_section = section in ("E_ai_urls", "2F_ai_urls")

    icon, short, title, color_fn = SECTION_META.get(section, (">>", section, section, cyan))

    # Filter out retrieval-chain summary rows from the visible count
    display_rows = [r for r in rows if r.get("ai_url_role", "") != "retrieval_chain_summary"] if is_url_section else rows
    chain_row    = next((r for r in rows if r.get("ai_url_role", "") == "retrieval_chain_summary"), None) if is_url_section else None

    count = len(display_rows)
    print()
    _rule(f"{icon}  {title}  ({count} artifact{'s' if count != 1 else ''})", color_fn=color_fn)

    AW, TW, VW, HW = 26, 10, 46, 34
    header = (bold(f"{'ARTIFACT':<{AW}}") + "  " +
              bold(f"{'ATTR':<{TW}}") + "  " +
              bold(f"{'VALUE / EVIDENCE':<{VW}}") + "  " +
              bold(f"{'HAR LOCATION':<{HW}}"))
    if verbose:
        RW = 40
        header += "  " + bold(f"{'RATIONALE':<{RW}}")
    print(dim("  " + "-" * 115))
    print("  " + header)
    print(dim("  " + "-" * 115))

    for row in display_rows:
        if is_url_section:
            # Build artifact label: base name + role badge
            role       = row.get("ai_url_role", "")
            role_badge = f"[{role[:10]}]" if role else ""
            artifact   = _truncate(f"{row.get('artifact', '')} {role_badge}".strip(), AW)
            # Value: prefer the extracted AI URL; fall back to generic value field
            raw_url    = row.get("ai_url", "") or row.get("value", "")
            domain     = row.get("ai_url_domain", "") or extract_domain_simple(raw_url)
            # Show domain + confidence badge in the value column
            conf       = row.get("ai_url_confidence", 0)
            try: conf  = int(conf)
            except (ValueError, TypeError): conf = 0
            conf_tag   = f" [{conf}%]" if conf else ""
            flags      = ""
            if row.get("ai_url_in_url_moderation"): flags += " MOD"
            if row.get("ai_url_after_search_start"): flags += " ↑SS"
            value      = _truncate(f"{domain}{conf_tag}{flags}", VW)
            har_loc    = _truncate(row.get("har_location", ""), HW)
        else:
            artifact   = _truncate(row.get("artifact", ""), AW)
            value      = _truncate(row.get("value", ""), VW)
            har_loc    = _truncate(row.get("har_location", ""), HW)

        attribution = row.get("attribution", "").upper()
        color_fn2, icon2 = ATTR_META.get(attribution, (white, "?"))
        attr_str = color_fn2(f"[{icon2}] {attribution:<{TW-4}}")

        line = f"  {artifact:<{AW}}  {attr_str}  {value:<{VW}}  {dim(har_loc):<{HW}}"
        if verbose:
            if is_url_section:
                # Show URL + title + rationale in verbose mode
                reason = _truncate(row.get("ai_url_title", "") or row.get("reason", ""), 40)
            else:
                reason = _truncate(row.get("reason", ""), 40)
            line += f"  {dim(reason)}"
        print(line)

    # ── URL section: print full URL lines below the table (verbose) ───────────
    if is_url_section and verbose:
        print()
        print(dim("  " + "·" * 115))
        print(f"  {dim('Full URLs  (verbose):')}")
        print(dim("  " + "·" * 115))
        for i, row in enumerate(display_rows, 1):
            raw_url = row.get("ai_url", "") or row.get("value", "")
            title_t = row.get("ai_url_title", "")
            snippet = (row.get("ai_url_snippet", "") or "")[:160]
            print(f"  {dim(f'{i:>2}.')}  {cyan(raw_url[:100])}")
            if title_t:
                print(f"        {dim('Title  :')} {title_t[:90]}")
            if snippet:
                print(f"        {dim('Content:')} {dim(snippet)}")

    # ── URL section: retrieval chain (always shown when present) ─────────────
    if is_url_section and chain_row:
        print()
        print(dim("  " + "·" * 115))
        print(f"  {dim('Retrieval Chain  — reconstructed from SSE stream evidence:')}")
        print(dim("  " + "·" * 115))
        chain = chain_row.get("ai_url_chain")
        if not chain:
            try:
                import json as _j
                chain = _j.loads(chain_row.get("value", "[]"))
            except Exception:
                chain = []
        if chain:
            prev_layer = None
            for item in chain:
                layer = item.get("layer", "")
                val   = item.get("url", "") or item.get("value", "")
                if layer != prev_layer:
                    print(f"  {dim(layer)}")
                    prev_layer = layer
                if val.startswith("http"):
                    dom = extract_domain_simple(val)
                    print(f"    {dim(chr(8594))}  {green(dom):<36}  {dim(val[:65])}")
                else:
                    print(f"    {dim(chr(8594))}  {yellow(val[:80])}")
        else:
            print(f"  {dim(chain_row.get('reason', '')[:200])}")

    print()


def print_ai_urls_section(rows: List[Dict], verbose: bool = False) -> None:
    """Backward-compatibility shim — delegates to the unified section renderer."""
    print_section_results("E_ai_urls", rows, verbose=verbose)


def print_forensic_summary(platform: str, results: Dict[str, List[Dict]],
                           source_file: str, elapsed: float,
                           cg: int = 0, gm: int = 0, cl: int = 0) -> None:
    all_rows = [r for s in results.values() for r in s]
    total    = len(all_rows)
    ai_count       = sum(1 for r in all_rows if r.get("attribution","").upper() == "AI")
    human_count    = sum(1 for r in all_rows if r.get("attribution","").upper() == "HUMAN")
    platform_count = total - ai_count - human_count

    id_count  = len(results.get("A_identity",   results.get("2A_identity",   [])))
    pr_count  = len(results.get("B_prompt",     results.get("2B_prompt",     [])))
    se_count  = len(results.get("C_security",   results.get("2C_security",   [])))
    au_count  = len(results.get("D_autonomous", results.get("2D_autonomous", [])))

    platform_display = {
        "chatgpt": "ChatGPT (OpenAI)",
        "gemini":  "Gemini (Google)",
        "claude":  "Claude (Anthropic)",
        "unknown": "UNKNOWN",
    }.get(platform, platform.upper())

    W = 58
    print()
    print(cyan("+" + "=" * W + "+"))
    t = "  FORENSIC SUMMARY"
    print(cyan("|") + cyan(bold(t)) + " " * (W - len(t)) + cyan("|"))
    print(cyan("+" + "-" * W + "+"))

    def row(label: str, val: str, cfn=white) -> None:
        content = f"  {bold(label)}  {cfn(val)}"
        pad = W - _visible_len(content)
        print(cyan("|") + content + " " * max(0, pad) + cyan("|"))

    def blank():
        print(cyan("|") + " " * W + cyan("|"))

    blank()
    row("Platform       :", platform_display, cyan)
    row("Source File    :", source_file)
    row("Analysis Time  :", f"{elapsed:.2f}s")
    row("Date           :", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    blank()
    print(cyan("|") + dim("-" * W) + cyan("|"))
    blank()
    row("Total Artifacts:", str(total), bold)
    row("[H] Human      :", str(human_count), green)
    row("[A] AI         :", str(ai_count), red)
    row("[P] Platform   :", str(platform_count), magenta)
    blank()
    print(cyan("|") + dim("-" * W) + cyan("|"))
    blank()
    row("A. Identity   :", str(id_count),  cyan)
    row("B. Prompt     :", str(pr_count),  green)
    row("C. Security   :", str(se_count),  yellow)
    row("D. Autonomous :", str(au_count),  magenta)
    # E. URLs / Domains Visited: AI URL retrieval stats (primary forensic evidence)
    ai_url_rows = [r for r in results.get("E_ai_urls", results.get("2F_ai_urls", []))
                   if r.get("ai_url_role","") != "retrieval_chain_summary"]
    cited_n   = sum(1 for r in ai_url_rows if r.get("ai_url_role","") in
                    ("cited_source","retrieved_content","url_moderation"))
    query_n   = len([r for r in results.get("E_ai_urls", results.get("2F_ai_urls", []))
                     if r.get("ai_url_role", "") == "retrieval_chain_summary"])
    sq_val    = ""
    for r in results.get("E_ai_urls", results.get("2F_ai_urls", [])):
        if r.get("ai_url_search_query",""):
            sq_val = r["ai_url_search_query"][:36]
            break
    blank()
    print(cyan("|") + dim("-" * W) + cyan("|"))
    blank()
    row("AI Retrieval   :", f"{len(ai_url_rows)} URLs  ({cited_n} cited/retrieved)", red)
    if sq_val:
        row("Search Query   :", sq_val, yellow)
    tool_val = ""
    for r in results.get("E_ai_urls", results.get("2F_ai_urls", [])):
        if r.get("ai_url_tool_name",""):
            tool_val = r["ai_url_tool_name"]
            break
    if tool_val:
        row("Tool Used      :", tool_val, magenta)
    blank()
    print(cyan("+" + "=" * W + "+"))
    print()


def print_stats_report(har_path: str, platform: str, entries_count: int,
                       results: Dict[str, List[Dict]],
                       cg: int, gm: int, cl: int) -> None:
    all_rows = [r for s in results.values() for r in s]
    total    = len(all_rows)

    by_artifact: Dict[str, int] = {}
    by_attr: Dict[str, int] = {"AI": 0, "HUMAN": 0, "PLATFORM": 0}
    for r in all_rows:
        k = r.get("artifact","")
        by_artifact[k] = by_artifact.get(k, 0) + 1
        a = r.get("attribution","").upper()
        if a in by_attr:
            by_attr[a] += 1

    print()
    _rule("HAR Statistics")
    print(f"  {bold('HAR File:')}    {har_path}")
    print(f"  {bold('Platform:')}    {platform.upper()}")
    print(f"  {bold('Entries:')}     {entries_count}")
    print(f"  {bold('Artifacts:')}   {total}")
    print(f"  {bold('Scores:')}      ChatGPT={cg}  Gemini={gm}  Claude={cl}")

    print()
    _rule("Artifact Frequency")
    for artifact, count in sorted(by_artifact.items(), key=lambda x: -x[1]):
        bar_w = min(count * 2, 28)
        print(f"  {artifact:<38}  {green('#' * bar_w)}  {count}")

    print()
    _rule("Attribution Breakdown")
    for attr, count in by_attr.items():
        pct      = count / max(total, 1) * 100
        cfn, ic  = ATTR_META.get(attr, (white, "?"))
        print(f"  {cfn(f'[{ic}] {attr}'):<22}  {count:>4}  ({pct:.1f}%)")
    print()


def print_batch_summary(results_list: List[Dict]) -> None:
    print()
    _rule("BATCH PROCESSING SUMMARY")

    header = (f"  {'FILE':<35}  {'PLATFORM':<10}  {'TOTAL':>6}  "
              f"{'AI':>4}  {'HUMAN':>5}  {'PLAT':>4}  STATUS")
    print(bold(header))
    print(dim("  " + "-" * 80))

    total_artifacts = 0
    for item in results_list:
        fname    = _truncate(item.get("file",""), 35)
        platform = item.get("platform","unknown")
        all_rows = [r for s in item.get("results",{}).values() for r in s]
        n        = len(all_rows)
        ai_n     = sum(1 for r in all_rows if r.get("attribution","").upper() == "AI")
        hu_n     = sum(1 for r in all_rows if r.get("attribution","").upper() == "HUMAN")
        pl_n     = n - ai_n - hu_n
        total_artifacts += n
        status   = item.get("status","OK")

        plat_c = {"chatgpt": green, "gemini": blue, "claude": yellow}.get(platform, dim)
        stat_c = green if status == "OK" else red

        print(f"  {fname:<35}  {plat_c(f'{platform.upper():<10}')}  "
              f"{n:>6}  {n - hu_n - pl_n:>4}  {hu_n:>5}  {pl_n:>4}  {stat_c(status)}")

    print(dim("  " + "-" * 80))
    print(f"\n  {bold('Files processed:')}  {len(results_list)}")
    print(f"  {bold('Total artifacts:')}  {total_artifacts}\n")


# ─────────────────────────────────────────────────────────────────────────────
#  ENHANCED DISPLAY — v2.0 (multi-platform, confidence scores, models)
# ─────────────────────────────────────────────────────────────────────────────

def print_multi_platform_detection(matches: list, sdks: list, models: list) -> None:
    """
    Display multi-platform detection results with confidence badges,
    evidence, detected SDKs, and detected models.

    Parameters
    ----------
    matches : List[PlatformMatch]  — from detect_all_platforms()
    sdks    : List[SDKMatch]       — from detect_sdks()
    models  : List[ModelDetection] — from extract_models()
    """
    W = 70
    print()
    print(cyan("+" + "=" * W + "+"))
    title = "  MULTI-PLATFORM DETECTION  v2.0"
    print(cyan("|") + cyan(bold(title)) + " " * (W - len(title)) + cyan("|"))
    print(cyan("+" + "-" * W + "+"))

    if not matches:
        msg = "  No known AI platform detected in this HAR file."
        print(cyan("|") + yellow(msg) + " " * (W - len(msg)) + cyan("|"))
        print(cyan("+" + "=" * W + "+"))
        print()
        return

    # ── Platform table ─────────────────────────────────────────────────────
    blank = cyan("|") + " " * W + cyan("|")
    print(blank)

    hdr = f"  {'PLATFORM':<28}  {'PROVIDER':<18}  {'CONFIDENCE':>10}"
    print(cyan("|") + bold(hdr) + " " * (W - len(hdr)) + cyan("|"))
    print(cyan("|") + dim("-" * W) + cyan("|"))

    _PLATFORM_COLORS = {
        "green":   green,
        "yellow":  yellow,
        "blue":    blue,
        "cyan":    cyan,
        "magenta": magenta,
        "red":     red,
    }

    for m in matches:
        conf = m.confidence
        if conf >= 80:
            conf_color = green
            badge = "●●●"
        elif conf >= 50:
            conf_color = yellow
            badge = "●●○"
        elif conf >= 20:
            conf_color = magenta
            badge = "●○○"
        else:
            conf_color = dim
            badge = "○○○"

        name_str     = m.platform_name[:26]
        provider_str = m.provider[:16]
        conf_str     = f"{badge} {conf:3d}%"
        row = f"  {name_str:<28}  {provider_str:<18}  {conf_str:>10}"
        print(cyan("|") + conf_color(row) + " " * max(0, W - _visible_len(row)) + cyan("|"))

        # Show top 3 evidence items indented
        for ev in m.evidence[:3]:
            ev_str = f"    ↳ {ev.description[:60]}"
            print(cyan("|") + dim(ev_str) + " " * max(0, W - _visible_len(ev_str)) + cyan("|"))

    # ── SDKs ──────────────────────────────────────────────────────────────
    if sdks:
        print(cyan("|") + dim("-" * W) + cyan("|"))
        sdk_hdr = "  FRAMEWORK / SDK FINGERPRINTS"
        print(cyan("|") + bold(sdk_hdr) + " " * (W - len(sdk_hdr)) + cyan("|"))
        for sdk in sdks:
            line = f"  {sdk.description:<40}  {sdk.confidence:3d}% confidence"
            print(cyan("|") + cyan(line) + " " * max(0, W - _visible_len(line)) + cyan("|"))

    # ── Models ────────────────────────────────────────────────────────────
    if models:
        print(cyan("|") + dim("-" * W) + cyan("|"))
        mdl_hdr = "  DETECTED AI MODELS"
        print(cyan("|") + bold(mdl_hdr) + " " * (W - len(mdl_hdr)) + cyan("|"))
        for model in models[:8]:
            line = f"  {model.model:<36}  [{model.provider}]"
            print(cyan("|") + green(line) + " " * max(0, W - _visible_len(line)) + cyan("|"))

    print(blank)
    print(cyan("+" + "=" * W + "+"))
    print()


def print_streaming_artifacts(streaming: dict) -> None:
    """Print detected streaming pattern summary."""
    if not any(v for v in streaming.values()):
        return
    print()
    _rule("Streaming Artifacts", color_fn=cyan)
    items = [
        ("SSE Streams",              streaming.get("sse_stream_count", 0)),
        ("WebSocket Sessions",       streaming.get("websocket_stream_count", 0)),
        ("Chunked Transfers",        streaming.get("chunked_transfer_count", 0)),
        ("Regeneration Requests",    streaming.get("regeneration_requests", 0)),
    ]
    for label, count in items:
        if count:
            bar = green("#" * min(count, 20))
            print(f"  {bold(label):<30}  {bar}  {count}")
    eps = streaming.get("stream_endpoints", [])
    if eps:
        print(f"  {dim('Stream endpoints:')}")
        for ep in eps[:5]:
            print(f"    {dim(ep)}")
    print()


def print_session_artifacts(sessions: dict) -> None:
    """Print extracted session/ID artifacts summary."""
    non_empty = {k: v for k, v in sessions.items() if v}
    if not non_empty:
        return
    print()
    _rule("Session & Correlation Artifacts", color_fn=yellow)
    for key, values in non_empty.items():
        label = key.replace("_", " ").title()
        print(f"  {bold(label + ':')} ({len(values)} found)")
        for val in values[:3]:
            print(f"    {dim(val[:80])}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
#  2E — URL ATTRIBUTION DISPLAY
# ─────────────────────────────────────────────────────────────────────────────

_URL_ROLE_ICONS = {
    "search_result":       "🔍",
    "cited_source":        "📰",
    "retrieved_content":   "📄",
    "supporting_source":   "🔗",
    "citation_patch_url":  "📎",
    "browsing_result":     "🌐",
    "tool_call_url":       "🛠",
    "favicon_cdn":         "🖼",
    "cdn_asset":           "📦",
    "telemetry":           "📡",
    "conversation_api":    "💬",
    "sentinel_endpoint":   "🛡",
    "platform_api":        "⚙",
    "analytics":           "📊",
    "auth_endpoint":       "🔑",
    "user_navigation":     "🧭",
    "retrieval_chain_summary": "🗺",
}


def print_url_attribution_section(rows: List[Dict], verbose: bool = False) -> None:
    """
    Display the 2E URL Attribution section with a rich evidence table.
    Shows: Role | Domain | Attribution | Confidence | Evidence
    """
    if not rows:
        return

    url_rows = [r for r in rows if r.get("url_role", "") != "retrieval_chain_summary"]
    chain_row = next((r for r in rows if r.get("url_role","") == "retrieval_chain_summary"), None)

    print()
    _rule(">>  URL ATTRIBUTION  (2E)  — Forensic URL Evidence", color_fn=blue)

    # ── Attribution breakdown ─────────────────────────────────────────────
    ai_urls   = [r for r in url_rows if r.get("attribution","").upper() == "AI"]
    hu_urls   = [r for r in url_rows if r.get("attribution","").upper() == "HUMAN"]
    pl_urls   = [r for r in url_rows if r.get("attribution","").upper() == "PLATFORM"]

    print()
    print(f"  {bold('Total URLs attributed:')} {len(url_rows)}  "
          f"  {red(f'[A] AI: {len(ai_urls)}')}"
          f"  {green(f'[H] Human: {len(hu_urls)}')}"
          f"  {magenta(f'[P] Platform: {len(pl_urls)}')}")
    print()

    # ── Table header ──────────────────────────────────────────────────────
    RW  = 4    # role icon
    DW  = 32   # domain
    AW  = 10   # attribution
    CW  = 6    # confidence
    EW  = 52   # evidence

    header = (bold(f"{'RO':<{RW}}") + "  " +
              bold(f"{'DOMAIN / URL':<{DW}}") + "  " +
              bold(f"{'ATTR':<{AW}}") + "  " +
              bold(f"{'CONF':<{CW}}") + "  " +
              bold(f"{'EVIDENCE SUMMARY':<{EW}}"))
    print(dim("  " + "-" * 112))
    print("  " + header)
    print(dim("  " + "-" * 112))

    def _print_url_row(r: Dict) -> None:
        role       = r.get("url_role", "unknown")
        icon       = _URL_ROLE_ICONS.get(role, "·")
        domain_val = r.get("url_domain") or r.get("value", "")
        # Prefer domain; truncate URL for display
        if domain_val.startswith("http"):
            domain_val = extract_domain_simple(domain_val)
        attr  = r.get("attribution", "").upper()
        conf  = r.get("url_confidence", 0)
        if isinstance(conf, str):
            try: conf = int(conf)
            except: conf = 0
        evidence  = r.get("reason", "")
        # First sentence of evidence for table
        ev_short = evidence.split(".")[0][:EW-2] if evidence else ""

        color_fn2, ic = ATTR_META.get(attr, (white, "?"))
        attr_str = color_fn2(f"[{ic}] {attr:<{AW-4}}")

        conf_color = green if conf >= 90 else (yellow if conf >= 70 else magenta)
        conf_str   = conf_color(f"{conf:3d}%")

        line = (f"  {icon:<{RW}}  {_truncate(domain_val, DW):<{DW}}  "
                f"{attr_str}  {conf_str:<{CW}}  {dim(_truncate(ev_short, EW))}")
        print(line)

        if verbose:
            # Show full evidence text indented
            full_ev = evidence[:300]
            for i in range(0, len(full_ev), 100):
                print(f"  {dim('  ↳ ' + full_ev[i:i+100])}")
            # Show snippet if available
            snippet = r.get("url_snippet", "")
            if snippet:
                print(f"  {dim('  📝 ' + str(snippet)[:100])}")
            # Show full URL
            raw = r.get("url_raw") or r.get("value","")
            if raw and raw.startswith("http"):
                print(f"  {dim('  🔗 ' + raw[:100])}")

    # ── AI URLs first (most forensically interesting) ─────────────────────
    if ai_urls:
        print()
        print(f"  {red(bold('[ AI-ATTRIBUTED URLs ]'))}  "
              f"{dim('— accessed by model tool use, not browser')}")
        print()

        # Group by role
        from collections import defaultdict
        by_role: dict = defaultdict(list)
        for r in ai_urls:
            by_role[r.get("url_role","unknown")].append(r)

        role_order = ["search_result","retrieved_content","cited_source",
                      "supporting_source","citation_patch_url","browsing_result","tool_call_url"]
        for role in role_order + [r for r in by_role if r not in role_order]:
            group = by_role.get(role, [])
            if not group:
                continue
            role_label = role.replace("_"," ").title()
            icon = _URL_ROLE_ICONS.get(role, "·")
            print(f"  {dim(f'  {icon}  {role_label} ({len(group)}):')}")
            for r in group:
                _print_url_row(r)
        print()

    # ── Human URLs ────────────────────────────────────────────────────────
    if hu_urls:
        print(f"  {green(bold('[ HUMAN-ATTRIBUTED URLs ]'))}  "
              f"{dim('— initiated by direct user action')}")
        print()
        for r in hu_urls:
            _print_url_row(r)
        print()

    # ── Platform URLs (summary — many, less interesting individually) ─────
    if pl_urls:
        print(f"  {magenta(bold('[ PLATFORM-ATTRIBUTED URLs ]'))}  "
              f"{dim('— infrastructure: CDN, telemetry, APIs')}")
        print()
        # Show top 10 only unless verbose
        shown = pl_urls if verbose else pl_urls[:10]
        for r in shown:
            _print_url_row(r)
        if not verbose and len(pl_urls) > 10:
            print(f"  {dim(f'  ... and {len(pl_urls)-10} more platform URLs (use --verbose to see all)')}")
        print()

    # ── Retrieval chain summary ───────────────────────────────────────────
    if chain_row:
        print(f"  {cyan(bold('[ URL RETRIEVAL CHAIN ]'))}  "
              f"{dim('— reconstructed from SSE stream metadata')}")
        print()
        try:
            import json as _json
            chain = _json.loads(chain_row.get("value","[]"))
            for item in chain:
                layer = item.get("layer","")
                url   = item.get("url","")[:80]
                print(f"  {dim('  →')} {bold(f'{layer:<28}')}  {dim(url)}")
        except Exception:
            print(f"  {dim(chain_row.get('value',''))}")
        print()
        print(f"  {dim(chain_row.get('reason',''))}")
        print()

    print(dim("  " + "-" * 112))


def extract_domain_simple(url: str) -> str:
    """Lightweight domain extractor for display — no imports needed."""
    try:
        import urllib.parse
        return urllib.parse.urlparse(url).netloc.lower()
    except Exception:
        return url


