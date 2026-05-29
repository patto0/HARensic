"""
ASCII banner for HARensic.
Stdlib-only — no external dependencies.
"""

import sys
import os
import re

RESET     = "\033[0m"
BOLD      = "\033[1m"
DIM       = "\033[2m"
BRIGHT_CYAN   = "\033[96m"
BRIGHT_YELLOW = "\033[93m"

def _no_color():
    return (not sys.stdout.isatty() or bool(os.environ.get("NO_COLOR"))
            or os.environ.get("TERM") == "dumb")

def _c(code, text):
    return text if _no_color() else f"{code}{text}{RESET}"


BANNER = r"""
  _   _      _      ____                      _
 | | | |    / \    |  _ \  ___   _ __   ___ (_)  ___
 | |_| |   / _ \   | |_) |/ _ \ | '_ \ / __|| | / __|
 |  _  |  / ___ \  |  _ <|  __/ | | | |\__ \| || (__
 |_| |_| /_/   \_\ |_| \_\\___| |_| |_||___/|_| \___|

          F O R   C O N V E R S A T I O N A L   A I
"""

def print_banner() -> None:
    print()
    print(_c(BRIGHT_CYAN, BANNER))
    subtitle = "  Digital Forensics  |  HAR Analysis  |  AI Attribution"
    support  = "  Platforms: ChatGPT | Claude | Gemini | Grok | Perplexity | Copilot | DeepSeek | +15 more"
    sep = _c(DIM, "  " + "=" * 58)
    print(sep)
    print(_c(DIM, subtitle))
    print(_c(DIM, support))
    print(sep)
    print()
