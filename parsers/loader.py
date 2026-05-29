"""
HAR file loading utilities.
Logic preserved exactly from original har_forensics_elite.py.
"""

import json
from typing import Dict, List


def load_har(path: str) -> Dict:
    """Load and validate a HAR file from disk."""
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            har = json.load(f)
    except FileNotFoundError:
        raise RuntimeError(f"File not found: {path}")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON: {e}")
    if "log" not in har or "entries" not in har["log"]:
        raise RuntimeError("Not a valid HAR file — missing log.entries")
    return har


def get_entries(har: Dict) -> List[Dict]:
    """Return the list of HAR log entries."""
    return har["log"]["entries"]
