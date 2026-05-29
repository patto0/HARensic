"""
Shared helper utilities.
Logic preserved exactly from original har_forensics_elite.py.
"""

import json
import base64
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


def _headers(entry: Dict) -> Dict[str, str]:
    return {h["name"].lower(): h["value"] for h in entry["request"].get("headers", [])}


def _req_body(entry: Dict) -> Optional[Dict]:
    text = entry["request"].get("postData", {}).get("text", "")
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def _resp_body(entry: Dict) -> Optional[Any]:
    content = entry["response"]["content"]
    text = content.get("text", "")
    if not text:
        return None
    enc = content.get("encoding", "")
    if enc == "base64":
        try:
            text = base64.b64decode(text).decode("utf-8", errors="replace")
        except Exception:
            return None
    try:
        return json.loads(text)
    except Exception:
        return None


def _resp_text_raw(entry: Dict) -> str:
    content = entry["response"]["content"]
    text = content.get("text", "")
    if not text:
        return ""
    enc = content.get("encoding", "")
    if enc == "base64":
        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except Exception:
            return ""
    return text


def _safe_jwt_decode(token: str) -> Optional[Dict]:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.b64decode(payload).decode("utf-8", errors="replace"))
    except Exception:
        return None


def _path(url: str) -> str:
    return urlparse(url).path


def _ts(entry: Dict) -> str:
    return entry.get("startedDateTime", "")


def _uuid_from_url(url: str, segment: str) -> str:
    m = re.search(rf"/{re.escape(segment)}/([0-9a-f-]{{8,}})", url, re.IGNORECASE)
    return m.group(1) if m else ""
