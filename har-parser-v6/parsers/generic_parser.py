"""
Generic HAR Parser — Forensic extraction for any AI platform.
=============================================================
Used when the detected platform does not have a dedicated parser
(e.g. Grok, Perplexity, Copilot, Poe, DeepSeek, …) or when the
platform is entirely unknown.

Extracts:
  A. Identity — Identity & Session Artifacts
  B. Prompt — Prompt & Response Artifacts
  C. Security — Security & Authentication
  D. Autonomous — Autonomous & Background Actions

All output rows follow the same schema as chatgpt.py / claude.py / gemini.py.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .helpers import _headers, _req_body, _resp_body, _resp_text_raw, _ts, _path
from .loader import get_entries


# ─── Shared helpers ──────────────────────────────────────────────────────────

def _get_cookies(entry: Dict) -> Dict[str, str]:
    cookies: Dict[str, str] = {}
    for c in entry.get("request", {}).get("cookies", []):
        cookies[c.get("name", "").lower()] = c.get("value", "")
    hdrs = _headers(entry)
    raw  = hdrs.get("cookie", "")
    for part in raw.split(";"):
        kv = part.strip().split("=", 1)
        if len(kv) == 2:
            cookies[kv[0].strip().lower()] = kv[1].strip()
    return cookies


def _resp_mime(entry: Dict) -> str:
    return entry.get("response", {}).get("content", {}).get("mimeType", "").lower()


def _is_sse(entry: Dict) -> bool:
    return "event-stream" in _resp_mime(entry)


def _is_json_resp(entry: Dict) -> bool:
    mime = _resp_mime(entry)
    return "json" in mime or "javascript" in mime


def _status(entry: Dict) -> int:
    return entry.get("response", {}).get("status", 0)


_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I
)
_MODEL_RE = re.compile(
    r'"model"\s*:\s*"([a-zA-Z0-9][a-zA-Z0-9_.\-:/]{2,60})"', re.I
)
_BEARER_RE = re.compile(r"^Bearer\s+(.+)$", re.I)


def _extract_sse_text(resp_text: str) -> str:
    """Concatenate all 'data:' lines from an SSE stream into plain text."""
    chunks: List[str] = []
    for line in resp_text.splitlines():
        s = line.strip()
        if not s.startswith("data:"):
            continue
        payload = s[5:].strip()
        if payload in ("[DONE]", ""):
            continue
        try:
            obj = json.loads(payload)
            # Try common content paths
            for path in [
                ["choices", 0, "delta", "content"],
                ["choices", 0, "message", "content"],
                ["delta", "text"],
                ["text"],
                ["token"],
                ["content", 0, "text"],
            ]:
                val = obj
                try:
                    for key in path:
                        val = val[key]
                    if isinstance(val, str) and val:
                        chunks.append(val)
                        break
                except (KeyError, IndexError, TypeError):
                    continue
        except json.JSONDecodeError:
            chunks.append(payload)
    return "".join(chunks)


# ─── Section A. Identity — Identity & Session ────────────────────────────────────────

_KNOWN_SESSION_HEADERS = [
    "x-session-id", "x-perplexity-session-id", "x-kimi-device-id",
    "x-request-id", "x-correlation-id", "x-trace-id", "x-transaction-id",
    "x-ms-client-request-id", "poe-formkey", "poe-tag-id", "poe-tchannel",
    "x-you-locale", "x-pi-session", "x-device-id", "x-app-version",
]

_KNOWN_AUTH_HEADERS = [
    "authorization", "x-api-key", "api-key", "bearer", "x-session-token",
    "x-auth-token",
]

_KNOWN_ID_COOKIES = [
    "p-b", "p-redir", "auth_token", "oai-did", "session",
    "hf-chat", "kimi_token", "mistral_session",
    "characterai_sso", "janitorai_token",
]


def _generic_A_identity(entries: List[Dict], platform_name: str) -> List[Dict]:
    rows: List[Dict] = []

    user_agents:     dict = {}
    session_ids:     dict = {}
    device_ids:      dict = {}
    conversation_ids: dict = {}
    org_ids:         dict = {}

    for idx, entry in enumerate(entries):
        url  = entry["request"]["url"]
        hdrs = _headers(entry)
        loc  = f"Entry {idx}: {url[:80]}"

        # User-Agent
        ua = hdrs.get("user-agent", "")
        if ua and ua not in user_agents:
            user_agents[ua] = loc

        # Session / device headers
        for hdr in _KNOWN_SESSION_HEADERS:
            val = hdrs.get(hdr, "")
            if val and val not in session_ids:
                session_ids[val] = (hdr, loc)

        # UUIDs from URL path
        for m in _UUID_RE.finditer(url):
            uid = m.group(0)
            if uid not in conversation_ids:
                conversation_ids[uid] = loc

        # Response body: conversation/org IDs
        body = _resp_body(entry)
        if isinstance(body, dict):
            for key in ["conversation_id", "chat_id", "thread_id", "session_id"]:
                val = body.get(key, "")
                if val and str(val) not in conversation_ids:
                    conversation_ids[str(val)] = f"Response body[{key}] @ Entry {idx}"
            for key in ["organization_id", "org_id", "workspace_id"]:
                val = body.get(key, "")
                if val and str(val) not in org_ids:
                    org_ids[str(val)] = f"Response body[{key}] @ Entry {idx}"

    def _row(artifact, value, har_location, json_path, attribution, reason):
        return {
            "artifact": artifact,
            "value": value,
            "har_location": har_location,
            "json_path": json_path,
            "attribution": attribution,
            "reason": reason,
        }

    for ua, loc in user_agents.items():
        rows.append(_row(
            "user_agent", ua, f"Request Header: user-agent @ {loc}",
            "request.headers[user-agent]", "PLATFORM",
            f"AI=FALSE | HUMAN=FALSE | Platform=TRUE. Browser/client user-agent string sent to {platform_name}.",
        ))

    for val, (hdr, loc) in session_ids.items():
        rows.append(_row(
            "session_identifier", val[:120], f"Request Header: {hdr} @ {loc}",
            f"request.headers[{hdr}]", "PLATFORM",
            f"AI=FALSE | HUMAN=TRUE | Platform=TRUE. {platform_name} session or device identifier found in header '{hdr}'.",
        ))

    for uid, loc in list(conversation_ids.items())[:20]:
        rows.append(_row(
            "conversation_id", uid, loc,
            "request.url|response.body", "PLATFORM",
            f"AI=FALSE | HUMAN=TRUE | Platform=TRUE. UUID identifying a conversation on {platform_name}.",
        ))

    for oid, loc in list(org_ids.items())[:10]:
        rows.append(_row(
            "organization_id", oid, loc,
            "response.body", "PLATFORM",
            f"AI=FALSE | HUMAN=TRUE | Platform=TRUE. Organization or workspace identifier on {platform_name}.",
        ))

    return rows


# ─── Section B. Prompt — Prompts & Responses ────────────────────────────────────────

def _generic_B_prompt(entries: List[Dict], platform_name: str) -> List[Dict]:
    rows: List[Dict] = []

    for idx, entry in enumerate(entries):
        url      = entry["request"]["url"]
        method   = entry["request"].get("method", "").upper()
        loc      = f"Entry {idx}: {url[:80]}"
        resp_txt = _resp_text_raw(entry)
        post_txt = entry["request"].get("postData", {}).get("text", "") or ""

        # ── Prompt detection (POST request body) ─────────────────────────
        if method == "POST" and post_txt:
            try:
                body = json.loads(post_txt)
                if isinstance(body, dict):
                    # OpenAI-style messages array
                    messages = body.get("messages", [])
                    if isinstance(messages, list):
                        for msg in messages:
                            if not isinstance(msg, dict):
                                continue
                            role    = msg.get("role", "")
                            content = msg.get("content", "")
                            if not isinstance(content, str):
                                # content can be a list of blocks
                                content = " ".join(
                                    str(b.get("text", ""))
                                    for b in content if isinstance(b, dict)
                                )
                            if content and role == "user":
                                rows.append({
                                    "artifact":     "user_prompt",
                                    "value":        content[:400],
                                    "har_location": f"POST body messages[role=user] @ {loc}",
                                    "json_path":    "request.postData.text[messages][role=user][content]",
                                    "attribution":  "HUMAN",
                                    "reason":       (
                                        f"AI=FALSE | HUMAN=TRUE | Platform=FALSE. "
                                        f"User message sent to {platform_name}."
                                    ),
                                })
                            elif content and role in ("system", "assistant"):
                                rows.append({
                                    "artifact":     f"{role}_message",
                                    "value":        content[:400],
                                    "har_location": f"POST body messages[role={role}] @ {loc}",
                                    "json_path":    f"request.postData.text[messages][role={role}][content]",
                                    "attribution":  "AI" if role == "assistant" else "PLATFORM",
                                    "reason":       (
                                        f"AI={'TRUE' if role == 'assistant' else 'FALSE'} | "
                                        f"HUMAN=FALSE | Platform={'FALSE' if role == 'assistant' else 'TRUE'}. "
                                        f"{role.title()} message in {platform_name} request."
                                    ),
                                })

                    # Single prompt field
                    for field in ["prompt", "query", "message", "text", "q"]:
                        val = body.get(field)
                        if isinstance(val, str) and val.strip():
                            rows.append({
                                "artifact":     "user_prompt",
                                "value":        val[:400],
                                "har_location": f"POST body[{field}] @ {loc}",
                                "json_path":    f"request.postData.text[{field}]",
                                "attribution":  "HUMAN",
                                "reason":       (
                                    f"AI=FALSE | HUMAN=TRUE | Platform=FALSE. "
                                    f"Prompt field '{field}' sent to {platform_name}."
                                ),
                            })

            except json.JSONDecodeError:
                pass

        # ── SSE response text ─────────────────────────────────────────────
        if _is_sse(entry) and resp_txt:
            ai_text = _extract_sse_text(resp_txt)
            if ai_text.strip():
                rows.append({
                    "artifact":     "ai_response",
                    "value":        ai_text[:400],
                    "har_location": f"SSE stream @ {loc}",
                    "json_path":    "response.content[SSE data]",
                    "attribution":  "AI",
                    "reason":       (
                        f"AI=TRUE | HUMAN=FALSE | Platform=FALSE. "
                        f"AI-generated response tokens streamed from {platform_name}."
                    ),
                })

        # ── JSON response body ────────────────────────────────────────────
        elif _is_json_resp(entry) and resp_txt:
            try:
                resp_body = json.loads(resp_txt)
                if isinstance(resp_body, dict):
                    # OpenAI-style completion
                    for choice in resp_body.get("choices", []):
                        if not isinstance(choice, dict):
                            continue
                        msg  = choice.get("message", {})
                        text = msg.get("content", "") or choice.get("text", "")
                        if text:
                            rows.append({
                                "artifact":     "ai_response",
                                "value":        str(text)[:400],
                                "har_location": f"JSON response choices[].message.content @ {loc}",
                                "json_path":    "response.content[choices][message][content]",
                                "attribution":  "AI",
                                "reason":       (
                                    f"AI=TRUE | HUMAN=FALSE | Platform=FALSE. "
                                    f"Completed AI response from {platform_name}."
                                ),
                            })

                    # Generic text / generated_text
                    for field in ["text", "generated_text", "response", "answer", "output"]:
                        val = resp_body.get(field)
                        if isinstance(val, str) and val.strip():
                            rows.append({
                                "artifact":     "ai_response",
                                "value":        val[:400],
                                "har_location": f"JSON response[{field}] @ {loc}",
                                "json_path":    f"response.content[{field}]",
                                "attribution":  "AI",
                                "reason":       (
                                    f"AI=TRUE | HUMAN=FALSE | Platform=FALSE. "
                                    f"AI-generated text from {platform_name} response field '{field}'."
                                ),
                            })
            except json.JSONDecodeError:
                pass

        # ── Model name in response ────────────────────────────────────────
        for src_text, src_label in [(resp_txt, "response"), (post_txt, "request")]:
            for m in _MODEL_RE.finditer(src_text):
                model_name = m.group(1)
                rows.append({
                    "artifact":     "model_identifier",
                    "value":        model_name,
                    "har_location": f"{src_label} body[model] @ {loc}",
                    "json_path":    f"{src_label}.{'content' if src_label == 'response' else 'postData.text'}[model]",
                    "attribution":  "PLATFORM",
                    "reason":       (
                        f"AI=FALSE | HUMAN=FALSE | Platform=TRUE. "
                        f"AI model identifier '{model_name}' found in {src_label} from {platform_name}."
                    ),
                })

    return rows


# ─── Section C. Security — Security & Authentication ──────────────────────────────────

def _generic_C_security(entries: List[Dict], platform_name: str) -> List[Dict]:
    rows: List[Dict] = []

    seen_tokens:  set = set()
    seen_cookies: set = set()

    for idx, entry in enumerate(entries):
        url  = entry["request"]["url"]
        hdrs = _headers(entry)
        cks  = _get_cookies(entry)
        loc  = f"Entry {idx}: {url[:80]}"

        # ── Authorization headers ─────────────────────────────────────────
        auth = hdrs.get("authorization", "")
        if auth:
            token_repr = auth[:30] + "..." if len(auth) > 30 else auth
            if token_repr not in seen_tokens:
                seen_tokens.add(token_repr)

                bearer_m = _BEARER_RE.match(auth)
                if bearer_m:
                    raw_token = bearer_m.group(1)
                    # Try JWT decode
                    try:
                        parts = raw_token.split(".")
                        if len(parts) == 3:
                            pad  = parts[1] + "==" * ((-len(parts[1])) % 4 or 0)
                            payload = json.loads(base64.b64decode(pad).decode("utf-8", errors="replace"))
                            rows.append({
                                "artifact":     "jwt_claims",
                                "value":        str(payload)[:400],
                                "har_location": f"Authorization header (JWT decoded) @ {loc}",
                                "json_path":    "request.headers[authorization]",
                                "attribution":  "PLATFORM",
                                "reason":       (
                                    f"AI=FALSE | HUMAN=TRUE | Platform=TRUE. "
                                    f"JWT Bearer token sent to {platform_name}. Claims may include user identity."
                                ),
                            })
                    except Exception:
                        pass

                rows.append({
                    "artifact":     "auth_token",
                    "value":        token_repr,
                    "har_location": f"Request Header: authorization @ {loc}",
                    "json_path":    "request.headers[authorization]",
                    "attribution":  "PLATFORM",
                    "reason":       (
                        f"AI=FALSE | HUMAN=TRUE | Platform=TRUE. "
                        f"Authorization credential transmitted to {platform_name}."
                    ),
                })

        # ── API key headers ───────────────────────────────────────────────
        for hdr in ["x-api-key", "api-key"]:
            val = hdrs.get(hdr, "")
            if val and val not in seen_tokens:
                seen_tokens.add(val)
                rows.append({
                    "artifact":     "api_key",
                    "value":        val[:20] + "...",
                    "har_location": f"Request Header: {hdr} @ {loc}",
                    "json_path":    f"request.headers[{hdr}]",
                    "attribution":  "HUMAN",
                    "reason":       (
                        f"AI=FALSE | HUMAN=TRUE | Platform=TRUE. "
                        f"API key credential for {platform_name}."
                    ),
                })

        # ── Sensitive cookies ─────────────────────────────────────────────
        for ck_name in _KNOWN_ID_COOKIES:
            val = cks.get(ck_name, "")
            if val and ck_name not in seen_cookies:
                seen_cookies.add(ck_name)
                rows.append({
                    "artifact":     "session_cookie",
                    "value":        val[:60],
                    "har_location": f"Cookie: {ck_name} @ {loc}",
                    "json_path":    f"request.cookies[{ck_name}]",
                    "attribution":  "PLATFORM",
                    "reason":       (
                        f"AI=FALSE | HUMAN=TRUE | Platform=TRUE. "
                        f"Session cookie '{ck_name}' used by {platform_name} for authentication."
                    ),
                })

        # ── CSRF tokens ───────────────────────────────────────────────────
        csrf = hdrs.get("x-csrf-token", "") or hdrs.get("x-xsrf-token", "")
        if csrf and csrf not in seen_tokens:
            seen_tokens.add(csrf)
            rows.append({
                "artifact":     "csrf_token",
                "value":        csrf[:60],
                "har_location": f"Request Header: x-csrf-token @ {loc}",
                "json_path":    "request.headers[x-csrf-token]",
                "attribution":  "PLATFORM",
                "reason":       (
                    f"AI=FALSE | HUMAN=FALSE | Platform=TRUE. "
                    f"CSRF protection token used by {platform_name}."
                ),
            })

        # ── Cloudflare / WAF ──────────────────────────────────────────────
        cf = cks.get("cf_clearance", "")
        if cf and "cf_clearance" not in seen_cookies:
            seen_cookies.add("cf_clearance")
            rows.append({
                "artifact":     "waf_clearance",
                "value":        cf[:60],
                "har_location": f"Cookie: cf_clearance @ {loc}",
                "json_path":    "request.cookies[cf_clearance]",
                "attribution":  "PLATFORM",
                "reason":       (
                    f"AI=FALSE | HUMAN=FALSE | Platform=TRUE. "
                    f"Cloudflare WAF clearance cookie present on {platform_name} requests."
                ),
            })

    return rows


# ─── Section D. Autonomous — Autonomous & Background Actions ────────────────────────────

_BACKGROUND_PATH_HINTS = [
    "/telemetry", "/analytics", "/metrics", "/events", "/log",
    "/track", "/beacon", "/ping", "/health", "/status",
    "/sync", "/poll", "/heartbeat", "/usage",
    "/tool", "/plugin", "/function", "/retrieval", "/rag",
    "/search", "/memory", "/file", "/upload", "/attachment",
    "/moderation", "/flagging",
]

_AUTONOMOUS_PATHS = [
    "/actions", "/agent", "/autonomous", "/run", "/execute",
    "/code_interpreter", "/tools/", "/plugins/",
]


def _generic_D_autonomous(entries: List[Dict], platform_name: str) -> List[Dict]:
    rows: List[Dict] = []

    for idx, entry in enumerate(entries):
        url    = entry["request"]["url"]
        method = entry["request"].get("method", "").upper()
        pth    = urlparse(url).path.lower()
        loc    = f"Entry {idx}: {url[:80]}"

        # ── Background telemetry / analytics ─────────────────────────────
        for hint in _BACKGROUND_PATH_HINTS:
            if hint in pth:
                rows.append({
                    "artifact":     "background_request",
                    "value":        url[:200],
                    "har_location": f"Request URL @ {loc}",
                    "json_path":    "request.url",
                    "attribution":  "PLATFORM",
                    "reason":       (
                        f"AI=FALSE | HUMAN=FALSE | Platform=TRUE. "
                        f"Background/telemetry request to '{pth}' detected on {platform_name}."
                    ),
                })
                break

        # ── Autonomous / agentic actions ──────────────────────────────────
        for hint in _AUTONOMOUS_PATHS:
            if hint in pth:
                post_txt = entry["request"].get("postData", {}).get("text", "") or ""
                try:
                    body = json.loads(post_txt)
                    tool_name = (
                        body.get("name") or body.get("tool") or
                        body.get("function", {}).get("name", "")
                        if isinstance(body, dict) else ""
                    )
                except Exception:
                    tool_name = ""

                rows.append({
                    "artifact":     "autonomous_action",
                    "value":        (tool_name or url)[:200],
                    "har_location": f"{method} {pth} @ {loc}",
                    "json_path":    "request.url",
                    "attribution":  "AI",
                    "reason":       (
                        f"AI=TRUE | HUMAN=FALSE | Platform=TRUE. "
                        f"Autonomous/agentic endpoint '{pth}' invoked on {platform_name}."
                        + (f" Tool: {tool_name}" if tool_name else "")
                    ),
                })
                break

        # ── File uploads ──────────────────────────────────────────────────
        if method in ("POST", "PUT") and "upload" in pth:
            hdrs = _headers(entry)
            ct   = hdrs.get("content-type", "")
            rows.append({
                "artifact":     "file_upload",
                "value":        f"{method} {pth} ({ct[:60]})",
                "har_location": f"Request @ {loc}",
                "json_path":    "request.url",
                "attribution":  "HUMAN",
                "reason":       (
                    f"AI=FALSE | HUMAN=TRUE | Platform=TRUE. "
                    f"File upload operation detected. Content-Type: {ct[:60]}."
                ),
            })

        # ── WebSocket ─────────────────────────────────────────────────────
        ws_msgs = entry.get("_webSocketMessages", [])
        if ws_msgs:
            rows.append({
                "artifact":     "websocket_session",
                "value":        f"{len(ws_msgs)} frames @ {url[:80]}",
                "har_location": f"WebSocket @ Entry {idx}",
                "json_path":    "_webSocketMessages",
                "attribution":  "PLATFORM",
                "reason":       (
                    f"AI=FALSE | HUMAN=TRUE | Platform=TRUE. "
                    f"WebSocket session with {len(ws_msgs)} messages on {platform_name}."
                ),
            })

    return rows


# ─── Public entry point ──────────────────────────────────────────────────────

def parse_generic(har: Dict, platform_name: str = "Unknown AI Platform") -> Dict:
    """
    Generic forensic parser for any AI platform.

    Parameters
    ----------
    har           : Full parsed HAR dict
    platform_name : Human-readable platform name for annotation

    Returns
    -------
    dict with 'results' key containing the four forensic sections.
    """
    entries = get_entries(har)

    results = {
        "A_identity":   _generic_A_identity(entries, platform_name),
        "B_prompt":     _generic_B_prompt(entries, platform_name),
        "C_security":   _generic_C_security(entries, platform_name),
        "D_autonomous": _generic_D_autonomous(entries, platform_name),
    }

    return {"results": results, "platform": platform_name}
