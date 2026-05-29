"""
Claude HAR parsing pipeline.
Logic preserved exactly from original har_forensics_elite.py.
Confirmed from real HAR capture (May 2026).
"""

import json
import re
from datetime import datetime as dt
from typing import Dict, List, Optional, Set

from .loader import get_entries
from .helpers import _headers, _req_body, _resp_body, _resp_text_raw, _uuid_from_url


def _claude_is_completion(entry: Dict) -> bool:
    url = entry["request"]["url"]
    return (entry["request"].get("method","").upper() == "POST"
            and "/completion" in url and "/chat_conversations/" in url)

def _claude_is_conv_get(entry: Dict) -> bool:
    url = entry["request"]["url"]
    return (entry["request"].get("method","").upper() == "GET"
            and "/chat_conversations/" in url and "tree=True" in url)

def _claude_is_org_info(entry: Dict) -> bool:
    url = entry["request"]["url"].split("?")[0]
    return (entry["request"].get("method","").upper() == "GET"
            and bool(re.search(r"/api/organizations/[0-9a-f-]{8,}$", url, re.IGNORECASE)))

def _claude_is_title(entry: Dict) -> bool:
    url = entry["request"]["url"]
    return (entry["request"].get("method","").upper() == "POST"
            and url.rstrip("/").endswith("/title"))

def _claude_is_bootstrap(entry: Dict) -> bool:
    url = entry["request"]["url"]
    return (entry["request"].get("method","").upper() == "GET"
            and "/api/bootstrap/" in url and "current_user_access" in url)

def _claude_is_sync_settings(entry: Dict) -> bool:
    return (entry["request"].get("method","").upper() == "GET"
            and "/sync/settings" in entry["request"]["url"])

def _claude_is_memory(entry: Dict) -> bool:
    url = entry["request"]["url"].split("?")[0]
    return (entry["request"].get("method","").upper() == "GET"
            and url.rstrip("/").endswith("/memory"))

def _claude_is_telemetry(entry: Dict) -> bool:
    url = entry["request"]["url"]
    return "a-api.anthropic.com" in url and (url.endswith("/v1/b") or url.endswith("/v1/m"))

def _claude_is_datadog(entry: Dict) -> bool:
    return "datadoghq.com" in entry["request"]["url"]

def _claude_is_event_log(entry: Dict) -> bool:
    return "/api/event_logging/" in entry["request"]["url"]


def _claude_parse_sse(body: str) -> List[Dict]:
    events = []
    current_type: Optional[str] = None
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line: current_type = None; continue
        if line.startswith("event:"): current_type = line[6:].strip(); continue
        if line.startswith("data:"):
            payload = line[5:].strip()
            if not payload or payload == "[DONE]": continue
            try:
                parsed = json.loads(payload)
                if isinstance(parsed,dict):
                    parsed["_event_type"] = current_type or parsed.get("type","")
                    events.append(parsed)
            except json.JSONDecodeError:
                events.append({"_event_type": current_type, "_raw": payload})
    return events


def _claude_reconstruct(events: List[Dict]) -> str:
    parts = []
    for ev in events:
        if ev.get("type") == "content_block_delta":
            delta = ev.get("delta",{})
            if isinstance(delta,dict) and delta.get("type") == "text_delta":
                t = delta.get("text","")
                if t: parts.append(t)
    return "".join(parts)


def _claude_sse_meta(events: List[Dict]) -> Dict[str,str]:
    meta: Dict[str,str] = {}
    for ev in events:
        etype = ev.get("type","")
        if etype == "message_start":
            msg = ev.get("message",{})
            if isinstance(msg,dict):
                meta["message_id"]   = msg.get("id","")
                meta["message_uuid"] = msg.get("uuid","")
                meta["parent_uuid"]  = msg.get("parent_uuid","")
                meta["trace_id"]     = msg.get("trace_id","")
                meta["request_id"]   = msg.get("request_id","")
        elif etype == "content_block_start":
            cb = ev.get("content_block",{})
            if isinstance(cb,dict) and cb.get("start_timestamp"):
                meta["start_timestamp"] = cb["start_timestamp"]
        elif etype == "content_block_stop":
            if ev.get("stop_timestamp"):
                meta["stop_timestamp"] = ev["stop_timestamp"]
        elif etype == "message_delta":
            delta = ev.get("delta",{})
            if isinstance(delta,dict) and delta.get("stop_reason"):
                meta["stop_reason"] = delta["stop_reason"]
    return meta


def _claude_gen_duration(start_ts: str, stop_ts: str) -> Optional[float]:
    if not start_ts or not stop_ts: return None
    try:
        t1 = dt.fromisoformat(start_ts.replace("Z","+00:00"))
        t2 = dt.fromisoformat(stop_ts.replace("Z","+00:00"))
        return round((t2-t1).total_seconds(),3)
    except Exception: return None


def _claude_extract_prompt(body: Optional[Dict]) -> str:
    if not body: return ""
    # Web UI: plain "prompt" string (confirmed from real HAR)
    prompt = body.get("prompt")
    if isinstance(prompt,str) and prompt.strip(): return prompt.strip()
    # API/SDK: messages array
    messages = body.get("messages")
    if isinstance(messages,list):
        for msg in reversed(messages):
            if not isinstance(msg,dict) or msg.get("role") != "user": continue
            content = msg.get("content")
            if isinstance(content,str): return content.strip()
            if isinstance(content,list):
                parts = [b.get("text","") for b in content
                         if isinstance(b,dict) and b.get("type")=="text"]
                if parts: return " ".join(parts).strip()
    return ""


def parse_claude(har: Dict) -> Dict:
    """Run the full Claude forensic parsing pipeline."""
    entries = get_entries(har)
    results = {
        "A_identity": [], "B_prompt": [],
        "C_security": [], "D_autonomous": [],
        "E_ai_urls": _claude_E_ai_urls(entries)
    }

    # ── Pre-pass 1: SSE completion streams ───────────────────────────────
    conversations = []
    for i, entry in enumerate(entries):
        if not _claude_is_completion(entry): continue
        url  = entry["request"]["url"]
        body_dict = _req_body(entry)
        conv_id   = _uuid_from_url(url, "chat_conversations")
        org_id    = _uuid_from_url(url, "organizations")
        prompt    = _claude_extract_prompt(body_dict)
        model_req = (body_dict or {}).get("model","")
        parent_msg_uuid = (body_dict or {}).get("parent_message_uuid","")
        timezone  = (body_dict or {}).get("timezone","")
        resp_body_text = _resp_text_raw(entry)
        sse_events     = _claude_parse_sse(resp_body_text)
        response       = _claude_reconstruct(sse_events)
        meta           = _claude_sse_meta(sse_events)
        duration       = _claude_gen_duration(meta.get("start_timestamp",""), meta.get("stop_timestamp",""))
        conversations.append({
            "entry_index": i, "url": url, "conv_id": conv_id, "org_id": org_id,
            "prompt": prompt, "response": response, "model": model_req,
            "message_id":   meta.get("message_id",""),
            "message_uuid": meta.get("message_uuid",""),
            "parent_uuid":  meta.get("parent_uuid",""),
            "parent_msg_uuid": parent_msg_uuid,
            "trace_id":     meta.get("trace_id",""),
            "start_timestamp": meta.get("start_timestamp",""),
            "stop_timestamp":  meta.get("stop_timestamp",""),
            "stop_reason":     meta.get("stop_reason",""),
            "generation_sec":  duration,
            "timezone": timezone,
            "sse_event_count": len(sse_events),
            "started": entry.get("startedDateTime",""),
        })

    # ── Pre-pass 2: REST metadata ─────────────────────────────────────────
    org_name = ""; conv_title = ""; account_id = ""
    enabled_features: List[str] = []
    sync_integrations: List[str] = []
    memory_text = ""; conv_created_at = ""; conv_updated_at = ""
    conv_model_from_get = ""

    for entry in entries:
        url = entry["request"]["url"]
        if _claude_is_org_info(entry):
            data = _resp_body(entry)
            if isinstance(data,dict): org_name = data.get("name","") or org_name
        if _claude_is_conv_get(entry):
            data = _resp_body(entry)
            if isinstance(data,dict):
                conv_title          = data.get("name","")       or conv_title
                conv_model_from_get = data.get("model","")      or conv_model_from_get
                conv_created_at     = data.get("created_at","") or conv_created_at
                conv_updated_at     = data.get("updated_at","") or conv_updated_at
        if _claude_is_title(entry):
            data = _resp_body(entry)
            if isinstance(data,dict): conv_title = data.get("title","") or conv_title
        if _claude_is_bootstrap(entry):
            data = _resp_body(entry)
            if isinstance(data,dict):
                for feat in data.get("features",[]):
                    if (isinstance(feat,dict) and feat.get("status")=="available"
                            and feat.get("feature") and feat["feature"] not in enabled_features):
                        enabled_features.append(feat["feature"])
        if "/api/accounts/" in url and not account_id:
            account_id = _uuid_from_url(url, "accounts")
        if _claude_is_sync_settings(entry):
            data = _resp_body(entry)
            if isinstance(data,list):
                for item in data:
                    if (isinstance(item,dict) and item.get("enabled") and item.get("type")
                            and item["type"] not in sync_integrations):
                        sync_integrations.append(item["type"])
        if _claude_is_memory(entry):
            data = _resp_body(entry)
            if isinstance(data,dict): memory_text = data.get("memory","") or ""

    # ── A. Identity — Identity ─────────────────────────────────────────────────────
    if entries:
        results["A_identity"].append({
            "artifact":"session_start_time","value":entries[0].get("startedDateTime",""),
            "har_location":"HAR first entry","json_path":"log.entries[0].startedDateTime",
            "attribution":"HUMAN","reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not manage session start times. The human initiates the session through their actions. The platform timestamps the exact moment the session begins and uses this for session tracking, billing calculations, analytics, and behavioral monitoring."})
        results["A_identity"].append({
            "artifact":"session_end_time","value":entries[-1].get("startedDateTime",""),
            "har_location":"HAR last entry","json_path":"log.entries[-1].startedDateTime",
            "attribution":"HUMAN","reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not manage sessions — this is a session tracking artifact, not AI output. The human's browsing session is being tracked, and the human ends the session through their actions. The platform timestamps the session termination and uses this for analytics and calculating total interaction duration."})
    if conv_created_at:
        results["A_identity"].append({
            "artifact":"conversation_created_at","value":conv_created_at,
            "har_location":"GET /api/organizations/.../chat_conversations/<id>",
            "json_path":"response.created_at","attribution":"PLATFORM",
            "reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not timestamp conversation creation. The human's action of starting a new conversation triggers this event. The platform records the ISO timestamp and uses it for sorting, display, and retention policy enforcement."})
    if conv_updated_at:
        results["A_identity"].append({
            "artifact":"conversation_updated_at","value":conv_updated_at,
            "har_location":"GET /api/organizations/.../chat_conversations/<id>",
            "json_path":"response.updated_at","attribution":"PLATFORM",
            "reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not timestamp conversation updates. The human's messages or edits trigger the update event. The platform records the ISO timestamp of the most recent change and uses it to detect stale sessions and sort the conversation list."})

    seen_org: Set[str] = set()
    for conv in conversations:
        if conv["org_id"] and conv["org_id"] not in seen_org:
            seen_org.add(conv["org_id"])
            name_str = f" ({org_name})" if org_name else ""
            results["A_identity"].append({
                "artifact":"organization_id","value":conv["org_id"]+name_str,
                "har_location":f"Request URL Entry #{conv['entry_index']}",
                "json_path":"request.url[/organizations/<uuid>]","attribution":"PLATFORM",
                "reason":"AI=FALSE | HUMAN=TRUE | Platform=FALSE. The AI does not manage organizational accounts. The human or their organization is the entity being identified. The platform assigns the identifier and uses it for access control and usage aggregation under Team or Enterprise plans, but the value directly identifies the human organizational entity without platform enrichment."})

    if account_id:
        results["A_identity"].append({
            "artifact":"account_id","value":account_id,
            "har_location":"GET /api/accounts/<uuid>/invites",
            "json_path":"request.url[/accounts/<uuid>]","attribution":"PLATFORM",
            "reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not create account identifiers. The human owns the account being identified. The platform assigns the unique identifier format, associates usage, billing, and settings to this account, and uses it for authentication and access control."})

    seen_conv: Set[str] = set()
    for conv in conversations:
        if conv["conv_id"] and conv["conv_id"] not in seen_conv:
            seen_conv.add(conv["conv_id"])
            title_str = f' ("{conv_title}")' if conv_title else ""
            results["A_identity"].append({
                "artifact":"conversation_id","value":conv["conv_id"]+title_str,
                "har_location":f"Request URL Entry #{conv['entry_index']}",
                "json_path":"request.url[/chat_conversations/<uuid>]","attribution":"PLATFORM",
                "reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not create conversation IDs — this is session management, not AI output. The human initiates the conversation by starting a new chat, and this action triggers conversation creation. The platform generates the UUID identifier format, assigns it, and uses it for grouping all messages within that conversation."})

    for conv in conversations:
        if conv["message_id"]:
            results["A_identity"].append({
                "artifact":"message_id","value":conv["message_id"],
                "har_location":f"SSE Stream Entry #{conv['entry_index']}",
                "json_path":"response.SSE[message_start].message.id","attribution":"PLATFORM",
                "reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not generate message identifiers. The human's act of sending a message triggers ID creation. The platform assigns a unique short-form identifier to each message for referencing, editing, or deleting individual messages."})
        if conv["message_uuid"]:
            results["A_identity"].append({
                "artifact":"message_uuid","value":conv["message_uuid"],
                "har_location":f"SSE Stream Entry #{conv['entry_index']}",
                "json_path":"response.SSE[message_start].message.uuid","attribution":"PLATFORM",
                "reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not generate UUID-format message identifiers. The human's act of sending triggers UUID creation. The platform assigns this UUID internally for deduplication and idempotency across distributed systems where multiple services may handle the same message."})

    seen_models: Set[str] = set()
    for conv in conversations:
        model = conv["model"] or conv_model_from_get
        if model and model not in seen_models:
            seen_models.add(model)
            results["A_identity"].append({
                "artifact":"model_version","value":model,
                "har_location":f"POST Body Entry #{conv['entry_index']}",
                "json_path":"request.postData.model","attribution":"PLATFORM",
                "reason":"AI=TRUE | HUMAN=FALSE | Platform=TRUE. The specific model version directly characterizes which AI handled the request and is classified as an AI artifact for that reason. The human does not select a specific version in most interactions. The platform routes requests to the appropriate model, logs the version string including suffix for reproducibility and billing, and controls model availability by account tier."})

    for entry in entries:
        hdrs = _headers(entry)
        if "user-agent" in hdrs:
            results["A_identity"].append({
                "artifact":"user_agent","value":hdrs["user-agent"][:200],
                "har_location":"Request Headers","json_path":"request.headers[user-agent]",
                "attribution":"PLATFORM","reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not generate user agent strings. Although the user agent reflects the user's browser choice, it is browser-generated rather than user-written, so attribution is conservatively assigned to infrastructure. The platform receives, logs, and parses the user agent for compatibility handling, telemetry, and security analytics."})
            break

    seen_tz: Set[str] = set()
    for conv in conversations:
        if conv["timezone"] and conv["timezone"] not in seen_tz:
            seen_tz.add(conv["timezone"])
            results["A_identity"].append({
                "artifact":"user_timezone","value":conv["timezone"],
                "har_location":f"POST Body Entry #{conv['entry_index']}",
                "json_path":"request.postData.timezone","attribution":"HUMAN",
                "reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not determine the user's timezone. The human's browser reports the local timezone, reflecting where the human is located. The platform stores this value, uses it to format timestamps correctly in the UI, and applies it for analytics segmentation."})

    # ── B. Prompt — Prompts ───────────────────────────────────────────────────────
    for conv in conversations:
        if conv["prompt"]:
            results["B_prompt"].append({
                "artifact":"user_prompt","value":conv["prompt"][:500],
                "har_location":f"POST Body Entry #{conv['entry_index']}",
                "json_path":"request.postData.prompt","attribution":"HUMAN",
                "reason":"AI=FALSE | HUMAN=TRUE | Platform=FALSE. The AI does not write prompts — this is input to the AI, not output from it. The human types and submits this text, making it pure human-generated content. The platform transports this text unchanged without enrichment or transformation."})
        if conv["response"]:
            results["B_prompt"].append({
                "artifact":"ai_response","value":conv["response"][:500],
                "har_location":f"SSE Stream Entry #{conv['entry_index']}",
                "json_path":"response.SSE[content_block_delta].delta.text (reconstructed)",
                "attribution":"AI","reason":"AI=TRUE | HUMAN=FALSE | Platform=FALSE. This is pure AI model output text and the primary AI-generated artifact. Humans do not generate AI responses — this is model output only. The platform delivers but does not generate or modify the text content; no transformation is applied."})
        if conv["start_timestamp"] and conv["stop_timestamp"]:
            dur_str = f"{conv['generation_sec']}s" if conv["generation_sec"] is not None else "?"
            results["B_prompt"].append({
                "artifact":"generation_timing",
                "value":f"start={conv['start_timestamp']}  stop={conv['stop_timestamp']}  duration={dur_str}",
                "har_location":f"SSE Stream Entry #{conv['entry_index']}",
                "json_path":"SSE[content_block_start].start_timestamp / [content_block_stop].stop_timestamp",
                "attribution":"AI","reason":"AI=TRUE | HUMAN=FALSE | Platform=TRUE. Timing metrics emerge directly from the AI inference process — first-token latency and total generation time are intrinsic to how the model runs. The human does not produce timing data. The platform measures, records, and monitors these metrics to identify latency bottlenecks and optimize inference performance."})
        if conv["stop_reason"]:
            results["B_prompt"].append({
                "artifact":"stop_reason","value":conv["stop_reason"],
                "har_location":f"SSE Stream Entry #{conv['entry_index']}",
                "json_path":"SSE[message_delta].delta.stop_reason","attribution":"PLATFORM",
                "reason":"AI=TRUE | HUMAN=FALSE | Platform=TRUE. The stop reason is determined by the AI model's own generation process — whether it reached end_turn, hit a token limit, or was stopped by a content filter. The human does not control this value. The platform reads and logs the stop reason so the client can handle incomplete or truncated responses appropriately."})
        if conv["parent_msg_uuid"] and conv["message_uuid"]:
            results["B_prompt"].append({
                "artifact":"turn_chain_link",
                "value":f"parent={conv['parent_msg_uuid']} → this={conv['message_uuid']}",
                "har_location":f"POST Body + SSE Entry #{conv['entry_index']}",
                "json_path":"postData.parent_message_uuid → SSE[message_start].message.uuid",
                "attribution":"PLATFORM","reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not manage message threading or chain linking. The human does not create linking tokens. The platform generates this identifier to connect sequential messages in a multi-turn conversation chain, ensuring correct ordering and threading on the backend."})
        if conv["trace_id"]:
            results["B_prompt"].append({
                "artifact":"backend_trace_id","value":conv["trace_id"],
                "har_location":f"SSE Stream Entry #{conv['entry_index']}",
                "json_path":"SSE[message_start].message.trace_id","attribution":"PLATFORM",
                "reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not generate tracing identifiers for backend systems. The human has no involvement in distributed tracing. The platform's tracing infrastructure generates this ID to follow a request end-to-end across microservices for debugging and performance profiling."})

    if conv_title:
        results["B_prompt"].append({
            "artifact":"conversation_title","value":conv_title,
            "har_location":"POST /api/organizations/.../title",
            "json_path":"response.title","attribution":"AI",
            "reason":"AI=TRUE | HUMAN=TRUE | Platform=FALSE. Both AI and human can originate this value — the AI auto-generates it from the first message, and the human may later edit it manually. The platform stores and displays the title in the sidebar but does not itself generate or transform the text content."})
    if memory_text:
        results["B_prompt"].append({
            "artifact":"user_memory","value":memory_text[:400],
            "har_location":"GET /api/organizations/.../memory",
            "json_path":"response.memory","attribution":"PLATFORM",
            "reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not store or inject its own memory. Users do not directly write to this memory store. The platform persists and injects user memory into the AI context autonomously, influencing AI responses across sessions."})

    # ── C. Security — Security ─────────────────────────────────────────────────────
    cookies_seen: Dict[str,str] = {}
    for entry in entries:
        for cookie in entry["request"].get("cookies",[]):
            name = cookie.get("name","")
            if name and name not in cookies_seen:
                cookies_seen[name] = cookie.get("value","")[:60]
    if cookies_seen:
        results["C_security"].append({
            "artifact":"session_cookies","value":", ".join(sorted(cookies_seen.keys())[:20]),
            "har_location":"Request Cookies","json_path":"request.cookies[].name",
            "attribution":"PLATFORM","reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not manage authentication cookies. The human does not create cookie values directly. The platform's authentication system generates and exchanges session cookies to maintain the logged-in state across page reloads and browser tabs."})

    for entry in entries:
        acv = _headers(entry).get("anthropic-client-version","")
        if acv:
            results["C_security"].append({
                "artifact":"anthropic_client_version","value":acv,
                "har_location":"Request Headers",
                "json_path":"request.headers[anthropic-client-version]","attribution":"PLATFORM",
                "reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not track frontend version strings. The human does not set this value. The platform embeds the version string in the client frontend and reports it to the backend so that version-specific behavior and deprecations can be handled correctly."})
            break

    if enabled_features:
        results["C_security"].append({
            "artifact":"enabled_features","value":", ".join(enabled_features),
            "har_location":"GET /api/bootstrap/<org_uuid>/current_user_access",
            "json_path":"response.features[].feature (status=available)","attribution":"PLATFORM",
            "reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not control feature flags. The human does not directly set which features are enabled, though their subscription tier influences the outcome. The platform reads account tier and account-specific overrides to produce the list of active feature flags controlling UI features and model capabilities for the session."})
        if "geolocation" in enabled_features:
            results["C_security"].append({
                "artifact":"geolocation_enabled","value":"ENABLED",
                "har_location":"GET /api/bootstrap/<org_uuid>/current_user_access",
                "json_path":"response.features[feature=geolocation].status","attribution":"PLATFORM",
                "reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not control browser permissions. The human grants or denies location access in the browser, making this a reflection of human choice. The platform reads this boolean from the browser permission state and may use it to influence locale defaults or compliance-related behavior."})

    if sync_integrations:
        results["C_security"].append({
            "artifact":"connected_integrations","value":", ".join(sync_integrations),
            "har_location":"GET /api/organizations/.../sync/settings",
            "json_path":"response[].type (enabled=true)","attribution":"PLATFORM",
            "reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not manage integration settings. The human enables or disables third-party connectors such as Google Drive or Gmail. The platform stores the list of active integrations and uses it to scope the available tools for each request."})

    # ── D. Autonomous — Autonomous ───────────────────────────────────────────────────
    if conversations:
        results["D_autonomous"].append({
            "artifact":"ai_generation_streams","value":f"{len(conversations)} completion stream(s)",
            "har_location":"POST .../chat_conversations/.../completion",
            "json_path":"request.url contains /completion","attribution":"AI",
            "reason":"AI=TRUE | HUMAN=FALSE | Platform=TRUE. This tracks whether the AI response is streamed, and the AI generates the stream of tokens — the boolean reflects the AI's generation mode. Users do not typically control whether streaming is used; this is automatic based on response length and system configuration. The platform implements the streaming protocol, decides when to use streaming, and handles the SSE or WebSocket infrastructure."})
    total_sse = sum(c["sse_event_count"] for c in conversations)
    if total_sse:
        results["D_autonomous"].append({
            "artifact":"sse_events_total",
            "value":f"{total_sse} events across {len(conversations)} stream(s)",
            "har_location":"SSE Streams","json_path":"response.content (text/event-stream)",
            "attribution":"AI","reason":"AI=TRUE | HUMAN=FALSE | Platform=TRUE. The total count of Server-Sent Events reflects the AI's token generation process — each SSE event corresponds to a chunk of streamed output from the model. The human does not produce SSE events. The platform counts and logs the total to assist with debugging streaming completeness and verifying token delivery."})

    telemetry = [e for e in entries if _claude_is_telemetry(e)]
    if telemetry:
        b_count = sum(1 for e in telemetry if e["request"]["url"].endswith("/v1/b"))
        m_count = sum(1 for e in telemetry if e["request"]["url"].endswith("/v1/m"))
        results["D_autonomous"].append({
            "artifact":"anthropic_telemetry",
            "value":f"{b_count} beacon (/v1/b), {m_count} metrics (/v1/m) → a-api.anthropic.com",
            "har_location":"a-api.anthropic.com/v1/b|m","json_path":"request.url",
            "attribution":"PLATFORM","reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not self-report performance telemetry. The human does not generate monitoring metrics. The platform's internal monitoring systems collect and transmit this payload — covering latency, error rates, and feature usage signals — to Anthropic's own observability infrastructure."})

    dd_entries = [e for e in entries if _claude_is_datadog(e)]
    if dd_entries:
        results["D_autonomous"].append({
            "artifact":"datadog_rum_telemetry",
            "value":f"{len(dd_entries)} requests → browser-intake-us5-datadoghq.com",
            "har_location":"browser-intake-us5-datadoghq.com/api/v2/rum","json_path":"request.url",
            "attribution":"HUMAN","reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not generate Real User Monitoring data. Human interactions — page loads, JavaScript errors, and UI interaction traces — are the data source. The platform instruments the frontend with Datadog's RUM SDK and reports session and performance metrics to the third-party observability platform."})

    ev_log = [e for e in entries if _claude_is_event_log(e)]
    if ev_log:
        results["D_autonomous"].append({
            "artifact":"client_event_logging",
            "value":f"{len(ev_log)} batch(es) → /api/event_logging/v2/batch",
            "har_location":"POST /api/event_logging/v2/batch","json_path":"request.url",
            "attribution":"HUMAN","reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not perform UI interactions such as button clicks or page loads. The human's UI actions are the source events being logged. The platform instruments the frontend to capture and structure these events for UX analytics and debugging."})

    bootstrap = [e for e in entries if _claude_is_bootstrap(e)]
    if bootstrap:
        results["D_autonomous"].append({
            "artifact":"bootstrap_polling",
            "value":f"{len(bootstrap)} poll(s) → /api/bootstrap/.../current_user_access",
            "har_location":"GET /api/bootstrap/<org_uuid>/current_user_access","json_path":"request.url",
            "attribution":"PLATFORM","reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not perform initialization polling. The human does not trigger bootstrap checks directly. The platform sends this polling signal during app startup to synchronize client state with the server before any message is sent."})

    conv_gets = [e for e in entries if _claude_is_conv_get(e)]
    if conv_gets:
        results["D_autonomous"].append({
            "artifact":"conversation_state_polling",
            "value":f"{len(conv_gets)} poll(s) → /chat_conversations/<id>?tree=True",
            "har_location":"GET /api/organizations/.../chat_conversations/<id>?tree=True",
            "json_path":"request.url contains /chat_conversations/ (GET)","attribution":"PLATFORM",
            "reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not poll its own conversation state. The human does not perform state checks. The platform periodically polls to detect updates such as new messages or edits arriving from another device, keeping the session synchronized across clients."})

    title_entries = [e for e in entries if _claude_is_title(e)]
    if title_entries:
        results["D_autonomous"].append({
            "artifact":"auto_title_generation",
            "value":f'"{conv_title}"' if conv_title else f"{len(title_entries)} request(s)",
            "har_location":"POST /api/organizations/.../title","json_path":"request.url ends with /title",
            "attribution":"AI","reason":"AI=TRUE | HUMAN=FALSE | Platform=TRUE. The AI generates the conversation title by summarizing the first message. The human does not write the title, though their message is the basis for it. The platform stores the boolean flag indicating whether the title was auto-generated and controls how it is displayed in the sidebar."})

    return {"platform": "claude", "results": results}


def _claude_E_ai_urls(entries):
    """Section E. URLs / Domains Visited: Claude AI URL extraction from SSE tool_use/tool_result blocks."""
    from .claude_ai_urls import extract_claude_ai_urls
    report = extract_claude_ai_urls(entries)
    rows   = [u.to_row() for u in report.urls]

    if report.chain:
        n_cited   = len(report.cited)
        n_search  = len(report.search_results)
        n_fetched = len(report.fetched)
        inv_summary = ", ".join(
            f"{inv.tool_name}({inv.input.get('query','') or inv.input.get('url','')[:40]})"
            for inv in report.tool_invocations
        )
        reason = (
            "AI: Claude retrieval chain from SSE tool_use/tool_result blocks. "
            + "Prompt: " + report.user_prompt[:60] + ". "
            + "Model: " + report.model_name + ". "
            + "Tool invocations: " + inv_summary + ". "
            + "Total AI URLs: " + str(len(report.urls))
            + " (" + str(n_cited) + " cited, " + str(n_fetched) + " fetched, "
            + str(n_search) + " search results)."
        )
        rows.append({
            "artifact":      "claude_ai_url_retrieval_chain",
            "value":         str(len(report.chain)) + " chain steps from SSE stream",
            "har_location":  "SSE /completion stream + GET /chat_conversations citations",
            "json_path":     "SSE content_block tool_result → citations[]",
            "attribution":   "AI",
            "reason":        reason,
            "ai_url":        "",
            "ai_url_raw":    "",
            "ai_url_domain": "",
            "ai_url_title":  "",
            "ai_url_snippet":"",
            "ai_url_pub_date":"",
            "ai_url_confidence": 99,
            "ai_url_role":   "retrieval_chain_summary",
            "ai_url_sse_source": "SSE content_block[N] tool_result + conversation citations[]",
            "ai_url_sse_seq": -1,
            "ai_url_after_search_start": True,
            "ai_url_in_url_moderation":  False,
            "ai_url_search_query": report.user_prompt[:100],
            "ai_url_tool_name":    "web_search + web_fetch",
            "ai_url_chain":  report.chain,
        })
    return rows
