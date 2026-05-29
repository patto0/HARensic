"""
ChatGPT HAR parsing pipeline.
Logic preserved exactly from original har_forensics_elite.py.
"""

import json
import base64
import re
from typing import Dict, List, Optional, Set

from .loader import get_entries
from .helpers import _headers, _req_body, _resp_body, _resp_text_raw, _safe_jwt_decode, _path, _ts


# ─────────────────────────────────────────────────────────────────────────────
#  DEBUG MODE  --debug-chatgpt
# ─────────────────────────────────────────────────────────────────────────────

def debug_chatgpt(entries: List[Dict], sse: List[Dict], results: Dict) -> None:
    """
    Print structured forensic debug output for a ChatGPT HAR.
    Activated by --debug-chatgpt CLI flag.
    """
    from collections import Counter
    sep = "=" * 65

    print(f"\n{sep}")
    print("  [ChatGPT Debug Report]")
    print(sep)

    # Detection summary
    sse_entries = [e for e in entries
                   if "event-stream" in e.get("response",{}).get("content",{}).get("mimeType","")]
    conv_entries = [e for e in entries if "/f/conversation" in e["request"]["url"]
                    and "prepare" not in e["request"]["url"]]
    print(f"\n[ChatGPT Detection]")
    print(f"  Total HAR entries:         {len(entries)}")
    print(f"  SSE streams:               {len(sse_entries)}")
    print(f"  Inference requests:        {len(conv_entries)}")
    print(f"  Total SSE events parsed:   {len(sse)}")
    print(f"  Sentinel calls:            {sum(1 for e in entries if 'sentinel' in e['request']['url'])}")
    print(f"  File upload calls:         {sum(1 for e in entries if '/backend-api/files' in e['request']['url'])}")

    # Endpoint coverage
    print(f"\n[Endpoint Matches]")
    endpoint_map = [
        ("/f/conversation (POST)",     lambda e: "/f/conversation" in e["request"]["url"] and "prepare" not in e["request"]["url"] and e["request"]["method"]=="POST"),
        ("/f/conversation/prepare",    lambda e: "/conversation/prepare" in e["request"]["url"]),
        ("/sentinel/chat-requirements",lambda e: "chat-requirements" in e["request"]["url"]),
        ("/sentinel/ping",             lambda e: "/sentinel/ping" in e["request"]["url"]),
        ("/backend-api/files",         lambda e: "/backend-api/files" in e["request"]["url"]),
        ("/ces/v1/t (CES analytics)",  lambda e: "/ces/v1/t" in e["request"]["url"]),
        ("/o11y/v1/traces",            lambda e: "/o11y/v1/traces" in e["request"]["url"]),
        ("/backend-api/conversations", lambda e: "/backend-api/conversations" in e["request"]["url"]),
    ]
    for label, pred in endpoint_map:
        count = sum(1 for e in entries if pred(e))
        flag = "✔" if count else "✘"
        print(f"  {flag}  {count:3}x  {label}")

    # SSE event types
    print(f"\n[SSE Events Found]")
    evt_types = Counter()
    for evt in sse:
        data = evt.get("data", {})
        et = evt.get("event_type", "")
        if isinstance(data, dict):
            tp = data.get("type", "")
            o  = data.get("o",  "")
            k  = f"event:{et}" if et else (f"type:{tp}" if tp else (f"op:{o}" if o else "(other)"))
        else:
            k = "(non-json)"
        evt_types[k] += 1
    for k, c in evt_types.most_common(12):
        print(f"  {c:4}x  {k}")

    # Per-section results
    attr_icon = {"AI": "🤖", "HUMAN": "🧑", "PLATFORM": "🏛"}
    for sec in ["A_identity","B_prompt","C_security","D_autonomous","E_urls"]:
        rows = results.get(sec, [])
        flag = "✔" if rows else "✘"
        print(f"\n[{flag} {sec}]  ({len(rows)} artifacts)")
        for r in rows:
            icon = attr_icon.get(r.get("attribution",""), "?")
            val  = str(r.get("value","")).replace("\n"," ")[:65]
            print(f"  {icon} {r.get('artifact',''):<34} = {val}")

    # Missing artifact report
    print(f"\n[Missed Artifact Analysis]")
    EXPECTED = {
        "A_identity":   ["device_id","user_id","anonymous_id","conversation_id",
                         "oai_language","user_agent","session_start_time","timezone"],
        "B_prompt":     ["user_prompt","ai_generated_response","model_used","ai_token_count",
                         "hidden_system_prompt","partial_keystroke"],
        "C_security":   ["sentinel_chat_requirements_token","sentinel_proof_token",
                         "sentinel_prepare_token","conduit_token_jwt",
                         "browser_fingerprint_blob","distributed_trace_ids"],
        "D_autonomous": ["hidden_system_prompt_injections","token_timing_telemetry",
                         "keystroke_capture_before_send","file_upload",
                         "opentelemetry_rum_telemetry","sentinel_ping_keepalive"],
    }
    any_missing = False
    for sec, wanted in EXPECTED.items():
        found = {r["artifact"] for r in results.get(sec, [])}
        for art in wanted:
            if art not in found:
                print(f"  ✘ MISSING   {sec}/{art}")
                any_missing = True
    if not any_missing:
        print("  ✔ All expected artifacts found.")
    print(f"\n{sep}\n")



def _chatgpt_extract_sse(entries: List[Dict]) -> List[Dict]:
    """Extract all SSE events from ChatGPT HAR entries."""
    all_events = []
    for i, entry in enumerate(entries):
        content = entry["response"]["content"]
        if "event-stream" not in content.get("mimeType", ""):
            continue
        text = _resp_text_raw(entry)
        if not text:
            continue
        events = []
        current_type = None
        data_lines: List[str] = []
        for line in text.splitlines():
            s = line.strip()
            if s.startswith(":"): continue
            if s.startswith("event:"):
                current_type = s[6:].strip(); continue
            if s.startswith("data:"):
                payload = s[5:].strip()
                if payload == "[DONE]":
                    current_type = None; data_lines = []; continue
                data_lines.append(payload)
                continue
            if s == "" and data_lines:
                raw = "".join(data_lines)
                try:   parsed = json.loads(raw)
                except json.JSONDecodeError: parsed = raw
                events.append({"event_type": current_type, "data": parsed})
                current_type = None; data_lines = []
        if data_lines:
            raw = "".join(data_lines)
            try:   parsed = json.loads(raw)
            except json.JSONDecodeError: parsed = raw
            events.append({"event_type": current_type, "data": parsed})
        for seq, evt in enumerate(events):
            evt["_source_entry"]   = i
            evt["_source_url"]     = entry["request"]["url"]
            evt["_source_started"] = entry.get("startedDateTime", "")
            evt["_seq"]            = seq
            all_events.append(evt)
    return all_events


def _chatgpt_A_identity(entries: List[Dict], sse: List[Dict]) -> List[Dict]:
    rows = []
    device_ids, session_ids, user_agents, languages = set(), set(), set(), set()
    for entry in entries:
        hdrs = _headers(entry)
        if "oai-device-id" in hdrs:   device_ids.add(hdrs["oai-device-id"])
        if "oai-session-id" in hdrs:  session_ids.add(hdrs["oai-session-id"])
        if "user-agent" in hdrs:      user_agents.add(hdrs["user-agent"])
        if "oai-language" in hdrs:    languages.add(hdrs["oai-language"])

    for v in device_ids:
        rows.append({"artifact":"device_id","value":v,"har_location":"Request Header: oai-device-id",
                     "json_path":"request.headers[oai-device-id]","attribution":"PLATFORM",
                     "reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not identify devices. The human owns and operates the device being identified. The platform assigns a persistent identifier to the device, stores it in cookies or localStorage, and uses it for cross-session tracking, fraud prevention, and multi-account detection."})
    for v in session_ids:
        rows.append({"artifact":"session_id","value":v,"har_location":"Request Header: oai-session-id",
                     "json_path":"request.headers[oai-session-id]","attribution":"PLATFORM",
                     "reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not manage sessions or generate session identifiers. The human's logical session is being tracked throughout their interaction. The platform generates the session identifier, assigns it, and uses it to correlate all requests, telemetry events, and conversation interactions within that session."})
    for v in user_agents:
        rows.append({"artifact":"user_agent","value":v,"har_location":"Request Header: user-agent",
                     "json_path":"request.headers[user-agent]","attribution":"PLATFORM",
                     "reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not generate user agent strings. Although the user agent reflects the user's browser choice, it is browser-generated rather than user-written, so attribution is conservatively assigned to infrastructure. The platform receives, logs, and parses the user agent for compatibility handling, telemetry, and security analytics."})
    for v in languages:
        rows.append({"artifact":"oai_language","value":v,"har_location":"Request Header: oai-language",
                     "json_path":"request.headers[oai-language]","attribution":"HUMAN",
                     "reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not select the interface language. The user selects their preferred language in settings, making human choice the driver of this value. The platform stores the language preference, applies localization based on it, and renders the UI in the selected language."})

    for entry in entries:
        if "/ces/v1/t" not in entry["request"]["url"]: continue
        body = _req_body(entry)
        if not body: continue
        if isinstance(body, list): body = body[0] if body else {}
        uid = body.get("userId") or (body.get("batch",[{}])[0].get("userId") if "batch" in body else None)
        anon = body.get("anonymousId")
        if uid:
            rows.append({"artifact":"user_id","value":uid,"har_location":"POST /ces/v1/t body",
                         "json_path":"request.postData.text[userId]","attribution":"HUMAN",
                         "reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not create user accounts or identifiers. The human owns this identity and is the entity being identified. The platform assigns the unique identifier format, manages user authentication, and uses this field for access control, attribution, and behavioral correlation."})
        if anon:
            rows.append({"artifact":"anonymous_id","value":anon,"har_location":"POST /ces/v1/t body",
                         "json_path":"request.postData.text[anonymousId]","attribution":"PLATFORM",
                         "reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not generate user identifiers. Users do not create their own anonymous IDs; this is assigned automatically before authentication. The platform generates a temporary identifier for pre-login tracking and manages it for session correlation."})
        break

    for evt in sse:
        data = evt.get("data",{})
        if isinstance(data,dict) and data.get("type") == "input_message":
            msg = data.get("input_message",{})
            uid_meta = ((msg.get("author",{}) or {}).get("metadata") or {})
            uid = uid_meta.get("user_id") if isinstance(uid_meta, dict) else None
            if uid:
                rows.append({"artifact":"user_id","value":uid,
                             "har_location":f"SSE input_message seq={evt['_seq']}",
                             "json_path":"SSE input_message.author.metadata.user_id",
                             "attribution":"HUMAN","reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not create user accounts or identifiers. The human owns this identity. The platform assigns the unique identifier format and uses it for access control, attribution, and behavioral correlation."})
                break

    for entry in entries:
        url = entry["request"]["url"]
        if "subscriptions" in url and "account_id=" in url:
            m = re.search(r"account_id=([a-f0-9\-]{36})", url)
            if m:
                rows.append({"artifact":"account_id","value":m.group(1),
                             "har_location":"GET /subscriptions query param",
                             "json_path":"request.url[account_id]","attribution":"HUMAN",
                             "reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not create account identifiers. The human owns the account being identified. The platform assigns the unique identifier format, associates usage, billing, and settings to this account, and uses it for authentication and access control."})
                break

    conv_ids: Set[str] = set()
    for entry in entries:
        url = entry["request"]["url"]
        m = re.search(r"/conversation/([a-f0-9\-]{36})", url)
        if m: conv_ids.add(m.group(1))
        body = _req_body(entry)
        if isinstance(body, dict) and body.get("conversation_id"):
            conv_ids.add(body["conversation_id"])
    for evt in sse:
        data = evt.get("data",{})
        if isinstance(data,dict) and data.get("type") == "resume_conversation_token":
            cid = data.get("conversation_id")
            if cid: conv_ids.add(cid)
    for cid in conv_ids:
        rows.append({"artifact":"conversation_id","value":cid,
                     "har_location":"URL / request body / SSE resume token",
                     "json_path":"request.url | postData | SSE resume_conversation_token",
                     "attribution":"HUMAN","reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not create conversation IDs — this is session management, not AI output. The human initiates the conversation by starting a new chat. The platform generates the UUID identifier format, assigns it, and uses it for grouping all messages within that conversation."})

    for entry in entries:
        url = entry["request"]["url"]
        if "conversation/prepare" in url or "f/conversation" in url:
            body = _req_body(entry)
            if isinstance(body,dict) and body.get("timezone"):
                rows.append({"artifact":"timezone","value":body["timezone"],
                             "har_location":f"POST {_path(url)}",
                             "json_path":"request.postData.text[timezone]","attribution":"HUMAN",
                             "reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not determine the user's regional timezone. The human's configured timezone setting reflects their geographic location and preference. The platform stores this value, normalizes timestamps using it, and presents localized times in the interface."})
                break

    server_ips: Dict[str,str] = {}
    for entry in entries:
        ip = entry.get("serverIPAddress","")
        if ip: server_ips[ip] = _path(entry["request"]["url"])
    for ip, path in server_ips.items():
        rows.append({"artifact":"server_ip","value":ip,
                     "har_location":f"HAR serverIPAddress (e.g. {path})",
                     "json_path":"log.entries[].serverIPAddress","attribution":"PLATFORM",
                     "reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI model does not control or generate server IP addresses — infrastructure that supports AI is not the same as AI-generated content. Users do not determine which server handles their request; this is automatic load balancing. The platform's load balancer routes to specific servers for geographic distribution and infrastructure management."})

    if entries:
        rows.append({"artifact":"session_start_time","value":_ts(entries[0]),
                     "har_location":"HAR first entry","json_path":"log.entries[0].startedDateTime",
                     "attribution":"HUMAN","reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not manage session start times. The human's actions initiate the session being recorded. The platform records this timestamp for session duration analytics and timeout enforcement."})
        rows.append({"artifact":"session_end_time","value":_ts(entries[-1]),
                     "har_location":"HAR last entry","json_path":"log.entries[-1].startedDateTime",
                     "attribution":"HUMAN","reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not manage session termination. The human's actions or inactivity end the session being tracked. The platform records this timestamp and pairs it with the start time to compute total session duration."})

    for evt in sse:
        data = evt.get("data",{})
        if isinstance(data,dict) and data.get("type") == "conversation_detail_metadata":
            for key in ("plan_type","cluster","cluster_region","server_request_id"):
                val = data.get(key)
                if val is not None:
                    rows.append({"artifact":key,"value":str(val),
                                 "har_location":f"SSE conversation_detail_metadata seq={evt['_seq']}",
                                 "json_path":f"SSE conversation_detail_metadata[{key}]",
                                 "attribution":"PLATFORM","reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not generate metadata fields. Users do not create SSE metadata. The platform embeds metadata such as request IDs, model identifiers, and trace information into the SSE stream for tracking and orchestration purposes."})

    return rows


def _chatgpt_B_prompt(entries: List[Dict], sse: List[Dict]) -> List[Dict]:
    rows = []

    for entry in entries:
        url = entry["request"]["url"]
        if "f/conversation" not in url or "prepare" in url: continue
        body = _req_body(entry)
        if not isinstance(body, dict): continue
        for msg in body.get("messages",[]):
            if (msg.get("author",{}) or {}).get("role") == "user":
                content = msg.get("content",{})
                parts = content.get("parts",[]) if isinstance(content,dict) else []
                text = " ".join(str(p) for p in parts if isinstance(p,str))
                if text:
                    rows.append({"artifact":"user_prompt","value":text,
                                 "har_location":f"POST {_path(url)}",
                                 "json_path":"request.postData.text[messages][role=user][content.parts]",
                                 "attribution":"HUMAN","reason":"AI=FALSE | HUMAN=TRUE | Platform=FALSE. The AI does not write prompts — this is input to the AI, not output from it. The human types and submits this text, making it pure human-generated content. The platform transports this text unchanged without enrichment or transformation."})

    for entry in entries:
        url = entry["request"]["url"]
        if "conversation/prepare" not in url: continue
        body = _req_body(entry)
        if not isinstance(body,dict): continue
        pq = body.get("partial_query") or {}
        parts = (pq.get("content") or {}).get("parts",[])
        keystroke = parts[0] if parts else None
        if keystroke is not None:
            rows.append({"artifact":"partial_keystroke","value":str(keystroke),
                         "har_location":f"POST {_path(url)}",
                         "json_path":"request.postData.text[partial_query.content.parts[0]]",
                         "attribution":"HUMAN","reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not type or capture keystrokes — this is human behavior telemetry. The human performs the typing action, and the artifact captures human behavior including pauses, edits, deletions, and typing cadence. The platform's telemetry system captures the keystroke data, creates structured records of typing behavior, and timestamps the draft evolution."})

    models_seen: Set[str] = set()
    for entry in entries:
        body = _req_body(entry)
        if isinstance(body,dict) and body.get("model"):
            models_seen.add(body["model"])
    for model in models_seen:
        rows.append({"artifact":"model_used","value":model,
                     "har_location":"Request body [model] field",
                     "json_path":"request.postData.text[model]","attribution":"AI",
                    "reason":"AI=TRUE | HUMAN=FALSE | Platform=TRUE. This identifies which AI model processed the request and is classified as an AI artifact because it directly characterizes the AI that generated the response. Users do not select the model in most requests — this is logged automatically based on subscription and availability. The platform routes requests to specific models, logs which model handled each request, and controls model selection based on account tier."})

    for evt in sse:
        data = evt.get("data",{})
        if isinstance(data,dict) and data.get("type") == "input_message":
            msg = data.get("input_message",{})
            content = msg.get("content",{})
            parts = content.get("parts",[]) if isinstance(content,dict) else []
            text = " ".join(str(p) for p in parts if isinstance(p,str))
            if text:
                rows.append({"artifact":"user_prompt_server_confirmed","value":text,
                             "har_location":f"SSE input_message seq={evt['_seq']}",
                             "json_path":"SSE input_message.content.parts","attribution":"HUMAN",
                             "reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. While this artifact is based on human input, it represents the server-processed version which may differ from what the user typed due to platform sanitization — so it is not purely human-generated. The AI processes this exact text during inference, making it the authoritative prompt the AI receives. The platform confirms, sanitizes, and potentially modifies the prompt to create this server-side authoritative version."})

    for evt in sse:
        data = evt.get("data",{})
        if not isinstance(data,dict): continue
        v = data.get("v",{})
        if not isinstance(v,dict): continue
        msg = v.get("message",{})
        if not isinstance(msg,dict): continue
        hidden = (msg.get("metadata") or {}).get("is_visually_hidden_from_conversation",False)
        author_role = (msg.get("author") or {}).get("role","")
        if hidden or author_role == "system":
            content = msg.get("content",{})
            parts = (content.get("parts",[]) if isinstance(content,dict) else [])
            text = " ".join(str(p) for p in parts if isinstance(p,str))
            rows.append({"artifact":"hidden_system_prompt","value":text[:500] if text else "[empty]",
                         "har_location":f"SSE delta seq={evt['_seq']}",
                         "json_path":"SSE delta.v.message.metadata.is_visually_hidden_from_conversation",
                         "attribution":"PLATFORM",
                         "reason":"AI=TRUE | HUMAN=FALSE | Platform=TRUE. The AI receives this as behavioral instructions defining its constraints, formatting rules, and operational policies — it is critical for understanding AI responses and is therefore categorized as an AI artifact. Users do not write the system prompt and it is hidden from the user interface entirely. The platform authors the system prompt, injects it into every AI request, and controls AI behavior through it."})

    # ── ai_generated_response: group per-turn by source SSE entry ──────────────
    # Each call to /f/conversation produces one SSE stream (one HAR entry).
    # We group append-patch events by _source_entry so each turn gets its own
    # ai_generated_response artifact rather than all turns concatenated.
    from collections import defaultdict
    turn_tokens: dict = defaultdict(list)
    for evt in sse:
        data = evt.get("data", {})
        if not isinstance(data, dict):
            continue
        src_entry = evt.get("_source_entry", -1)
        o = data.get("o", "")
        p = str(data.get("p", ""))

        # Strategy A: delta append patch  {"p": ".../parts/0", "o": "append", "v": "chunk"}
        if o == "append" and "content/parts" in p:
            val = data.get("v", "")
            if isinstance(val, str):
                turn_tokens[src_entry].append(val)
            continue

        # Strategy B: root-level delta with full/partial parts list
        # (assistant message delta with content already set)
        v = data.get("v", {})
        if isinstance(v, dict) and not p:
            msg = v.get("message", {})
            if isinstance(msg, dict):
                author = (msg.get("author") or {})
                if isinstance(author, dict) and author.get("role") == "assistant":
                    content = msg.get("content", {})
                    if isinstance(content, dict):
                        for part in content.get("parts", []):
                            if isinstance(part, str) and part:
                                if not turn_tokens[src_entry]:
                                    turn_tokens[src_entry].append(part)

        # Strategy C: implicit text continuation — v is a plain string, no o/p
        # ChatGPT sends most response tokens as bare {"v": "chunk"} events after
        # the initial append. These have o="" and p="" but v is the next text chunk.
        elif isinstance(v, str) and v and not o and not p:
            turn_tokens[src_entry].append(v)

    total_tokens = sum(len(v) for v in turn_tokens.values())
    for src_entry_idx in sorted(turn_tokens.keys()):
        toks = turn_tokens[src_entry_idx]
        if not toks:
            continue
        response_text = "".join(toks)
        rows.append({"artifact": "ai_generated_response",
                     "value": response_text[:800],
                     "har_location": f"SSE delta stream (HAR entry #{src_entry_idx})",
                     "json_path": "SSE delta[o=append][p~content/parts][v]",
                     "attribution": "AI",
                     "reason": "AI=TRUE | HUMAN=FALSE | Platform=FALSE. This is the core output text produced by the language model during inference and is the primary AI artifact in any conversation. Humans do not generate this text — they generate the prompt that triggers it. The platform streams and delivers the response but does not generate or modify the text content."})
    if total_tokens:
        rows.append({"artifact": "ai_token_count",
                     "value": str(total_tokens),
                     "har_location": "SSE delta append operations (all turns)",
                     "json_path": "SSE delta[o=append] count",
                     "attribution": "AI",
                     "reason": "AI=TRUE | HUMAN=FALSE | Platform=TRUE. Token count emerges directly from the AI inference process — tokens are generated during model processing and the count is a byproduct of AI generation. Humans do not count tokens; this is computed automatically during inference. The platform measures, records, and reports the token count for billing calculations and context window management."})

    for evt in sse:
        data = evt.get("data",{})
        if isinstance(data,dict) and data.get("type") == "title_generation":
            rows.append({"artifact":"ai_auto_title","value":data.get("title",""),
                         "har_location":f"SSE title_generation seq={evt['_seq']}",
                         "json_path":"SSE title_generation[title]","attribution":"AI",
                         "reason":"AI=TRUE | HUMAN=FALSE | Platform=FALSE. The AI model generates the title using summarization techniques by analyzing conversation content through inference. The human does not write this title, though they write the conversation content it is based on. The platform only stores and displays what the AI generated."})

    for entry in entries:
        if "user_system_messages" not in entry["request"]["url"]: continue
        resp = _resp_body(entry)
        if isinstance(resp,dict):
            rows.append({"artifact":"custom_instructions_enabled",
                         "value":str(resp.get("enabled","")),
                         "har_location":"GET /user_system_messages","json_path":"response[enabled]",
                         "attribution":"HUMAN","reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not control custom instruction settings. The human enables or disables custom instructions through their account settings. The platform reads and applies this toggle to shape AI behavior per the user's preference."})
            for field in ("about_user_message","about_model_message"):
                val = resp.get(field,"")
                if val:
                    rows.append({"artifact":f"custom_instructions_{field}","value":str(val)[:500],
                                 "har_location":"GET /user_system_messages",
                                 "json_path":f"response[{field}]","attribution":"HUMAN",
                                 "reason":"AI=FALSE | HUMAN=TRUE | Platform=FALSE. The AI does not write custom instructions. The human authors and saves this text as personal preferences. The platform stores and injects this text into the system prompt but does not modify or generate the content itself."})
        break

    for entry in entries:
        if "/memories" not in entry["request"]["url"]: continue
        resp = _resp_body(entry)
        if isinstance(resp,dict):
            rows.append({"artifact":"memory_tokens_loaded","value":str(resp.get("memory_num_tokens",0)),
                         "har_location":"GET /memories","json_path":"response[memory_num_tokens]",
                         "attribution":"PLATFORM","reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not store or inject its own memory. Users do not directly write to this memory store. The platform persists and injects user memory token counts into context, influencing AI responses across sessions."})
        break

    return rows


def _chatgpt_C_security(entries: List[Dict], sse: List[Dict]) -> List[Dict]:
    rows = []
    auth_bearer = None
    sentinel_req_tokens: Dict[str,str] = {}
    sentinel_proof_tokens: Dict[str,str] = {}

    for entry in entries:
        hdrs = _headers(entry)
        url = entry["request"]["url"]
        ts  = _ts(entry)

        if "authorization" in hdrs and auth_bearer is None:
            auth_bearer = hdrs["authorization"]
            rows.append({"artifact":"auth_bearer_token","value":auth_bearer[:60]+"...",
                         "har_location":f"Request Header: authorization ({_path(url)})",
                         "json_path":"request.headers[authorization]","attribution":"HUMAN",
                         "reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not manage session authentication. Users do not create bearer tokens manually. The platform's authentication system generates and validates this token to maintain the logged-in state and authorize API requests."})

        tok = hdrs.get("openai-sentinel-chat-requirements-token","")
        if tok and tok not in sentinel_req_tokens:
            sentinel_req_tokens[tok] = ts
            rows.append({"artifact":"sentinel_chat_requirements_token","value":tok[:80]+"...",
                         "har_location":"Request Header (sentinel)","attribution":"PLATFORM",
                         "json_path":"request.headers[openai-sentinel-chat-requirements-token]",
                         "reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not generate security tokens — these are anti-abuse and validation mechanisms, not AI output. Users do not create security tokens; they are automatically generated during security workflows. The platform security system generates this token to validate chat prerequisites before inference begins and to enforce anti-abuse checks."})

        proof = hdrs.get("openai-sentinel-proof-token","")
        if proof and proof not in sentinel_proof_tokens:
            sentinel_proof_tokens[proof] = ts
            rows.append({"artifact":"sentinel_proof_token","value":proof[:80]+"...",
                         "har_location":"Request Header","attribution":"PLATFORM",
                         "json_path":"request.headers[openai-sentinel-proof-token]",
                         "reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not generate proof of human interaction tokens. Users do not directly create these tokens, though they are derived from legitimate human behavior signals. The platform's anti-automation system generates this token to prove legitimate browser or human interaction as part of its abuse prevention workflow."})

        extra = hdrs.get("openai-sentinel-extra-data","")
        if extra:
            try:
                pad = extra + "=" * (-len(extra) % 4)
                decoded = json.loads(base64.b64decode(pad).decode("utf-8","replace"))
                rows.append({"artifact":"sentinel_extra_data","value":json.dumps(decoded)[:200],
                             "har_location":"Request Header: openai-sentinel-extra-data (decoded)",
                             "json_path":"request.headers[openai-sentinel-extra-data]",
                             "attribution":"PLATFORM","reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not generate supplementary security telemetry. Users do not create this artifact manually. The platform's security systems collect this supplementary payload containing behavioral metrics, device information, and anti-bot signals for fraud detection and anomaly analysis."})
            except Exception: pass

    for entry in entries:
        if "sentinel/chat-requirements/prepare" not in entry["request"]["url"]: continue
        body = _req_body(entry)
        if isinstance(body,dict) and "p" in body:
            fp_blob = body["p"]
            rows.append({"artifact":"browser_fingerprint_blob","value":fp_blob[:100]+"...",
                         "har_location":"POST /sentinel/chat-requirements/prepare",
                         "json_path":"request.postData.text[p]","attribution":"PLATFORM",
                         "reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not perform browser fingerprinting — this is security and tracking infrastructure, not AI generation. Although the fingerprint is derived from the user's device characteristics, the user does not actively create it; it is passively collected. The platform's fingerprinting scripts collect device signals, encode and process the blob, and use it for fraud detection and device correlation."})
        resp = _resp_body(entry)
        if isinstance(resp,dict) and resp.get("prepare_token"):
            rows.append({"artifact":"sentinel_prepare_token","value":resp["prepare_token"][:80]+"...",
                         "har_location":"POST /sentinel/chat-requirements/prepare response",
                         "json_path":"response[prepare_token]","attribution":"PLATFORM",
                         "reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not initialize security verification pipelines. Users do not create preparation tokens. The platform generates this initialization token during the preparation stage of its security verification pipeline to establish anti-bot and abuse-prevention context before processing begins."})
        if isinstance(resp,dict) and resp.get("persona"):
            rows.append({"artifact":"account_privilege_flag","value":resp["persona"],
                         "har_location":"POST /sentinel/chat-requirements/prepare response",
                         "json_path":"response[persona]","attribution":"PLATFORM",
                         "reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI model does not determine or generate subscription tiers — this is a business and billing system decision, not an AI inference output. The platform's billing system assigns the tier (Free, Plus, Pro, Enterprise) and reads this flag to gate features and model access."})
        break

    for entry in entries:
        if "sentinel/chat-requirements/finalize" not in entry["request"]["url"]: continue
        resp = _resp_body(entry)
        if isinstance(resp,dict) and resp.get("token"):
            rows.append({"artifact":"sentinel_finalize_token","value":resp["token"][:80]+"...",
                         "har_location":"POST /sentinel/chat-requirements/finalize",
                         "json_path":"response[token]","attribution":"PLATFORM",
                         "reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI plays no role in finalizing security verification. Users do not create finalization tokens. The platform generates this token during the final stage of request verification to confirm that earlier security checks completed successfully."})
        break

    for entry in entries:
        if "conversation/prepare" not in entry["request"]["url"]: continue
        resp = _resp_body(entry)
        if isinstance(resp,dict) and resp.get("conduit_token"):
            token = resp["conduit_token"]
            decoded = _safe_jwt_decode(token)
            rows.append({"artifact":"conduit_token_jwt","value":token[:80]+"...",
                         "har_location":"POST /f/conversation/prepare response",
                         "json_path":"response[conduit_token]","attribution":"PLATFORM",
                         "reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI model does not generate authentication or routing tokens. Users do not create JWT tokens manually. The platform's gateway and conduit systems generate this token containing claims related to permissions, regions, clusters, expiry, and user state for backend routing and authorization."})
            if decoded:
                for k in ("conduit_uuid","conduit_location","cluster"):
                    if decoded.get(k):
                        rows.append({"artifact":f"conduit_{k}","value":str(decoded[k]),
                                     "har_location":"conduit_token JWT payload",
                                     "json_path":f"JWT.{k}","attribution":"PLATFORM",
                                     "reason":f"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI plays no role in geographic or cluster routing embedded in JWT tokens. Users do not create or control conduit JWT claims. The platform embeds these routing claims (conduit_uuid, conduit_location, cluster) so that load balancers and orchestration systems can route requests efficiently across data centers."})
        break

    trace_ids: Set[str] = set()
    for entry in entries:
        tp = _headers(entry).get("traceparent","")
        if tp:
            parts = tp.split("-")
            if len(parts) == 4: trace_ids.add(parts[1])
    if trace_ids:
        rows.append({"artifact":"distributed_trace_ids","value":"|".join(list(trace_ids)[:10]),
                     "har_location":"Request Header: traceparent","json_path":"request.headers[traceparent]",
                     "attribution":"PLATFORM","reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not generate tracing IDs — this is backend observability infrastructure, not AI output. Users do not create trace IDs; this is automatic backend instrumentation. The platform's distributed tracing system such as OpenTelemetry or Jaeger generates these identifiers to follow requests across microservices."})

    return rows


def _chatgpt_D_autonomous(entries: List[Dict], sse: List[Dict]) -> List[Dict]:
    rows = []
    raw_data = json.dumps([e.get("data") for e in sse])

    if "super_widget" in raw_data:
        for evt in sse:
            data = evt.get("data",{})
            if isinstance(data,dict) and "super_widget" in json.dumps(data):
                rows.append({"artifact":"autonomous_web_search","value":"DETECTED",
                             "har_location":f"SSE event seq={evt['_seq']}",
                             "json_path":"SSE delta[v contains super_widget]","attribution":"AI",
                             "reason":"AI=TRUE | HUMAN=FALSE | Platform=TRUE. The AI autonomously initiated a web search without the user clicking a search button. This is a platform-mediated AI action — the AI model decided to search, and the platform executed the retrieval on the model's behalf."})
                break

    navlink_count = raw_data.count("navlinks")
    if navlink_count > 0:
        rows.append({"artifact":"web_search_results_injected","value":f"{navlink_count} navlink block(s)",
                     "har_location":"SSE events containing navlinks",
                     "json_path":"SSE delta[v contains navlinks]","attribution":"AI",
                     "reason":"AI=TRUE | HUMAN=FALSE | Platform=TRUE. External web data was retrieved and injected into the AI context by the platform at the AI's request. The AI's generation is shaped by this external data, making it an AI-associated artifact."})

    hidden_count = 0
    for evt in sse:
        data = evt.get("data",{})
        if not isinstance(data,dict): continue
        v = data.get("v",{})
        if isinstance(v,dict):
            msg = v.get("message",{})
            if isinstance(msg,dict):
                if (msg.get("metadata") or {}).get("is_visually_hidden_from_conversation",False):
                    hidden_count += 1
    if hidden_count:
        rows.append({"artifact":"hidden_system_prompt_injections","value":str(hidden_count),
                     "har_location":"SSE events with is_visually_hidden=True",
                     "json_path":"SSE delta.v.message.metadata.is_visually_hidden_from_conversation",
                     "attribution":"AI",
                     "reason":"AI=TRUE | HUMAN=FALSE | Platform=TRUE. The AI receives these as instructions that modify its behavior, defining how it responds and what constraints it follows. Users do not write system prompt injections; these are internal platform instructions. The platform dynamically inserts these instructions, including safety rules, temporary policies, and tool permissions, and controls when and how they are applied."})

    for entry in entries:
        if "conversation/prepare" not in entry["request"]["url"]: continue
        body = _req_body(entry)
        if isinstance(body,dict) and body.get("partial_query"):
            rows.append({"artifact":"keystroke_capture_before_send","value":"DETECTED",
                         "har_location":f"POST {_path(entry['request']['url'])}",
                         "json_path":"request.postData.text[partial_query]","attribution":"PLATFORM",
                         "reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not type or capture keystrokes — this is human behavior telemetry. The human performs the typing action, and the artifact captures human behavior including pauses, edits, deletions, and typing cadence. The platform's telemetry system captures the keystroke data, creates structured records of typing behavior, and timestamps the draft evolution."})
            break

    for entry in entries:
        if "/lat/r" in entry["request"]["url"]:
            body = _req_body(entry)
            if isinstance(body,dict):
                timing = {k:body.get(k) for k in ("model","count_tokens","ts_first_token_ms",
                          "ts_mean_token_without_first_ms","ts_total_request_ms") if body.get(k) is not None}
                rows.append({"artifact":"token_timing_telemetry","value":json.dumps(timing),
                             "har_location":"POST /lat/r","json_path":"request.postData[ts_first_token_ms ...]",
                             "attribution":"AI","reason":"AI=TRUE | HUMAN=FALSE | Platform=TRUE. Timing metrics emerge directly from the AI inference process — first-token latency, streaming intervals, and throughput are intrinsic to how the model generates tokens. Humans do not produce timing metrics; this is computed automatically during inference. The platform measures, records, and monitors these metrics for performance optimization and AI attribution analysis."})

    o11y_calls = sum(1 for e in entries if "o11y/v1/traces" in e["request"]["url"])
    if o11y_calls:
        rows.append({"artifact":"opentelemetry_rum_telemetry","value":f"{o11y_calls} batches",
                     "har_location":f"POST /o11y/v1/traces ({o11y_calls}×)",
                     "json_path":"request.postData resourceSpans","attribution":"PLATFORM",
                    "reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not generate Real User Monitoring telemetry — this tracks user interactions, not AI output. Human interactions including clicks, navigation, and scrolling are the data source. The platform's RUM system instruments the frontend to capture metrics and reports latency, resource loading, and performance data."})

    ces_count = sum(1 for e in entries if "/ces/v1/t" in e["request"]["url"])
    if ces_count:
        rows.append({"artifact":"user_behaviour_analytics","value":f"{ces_count} events",
                     "har_location":f"POST /ces/v1/t ({ces_count}×)",
                     "json_path":"request.postData.text[event]","attribution":"PLATFORM",
                    "reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not perform analytics on user behavior — this tracks human interactions, not AI output. Human actions including typing speed, scrolling, and clicks are the data source. The platform's analytics system generates the structured behavioral telemetry, measures interaction patterns, and uses this for UX optimization and bot detection."})

    connector_polls = sum(1 for e in entries if "aip/connectors" in e["request"]["url"])
    if connector_polls:
        rows.append({"artifact":"connector_state_polling","value":f"{connector_polls} polls",
                     "har_location":f"POST /aip/connectors ({connector_polls}×)",
                     "json_path":"request.url contains /aip/connectors","attribution":"PLATFORM",
                    "reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not monitor external integrations — this is infrastructure monitoring, not AI generation. Users do not perform polling checks manually. The platform periodically checks the status of connectors such as Google Drive or Slack and manages integration health monitoring automatically in the background."})

    sentinel_pings = sum(1 for e in entries if "sentinel/ping" in e["request"]["url"])
    if sentinel_pings:
        rows.append({"artifact":"sentinel_ping_keepalive","value":f"{sentinel_pings} pings",
                     "har_location":f"POST /sentinel/ping ({sentinel_pings}×)",
                     "json_path":"request.url contains /sentinel/ping","attribution":"PLATFORM",
                    "reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not send heartbeat requests to maintain sessions. Users do not trigger keepalive pings manually. The platform's session management system sends these periodic signals to confirm the browser remains connected and responsive, preventing session timeouts."})

    stream_polls = sum(1 for e in entries if "stream_status" in e["request"]["url"])
    if stream_polls:
        rows.append({"artifact":"stream_status_polling","value":f"{stream_polls} polls",
                     "har_location":"GET /conversation/.../stream_status","json_path":"request.url",
                     "attribution":"PLATFORM","reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not monitor its own streaming status. Users do not perform streaming status checks manually. The platform's frontend uses this mechanism to monitor whether AI response streaming is active, completed, interrupted, or stalled, managing SSE and WebSocket architectures accordingly."})


    # ── File upload artifacts (user uploaded files to ChatGPT) ───────────────
    seen_file_ids: Set[str] = set()
    for _fu_entry in entries:
        _fu_url    = _fu_entry["request"]["url"]
        _fu_method = _fu_entry["request"].get("method", "").upper()
        if _fu_method == "POST" and "/backend-api/files" in _fu_url and "process_upload" not in _fu_url:
            _fu_body = _req_body(_fu_entry)
            _fu_resp = _resp_body(_fu_entry)
            if isinstance(_fu_body, dict) and _fu_body.get("file_name"):
                _fu_fname  = _fu_body["file_name"]
                _fu_fsize  = _fu_body.get("file_size", 0)
                _fu_tz_min = _fu_body.get("timezone_offset_min")
                _fu_fid    = (_fu_resp.get("file_id","") if isinstance(_fu_resp,dict) else "")
                if _fu_fid and _fu_fid not in seen_file_ids:
                    seen_file_ids.add(_fu_fid)
                    rows.append({"artifact":"file_upload",
                                 "value":f"{_fu_fname} ({_fu_fsize} bytes) → {_fu_fid}",
                                 "har_location":f"POST {_path(_fu_url)}",
                                 "json_path":"request.postData.text[file_name|file_size] / response[file_id]",
                                 "attribution":"HUMAN",
                                 "reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The file was chosen and submitted by the human user. The AI does not upload files — it receives and processes them. The platform registers the upload, assigns a file_id, and stages the file for AI processing."})
                    if _fu_tz_min is not None:
                        rows.append({"artifact":"timezone_offset_min",
                                     "value":str(_fu_tz_min),
                                     "har_location":f"POST {_path(_fu_url)} body",
                                     "json_path":"request.postData.text[timezone_offset_min]",
                                     "attribution":"HUMAN",
                                     "reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not determine the user timezone. The value reflects where the human is located. The platform uses it to calculate local timestamps and reconstruct accurate event timelines."})

    return rows


def parse_chatgpt(har: Dict) -> Dict:
    """Run the full ChatGPT forensic parsing pipeline."""
    entries = get_entries(har)
    sse     = _chatgpt_extract_sse(entries)
    return {
        "platform": "chatgpt",
        "results": {
            "A_identity":   _chatgpt_A_identity(entries, sse),
            "B_prompt":     _chatgpt_B_prompt(entries, sse),
            "C_security":   _chatgpt_C_security(entries, sse),
            "D_autonomous": _chatgpt_D_autonomous(entries, sse),
        }
    }


# ─────────────────────────────────────────────────────────────────────────────
#  2E — URL ATTRIBUTION (new forensic section)
# ─────────────────────────────────────────────────────────────────────────────

def _chatgpt_E_urls(entries: List[Dict], sse: List[Dict]) -> List[Dict]:
    """
    Forensic URL attribution section (2E).

    Runs the full URL attribution pipeline and returns rows in the
    standard artifact-row format so they slot into existing display/export.
    Each row carries extended URL-specific fields:
        url_raw, url_domain, url_confidence, url_trigger,
        url_role, url_snippet, url_pub_date, url_timeline, url_source_type
    """
    from .url_attribution import run_url_attribution
    artifacts, timeline, chain = run_url_attribution(entries)

    rows = []
    for a in artifacts:
        rows.append(a.to_row())

    # Append the relationship chain as a single summary row
    if chain:
        import json as _json
        rows.append({
            "artifact":     "url_retrieval_chain",
            "value":        _json.dumps(
                [{"layer": c["layer_name"], "url": c["value"]} for c in chain], indent=None
            )[:500],
            "har_location": "SSE stream metadata (reconstructed chain)",
            "json_path":    "SSE search_result_groups → content_references → sources_footnote",
            "attribution":  "AI",
            "reason": (
                "AI: The complete URL retrieval chain was reconstructed from SSE stream metadata. "
                f"The AI issued {len(timeline.search_queries)} search query(ies), "
                f"received {sum(1 for c in chain if c['layer']==1)} raw results, "
                f"read {sum(1 for c in chain if c['layer']==2)} pages, "
                f"and cited {sum(1 for c in chain if c['layer']==3)} sources. "
                "This chain proves end-to-end AI autonomous web retrieval."
            ),
            "url_raw":          "",
            "url_domain":       "",
            "url_confidence":   99,
            "url_trigger":      "search_start",
            "url_role":         "retrieval_chain_summary",
            "url_snippet":      "",
            "url_pub_date":     "",
            "url_timeline":     timeline.search_start_ts,
            "url_source_type":  "derived",
        })

    return rows


# ── Monkey-patch parse_chatgpt to include 2E ─────────────────────────────────
_original_parse_chatgpt = parse_chatgpt

def parse_chatgpt(har: Dict) -> Dict:
    """Run the full ChatGPT forensic parsing pipeline including URL attribution (E_urls/E_ai_urls)."""
    entries = get_entries(har)
    sse     = _chatgpt_extract_sse(entries)
    return {
        "platform": "chatgpt",
        "results": {
            "A_identity":   _chatgpt_A_identity(entries, sse),
            "B_prompt":     _chatgpt_B_prompt(entries, sse),
            "C_security":   _chatgpt_C_security(entries, sse),
            "D_autonomous": _chatgpt_D_autonomous(entries, sse),
            "E_urls":        _chatgpt_E_urls(entries, sse),
            "E_ai_urls":    _chatgpt_E_ai_urls(entries),
        }
    }


# ─────────────────────────────────────────────────────────────────────────────
# E. URLs / Domains Visited — AI URLs ONLY (focused, filtered section)
# ─────────────────────────────────────────────────────────────────────────────

def _chatgpt_E_ai_urls(entries: List[Dict]) -> List[Dict]:
    """
    Section E. URLs / Domains Visited: AI-only URL extraction.
    Returns ONLY URLs the AI accessed/cited/retrieved — nothing else.
    """
    from .ai_urls import extract_ai_urls
    import json as _json
    report = extract_ai_urls(entries)
    rows = [u.to_row() for u in report.urls]

    # Append retrieval chain as a summary row
    if report.chain:
        rows.append({
            "artifact":     "ai_url_retrieval_chain",
            "value":        f"{len(report.chain)} chain steps reconstructed from SSE metadata",
            "ai_url_chain": report.chain,
            "har_location": "SSE stream — reconstructed retrieval chain",
            "json_path":    "SSE search_model_queries → content_references → url_moderation",
            "attribution":  "AI",
            "reason": (
                f"AI: Retrieval chain reconstructed from SSE metadata. "
                f"Search query: \"{report.search_queries[0] if report.search_queries else 'N/A'}\". "
                f"Tool: {report.tool_name or 'SonicBrowserTool'}. "
                f"Total AI URLs: {len(report.urls)} "
                f"({len(report.cited)} cited/retrieved, "
                f"{len(report.search_results)} raw search results)."
            ),
            "ai_url":           "",
            "ai_url_raw":       "",
            "ai_url_domain":    "",
            "ai_url_title":     "",
            "ai_url_snippet":   "",
            "ai_url_pub_date":  "",
            "ai_url_confidence": 99,
            "ai_url_role":      "retrieval_chain_summary",
            "ai_url_sse_source": "derived",
            "ai_url_sse_seq":   -1,
            "ai_url_after_search_start": True,
            "ai_url_in_url_moderation": False,
            "ai_url_search_query": report.search_queries[0] if report.search_queries else "",
            "ai_url_tool_name":  report.tool_name,
        })

    return rows
