"""
Gemini HAR parsing pipeline.
Logic preserved exactly from original har_forensics_elite.py.
"""

import json
import re
from typing import Dict, List, Optional, Set
from urllib.parse import unquote

from .loader import get_entries
from .helpers import _headers, _req_body, _resp_body, _resp_text_raw, _path, _ts


def _gemini_decode_body(text: str) -> Optional[str]:
    if not text: return None
    if text.startswith(")]}'\n"): text = text[5:]
    return text


def _gemini_parse_chunks(text: str) -> List[Dict]:
    chunks = []
    lines = text.strip().split('\n')
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.isdigit():
            i += 1
            if i < len(lines):
                try: chunks.append(json.loads(lines[i]))
                except Exception: pass
            i += 1
        else:
            i += 1
    return chunks


def _gemini_conv_ids(chunks: List[Dict]) -> Dict[str,str]:
    ids = {}
    for chunk in chunks:
        if not isinstance(chunk,list): continue
        for item in chunk:
            if not isinstance(item,list) or len(item) < 3: continue
            try:
                payload = item[2]
                if isinstance(payload,str):
                    pp = json.loads(payload)
                    if isinstance(pp,list) and len(pp) >= 2:
                        cv = pp[1]
                        if isinstance(cv,list) and len(cv) >= 2:
                            ids["conversation_id"] = cv[0]
                            ids["response_id"]     = cv[1]
            except Exception: pass
    return ids


def _gemini_response_text(chunks: List[Dict]) -> str:
    longest = ""
    for chunk in chunks:
        if not isinstance(chunk,list): continue
        for item in chunk:
            if not isinstance(item,list) or len(item) < 3: continue
            try:
                payload = item[2]
                if isinstance(payload,str):
                    pp = json.loads(payload)
                    if isinstance(pp,list) and len(pp) >= 5:
                        for resp in (pp[4] or []):
                            if isinstance(resp,list) and len(resp) >= 2:
                                tc = resp[1]
                                if isinstance(tc,list) and tc and isinstance(tc[0],str) and len(tc[0]) > len(longest):
                                    longest = tc[0]
            except Exception: pass
    return longest


def _gemini_prompt(entry: Dict) -> Optional[str]:
    post_data = entry["request"].get("postData",{})
    text = post_data.get("text","")
    if not text: return None
    decoded = unquote(text)
    if "f.req=" not in decoded: return None
    try:
        freq_value = decoded.split("f.req=")[1].split("&")[0]
        parsed = json.loads(freq_value)
        if isinstance(parsed,list) and len(parsed) >= 2:
            inner = parsed[1]
            if isinstance(inner,str):
                inner_parsed = json.loads(inner)
                if isinstance(inner_parsed,list) and inner_parsed:
                    first = inner_parsed[0]
                    if isinstance(first,list) and first and isinstance(first[0],str):
                        return first[0]
    except Exception: pass
    return None


def parse_gemini(har: Dict) -> Dict:
    """Run the full Gemini forensic parsing pipeline."""
    entries = get_entries(har)
    results = {
        "A_identity": [], "B_prompt": [],
        "C_security": [], "D_autonomous": [],
        "E_ai_urls":    _gemini_E_ai_urls(entries),
        "E_ai_urls":    _gemini_E_ai_urls(entries),
    }

    conversations = []
    for i, entry in enumerate(entries):
        url = entry["request"]["url"]
        if "StreamGenerate" not in url: continue
        prompt    = _gemini_prompt(entry)
        resp_text = _resp_text_raw(entry)
        decoded   = _gemini_decode_body(resp_text)
        if not decoded: continue
        chunks  = _gemini_parse_chunks(decoded)
        ids     = _gemini_conv_ids(chunks)
        resp    = _gemini_response_text(chunks)
        conversations.append({
            "entry_index": i, "prompt": prompt, "response": resp,
            "conversation_id": ids.get("conversation_id",""),
            "response_id":     ids.get("response_id",""),
            "timestamp":       entry.get("startedDateTime",""),
        })

    # A. Identity
    for entry in entries:
        url = entry["request"]["url"]
        if "f.sid=" in url:
            m = re.search(r"f\.sid=(\d+)", url)
            if m:
                results["A_identity"].append({
                    "artifact":"session_id","value":m.group(1),
                    "har_location":"Query Parameters","json_path":"request.url[f.sid]",
                   "attribution":"PLATFORM","reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not generate session identifiers. Users do not create session IDs. The platform generates this identifier and ties all API calls together within a single login session."})
                break
    for conv in conversations:
        if conv["conversation_id"]:
            results["A_identity"].append({
                "artifact":"conversation_id","value":conv["conversation_id"],
                "har_location":f"Response Entry #{conv['entry_index']}",
                "json_path":"response.content[1][1][0]","attribution":"PLATFORM",
            "reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not create conversation IDs — this is session management infrastructure. The human initiates the conversation, triggering ID generation. The platform generates the UUID identifier and uses it for grouping all messages within that thread."})
        if conv["response_id"]:
            results["A_identity"].append({
                "artifact":"response_id","value":conv["response_id"],
                "har_location":f"Response Entry #{conv['entry_index']}",
                "json_path":"response.content[1][1][1]","attribution":"PLATFORM",
            "reason":"AI=TRUE | HUMAN=FALSE | Platform=TRUE. Each individual AI response receives a unique identifier, making this an AI-associated artifact. Users do not create response IDs; they are automatically assigned. The platform assigns the unique ID to each response and uses it for logging, deduplication, and feedback attribution."})
    for entry in entries:
        hdrs = _headers(entry)
        if "user-agent" in hdrs:
            results["A_identity"].append({
                "artifact":"user_agent","value":hdrs["user-agent"][:200],
                "har_location":"Request Headers","json_path":"request.headers[user-agent]",
                "attribution":"PLATFORM","reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not generate user agent strings. Although the user agent reflects the browser the human chose, it is browser-generated rather than user-written. The platform receives and uses the user agent for compatibility handling, telemetry, and security monitoring."})
            break
    if entries:
        results["A_identity"].append({
            "artifact":"session_start_time","value":entries[0].get("startedDateTime",""),
            "har_location":"HAR first entry","json_path":"log.entries[0].startedDateTime",
            "attribution":"HUMAN","reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not manage session start times. The human's actions initiate the session being recorded. The platform records this timestamp for session duration analytics and timeout enforcement."})
        results["A_identity"].append({
            "artifact":"session_end_time","value":entries[-1].get("startedDateTime",""),
            "har_location":"HAR last entry","json_path":"log.entries[-1].startedDateTime",
            "attribution":"HUMAN","reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not manage session termination. The human's actions or inactivity end the session being tracked. The platform records this timestamp and pairs it with the start time to compute total session duration."})

    # B. Prompt
    for conv in conversations:
        if conv["prompt"]:
            results["B_prompt"].append({
                "artifact":"user_prompt","value":conv["prompt"][:500],
                "har_location":f"POST StreamGenerate Entry #{conv['entry_index']}",
                "json_path":"request.postData.f.req[1][0][0]","attribution":"HUMAN",
                "reason":"AI=FALSE | HUMAN=TRUE | Platform=FALSE. The AI does not write prompts — this is the input sent to the AI, not output from it. The human types and submits this exact text. The platform sends it to the backend for processing without modifying the content itself."})
        if conv["response"]:
            results["B_prompt"].append({
                "artifact":"ai_response","value":conv["response"][:500],
                "har_location":f"Response Entry #{conv['entry_index']}",
                "json_path":"response.content (reconstructed from Gemini chunks)","attribution":"AI",
                "reason":"AI=TRUE | HUMAN=FALSE | Platform=FALSE. This is pure AI model output text and the primary AI-generated artifact. Humans do not generate AI responses — this is model output only. The platform delivers but does not generate or modify the text content; no transformation is applied."})

    # C. Security
    for entry in entries:
        url = entry["request"]["url"]
        if "StreamGenerate" not in url: continue
        resp_t = _resp_text_raw(entry)
        if ("Maharashtra" in resp_t or "SWML_DESCRIPTION_FROM_YOUR_INTERNET_ADDRESS" in resp_t
                or "your location" in resp_t.lower()):
            results["C_security"].append({
                "artifact":"location_tracking","value":"DETECTED",
                "har_location":"Response Body (StreamGenerate)",
                "json_path":"response.content","attribution":"PLATFORM",
                "reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. The AI does not track user location — geographic data about the user is not AI output. The artifact captures the human's approximate geographic position. The platform captures location data and uses it for localization, compliance, and analytics segmentation."})
            break

    cookies_found: Set[str] = set()
    for entry in entries:
        for cookie in entry["request"].get("cookies",[]):
            name = cookie.get("name","")
            if name: cookies_found.add(name)
    if cookies_found:
        results["C_security"].append({
            "artifact":"session_cookies","value":", ".join(sorted(cookies_found)[:10]),
            "har_location":"Request Cookies","json_path":"request.cookies[].name",
            "attribution":"PLATFORM","reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not manage authentication cookies. The human does not create cookie values directly. The platform's authentication system generates and exchanges session cookies to maintain the logged-in state across page reloads and browser tabs."})

    # D. Autonomous
    analytics_count = sum(1 for e in entries if "analytics.google.com" in e["request"]["url"])
    if analytics_count:
        results["D_autonomous"].append({
            "artifact":"analytics_tracking","value":f"{analytics_count} requests",
            "har_location":"Google Analytics endpoints",
            "json_path":"request.url contains analytics.google.com","attribution":"PLATFORM",
            "reason":"AI=FALSE | HUMAN=TRUE | Platform=TRUE. This tracks user actions and session usage, not AI output. The human's actions and events are the data source being logged. The platform feeds analytics to dashboards, structures and sends analytics events, and routes this to Google Analytics infrastructure."})
    batch_count = sum(1 for e in entries if "batchexecute" in e["request"]["url"])
    if batch_count:
        results["D_autonomous"].append({
            "artifact":"batch_requests","value":f"{batch_count} requests",
            "har_location":"Batch Execute Endpoint",
            "json_path":"request.url contains /batchexecute","attribution":"PLATFORM",
            "reason":"AI=FALSE | HUMAN=FALSE | Platform=TRUE. The AI does not perform batch background operations. Users do not trigger batch requests manually. These are background platform operations executed autonomously by the platform infrastructure."})
    if conversations:
        results["D_autonomous"].append({
            "artifact":"ai_generation_streams","value":f"{len(conversations)} streams",
            "har_location":"StreamGenerate endpoints",
            "json_path":"request.url contains StreamGenerate","attribution":"AI",
            "reason":"AI=TRUE | HUMAN=FALSE | Platform=TRUE. This tracks whether the AI response is streamed, and the AI generates the stream of tokens — the boolean reflects the AI's generation mode. Users do not typically control whether streaming is used; this is automatic. The platform implements the streaming protocol and handles the SSE or WebSocket infrastructure."})

    return {"platform": "gemini", "results": results}



def _gemini_E_ai_urls(entries):
    from .gemini_ai_urls import extract_gemini_ai_urls
    report = extract_gemini_ai_urls(entries)
    rows   = [u.to_row() for u in report.urls]
    if report.chain:
        invoked = "YES" if report.search_tool_invoked else "NO"
        reason  = (
            "AI: Gemini retrieval chain from StreamGenerate BardFrontendService RPC. "
            + "Prompt: " + report.user_prompt[:60] + ". "
            + "Model: " + report.model_name + ". "
            + "Google Search grounding: " + invoked + ". "
            + "Total AI URLs: " + str(len(report.urls)) + "."
        )
        rows.append({
            "artifact":      "gemini_ai_url_retrieval_chain",
            "value":         str(len(report.chain)) + " chain steps from StreamGenerate",
            "har_location":  "StreamGenerate response — BardFrontendService RPC",
            "json_path":     "StreamGenerate inner[4][0][2][1][N]",
            "attribution":   "AI",
            "reason":        reason,
            "ai_url":        "",
            "ai_url_raw":    "",
            "ai_url_domain": "",
            "ai_url_title":  "",
            "ai_url_snippet":"",
            "ai_url_pub_date": "",
            "ai_url_confidence": 99,
            "ai_url_role":   "retrieval_chain_summary",
            "ai_url_sse_source": "StreamGenerate BardFrontendService",
            "ai_url_sse_seq": -1,
            "ai_url_after_search_start": report.search_tool_invoked,
            "ai_url_in_url_moderation":  False,
            "ai_url_search_query": report.user_prompt[:100],
            "ai_url_tool_name": "Google Search (Gemini grounding)",
            "ai_url_chain":  report.chain,
        })
    return rows
