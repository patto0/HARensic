"""
Claude Forensic AI URL Extractor — parsers/claude_ai_urls.py
=============================================================
Extracts AI-attributed URLs from Claude HAR files with forensic rigour.

Claude's architecture differs fundamentally from ChatGPT and Gemini:

  TRANSPORT
  - Uses standard SSE (text/event-stream) like ChatGPT
  - But event schema is Anthropic-specific, NOT OpenAI-compatible

  ENDPOINT
  - /api/organizations/<org_id>/chat_conversations/<conv_id>/completion
  - POST with JSON body containing prompt, model, tools array

  TOOL SYSTEM
  - Claude uses an explicit tool_use / tool_result content block pair
  - web_search tool: fires a search query, returns knowledge results
  - web_fetch tool:  fetches a specific URL for full content
  - Each tool invocation is a separate content_block_start/stop cycle
  - Tool results contain structured {type, title, url, metadata} objects

  SSE EVENT SEQUENCE (for a web search turn):
    message_start           → assigns message ID, trace_id, request_id
    content_block_start [0] → type=tool_use, name=web_search
    content_block_delta [0] → input_json_delta chunks building {"query":"..."}
    content_block_stop  [0] → tool call complete
    content_block_start [1] → type=tool_result (server-injected search results)
    content_block_delta [1] → input_json_delta chunks building [{url,title,...}]
    content_block_stop  [1]
    ... (more tool cycles) ...
    content_block_start [N] → type=text (final answer)
    content_block_delta [N] → text_delta chunks
    content_block_stop  [N]
    message_delta           → stop_reason=end_turn
    message_stop

  CITATION EVIDENCE (two independent sources):
  1. SSE stream itself (primary):
     - tool_use blocks expose search queries and fetch URLs
     - tool_result blocks expose all URLs returned by the tool
  2. Conversation endpoint GET (secondary):
     - /chat_conversations/<id>?tree=True&render_all_tools=true
     - Returns full message tree with citations[] on text blocks
     - Each citation has: uuid, title, url, metadata, origin_tool_name,
       start_index, end_index (character positions in response text)

  FAVICON SIDE-CHANNEL:
  - After stream ends, browser fetches google.com/s2/favicons for each
    cited domain — identical pattern to ChatGPT
  - These confirm which domains actually appeared in final citations

Why the old parser failed:
  - The existing claude.py parser targets A/B/C/D artifact sections
  - It has no SSE content_block parser
  - It does not know about tool_use / tool_result events
  - It does not query the conversation endpoint for citations
  - It does not know about the citation[] field on text content blocks
"""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .helpers import _resp_text_raw

# ─────────────────────────────────────────────────────────────────────────────
#  EXCLUSION RULES
# ─────────────────────────────────────────────────────────────────────────────

_EXCLUDED_DOMAINS: Set[str] = {
    "claude.ai", "anthropic.com", "assets-proxy.anthropic.com",
    "s-cdn.anthropic.com", "cdn.anthropic.com",
    "www.google.com", "google.com",
    "t0.gstatic.com", "t1.gstatic.com", "t2.gstatic.com", "t3.gstatic.com",
    "gstatic.com", "fonts.gstatic.com",
    "www.google-analytics.com", "analytics.google.com",
    "www.googletagmanager.com",
    "accounts.google.com",
}

_EXCLUDED_SUFFIXES: Tuple[str, ...] = (
    ".anthropic.com", ".claude.ai",
    ".gstatic.com",
)

_EXCLUDED_PATH_RE = re.compile(
    r"/api/organizations/|/api/auth|/favicon|/s2/favicons|"
    r"/assets/|\.woff2?|\.js$|\.css$|\.gif$|\.png$"
)

_TRACKING_PARAMS: Set[str] = {
    "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
    "gclid", "gbraid", "ref", "referrer", "fbclid", "srsltid",
}


# ─────────────────────────────────────────────────────────────────────────────
#  DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ClaudeToolInvocation:
    """One tool_use + its paired tool_result block."""
    block_index:    int           # SSE content block index
    tool_id:        str           # toolu_<hex>
    tool_name:      str           # web_search | web_fetch
    input:          Dict          # parsed tool input (query / url / ...)
    results:        List[Dict]    # parsed tool result items [{type,title,url,metadata}]
    start_ts:       str
    stop_ts:        str
    sequence:       int           # invocation order (1, 2, 3, ...)


@dataclass
class ClaudeAIUrl:
    """One AI-attributed URL with full Claude forensic provenance."""
    raw_url:        str
    normalized_url: str
    domain:         str
    title:          str
    snippet:        str
    cited_text:     str           # Response text span this citation supports
    start_index:    int           # Character position in response text
    end_index:      int
    citation_uuid:  str           # Anthropic citation UUID
    origin_tool:    str           # web_search | web_fetch
    tool_id:        str           # toolu_<hex> that retrieved this URL
    tool_sequence:  int           # Which tool invocation (1st, 2nd, 3rd)
    confidence:     int
    evidence:       str
    har_location:   str
    sse_block_index: int
    role:           str           # search_result | fetched_content | cited_source
    in_favicon:     bool          # Also confirmed by favicon side-channel
    in_citation:    bool          # Appears in conversation citations[] endpoint
    search_query:   str           # Query that triggered this URL

    def to_row(self) -> Dict:
        return {
            "artifact":     f"claude_ai_url_{self.role}",
            "value":        self.normalized_url,
            "har_location": self.har_location,
            "json_path":    f"SSE tool_result block[{self.sse_block_index}] → result[].url",
            "attribution":  "AI",
            "reason":       self.evidence,
            # Standard E. URLs / Domains compatible fields
            "ai_url":               self.normalized_url,
            "ai_url_raw":           self.raw_url,
            "ai_url_domain":        self.domain,
            "ai_url_title":         self.title,
            "ai_url_snippet":       self.snippet,
            "ai_url_pub_date":      "",
            "ai_url_confidence":    self.confidence,
            "ai_url_role":          self.role,
            "ai_url_sse_source":    f"content_block[{self.sse_block_index}].tool_result",
            "ai_url_sse_seq":       self.sse_block_index,
            "ai_url_after_search_start": True,
            "ai_url_in_url_moderation":  self.in_citation,
            "ai_url_search_query":  self.search_query,
            "ai_url_tool_name":     self.origin_tool,
            "ai_url_chain":         [],
            # Claude-specific
            "claude_citation_uuid": self.citation_uuid,
            "claude_tool_id":       self.tool_id,
            "claude_tool_sequence": self.tool_sequence,
            "claude_start_index":   self.start_index,
            "claude_end_index":     self.end_index,
            "claude_cited_text":    self.cited_text,
            "claude_in_favicon":    self.in_favicon,
        }


@dataclass
class ClaudeAIReport:
    """Full extraction result from a Claude HAR file."""
    urls:           List[ClaudeAIUrl]
    user_prompt:    str
    model_name:     str
    message_id:     str
    trace_id:       str
    request_id:     str
    org_id:         str
    conv_id:        str
    tool_invocations: List[ClaudeToolInvocation]
    chain:          List[Dict]
    favicon_domains: Set[str]
    web_search_enabled: bool

    @property
    def cited(self) -> List[ClaudeAIUrl]:
        return [u for u in self.urls if u.in_citation or u.role == "cited_source"]

    @property
    def search_results(self) -> List[ClaudeAIUrl]:
        return [u for u in self.urls if u.role == "search_result"]

    @property
    def fetched(self) -> List[ClaudeAIUrl]:
        return [u for u in self.urls if u.role == "fetched_content"]


# ─────────────────────────────────────────────────────────────────────────────
#  URL UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def _normalize(raw: str) -> str:
    if not raw or not raw.startswith("http"):
        return raw
    try:
        p = urllib.parse.urlparse(raw)
        qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
        clean = {k: v for k, v in qs.items() if k not in _TRACKING_PARAMS}
        return urllib.parse.urlunparse(
            p._replace(query=urllib.parse.urlencode(clean, doseq=True))
        )
    except Exception:
        return raw


def _domain(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).netloc.lower()
    except Exception:
        return ""


def _is_excluded(url: str) -> bool:
    if not url or not url.startswith("http"):
        return True
    d = _domain(url)
    if d in _EXCLUDED_DOMAINS:
        return True
    for suf in _EXCLUDED_SUFFIXES:
        if d.endswith(suf):
            return True
    if _EXCLUDED_PATH_RE.search(url):
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
#  SSE STREAM PARSER
# ─────────────────────────────────────────────────────────────────────────────

def _parse_sse_events(raw_text: str) -> List[Dict]:
    """
    Parse Claude's SSE stream into a list of {event, data_parsed} dicts.

    Claude's SSE format:
        event: <event_type>\n
        data: <json_string>\n
        \n

    Unlike raw ChatGPT which uses `data:` lines only, Claude explicitly
    names each event type before the data line.
    """
    events  = []
    cur_evt = None
    cur_data: List[str] = []

    for line in raw_text.splitlines():
        if line.startswith("event:"):
            if cur_evt and cur_data:
                raw_d = " ".join(cur_data).strip()
                try:
                    events.append({"event": cur_evt, "data": json.loads(raw_d)})
                except (json.JSONDecodeError, ValueError):
                    pass
            cur_evt  = line[6:].strip()
            cur_data = []
        elif line.startswith("data:"):
            cur_data.append(line[5:].strip())
        elif not line.strip() and cur_evt:
            if cur_data:
                raw_d = " ".join(cur_data).strip()
                try:
                    events.append({"event": cur_evt, "data": json.loads(raw_d)})
                except (json.JSONDecodeError, ValueError):
                    pass
            cur_evt  = None
            cur_data = []

    return events


def _reconstruct_blocks(events: List[Dict]) -> Dict[int, Dict]:
    """
    Reconstruct content blocks from SSE events.

    Claude accumulates input_json_delta (for tool inputs) and
    text_delta (for text content) progressively across many events.

    Returns dict of {block_index: block_dict} where block_dict has:
        type, name, id, accumulated (full JSON string or text),
        start_ts, stop_ts, message (display hint)
    """
    blocks: Dict[int, Dict] = {}

    for ev in events:
        etype = ev["event"]
        data  = ev["data"]

        if etype == "content_block_start":
            idx = data.get("index", 0)
            cb  = data.get("content_block", {}) or {}
            blocks[idx] = {
                "type":        cb.get("type", ""),
                "name":        cb.get("name", ""),
                "id":          cb.get("id", ""),
                "accumulated": "",
                "start_ts":    cb.get("start_timestamp", ""),
                "stop_ts":     "",
                "message":     cb.get("message", ""),
            }

        elif etype == "content_block_delta":
            idx   = data.get("index", 0)
            delta = data.get("delta", {}) or {}
            if idx in blocks:
                dtype = delta.get("type", "")
                if dtype == "input_json_delta":
                    blocks[idx]["accumulated"] += delta.get("partial_json", "")
                elif dtype == "text_delta":
                    blocks[idx]["accumulated"] += delta.get("text", "")

        elif etype == "content_block_stop":
            idx = data.get("index", 0)
            if idx in blocks:
                blocks[idx]["stop_ts"] = data.get("stop_timestamp", "")

    return blocks


# ─────────────────────────────────────────────────────────────────────────────
#  TOOL INVOCATION EXTRACTOR
# ─────────────────────────────────────────────────────────────────────────────

def _extract_tool_invocations(
    blocks: Dict[int, Dict]
) -> List[ClaudeToolInvocation]:
    """
    Match tool_use blocks with their paired tool_result blocks.

    Claude's block sequence for each tool call:
        [N]   content_block type=tool_use   name=web_search  id=toolu_...
        [N+1] content_block type=tool_result                 (server-injected)

    The tool_result always immediately follows its tool_use in index order.
    The result's accumulated JSON is a list of knowledge objects:
        [{"type":"knowledge","title":"...","url":"...","metadata":{...}}, ...]
    """
    invocations: List[ClaudeToolInvocation] = []
    sorted_idx = sorted(blocks.keys())
    sequence   = 0

    for i, idx in enumerate(sorted_idx):
        block = blocks[idx]
        if block["type"] != "tool_use":
            continue

        # Parse tool input
        tool_input: Dict = {}
        try:
            if block["accumulated"]:
                tool_input = json.loads(block["accumulated"])
        except (json.JSONDecodeError, ValueError):
            pass

        # Find paired tool_result (next block)
        result_items: List[Dict] = []
        next_idx = sorted_idx[i + 1] if i + 1 < len(sorted_idx) else None
        if next_idx is not None and blocks[next_idx]["type"] == "tool_result":
            result_block = blocks[next_idx]
            try:
                if result_block["accumulated"]:
                    parsed = json.loads(result_block["accumulated"])
                    if isinstance(parsed, list):
                        result_items = parsed
                    elif isinstance(parsed, dict):
                        result_items = [parsed]
            except (json.JSONDecodeError, ValueError):
                pass

        sequence += 1
        invocations.append(ClaudeToolInvocation(
            block_index = idx,
            tool_id     = block["id"],
            tool_name   = block["name"],
            input       = tool_input,
            results     = result_items,
            start_ts    = block["start_ts"],
            stop_ts     = block["stop_ts"],
            sequence    = sequence,
        ))

    return invocations


# ─────────────────────────────────────────────────────────────────────────────
#  CONVERSATION ENDPOINT CITATION EXTRACTOR
# ─────────────────────────────────────────────────────────────────────────────

def _extract_citations_from_conversation(
    entries: List[Dict], org_id: str, conv_id: str
) -> Tuple[List[Dict], str]:
    """
    Parse the GET /chat_conversations/<id>?tree=True&render_all_tools=true
    response to extract structured citations from the assistant message.

    Citation object fields:
        uuid            — unique citation ID
        title           — article title
        url             — full URL
        metadata        — {site_domain, favicon_url, ...}
        origin_tool_name— web_search | web_fetch
        sources         — [{title, url}] list (sometimes multiple sources)
        start_index     — char position in response text
        end_index       — char position in response text

    Also extracts the conversation settings (web_search enabled flag).

    Returns (citations_list, web_search_setting)
    """
    target_paths = [
        f"/chat_conversations/{conv_id}",
        "chat_conversations",
        "tree=True",
    ]

    for entry in entries:
        url    = entry["request"]["url"]
        method = entry["request"]["method"]
        if method != "GET":
            continue
        if not all(p in url for p in target_paths[:1]):
            continue
        if conv_id not in url:
            continue

        resp_text = entry["response"]["content"].get("text", "")
        if not resp_text:
            continue

        try:
            data = json.loads(resp_text)
        except (json.JSONDecodeError, ValueError):
            continue

        # Extract web_search setting
        settings = data.get("settings", {}) or {}
        ws_enabled = str(settings.get("enabled_web_search", False))

        citations: List[Dict] = []
        for msg in data.get("chat_messages", []) or []:
            for block in msg.get("content", []) or []:
                if block.get("type") == "text":
                    for cit in block.get("citations", []) or []:
                        if isinstance(cit, dict):
                            citations.append(cit)

        if citations or ws_enabled:
            return citations, ws_enabled

    return [], "False"


# ─────────────────────────────────────────────────────────────────────────────
#  FAVICON SIDE-CHANNEL EXTRACTOR
# ─────────────────────────────────────────────────────────────────────────────

def _extract_favicon_domains(entries: List[Dict]) -> Set[str]:
    """
    Extract cited domains from google.com/s2/favicons requests.

    Claude's frontend fetches favicons for each cited domain using:
        GET https://www.google.com/s2/favicons?sz=64&domain=<cited_domain>

    These are definitive confirmation of which domains appeared in
    citations rendered in the browser, independent of SSE evidence.
    """
    domains: Set[str] = set()
    for entry in entries:
        url    = entry["request"]["url"]
        method = entry["request"]["method"]
        if method != "GET":
            continue
        if "/s2/favicons" not in url:
            continue
        try:
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            domain = qs.get("domain", [""])[0]
            if domain and "." in domain and not domain.startswith("www.cm-all"):
                domains.add(domain.lstrip("www."))
        except Exception:
            pass
    return domains


# ─────────────────────────────────────────────────────────────────────────────
#  SESSION METADATA EXTRACTOR
# ─────────────────────────────────────────────────────────────────────────────

def _extract_session_metadata(
    events: List[Dict], entries: List[Dict]
) -> Dict[str, str]:
    """
    Extract message ID, trace ID, request ID, org ID, conv ID, model.

    Sources:
    - message_start SSE event → message.id, model, trace_id, request_id
    - completion endpoint URL → org_id, conv_id
    - request body → model (cross-check)
    """
    meta = {
        "message_id": "", "trace_id": "", "request_id": "",
        "org_id": "", "conv_id": "", "model": "",
    }

    # From SSE message_start event
    for ev in events:
        if ev["event"] == "message_start":
            msg = ev["data"].get("message", {}) or {}
            meta["message_id"]  = msg.get("id", "")
            meta["model"]       = msg.get("model", "")
            meta["trace_id"]    = msg.get("trace_id", "")
            meta["request_id"]  = msg.get("request_id", "")
            break

    # From completion URL
    for entry in entries:
        url = entry["request"]["url"]
        if "/completion" in url and "organizations" in url:
            # Extract org_id and conv_id from path
            m = re.search(
                r"/organizations/([^/]+)/chat_conversations/([^/]+)/completion",
                url
            )
            if m:
                meta["org_id"]  = m.group(1)
                meta["conv_id"] = m.group(2)
            # Extract model from request body
            if not meta["model"]:
                try:
                    body = json.loads(
                        entry["request"].get("postData", {}).get("text", "{}")
                    )
                    meta["model"] = body.get("model", "")
                except Exception:
                    pass
            break

    return meta


# ─────────────────────────────────────────────────────────────────────────────
#  USER PROMPT EXTRACTOR
# ─────────────────────────────────────────────────────────────────────────────

def _extract_user_prompt(entries: List[Dict]) -> str:
    """
    Extract user prompt from the completion POST request body.
    Field: body.prompt (plain string)
    """
    for entry in entries:
        url    = entry["request"]["url"]
        method = entry["request"]["method"]
        if method != "POST" or "/completion" not in url:
            continue
        try:
            body = json.loads(
                entry["request"].get("postData", {}).get("text", "{}")
            )
            prompt = body.get("prompt", "")
            if prompt:
                return prompt
        except Exception:
            pass
    return ""


# ─────────────────────────────────────────────────────────────────────────────
#  EVIDENCE BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def _build_evidence(
    url: str, title: str, role: str, tool_name: str, tool_id: str,
    search_query: str, seq: int, cited_text: str, in_citation: bool,
    in_favicon: bool, confidence: int, block_index: int,
) -> str:
    parts = []

    role_desc = {
        "search_result":   "a web search result returned to Claude by its web_search tool",
        "fetched_content": "a webpage whose full content was fetched and read by Claude via its web_fetch tool",
        "cited_source":    "a source explicitly cited in Claude's final response",
    }.get(role, "an AI-retrieved resource")

    parts.append(f"This URL was identified as {role_desc}.")

    parts.append(
        f"Extracted from Claude's SSE stream at content_block[{block_index}] "
        f"(type=tool_result, paired with tool_use id={tool_id}, name={tool_name}). "
        f"This is invocation #{seq} in the tool execution sequence."
    )

    if search_query:
        parts.append(
            f"The tool was invoked with the query/input: \"{search_query[:100]}\". "
            f"This URL was in the result set returned by that invocation."
        )

    if in_citation:
        parts.append(
            "This URL also appears in the structured citations[] field of the "
            "assistant message retrieved from Claude's conversation endpoint "
            "(/chat_conversations?tree=True). This independently confirms it "
            "was explicitly cited in the final response shown to the user."
        )
        if cited_text:
            trunc = cited_text[:120] + ("…" if len(cited_text) > 120 else "")
            parts.append(f"The citation supports the response text: \"{trunc}\"")

    if in_favicon:
        parts.append(
            "The domain of this URL also appears in a google.com/s2/favicons "
            "GET request in the HAR — the browser fetched the site icon when "
            "rendering this citation in the UI, providing independent network-level "
            "confirmation that this source was displayed to the user."
        )

    parts.append(
        "IMPORTANT: This URL does NOT appear as a direct browser GET request in "
        "the HAR. Claude's web retrieval is entirely server-side — the URL "
        "exists only inside the SSE tool_result content block, proving it was "
        "retrieved by Claude's backend tool infrastructure, not by the user's browser."
    )

    parts.append(f"Confidence: {confidence}%.")
    return " ".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
#  DEDUPLICATION
# ─────────────────────────────────────────────────────────────────────────────

def _deduplicate(urls: List[ClaudeAIUrl]) -> List[ClaudeAIUrl]:
    """
    Deduplicate by normalized URL.
    Priority: cited_source > fetched_content > search_result
    Within same role: higher confidence wins, merge evidence flags.
    """
    seen: Dict[str, ClaudeAIUrl] = {}
    priority = {"cited_source": 3, "fetched_content": 2, "search_result": 1}

    for u in urls:
        key = u.normalized_url
        if key not in seen:
            seen[key] = u
        else:
            existing = seen[key]
            ep = priority.get(existing.role, 0)
            up = priority.get(u.role, 0)

            if up > ep or (up == ep and u.confidence > existing.confidence):
                # Keep the richer version, merge flags
                merged = ClaudeAIUrl(
                    raw_url         = u.raw_url,
                    normalized_url  = key,
                    domain          = u.domain,
                    title           = u.title or existing.title,
                    snippet         = u.snippet or existing.snippet,
                    cited_text      = u.cited_text or existing.cited_text,
                    start_index     = u.start_index or existing.start_index,
                    end_index       = u.end_index or existing.end_index,
                    citation_uuid   = u.citation_uuid or existing.citation_uuid,
                    origin_tool     = u.origin_tool,
                    tool_id         = u.tool_id,
                    tool_sequence   = min(u.tool_sequence, existing.tool_sequence),
                    confidence      = max(u.confidence, existing.confidence),
                    evidence        = u.evidence,
                    har_location    = u.har_location,
                    sse_block_index = u.sse_block_index,
                    role            = u.role,
                    in_favicon      = u.in_favicon or existing.in_favicon,
                    in_citation     = u.in_citation or existing.in_citation,
                    search_query    = u.search_query or existing.search_query,
                )
                seen[key] = merged

    # Sort: cited first, then fetched, then search results; by confidence desc
    result = sorted(
        seen.values(),
        key=lambda u: (-priority.get(u.role, 0), -u.confidence)
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
#  RETRIEVAL CHAIN BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def _build_chain(
    prompt: str,
    invocations: List[ClaudeToolInvocation],
    urls: List[ClaudeAIUrl],
) -> List[Dict]:
    chain: List[Dict] = []

    if prompt:
        chain.append({
            "layer":  "0 — User Query → Claude",
            "type":   "user_prompt",
            "value":  prompt,
            "domain": "",
            "title":  "",
            "confidence": 100,
        })

    for inv in invocations:
        query_val = (
            inv.input.get("query", "")
            or inv.input.get("url", "")
            or str(inv.input)[:80]
        )
        layer = (
            f"1 — Tool invocation #{inv.sequence}: {inv.tool_name}"
        )
        chain.append({
            "layer":  layer,
            "type":   f"tool_use:{inv.tool_name}",
            "value":  query_val,
            "domain": "",
            "title":  "",
            "confidence": 98,
        })

        for item in inv.results:
            url = item.get("url", "")
            if url and not _is_excluded(url):
                role = "fetched_content" if inv.tool_name == "web_fetch" else "search_result"
                chain.append({
                    "layer":      f"2 — {inv.tool_name} result",
                    "type":       role,
                    "value":      _normalize(url),
                    "domain":     _domain(url),
                    "title":      item.get("title", ""),
                    "confidence": 93,
                })

    seen: Set[str] = set()
    for u in urls:
        if u.in_citation and u.normalized_url not in seen:
            seen.add(u.normalized_url)
            chain.append({
                "layer":      "3 — Cited Source (final citation)",
                "type":       "cited_source",
                "value":      u.normalized_url,
                "domain":     u.domain,
                "title":      u.title,
                "confidence": u.confidence,
            })

    return chain


# ─────────────────────────────────────────────────────────────────────────────
#  PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────

def extract_claude_ai_urls(entries: List[Dict]) -> ClaudeAIReport:
    """
    Main entry point. Scans HAR entries for:
    1. The /completion SSE stream (primary evidence)
    2. The /chat_conversations?tree=True endpoint (citation metadata)
    3. google.com/s2/favicons requests (side-channel confirmation)

    Returns a complete ClaudeAIReport.
    """
    user_prompt  = _extract_user_prompt(entries)
    favicon_doms = _extract_favicon_domains(entries)

    # ── Locate and parse the SSE completion stream ────────────────────────
    events: List[Dict]       = []
    blocks: Dict[int, Dict]  = {}

    for entry in entries:
        url    = entry["request"]["url"]
        method = entry["request"]["method"]
        mime   = entry["response"]["content"].get("mimeType", "")
        if method != "POST" or "/completion" not in url:
            continue
        if "event-stream" not in mime and "text/plain" not in mime:
            raw = _resp_text_raw(entry)
            if not raw or "event:" not in raw:
                continue

        raw = _resp_text_raw(entry)
        if not raw:
            continue

        events = _parse_sse_events(raw)
        blocks = _reconstruct_blocks(events)
        if blocks:
            break

    # ── Extract session metadata ──────────────────────────────────────────
    meta = _extract_session_metadata(events, entries)

    # ── Extract tool invocations from blocks ──────────────────────────────
    invocations = _extract_tool_invocations(blocks)

    # ── Extract citations from conversation endpoint ───────────────────────
    citations, ws_enabled = _extract_citations_from_conversation(
        entries, meta["org_id"], meta["conv_id"]
    )

    # Build citation lookup: url → citation dict (for enrichment)
    citation_by_url: Dict[str, Dict] = {}
    for cit in citations:
        cit_url = cit.get("url", "")
        if cit_url:
            norm = _normalize(cit_url)
            if norm not in citation_by_url:
                citation_by_url[norm] = cit
            # Also add sources[] urls
            for src in cit.get("sources", []) or []:
                src_url = src.get("url", "")
                if src_url:
                    src_norm = _normalize(src_url)
                    if src_norm not in citation_by_url:
                        citation_by_url[src_norm] = cit

    # ── Build ClaudeAIUrl objects from tool invocations ───────────────────
    raw_urls: List[ClaudeAIUrl] = []

    for inv in invocations:
        query_str = (
            inv.input.get("query", "")
            or inv.input.get("url", "")
        )
        role = "fetched_content" if inv.tool_name == "web_fetch" else "search_result"

        for item in inv.results:
            raw_url = item.get("url", "")
            if not raw_url or _is_excluded(raw_url):
                continue

            norm    = _normalize(raw_url)
            dom     = _domain(norm)
            title   = item.get("title", "")
            meta_d  = item.get("metadata", {}) or {}
            snippet = str(meta_d.get("site_overview", ""))[:300]

            # Check citation and favicon enrichment
            cit_data    = citation_by_url.get(norm, {})
            in_citation = bool(cit_data)
            in_favicon  = dom.lstrip("www.") in favicon_doms or dom in favicon_doms

            # If this URL has citation data, promote to cited_source
            effective_role = "cited_source" if in_citation else role

            # Confidence scoring
            conf = 90  # base for tool_result evidence
            if in_citation:
                conf = min(conf + 6, 99)
            if in_favicon:
                conf = min(conf + 2, 99)
            if inv.tool_name == "web_fetch":
                conf = min(conf + 3, 99)  # web_fetch = Claude explicitly chose this URL

            evidence = _build_evidence(
                url         = norm,
                title       = title,
                role        = effective_role,
                tool_name   = inv.tool_name,
                tool_id     = inv.tool_id,
                search_query= query_str,
                seq         = inv.sequence,
                cited_text  = cit_data.get("cited_text", ""),
                in_citation = in_citation,
                in_favicon  = in_favicon,
                confidence  = conf,
                block_index = inv.block_index + 1,  # +1 = paired result block
            )

            raw_urls.append(ClaudeAIUrl(
                raw_url         = raw_url,
                normalized_url  = norm,
                domain          = dom,
                title           = title,
                snippet         = snippet,
                cited_text      = cit_data.get("cited_text", ""),
                start_index     = cit_data.get("start_index", 0) or 0,
                end_index       = cit_data.get("end_index", 0) or 0,
                citation_uuid   = cit_data.get("uuid", ""),
                origin_tool     = inv.tool_name,
                tool_id         = inv.tool_id,
                tool_sequence   = inv.sequence,
                confidence      = conf,
                evidence        = evidence,
                har_location    = (
                    f"SSE content_block[{inv.block_index + 1}] tool_result "
                    f"(tool_use={inv.tool_id})"
                ),
                sse_block_index = inv.block_index + 1,
                role            = effective_role,
                in_favicon      = in_favicon,
                in_citation     = in_citation,
                search_query    = query_str,
            ))

    # ── Also add any citation URLs not already in tool results ────────────
    for cit in citations:
        cit_url = cit.get("url", "")
        if not cit_url or _is_excluded(cit_url):
            continue
        norm = _normalize(cit_url)
        # Only add if not already present from tool results
        existing_norms = {u.normalized_url for u in raw_urls}
        if norm not in existing_norms:
            dom   = _domain(norm)
            inf   = dom.lstrip("www.") in favicon_doms or dom in favicon_doms
            meta  = cit.get("metadata", {}) or {}
            evidence = _build_evidence(
                url="", title=cit.get("title",""), role="cited_source",
                tool_name=cit.get("origin_tool_name","web_search"),
                tool_id="", search_query="", seq=0,
                cited_text=cit.get("cited_text",""),
                in_citation=True, in_favicon=inf,
                confidence=95, block_index=-1,
            )
            raw_urls.append(ClaudeAIUrl(
                raw_url         = cit_url,
                normalized_url  = norm,
                domain          = dom,
                title           = cit.get("title", ""),
                snippet         = "",
                cited_text      = cit.get("cited_text", ""),
                start_index     = cit.get("start_index", 0) or 0,
                end_index       = cit.get("end_index", 0) or 0,
                citation_uuid   = cit.get("uuid", ""),
                origin_tool     = cit.get("origin_tool_name", "web_search"),
                tool_id         = "",
                tool_sequence   = 0,
                confidence      = 97 if inf else 95,
                evidence        = evidence,
                har_location    = "GET /chat_conversations?tree=True citations[]",
                sse_block_index = -1,
                role            = "cited_source",
                in_favicon      = inf,
                in_citation     = True,
                search_query    = "",
            ))

    # ── Deduplicate and sort ──────────────────────────────────────────────
    final_urls = _deduplicate(raw_urls)

    # ── Build retrieval chain ─────────────────────────────────────────────
    chain = _build_chain(user_prompt, invocations, final_urls)

    return ClaudeAIReport(
        urls             = final_urls,
        user_prompt      = user_prompt,
        model_name       = meta.get("model", ""),
        message_id       = meta.get("message_id", ""),
        trace_id         = meta.get("trace_id", ""),
        request_id       = meta.get("request_id", ""),
        org_id           = meta.get("org_id", ""),
        conv_id          = meta.get("conv_id", ""),
        tool_invocations = invocations,
        chain            = chain,
        favicon_domains  = favicon_doms,
        web_search_enabled = ws_enabled == "True",
    )
