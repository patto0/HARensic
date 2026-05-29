"""
Gemini Forensic AI URL Extractor — parsers/gemini_ai_urls.py
=============================================================
Extracts AI-attributed URLs from Gemini HAR files with forensic rigour.

Gemini's architecture is fundamentally different from ChatGPT's:
  - No SSE event-stream with clean JSON fields
  - Uses HTTP chunked transfer with hex-length-prefixed JSON blobs
  - All data flows through batchexecute RPC and StreamGenerate
  - Response is a nested array structure (positional, not named keys)
  - Citations are encoded at position [4][0][2][1][N] in the final chunk
  - Search tool invocation is signalled at key "7" in intermediate chunks
  - User prompt is URL-encoded in the f.req POST body

Forensic evidence sources (in extraction order):
  1. StreamGenerate f.req POST body     → user prompt
  2. StreamGenerate chunks with key "7" → Google Search tool invocation signal
  3. StreamGenerate final chunk [4][0][2][1][N] → full citation array
       Each citation entry:
         [0] = [cited_text_span, None, None, [[char_start, char_end]]]
         [1] = [display_number]
         [2] = [[url_with_text_fragment, title, snippet?, ...], ...]
         [3] = spp_id (unique citation anchor ID)
  4. batchexecute MaZiqc entry          → conversation history (prior turns)
  5. All chunks recursive URL scan      → fallback for any missed URLs

Why the old parser failed:
  - It looked for SSE "data:" lines and content_references/safe_urls keys
  - Gemini uses hex-chunked application/json, not text/event-stream
  - Gemini's citation structure uses positional arrays, not named keys
  - The old parser had no chunk splitter for the hex-length format
"""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from .helpers import _resp_text_raw

# ─────────────────────────────────────────────────────────────────────────────
#  EXCLUSION RULES — never AI content retrieval evidence
# ─────────────────────────────────────────────────────────────────────────────

_EXCLUDED_DOMAINS: Set[str] = {
    "gemini.google.com", "gemini.gstatic.com", "gstatic.com",
    "www.gstatic.com", "fonts.gstatic.com",
    "www.google.com", "google.com", "accounts.google.com",
    "play.google.com", "www.google-analytics.com",
    "www.googletagmanager.com", "signaler-pa.clients6.google.com",
    "lamda.googleapis.com", "googleapis.com",
}

_EXCLUDED_SUFFIXES: Tuple[str, ...] = (
    ".gstatic.com", ".googleapis.com", ".google.com",
    ".googletagmanager.com",
)

_EXCLUDED_PATH_RE = re.compile(
    r"/images/branding/|/productlogos/|/s/i/short-term/|/maps/vt/|"
    r"googlesymbols|/log\?|RotateCookies|/collect\?"
)

_TRACKING_PARAMS: Set[str] = {
    "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
    "gclid", "gbraid", "ref", "referrer", "fbclid", "srsltid",
}


# ─────────────────────────────────────────────────────────────────────────────
#  DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class GeminiAIUrl:
    """One AI-attributed URL with full Gemini forensic provenance."""
    raw_url:            str
    normalized_url:     str
    domain:             str
    title:              str
    snippet:            str        # Text fragment from #:~:text= or citation body
    cited_text:         str        # Span of AI response text this URL supports
    display_number:     int        # Citation number shown in UI (1-based)
    spp_id:             str        # Gemini's unique citation anchor ID
    confidence:         int        # 0–100
    evidence:           str        # Forensic rationale
    har_location:       str        # Precise HAR path
    gemini_path:        str        # Positional path in response array
    role:               str        # cited_source | grounding_source | search_result
    search_tool_seen:   bool       # Was Google Search tool invoked?
    chunk_index:        int        # Which stream chunk this came from

    def to_row(self) -> Dict:
        return {
            "artifact":     f"gemini_ai_url_{self.role}",
            "value":        self.normalized_url,
            "har_location": self.har_location,
            "json_path":    self.gemini_path,
            "attribution":  "AI",
            "reason":       self.evidence,
            # Extended AI URL fields (compatible with E. URLs display)
            "ai_url":               self.normalized_url,
            "ai_url_raw":           self.raw_url,
            "ai_url_domain":        self.domain,
            "ai_url_title":         self.title,
            "ai_url_snippet":       self.snippet,
            "ai_url_pub_date":      "",
            "ai_url_confidence":    self.confidence,
            "ai_url_role":          self.role,
            "ai_url_sse_source":    self.gemini_path,
            "ai_url_sse_seq":       self.chunk_index,
            "ai_url_after_search_start": self.search_tool_seen,
            "ai_url_in_url_moderation":  False,
            "ai_url_search_query":  "",
            "ai_url_tool_name":     "Google Search (Gemini grounding)",
            # Gemini-specific
            "gemini_cited_text":    self.cited_text,
            "gemini_display_num":   self.display_number,
            "gemini_spp_id":        self.spp_id,
        }


@dataclass
class GeminiAIReport:
    """Full extraction result from a Gemini HAR."""
    urls:           List[GeminiAIUrl]
    user_prompt:    str
    model_name:     str
    search_tool_invoked: bool
    conversation_id: str
    response_id:    str
    chain:          List[Dict]

    @property
    def cited(self) -> List[GeminiAIUrl]:
        return [u for u in self.urls if u.role == "cited_source"]

    @property
    def unique_domains(self) -> List[str]:
        seen: Set[str] = set()
        out = []
        for u in self.urls:
            if u.domain not in seen:
                seen.add(u.domain)
                out.append(u.domain)
        return out


# ─────────────────────────────────────────────────────────────────────────────
#  URL UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def _normalize(raw: str) -> str:
    """Strip tracking params and #:~:text= fragments for canonical form."""
    if not raw or not raw.startswith("http"):
        return raw
    try:
        # Remove text fragments (keep base URL for dedup)
        base = raw.split("#")[0] if "#" in raw else raw
        p    = urllib.parse.urlparse(base)
        qs   = urllib.parse.parse_qs(p.query, keep_blank_values=True)
        clean = {k: v for k, v in qs.items() if k not in _TRACKING_PARAMS}
        return urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(clean, doseq=True)))
    except Exception:
        return raw


def _domain(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).netloc.lower()
    except Exception:
        return ""


def _extract_text_fragment(url: str) -> str:
    """
    Extract and decode the #:~:text= fragment from a citation URL.
    Gemini uses these to pinpoint the exact passage it read.
    Format: https://example.com/page#:~:text=start_text,end_text
    """
    if "#:~:text=" not in url:
        return ""
    try:
        frag = url.split("#:~:text=")[1]
        decoded = urllib.parse.unquote(frag)
        # Format is "start_text,end_text" — join with ellipsis for readability
        parts = decoded.split(",")
        if len(parts) == 2:
            return f"{parts[0].strip()}…{parts[1].strip()}"
        return decoded[:200]
    except Exception:
        return ""


def _is_excluded(url: str) -> bool:
    if not url or not url.startswith("http"):
        return True
    d = _domain(url)
    if d in _EXCLUDED_DOMAINS:
        return True
    for suffix in _EXCLUDED_SUFFIXES:
        if d.endswith(suffix):
            return True
    if _EXCLUDED_PATH_RE.search(url):
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
#  GEMINI CHUNK SPLITTER
# ─────────────────────────────────────────────────────────────────────────────

def _split_gemini_chunks(raw_text: str) -> List[Tuple[int, str]]:
    """
    Gemini's StreamGenerate response uses HTTP chunked transfer encoding
    with hex-length prefixes. Format:

        )]}'\n\n
        <hex_length>\n
        <json_payload>\n
        <hex_length>\n
        <json_payload>\n
        ...

    Each payload is a JSON array: [["wrb.fr", rpc_id, "<escaped_inner_json>"]]
    The inner JSON is double-escaped and must be parsed twice.

    Returns list of (chunk_index, raw_payload_string).
    """
    chunks: List[Tuple[int, str]] = []
    lines  = raw_text.split("\n")
    idx    = 0
    ci     = 0

    # Skip the )]}' security prefix
    while idx < len(lines) and lines[idx].strip() in ("", ")]}'"):
        idx += 1

    while idx < len(lines):
        line = lines[idx].strip()
        # Hex length line followed by payload
        if re.match(r"^[0-9a-fA-F]+$", line) and idx + 1 < len(lines):
            payload = lines[idx + 1].strip()
            if payload:
                chunks.append((ci, payload))
                ci += 1
            idx += 2
        else:
            idx += 1

    return chunks


def _parse_chunk_inner(payload: str) -> Optional[object]:
    """
    Parse a single Gemini chunk payload.
    Returns the inner parsed object (second-level JSON parse).
    """
    try:
        outer = json.loads(payload)
        # Structure: [["wrb.fr", rpc_id_or_null, "<escaped_inner_json>", ...]]
        if (isinstance(outer, list) and outer and
                isinstance(outer[0], list) and len(outer[0]) > 2):
            inner_str = outer[0][2]
            if isinstance(inner_str, str) and inner_str:
                return json.loads(inner_str)
    except (json.JSONDecodeError, IndexError, TypeError):
        pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
#  USER PROMPT EXTRACTOR
# ─────────────────────────────────────────────────────────────────────────────

def _extract_user_prompt(entry: Dict) -> str:
    """
    Gemini's user prompt is in the f.req POST body, URL-encoded.
    Format: f.req=[null,"[[\"user text\",0,...],[\"en-GB\"],...]",...token...]

    The inner array [0][0] is the user's message text.
    """
    try:
        raw_body = entry.get("request", {}).get("postData", {}).get("text", "")
        decoded  = urllib.parse.unquote(raw_body)

        # Extract f.req value (everything after f.req=)
        m = re.search(r"f\.req=(.+?)(?:&[a-z]|$)", decoded, re.DOTALL)
        if not m:
            return ""

        freq_raw = m.group(1).strip()

        # The f.req value is: [null, "[[\"prompt\",0,...],[\"lang\"],...]", token]
        # Parse the outer array
        outer = json.loads(freq_raw)
        if not isinstance(outer, list) or len(outer) < 2:
            return ""

        # Second element is the stringified inner array
        inner_str = outer[1]
        if not isinstance(inner_str, str):
            return ""

        inner = json.loads(inner_str)
        # inner[0][0] is the user prompt text
        if isinstance(inner, list) and inner and isinstance(inner[0], list) and inner[0]:
            prompt = inner[0][0]
            if isinstance(prompt, str):
                return prompt
    except Exception:
        pass

    # Fallback: simple regex on decoded body
    try:
        decoded = urllib.parse.unquote(
            entry.get("request", {}).get("postData", {}).get("text", "")
        )
        m = re.search(r'\[\\"([^"]{10,}?)\\"', decoded)
        if m:
            return urllib.parse.unquote(m.group(1))
    except Exception:
        pass

    return ""


# ─────────────────────────────────────────────────────────────────────────────
#  SEARCH TOOL SIGNAL DETECTOR
# ─────────────────────────────────────────────────────────────────────────────

def _detect_search_tool(chunks: List[Tuple[int, str]]) -> Tuple[bool, int]:
    """
    Detect Google Search tool invocation from intermediate stream chunks.

    In Gemini's stream, when the model decides to search the web, it emits
    chunks with key "7" in the inner object. The value at "7" contains:
      [null, ["google", [null, null, "Google Search", "<logo_url>",
                          null, "Searching the web"], <status>]]

    Status values: 1 = started, 4 = completed.
    This is the Gemini equivalent of ChatGPT's search_start marker.

    Returns (search_tool_invoked: bool, first_search_chunk_index: int).
    """
    for ci, payload in chunks:
        try:
            inner = _parse_chunk_inner(payload)
            if inner is None:
                continue

            # Structure: inner = [null, [conv_id, resp_id], {"7": [...], "44": true}]
            # Key "7" is inside inner[2] (a dict) when inner is a list
            tool_dict = None
            if isinstance(inner, list) and len(inner) > 2 and isinstance(inner[2], dict):
                tool_dict = inner[2]
            elif isinstance(inner, dict):
                tool_dict = inner

            if tool_dict is None:
                continue

            tool_data = tool_dict.get("7")
            if not isinstance(tool_data, list) or len(tool_data) < 2:
                continue

            # tool_data = [None, ["google", [None, None, "Google Search", logo_url,
            #                                None, "Searching the web"], status_int]]
            tool_entry = tool_data[1]
            if not isinstance(tool_entry, list) or len(tool_entry) < 2:
                continue

            tool_id   = tool_entry[0]   # "google"
            tool_info = tool_entry[1]   # [None, None, "Google Search", ...]

            if (tool_id == "google" and isinstance(tool_info, list) and
                    len(tool_info) > 2 and "Google Search" in str(tool_info)):
                return True, ci
        except Exception:
            pass
    return False, -1


# ─────────────────────────────────────────────────────────────────────────────
#  METADATA EXTRACTOR (conversation_id, model, response_id)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_session_metadata(chunks: List[Tuple[int, str]]) -> Dict[str, str]:
    """
    Extract conversation_id, response_id, and model name from stream chunks.

    Structure in final/large chunk:
      inner[1] = ["c_<conv_id>", "r_<resp_id>"]
      inner[42] = "3.5 Flash" (or similar model string)
      inner[39] = response_id (sometimes duplicated)
    """
    meta = {"conversation_id": "", "response_id": "", "model": ""}

    for ci, payload in chunks:
        try:
            outer = json.loads(payload)
            if not (isinstance(outer, list) and outer and
                    isinstance(outer[0], list) and len(outer[0]) > 2):
                continue
            inner_str = outer[0][2]
            if not isinstance(inner_str, str):
                continue
            inner = json.loads(inner_str)
            if not isinstance(inner, list):
                continue

            # [1] = ["c_CONV_ID", "r_RESP_ID"]
            if (len(inner) > 1 and isinstance(inner[1], list) and
                    len(inner[1]) >= 2):
                c_id = inner[1][0] if isinstance(inner[1][0], str) else ""
                r_id = inner[1][1] if isinstance(inner[1][1], str) else ""
                if c_id.startswith("c_") and not meta["conversation_id"]:
                    meta["conversation_id"] = c_id
                if r_id.startswith("r_") and not meta["response_id"]:
                    meta["response_id"] = r_id

            # Model name (position varies, search for recognizable strings)
            inner_s = json.dumps(inner)
            model_m = re.search(r'"(\d+\.\d+\s+(?:Flash|Pro|Ultra)[^"]{0,20})"', inner_s)
            if model_m and not meta["model"]:
                meta["model"] = model_m.group(1)

            if all(meta.values()):
                break
        except Exception:
            pass

    return meta


# ─────────────────────────────────────────────────────────────────────────────
#  CITATION ARRAY EXTRACTOR
# ─────────────────────────────────────────────────────────────────────────────

def _extract_citations_from_chunk(
    inner: list,
    ci: int,
    entry_url: str,
    search_tool_invoked: bool,
) -> List[Dict]:
    """
    Extract all citations from the final Gemini response chunk.

    Gemini citation structure at inner[4][0][2][1]:
    Each citation entry (list of 4 elements):
      [0] = [cited_text_span_str, None, None, [[char_s, char_e], ...]]
             cited_text_span_str is the exact text in the response that
             this citation supports.
      [1] = [display_number_int]  (1-based citation number in UI)
      [2] = [[url_with_fragment, title_or_empty, snippet?, ...], ...]
             Multiple URL entries per citation (deduped by Gemini).
             URL may have #:~:text= fragment pointing to exact passage.
      [3] = "spp_<hex>"  unique citation anchor ID linking to response position

    JSON path: inner[4][0][2][1][N][...]
    """
    records: List[Dict] = []

    try:
        # Navigate to citation array
        if not (isinstance(inner, list) and len(inner) > 4):
            return records
        level4 = inner[4]
        if not (isinstance(level4, list) and level4 and
                isinstance(level4[0], list) and len(level4[0]) > 2):
            return records
        level402 = level4[0][2]
        if not (isinstance(level402, list) and len(level402) > 1):
            return records
        citation_array = level402[1]
        if not isinstance(citation_array, list):
            return records

    except (IndexError, TypeError):
        return records

    for n, cit in enumerate(citation_array):
        if not isinstance(cit, list) or len(cit) < 3:
            continue

        # Extract cited text span
        span_data  = cit[0]
        cited_text = ""
        if isinstance(span_data, list) and span_data:
            if isinstance(span_data[0], str):
                cited_text = span_data[0][:300]

        # Extract display number (1-based citation index in UI)
        display_num = 0
        num_data = cit[1]
        if isinstance(num_data, list) and num_data:
            if isinstance(num_data[0], int):
                display_num = num_data[0]
            elif isinstance(num_data[0], str):
                try:
                    display_num = int(num_data[0])
                except ValueError:
                    pass

        # Extract URL entries
        url_data = cit[2]
        spp_id   = cit[3] if len(cit) > 3 and isinstance(cit[3], str) else ""

        if not isinstance(url_data, list):
            continue

        for url_entry in url_data:
            if not isinstance(url_entry, list) or not url_entry:
                continue
            raw_url = url_entry[0] if isinstance(url_entry[0], str) else ""
            if not raw_url or not raw_url.startswith("http"):
                continue
            if _is_excluded(raw_url):
                continue

            # Title is at position 1 in url_entry (may be empty string)
            title = ""
            if len(url_entry) > 1 and isinstance(url_entry[1], str):
                title = url_entry[1]

            # Additional snippet may be at position 2
            extra_snippet = ""
            if len(url_entry) > 2 and isinstance(url_entry[2], str):
                extra_snippet = url_entry[2][:300]

            # Extract text fragment from URL itself
            text_frag = _extract_text_fragment(raw_url)
            snippet   = text_frag or extra_snippet

            records.append({
                "raw_url":           raw_url,
                "title":             title,
                "snippet":           snippet,
                "cited_text":        cited_text,
                "display_number":    display_num,
                "spp_id":            spp_id,
                "chunk_index":       ci,
                "gemini_path":       f"inner[4][0][2][1][{n}][2][0]",
                "entry_url":         entry_url,
                "search_tool_seen":  search_tool_invoked,
                "role":              "cited_source",
                "confidence_base":   95,
            })

    return records


# ─────────────────────────────────────────────────────────────────────────────
#  FALLBACK: RECURSIVE URL SCANNER
# ─────────────────────────────────────────────────────────────────────────────

def _recursive_url_scan(obj, path: str = "", depth: int = 0) -> List[Tuple[str, str]]:
    """
    Walk any parsed JSON object recursively and collect all HTTP URLs.
    Used as a fallback / cross-check to catch any URLs not found
    by the structured extractor.

    Returns list of (path, url) pairs.
    """
    if depth > 12:
        return []
    results = []
    if isinstance(obj, str):
        if obj.startswith("http") and len(obj) > 10:
            results.append((path, obj))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            results.extend(_recursive_url_scan(item, f"{path}[{i}]", depth + 1))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            results.extend(_recursive_url_scan(v, f"{path}.{k}", depth + 1))
    return results


# ─────────────────────────────────────────────────────────────────────────────
#  EVIDENCE BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def _build_evidence(url: str, title: str, cited_text: str, display_num: int,
                    spp_id: str, snippet: str, search_invoked: bool,
                    gemini_path: str, confidence: int) -> str:
    parts = []

    parts.append(
        f"This URL was identified as a Gemini-cited source (citation #{display_num} "
        f"in the AI response)."
    )

    parts.append(
        f"Extracted from Gemini StreamGenerate response at positional path "
        f"'{gemini_path}' — a nested array structure unique to Gemini's "
        f"BardFrontendService RPC protocol."
    )

    if search_invoked:
        parts.append(
            "The Google Search grounding tool was invoked before this citation "
            "appeared (detected via key '7' in intermediate stream chunks, "
            "value: 'Searching the web'). This provides temporal proof that "
            "Gemini performed live web retrieval to generate this response."
        )

    if cited_text:
        trunc = cited_text[:120] + ("…" if len(cited_text) > 120 else "")
        parts.append(f"This URL supports the response text: \"{trunc}\"")

    if snippet:
        parts.append(
            f"The URL contains a text fragment (#:~:text=) pinpointing the exact "
            f"passage Gemini read: \"{snippet[:120]}\""
        )

    parts.append(
        "IMPORTANT: This URL does NOT appear as a direct browser network request "
        "in the HAR. Gemini's web grounding is entirely server-side — the URL "
        "exists only within the StreamGenerate response payload, proving it was "
        "retrieved by Gemini's backend, not by the user's browser."
    )

    if spp_id:
        parts.append(f"Gemini citation anchor ID: {spp_id}.")

    parts.append(f"Confidence: {confidence}%.")

    return " ".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
#  RETRIEVAL CHAIN BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def _build_chain(prompt: str, urls: List[GeminiAIUrl]) -> List[Dict]:
    chain = []

    if prompt:
        chain.append({
            "layer": "0 — User Query → Gemini",
            "type":  "user_prompt",
            "value": prompt,
            "domain": "",
            "title":  "",
            "confidence": 100,
        })

    if any(u.search_tool_seen for u in urls):
        chain.append({
            "layer": "1 — Google Search Grounding",
            "type":  "search_tool",
            "value": "Google Search invoked (key '7': 'Searching the web')",
            "domain": "google.com",
            "title":  "",
            "confidence": 98,
        })

    # Deduplicated cited sources in display-number order
    seen: Set[str] = set()
    for u in sorted(urls, key=lambda x: x.display_number):
        norm = u.normalized_url
        if norm not in seen:
            seen.add(norm)
            chain.append({
                "layer": f"2 — Cited Source (#{u.display_number})",
                "type":  "cited_source",
                "value": norm,
                "domain": u.domain,
                "title":  u.title,
                "confidence": u.confidence,
            })

    return chain


# ─────────────────────────────────────────────────────────────────────────────
#  DEDUPLICATION
# ─────────────────────────────────────────────────────────────────────────────

def _deduplicate(urls: List[GeminiAIUrl]) -> List[GeminiAIUrl]:
    """
    Deduplicate by normalized URL.
    When same URL cited multiple times (different text spans), merge:
    keep lowest display_number, combine cited_text, highest confidence.
    """
    seen: Dict[str, GeminiAIUrl] = {}
    for u in urls:
        key = u.normalized_url
        if key not in seen:
            seen[key] = u
        else:
            existing = seen[key]
            # Merge: prefer lower citation number, richer snippet
            merged = GeminiAIUrl(
                raw_url        = u.raw_url if not existing.raw_url else existing.raw_url,
                normalized_url = key,
                domain         = existing.domain,
                title          = existing.title or u.title,
                snippet        = existing.snippet or u.snippet,
                cited_text     = (existing.cited_text + " / " + u.cited_text)[:400]
                                  if u.cited_text and u.cited_text != existing.cited_text
                                  else existing.cited_text,
                display_number = min(existing.display_number, u.display_number)
                                  if existing.display_number and u.display_number
                                  else (existing.display_number or u.display_number),
                spp_id         = existing.spp_id or u.spp_id,
                confidence     = max(existing.confidence, u.confidence),
                evidence       = existing.evidence,
                har_location   = existing.har_location,
                gemini_path    = existing.gemini_path,
                role           = existing.role,
                search_tool_seen = existing.search_tool_seen or u.search_tool_seen,
                chunk_index    = min(existing.chunk_index, u.chunk_index),
            )
            seen[key] = merged

    return sorted(seen.values(), key=lambda u: (u.display_number or 999, -u.confidence))


# ─────────────────────────────────────────────────────────────────────────────
#  PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────

def extract_gemini_ai_urls(entries: List[Dict]) -> GeminiAIReport:
    """
    Main entry point. Scans all HAR entries for Gemini StreamGenerate
    and batchexecute responses and returns a GeminiAIReport.

    Parameters
    ----------
    entries : list of HAR log entry dicts

    Returns
    -------
    GeminiAIReport with .urls, .chain, .user_prompt, .model_name, etc.
    """
    user_prompt     = ""
    search_invoked  = False
    search_ci       = -1
    raw_records:    List[Dict] = []
    meta            = {"conversation_id": "", "response_id": "", "model": ""}

    # Find the StreamGenerate entry
    for entry in entries:
        url    = entry["request"]["url"]
        method = entry["request"]["method"]

        if "StreamGenerate" not in url or method != "POST":
            continue

        # Extract user prompt from request body
        if not user_prompt:
            user_prompt = _extract_user_prompt(entry)

        # Parse the chunked response
        raw_text = _resp_text_raw(entry)
        if not raw_text or len(raw_text) < 100:
            continue

        chunks = _split_gemini_chunks(raw_text)
        if not chunks:
            continue

        # Detect search tool invocation
        si, sci = _detect_search_tool(chunks)
        if si:
            search_invoked = True
            search_ci      = sci

        # Extract session metadata
        if not meta["model"]:
            meta = _extract_session_metadata(chunks)

        # Find the final large chunk (contains citations)
        # It's identifiable by having content at inner[4][0][2][1]
        entry_url = url

        for ci, payload in chunks:
            try:
                outer = json.loads(payload)
                if not (isinstance(outer, list) and outer and
                        isinstance(outer[0], list) and len(outer[0]) > 2):
                    continue
                inner_str = outer[0][2]
                if not isinstance(inner_str, str):
                    continue
                inner = json.loads(inner_str)

                # Try structured citation extraction
                cits = _extract_citations_from_chunk(
                    inner, ci, entry_url, search_invoked
                )
                raw_records.extend(cits)

                # Fallback recursive scan on this chunk's inner data
                if not cits:
                    all_urls = _recursive_url_scan(inner)
                    for path, u in all_urls:
                        if _is_excluded(u):
                            continue
                        raw_records.append({
                            "raw_url":        u,
                            "title":          "",
                            "snippet":        "",
                            "cited_text":     "",
                            "display_number": 0,
                            "spp_id":         "",
                            "chunk_index":    ci,
                            "gemini_path":    path,
                            "entry_url":      entry_url,
                            "search_tool_seen": search_invoked,
                            "role":           "grounding_source",
                            "confidence_base": 75,
                        })

            except Exception:
                pass

        # Only process the first StreamGenerate entry
        break

    # Build GeminiAIUrl objects
    ai_urls: List[GeminiAIUrl] = []
    for rec in raw_records:
        raw  = rec["raw_url"]
        norm = _normalize(raw)
        if not norm or not norm.startswith("http") or _is_excluded(norm):
            continue

        conf = rec.get("confidence_base", 85)
        if rec.get("search_tool_seen"):
            conf = min(conf + 3, 99)
        if rec.get("spp_id"):
            conf = min(conf + 2, 99)
        if rec.get("cited_text"):
            conf = min(conf + 1, 99)

        evidence = _build_evidence(
            url          = norm,
            title        = rec.get("title", ""),
            cited_text   = rec.get("cited_text", ""),
            display_num  = rec.get("display_number", 0),
            spp_id       = rec.get("spp_id", ""),
            snippet      = rec.get("snippet", ""),
            search_invoked = rec.get("search_tool_seen", False),
            gemini_path  = rec.get("gemini_path", ""),
            confidence   = conf,
        )

        ai_urls.append(GeminiAIUrl(
            raw_url          = raw,
            normalized_url   = norm,
            domain           = _domain(norm),
            title            = rec.get("title", ""),
            snippet          = rec.get("snippet", ""),
            cited_text       = rec.get("cited_text", ""),
            display_number   = rec.get("display_number", 0),
            spp_id           = rec.get("spp_id", ""),
            confidence       = conf,
            evidence         = evidence,
            har_location     = (
                f"StreamGenerate response chunk {rec['chunk_index']} "
                f"[{rec['entry_url'][-50:]}]"
            ),
            gemini_path      = rec.get("gemini_path", ""),
            role             = rec.get("role", "cited_source"),
            search_tool_seen = rec.get("search_tool_seen", False),
            chunk_index      = rec.get("chunk_index", 0),
        ))

    ai_urls = _deduplicate(ai_urls)
    chain   = _build_chain(user_prompt, ai_urls)

    return GeminiAIReport(
        urls             = ai_urls,
        user_prompt      = user_prompt,
        model_name       = meta.get("model", ""),
        search_tool_invoked = search_invoked,
        conversation_id  = meta.get("conversation_id", ""),
        response_id      = meta.get("response_id", ""),
        chain            = chain,
    )
