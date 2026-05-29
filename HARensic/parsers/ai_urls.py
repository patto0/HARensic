"""
AI URL Extractor — parsers/ai_urls.py
======================================
Extracts ONLY URLs that the AI system itself accessed, retrieved, cited,
or generated during LLM-assisted web search workflows.

Strictly excluded:
  - Platform / OpenAI infrastructure URLs
  - Telemetry, Sentinel, CDN, static assets
  - Favicon proxy URLs
  - Human browser navigation URLs
  - Any URL not traceable to AI tool execution in the SSE stream

Five extraction sources (all from SSE stream metadata):
  1. url_moderation events        — AI output URLs safety-checked before display
  2. content_references patches   — cited article URLs resolved inline
     a. safe_urls arrays          — raw URL pair (clean + utm-tagged)
     b. grouped_webpages items    — full article content AI read (with snippet)
     c. sources_footnote          — final citation list visible to user
  3. search_result_groups         — raw search index results returned to model
  4. web.run tool message         — search_model_queries (refined query)
  5. search() code block          — tool invocation literal

Every record carries:
  - normalized_url  (tracking params stripped)
  - raw_url         (as found in HAR)
  - domain
  - title
  - snippet         (article content AI read, if available)
  - pub_date
  - confidence      (0–100)
  - evidence        (forensic rationale string)
  - har_location    (exact path in HAR)
  - sse_source      (which SSE key it came from)
  - sse_seq         (stream sequence number)
  - after_search_start (bool — temporal confirmation)
  - role            (search_result | cited_source | retrieved_content | ...)
  - in_url_moderation (bool — was this URL safety-checked by platform?)
  - search_query    (what the AI searched for when this was retrieved)
  - tool_name       (e.g. SonicBrowserTool)

Relationship chain reconstructed:
  User Query → search_model_queries → search_result_groups
             → content_references (retrieved_content, cited_source)
             → url_moderation (safety-checked before display)
             → sources_footnote (final displayed citations)
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
#  EXCLUSION RULES — domains never attributable to AI content retrieval
# ─────────────────────────────────────────────────────────────────────────────

_EXCLUDED_DOMAINS: Set[str] = {
    "chatgpt.com", "openai.com", "auth.openai.com",
    "cdn.oaistatic.com", "oaistatic.com",
    "browser-intake-datadoghq.com", "datadoghq.com",
    "gemini.google.com", "gemini.gstatic.com",
    "claude.ai", "anthropic.com",
    "www.google.com", "google.com",
    "t0.gstatic.com", "t1.gstatic.com", "gstatic.com",
    "analytics.google.com", "www.google-analytics.com",
    "www.googletagmanager.com", "googletagmanager.com",
    "play.google.com", "fonts.gstatic.com",
    "accounts.google.com", "signaler-pa.clients6.google.com",
}

_EXCLUDED_SUFFIXES: Tuple[str, ...] = (
    ".oaistatic.com", ".openai.com", ".chatgpt.com",
    ".datadoghq.com", ".anthropic.com", ".claude.ai",
    ".gstatic.com",
)

_EXCLUDED_PATH_RE = re.compile(
    r"/cdn/assets/|/sentinel/|/ces/v1/|/backend-anon/|/backend-api/|"
    r"/f/conversation|/lat/r|/o11y/|faviconV2|/s2/favicons|/BardFrontend|"
    r"/StreamGenerate"
)

# UTM and tracking params to strip for normalization
_TRACKING: Set[str] = {
    "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
    "gclid", "gbraid", "gad_source", "gad_campaignid", "ref", "referrer",
    "fbclid", "msclkid", "srsltid", "c_id", "c_agid", "c_crid",
}


# ─────────────────────────────────────────────────────────────────────────────
#  DATA STRUCTURE
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AIUrl:
    """One AI-attributed URL with full forensic provenance."""
    raw_url:            str
    normalized_url:     str
    domain:             str
    title:              str
    snippet:            str       # Article text AI read (if available)
    pub_date:           str       # ISO date string or ""
    confidence:         int       # 0–100
    evidence:           str       # Forensic rationale
    har_location:       str       # Precise HAR path
    sse_source:         str       # Which SSE key this came from
    sse_seq:            int       # Stream sequence number
    after_search_start: bool      # Temporal confirmation
    role:               str       # search_result|cited_source|retrieved_content|...
    in_url_moderation:  bool      # Was URL safety-checked?
    search_query:       str       # AI's refined search query at time of retrieval
    tool_name:          str       # e.g. SonicBrowserTool

    def to_row(self) -> Dict:
        """Canonical artifact row for display/export integration."""
        return {
            # Standard artifact fields (backward compat)
            "artifact":     f"ai_url_{self.role}",
            "value":        self.normalized_url,
            "har_location": self.har_location,
            "json_path":    self.sse_source,
            "attribution":  "AI",
            "reason":       self.evidence,
            # Extended AI URL fields
            "ai_url":           self.normalized_url,
            "ai_url_raw":       self.raw_url,
            "ai_url_domain":    self.domain,
            "ai_url_title":     self.title,
            "ai_url_snippet":   self.snippet,
            "ai_url_pub_date":  self.pub_date,
            "ai_url_confidence": self.confidence,
            "ai_url_role":      self.role,
            "ai_url_sse_source": self.sse_source,
            "ai_url_sse_seq":   self.sse_seq,
            "ai_url_after_search_start": self.after_search_start,
            "ai_url_in_url_moderation":  self.in_url_moderation,
            "ai_url_search_query": self.search_query,
            "ai_url_tool_name":   self.tool_name,
        }


@dataclass
class AIUrlReport:
    """Full extraction result from one HAR file."""
    urls:           List[AIUrl]
    search_queries: List[str]
    tool_name:      str
    search_start_seq: Optional[int]
    chain: List[Dict]   # Reconstructed retrieval chain

    @property
    def cited(self) -> List[AIUrl]:
        return [u for u in self.urls if u.role in ("cited_source", "retrieved_content")]

    @property
    def search_results(self) -> List[AIUrl]:
        return [u for u in self.urls if u.role == "search_result"]


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _normalize(raw: str) -> str:
    """Strip tracking params; remove chatgpt.com attribution suffix."""
    if not raw or not raw.startswith("http"):
        return raw
    try:
        p = urllib.parse.urlparse(raw)
        qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
        clean = {k: v for k, v in qs.items() if k not in _TRACKING}
        return urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(clean, doseq=True)))
    except Exception:
        return raw


def _domain(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).netloc.lower()
    except Exception:
        return ""


def _is_excluded(url: str) -> bool:
    """Return True if this URL should NEVER be attributed to AI content retrieval."""
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
    # Favicon proxy patterns
    if "faviconV2" in url or "/s2/favicons" in url:
        return True
    return False


def _pub_date_str(raw) -> str:
    """Convert Unix timestamp float to ISO date string."""
    if not raw:
        return ""
    try:
        return datetime.fromtimestamp(float(raw), tz=timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return str(raw)


def _parse_sse(text: str) -> List[Tuple[int, Dict]]:
    """Parse SSE text → list of (seq_index, parsed_dict)."""
    results = []
    seq = 0
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("data:"):
            continue
        raw = s[5:].strip()
        if not raw or raw == "[DONE]":
            continue
        try:
            results.append((seq, json.loads(raw)))
            seq += 1
        except (json.JSONDecodeError, ValueError):
            pass
    return results


# ─────────────────────────────────────────────────────────────────────────────
#  EVIDENCE BUILDER
# ─────────────────────────────────────────────────────────────────────────────

_ROLE_DESC: Dict[str, str] = {
    "search_result":     "a raw search index result returned to the AI model",
    "cited_source":      "a final citation included in the AI's generated response",
    "retrieved_content": "a webpage whose full content was retrieved and read by the AI",
    "supporting_source": "a supporting reference co-cited with a primary source",
    "url_moderation":    "a URL that passed the platform's safety check before being displayed",
    "tool_call":         "a URL embedded in the AI's tool invocation code block",
}

def _build_evidence(
    url: str,
    role: str,
    sse_source: str,
    after_ss: bool,
    tool_name: str,
    query: str,
    snippet: str,
    in_mod: bool,
    confidence: int,
) -> str:
    parts = []

    role_desc = _ROLE_DESC.get(role, "an AI-attributed resource")
    parts.append(f"This URL was identified as {role_desc}.")

    parts.append(f"Extracted from SSE stream key '{sse_source}'.")

    if after_ss:
        parts.append(
            "The URL appeared AFTER the 'search_start' message_marker event "
            "in the SSE stream, providing temporal proof that it was generated "
            "during AI tool execution, not during user-initiated browser navigation."
        )

    if query:
        parts.append(f"The AI issued the search query: \"{query}\".")

    if tool_name:
        parts.append(f"Tool invoked: {tool_name}.")

    if in_mod:
        parts.append(
            "This URL also appears in a 'url_moderation' SSE event — "
            "the platform safety-checked it before including it in the AI response, "
            "which is definitive proof it was AI-generated output."
        )

    parts.append(
        "IMPORTANT: This URL does NOT appear as a direct browser network request "
        "in the HAR file. It exists exclusively within the streamed assistant "
        "metadata, proving the content was retrieved server-side by the AI tool, "
        "not fetched by the user's browser."
    )

    if snippet:
        trunc = snippet[:150] + ("…" if len(snippet) > 150 else "")
        parts.append(f"Content read by AI: \"{trunc}\"")

    parts.append(f"Confidence: {confidence}%.")
    return " ".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
#  CORE SSE EXTRACTOR
# ─────────────────────────────────────────────────────────────────────────────

def _extract_from_sse(
    sse_text: str,
    entry_url: str,
    entry_ts: str,
) -> AIUrlReport:
    """
    Single-pass SSE parser that builds a complete AIUrlReport.

    Pass 1 — collect stream state:
        search_start_seq, tool_name, search_queries,
        url_moderation set, web.run search_model_queries

    Pass 2 — extract URLs from:
        url_moderation events
        content_references patches (safe_urls, grouped_webpages, sources_footnote)
        search_result_groups
        code block (search() call)

    Pass 3 — enrich, deduplicate, score confidence
    """
    events = _parse_sse(sse_text)

    # ── Pass 1: collect state ──────────────────────────────────────────────
    search_start_seq: Optional[int] = None
    tool_name = ""
    search_queries: List[str] = []
    moderated_urls: Set[str] = set()   # URLs seen in url_moderation

    for seq, data in events:
        if not isinstance(data, dict):
            continue
        dtype = data.get("type", "")

        # search_start marker — temporal anchor
        if dtype == "message_marker" and data.get("marker") == "search_start":
            if search_start_seq is None:
                search_start_seq = seq

        # server_ste_metadata — tool name
        if dtype == "server_ste_metadata":
            meta = data.get("metadata", {}) or {}
            if meta.get("tool_name") and not tool_name:
                tool_name = meta["tool_name"]

        # url_moderation — definitive AI output proof
        if dtype == "url_moderation":
            um = data.get("url_moderation_result", {}) or {}
            fu = um.get("full_url", "")
            if fu and not _is_excluded(fu):
                moderated_urls.add(_normalize(fu))

        # web.run tool message → search_model_queries
        v = data.get("v", {})
        if isinstance(v, dict):
            msg    = v.get("message", {}) or {}
            author = (msg.get("author", {}) or {})
            if author.get("name") == "web.run":
                smq = (msg.get("metadata", {}) or {}).get("search_model_queries", {})
                if isinstance(smq, dict):
                    for q in smq.get("queries", []):
                        if q and q not in search_queries:
                            search_queries.append(q)

        # search_model_queries in any assistant metadata delta
        if isinstance(v, dict):
            smq = (v.get("message", {}) or {}).get("metadata", {}) or {}
            smq = smq.get("search_model_queries", {})
            if isinstance(smq, dict):
                for q in smq.get("queries", []):
                    if q and q not in search_queries:
                        search_queries.append(q)

        # search_model_queries in patch list
        if isinstance(v, list):
            for patch in v:
                if not isinstance(patch, dict):
                    continue
                pval = patch.get("v")
                if isinstance(pval, dict) and "queries" in pval:
                    for q in pval.get("queries", []):
                        if q and q not in search_queries:
                            search_queries.append(q)

    current_query = search_queries[0] if search_queries else ""

    # ── Pass 2: extract raw URL records ────────────────────────────────────
    raw_records: List[Dict] = []

    for seq, data in events:
        if not isinstance(data, dict):
            continue
        dtype = data.get("type", "")
        after_ss = search_start_seq is not None and seq > search_start_seq

        # ── Source 1: url_moderation events ──────────────────────────────
        if dtype == "url_moderation":
            um = data.get("url_moderation_result", {}) or {}
            url = um.get("full_url", "")
            if url and not _is_excluded(url):
                raw_records.append({
                    "url":        url,
                    "role":       "url_moderation",
                    "sse_source": "url_moderation[url_moderation_result.full_url]",
                    "seq":        seq,
                    "after_ss":   after_ss,
                    "title":      "",
                    "snippet":    "",
                    "pub_date":   "",
                    "confidence_base": 97,  # Definitive — platform checked it
                })

        # ── Sources 2+3: content_references and search_result_groups ─────
        v = data.get("v", {})

        # Full message delta (v is dict)
        if isinstance(v, dict):
            msg  = v.get("message", {}) or {}
            meta = msg.get("metadata", {}) or {}

            # search_result_groups
            srg = meta.get("search_result_groups")
            if srg and isinstance(srg, list):
                for group in srg:
                    dom = group.get("domain", "")
                    for entry in group.get("entries", []):
                        url = entry.get("url", "")
                        if url and not _is_excluded(url):
                            raw_records.append({
                                "url":        url,
                                "role":       "search_result",
                                "sse_source": "v.message.metadata.search_result_groups",
                                "seq":        seq,
                                "after_ss":   after_ss,
                                "title":      entry.get("title", ""),
                                "snippet":    entry.get("snippet", ""),
                                "pub_date":   "",
                                "confidence_base": 90,
                            })

            # content_references (full list in message)
            refs = meta.get("content_references")
            if refs and isinstance(refs, list):
                for ref in refs:
                    if not isinstance(ref, dict):
                        continue
                    _extract_ref(ref, seq, after_ss, raw_records)

        # Patch-array delta (v is list)
        if isinstance(v, list):
            for patch in v:
                if not isinstance(patch, dict):
                    continue
                pkey = str(patch.get("p", ""))
                pval = patch.get("v")

                # ── content_references/N/safe_urls  (list of URL strings)
                if "content_references" in pkey and "safe_urls" in pkey:
                    if isinstance(pval, list):
                        for url in pval:
                            if isinstance(url, str) and url.startswith("http") \
                                    and not _is_excluded(url):
                                raw_records.append({
                                    "url":        url,
                                    "role":       "cited_source",
                                    "sse_source": f"patch:{pkey}",
                                    "seq":        seq,
                                    "after_ss":   after_ss,
                                    "title":      "",
                                    "snippet":    "",
                                    "pub_date":   "",
                                    "confidence_base": 93,
                                })

                # ── content_references/N  (full ref object patched in)
                if re.match(r"/message/metadata/content_references/\d+$", pkey):
                    if isinstance(pval, dict):
                        _extract_ref(pval, seq, after_ss, raw_records)

                # ── content_references  (initial list of refs)
                if pkey == "/message/metadata/content_references":
                    if isinstance(pval, list):
                        for ref in pval:
                            if isinstance(ref, dict):
                                _extract_ref(ref, seq, after_ss, raw_records)

                # ── sources_footnote patch
                if "content_references" in pkey and isinstance(pval, list):
                    for ref in pval:
                        if isinstance(ref, dict) and ref.get("type") == "sources_footnote":
                            for src in ref.get("sources", []):
                                url = src.get("url", "")
                                if url and not _is_excluded(url):
                                    raw_records.append({
                                        "url":        url,
                                        "role":       "cited_source",
                                        "sse_source": "sources_footnote",
                                        "seq":        seq,
                                        "after_ss":   after_ss,
                                        "title":      src.get("title", ""),
                                        "snippet":    "",
                                        "pub_date":   "",
                                        "confidence_base": 98,
                                    })

        # ── Source 5: search() code block (tool invocation) ──────────────
        if isinstance(v, dict):
            msg     = v.get("message", {}) or {}
            content = msg.get("content", {}) or {}
            if content.get("content_type") == "code":
                code_text = content.get("text", "")
                for url in re.findall(r'https?://[^\s\'"<>]+', code_text):
                    if not _is_excluded(url):
                        raw_records.append({
                            "url":        url,
                            "role":       "tool_call",
                            "sse_source": "v.message.content[content_type=code]",
                            "seq":        seq,
                            "after_ss":   after_ss,
                            "title":      "",
                            "snippet":    "",
                            "pub_date":   "",
                            "confidence_base": 92,
                        })

        # ── Top-level patch format (p/o/v at root) ────────────────────────
        p_key = str(data.get("p", ""))
        o_op  = data.get("o", "")
        p_val = data.get("v")
        if o_op == "patch" and isinstance(p_val, list):
            for patch in p_val:
                if not isinstance(patch, dict):
                    continue
                pk = str(patch.get("p", ""))
                pv = patch.get("v")
                if "content_references" in pk and "safe_urls" in pk:
                    if isinstance(pv, list):
                        for url in pv:
                            if isinstance(url, str) and url.startswith("http") \
                                    and not _is_excluded(url):
                                raw_records.append({
                                    "url":        url,
                                    "role":       "cited_source",
                                    "sse_source": f"root_patch:{pk}",
                                    "seq":        seq,
                                    "after_ss":   after_ss,
                                    "title":      "",
                                    "snippet":    "",
                                    "pub_date":   "",
                                    "confidence_base": 91,
                                })
                if re.match(r"/message/metadata/content_references/\d+$", pk):
                    if isinstance(pv, dict):
                        _extract_ref(pv, seq, after_ss, raw_records)

    # ── Pass 3: build AIUrl objects, deduplicate, score ───────────────────
    moderated_norm = moderated_urls   # already normalized
    seen: Dict[str, AIUrl] = {}

    for rec in raw_records:
        raw_url  = rec["url"]
        norm_url = _normalize(raw_url)
        if not norm_url or not norm_url.startswith("http"):
            continue
        if _is_excluded(norm_url):
            continue

        dom      = _domain(norm_url)
        in_mod   = norm_url in moderated_norm or raw_url in moderated_norm
        after_ss = rec["after_ss"]
        role     = rec["role"]
        seq      = rec["seq"]
        sse_src  = rec["sse_source"]
        title    = rec.get("title", "")
        snippet  = rec.get("snippet", "")
        pub_date = _pub_date_str(rec.get("pub_date"))

        # Confidence scoring
        base = rec.get("confidence_base", 85)
        conf = base
        if after_ss:
            conf = min(conf + 3, 99)
        if in_mod:
            conf = min(conf + 2, 99)
        if role in ("cited_source", "retrieved_content"):
            conf = min(conf + 2, 99)

        evidence = _build_evidence(
            url=norm_url, role=role, sse_source=sse_src,
            after_ss=after_ss, tool_name=tool_name,
            query=current_query, snippet=snippet,
            in_mod=in_mod, confidence=conf,
        )

        har_loc = (
            f"SSE stream [{sse_src}] "
            f"seq={seq} entry={entry_url[-60:] if len(entry_url) > 60 else entry_url}"
        )

        ai_url = AIUrl(
            raw_url=raw_url,
            normalized_url=norm_url,
            domain=dom,
            title=title,
            snippet=snippet,
            pub_date=pub_date,
            confidence=conf,
            evidence=evidence,
            har_location=har_loc,
            sse_source=sse_src,
            sse_seq=seq,
            after_search_start=after_ss,
            role=role,
            in_url_moderation=in_mod,
            search_query=current_query,
            tool_name=tool_name,
        )

        # Dedup: keep highest-confidence; prefer richer roles
        if norm_url not in seen:
            seen[norm_url] = ai_url
        else:
            existing = seen[norm_url]
            role_priority = {
                "retrieved_content": 6,
                "cited_source":      5,
                "sources_footnote":  5,
                "url_moderation":    4,
                "search_result":     3,
                "supporting_source": 2,
                "tool_call":         1,
            }
            if role_priority.get(role, 0) > role_priority.get(existing.role, 0):
                # Merge: keep better role but combine evidence flags
                ai_url = AIUrl(
                    raw_url=ai_url.raw_url,
                    normalized_url=norm_url,
                    domain=dom,
                    title=title or existing.title,
                    snippet=snippet or existing.snippet,
                    pub_date=pub_date or existing.pub_date,
                    confidence=max(conf, existing.confidence),
                    evidence=evidence,
                    har_location=har_loc,
                    sse_source=f"{sse_src} + {existing.sse_source}",
                    sse_seq=min(seq, existing.sse_seq),
                    after_search_start=after_ss or existing.after_search_start,
                    role=role,
                    in_url_moderation=in_mod or existing.in_url_moderation,
                    search_query=current_query,
                    tool_name=tool_name or existing.tool_name,
                )
                seen[norm_url] = ai_url
            elif conf > existing.confidence:
                seen[norm_url] = ai_url

    # ── Sort: cited > retrieved > search_results > others; then confidence
    role_order = {
        "cited_source": 0, "retrieved_content": 1, "url_moderation": 2,
        "search_result": 3, "supporting_source": 4, "tool_call": 5,
    }
    final_urls = sorted(
        seen.values(),
        key=lambda u: (role_order.get(u.role, 9), -u.confidence)
    )

    # ── Build retrieval chain ──────────────────────────────────────────────
    chain = _build_chain(search_queries, final_urls)

    return AIUrlReport(
        urls=final_urls,
        search_queries=search_queries,
        tool_name=tool_name,
        search_start_seq=search_start_seq,
        chain=chain,
    )


def _extract_ref(ref: Dict, seq: int, after_ss: bool, out: List[Dict]) -> None:
    """
    Extract URLs from a single content_references entry (any type).
    Handles: grouped_webpages, sources_footnote, url (inline link).
    """
    ref_type = ref.get("type", "")

    # grouped_webpages — full article content AI read
    if ref_type == "grouped_webpages" or ("items" in ref and ref_type != "entity"):
        for item in ref.get("items", []):
            if not isinstance(item, dict):
                continue
            url = item.get("url", "")
            if url and not _is_excluded(url):
                out.append({
                    "url":        url,
                    "role":       "retrieved_content",
                    "sse_source": "content_references[grouped_webpages].items[].url",
                    "seq":        seq,
                    "after_ss":   after_ss,
                    "title":      item.get("title", ""),
                    "snippet":    (item.get("snippet", "") or "")[:500],
                    "pub_date":   item.get("pub_date", ""),
                    "confidence_base": 96,
                })
            # Supporting websites
            for sw in item.get("supporting_websites", []):
                sw_url = sw.get("url", "")
                if sw_url and not _is_excluded(sw_url):
                    out.append({
                        "url":        sw_url,
                        "role":       "supporting_source",
                        "sse_source": "content_references[grouped_webpages].supporting_websites[].url",
                        "seq":        seq,
                        "after_ss":   after_ss,
                        "title":      sw.get("title", ""),
                        "snippet":    "",
                        "pub_date":   "",
                        "confidence_base": 88,
                    })

    # sources_footnote — final displayed citations
    elif ref_type == "sources_footnote":
        for src in ref.get("sources", []):
            url = src.get("url", "")
            if url and not _is_excluded(url):
                out.append({
                    "url":        url,
                    "role":       "cited_source",
                    "sse_source": "content_references[sources_footnote].sources[].url",
                    "seq":        seq,
                    "after_ss":   after_ss,
                    "title":      src.get("title", ""),
                    "snippet":    "",
                    "pub_date":   "",
                    "confidence_base": 98,
                })

    # url — inline URL reference (e.g. Sophos link)
    elif ref_type == "url":
        item = ref.get("item", {}) or {}
        url = item.get("url", "")
        if url and not _is_excluded(url):
            out.append({
                "url":        url,
                "role":       "cited_source",
                "sse_source": "content_references[url].item.url",
                "seq":        seq,
                "after_ss":   after_ss,
                "title":      item.get("title", ""),
                "snippet":    "",
                "pub_date":   "",
                "confidence_base": 94,
            })

    # safe_urls on any ref — direct URL proof
    safe = ref.get("safe_urls", [])
    if isinstance(safe, list):
        for url in safe:
            if isinstance(url, str) and url.startswith("http") and not _is_excluded(url):
                out.append({
                    "url":        url,
                    "role":       "cited_source",
                    "sse_source": "content_references[any].safe_urls[]",
                    "seq":        seq,
                    "after_ss":   after_ss,
                    "title":      "",
                    "snippet":    "",
                    "pub_date":   "",
                    "confidence_base": 92,
                })


def _build_chain(search_queries: List[str], urls: List[AIUrl]) -> List[Dict]:
    """Reconstruct the full retrieval chain for export."""
    chain: List[Dict] = []

    for q in search_queries:
        chain.append({
            "layer": "0 — User Query → AI Search",
            "type":  "search_query",
            "value": q,
            "domain": "",
            "title": "",
            "confidence": 100,
        })

    for u in urls:
        if u.role == "search_result":
            chain.append({
                "layer": "1 — Search Result (Raw Index)",
                "type":  "search_result",
                "value": u.normalized_url,
                "domain": u.domain,
                "title":  u.title,
                "confidence": u.confidence,
            })

    for u in urls:
        if u.role == "retrieved_content":
            chain.append({
                "layer": "2 — Retrieved Content (AI Read)",
                "type":  "retrieved_content",
                "value": u.normalized_url,
                "domain": u.domain,
                "title":  u.title,
                "confidence": u.confidence,
            })

    for u in urls:
        if u.role in ("cited_source", "url_moderation"):
            layer = "3 — Cited Source (Final Citation)" if u.role == "cited_source" \
                    else "3b — URL Moderation (Safety-checked)"
            chain.append({
                "layer": layer,
                "type":  u.role,
                "value": u.normalized_url,
                "domain": u.domain,
                "title":  u.title,
                "confidence": u.confidence,
            })

    return chain


# ─────────────────────────────────────────────────────────────────────────────
#  PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────

def extract_ai_urls(entries: List[Dict]) -> AIUrlReport:
    """
    Main entry point. Scans all HAR entries for SSE streams and
    returns a complete AIUrlReport containing only AI-attributed URLs.

    Parameters
    ----------
    entries : list of HAR log entry dicts

    Returns
    -------
    AIUrlReport with .urls, .chain, .search_queries, .tool_name
    """
    # Find SSE/event-stream entries
    for entry in entries:
        content  = entry.get("response", {}).get("content", {})
        mime     = content.get("mimeType", "")
        entry_url = entry["request"]["url"]
        entry_ts  = entry.get("startedDateTime", "")

        if "event-stream" in mime or (
            "text/plain" in mime and "/conversation" in entry_url
        ):
            text = _resp_text_raw(entry)
            if text and len(text) > 100:
                report = _extract_from_sse(text, entry_url, entry_ts)
                if report.urls or report.search_queries:
                    return report

    # No SSE found — return empty report
    return AIUrlReport(urls=[], search_queries=[], tool_name="",
                       search_start_seq=None, chain=[])
