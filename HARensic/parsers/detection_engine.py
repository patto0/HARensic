"""
HARensic — Multi-Platform Detection Engine v2.0
=======================================================================
Replaces the original detection.py with a fully modular, rule-based,
weighted-evidence detection system that supports 20+ AI platforms.

Backward compatibility: detect_platform() and detect_platform_with_scores()
preserve exactly the same signature and return type as the original.

New API:
    detect_all_platforms(entries)  -> List[PlatformMatch]
    detect_sdks(entries)           -> List[SDKMatch]
    extract_models(entries)        -> List[ModelDetection]
    build_detection_log(...)       -> dict  (writes detection_log.json)
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ─── Load platform rules ────────────────────────────────────────────────────
_RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "platform_rules.json")


def _load_rules() -> Dict[str, Any]:
    try:
        with open(_RULES_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        logger.error("Failed to load platform_rules.json: %s", exc)
        return {"platforms": [], "sdk_fingerprints": {}}


_RULES: Dict[str, Any] = _load_rules()
_PLATFORM_CONFIGS: List[Dict] = _RULES.get("platforms", [])
_SDK_CONFIGS: Dict[str, Dict] = _RULES.get("sdk_fingerprints", {})


# ─── Data classes ───────────────────────────────────────────────────────────

@dataclass
class EvidenceItem:
    """Single piece of evidence contributing to platform detection."""
    category: str          # domain | path | header | cookie | response | sse | websocket
    description: str
    weight: int
    entry_index: int = -1
    raw_value: str = ""


@dataclass
class PlatformMatch:
    """Detected platform with confidence score and supporting evidence."""
    platform_id: str
    platform_name: str
    provider: str
    confidence: int           # 0–100
    raw_score: int
    evidence: List[EvidenceItem] = field(default_factory=list)

    @property
    def evidence_summary(self) -> List[str]:
        return [e.description for e in self.evidence]

    def to_dict(self) -> Dict:
        return {
            "platform": self.platform_name,
            "platform_id": self.platform_id,
            "provider": self.provider,
            "confidence": self.confidence,
            "raw_score": self.raw_score,
            "evidence": [
                {
                    "category": e.category,
                    "description": e.description,
                    "weight": e.weight,
                    "entry_index": e.entry_index,
                }
                for e in self.evidence
            ],
        }


@dataclass
class SDKMatch:
    """Detected SDK or framework fingerprint."""
    sdk_id: str
    description: str
    confidence: int
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "sdk": self.sdk_id,
            "description": self.description,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


@dataclass
class ModelDetection:
    """Detected AI model from network traffic."""
    model: str
    provider: str
    source: str   # where it was found
    entry_index: int = -1

    def to_dict(self) -> Dict:
        return {
            "model": self.model,
            "provider": self.provider,
            "source": self.source,
            "entry_index": self.entry_index,
        }


# ─── Model patterns ─────────────────────────────────────────────────────────

_MODEL_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # OpenAI
    (re.compile(r'"model"\s*:\s*"(gpt-4[^"]*)"', re.I), "OpenAI"),
    (re.compile(r'"model"\s*:\s*"(gpt-3\.5[^"]*)"', re.I), "OpenAI"),
    (re.compile(r'"model"\s*:\s*"(o1[^"]*)"', re.I), "OpenAI"),
    (re.compile(r'"model"\s*:\s*"(o3[^"]*)"', re.I), "OpenAI"),
    (re.compile(r'"model"\s*:\s*"(text-davinci[^"]*)"', re.I), "OpenAI"),
    # Anthropic
    (re.compile(r'"model"\s*:\s*"(claude-[^"]+)"', re.I), "Anthropic"),
    # Google
    (re.compile(r'"model"\s*:\s*"(gemini-[^"]+)"', re.I), "Google"),
    (re.compile(r'"modelVersion"\s*:\s*"(gemini[^"]+)"', re.I), "Google"),
    # xAI
    (re.compile(r'"model"\s*:\s*"(grok-[^"]+)"', re.I), "xAI"),
    # Mistral
    (re.compile(r'"model"\s*:\s*"(mistral-[^"]+)"', re.I), "Mistral AI"),
    (re.compile(r'"model"\s*:\s*"(mixtral-[^"]+)"', re.I), "Mistral AI"),
    (re.compile(r'"model"\s*:\s*"(codestral[^"]*)"', re.I), "Mistral AI"),
    # DeepSeek
    (re.compile(r'"model"\s*:\s*"(deepseek-[^"]+)"', re.I), "DeepSeek"),
    # Cohere
    (re.compile(r'"model"\s*:\s*"(command-[^"]+)"', re.I), "Cohere"),
    # Moonshot / Kimi
    (re.compile(r'"model"\s*:\s*"(moonshot-[^"]+)"', re.I), "Moonshot AI"),
    # Qwen / Alibaba
    (re.compile(r'"model"\s*:\s*"(qwen[^"]+)"', re.I), "Alibaba Cloud"),
    # Meta Llama
    (re.compile(r'"model"\s*:\s*"(llama[^"]+)"', re.I), "Meta"),
    (re.compile(r'"model"\s*:\s*"(meta-llama[^"]+)"', re.I), "Meta"),
    # Generic: any model field
    (re.compile(r'"model"\s*:\s*"([a-z0-9][-a-z0-9_.:/]{3,60})"', re.I), "Unknown Provider"),
]


# ─── Helper functions ────────────────────────────────────────────────────────

def _get_url(entry: Dict) -> str:
    return entry.get("request", {}).get("url", "").lower()


def _get_headers(entry: Dict) -> Dict[str, str]:
    return {
        h["name"].lower(): h.get("value", "")
        for h in entry.get("request", {}).get("headers", [])
    }


def _get_cookies(entry: Dict) -> Dict[str, str]:
    cookies: Dict[str, str] = {}
    for c in entry.get("request", {}).get("cookies", []):
        cookies[c.get("name", "").lower()] = c.get("value", "")
    # Also parse Cookie header
    hdrs = _get_headers(entry)
    raw_cookie = hdrs.get("cookie", "")
    for part in raw_cookie.split(";"):
        kv = part.strip().split("=", 1)
        if len(kv) == 2:
            cookies[kv[0].strip().lower()] = kv[1].strip()
    return cookies


def _get_resp_text(entry: Dict) -> str:
    content = entry.get("response", {}).get("content", {})
    text = content.get("text", "") or ""
    if content.get("encoding") == "base64" and text:
        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except Exception:
            return ""
    return text


def _get_post_text(entry: Dict) -> str:
    return entry.get("request", {}).get("postData", {}).get("text", "") or ""


def _get_ws_frames(entry: Dict) -> List[str]:
    """Extract WebSocket message text from HAR entry."""
    frames = []
    for msg in entry.get("_webSocketMessages", []):
        data = msg.get("data", "")
        if isinstance(data, str):
            frames.append(data)
    return frames


def _normalize_confidence(raw_score: int, max_possible: int) -> int:
    """Map raw score to 0–100 confidence using a sigmoid-like curve."""
    if max_possible <= 0 or raw_score <= 0:
        return 0
    ratio = raw_score / max_possible
    # Sigmoid-ish: reaches ~95 at full score, diminishing returns
    confidence = min(int(ratio * 110), 100)
    return confidence


# ─── Per-platform scorer ─────────────────────────────────────────────────────

def _score_platform(config: Dict, entries: List[Dict]) -> PlatformMatch:
    """
    Score a single platform config against all HAR entries.
    Returns a PlatformMatch with accumulated evidence.
    """
    pid      = config["id"]
    pname    = config["name"]
    provider = config["provider"]

    domains          = [d.lower() for d in config.get("domains", [])]
    paths            = [p.lower() for p in config.get("paths", [])]
    req_headers      = [h.lower() for h in config.get("request_headers", [])]
    cookies_keys     = [c.lower() for c in config.get("cookies", [])]
    resp_markers     = config.get("response_markers", [])
    sse_patterns     = config.get("sse_patterns", [])
    ws_paths         = [p.lower() for p in config.get("websocket_paths", [])]

    domain_w  = config.get("domain_weight", 10)
    path_w    = config.get("path_weight", 5)
    header_w  = config.get("header_weight", 8)
    cookie_w  = config.get("cookie_weight", 4)
    resp_w    = config.get("response_marker_weight", 6)
    sse_w     = config.get("sse_weight", 4)
    ws_w      = config.get("websocket_weight", 3)

    evidence: List[EvidenceItem] = []
    raw_score = 0

    # Track already-matched domains/paths/headers to avoid double-scoring
    matched_domains: set  = set()
    matched_paths: set    = set()
    matched_headers: set  = set()
    matched_cookies: set  = set()
    matched_markers: set  = set()
    matched_sse: set      = set()

    for idx, entry in enumerate(entries):
        url      = _get_url(entry)
        headers  = _get_headers(entry)
        cookies  = _get_cookies(entry)
        resp_txt = _get_resp_text(entry)
        post_txt = _get_post_text(entry)
        ws_msgs  = _get_ws_frames(entry)

        # ── Domain match ──────────────────────────────────────────────────
        for domain in domains:
            if domain in url and domain not in matched_domains:
                matched_domains.add(domain)
                raw_score += domain_w
                evidence.append(EvidenceItem(
                    category="domain",
                    description=f"Matched domain: {domain}",
                    weight=domain_w,
                    entry_index=idx,
                    raw_value=domain,
                ))
                break  # one per entry for domains

        # ── Path match ────────────────────────────────────────────────────
        for path in paths:
            if path in url and path not in matched_paths:
                matched_paths.add(path)
                raw_score += path_w
                evidence.append(EvidenceItem(
                    category="path",
                    description=f"Matched endpoint: {path}",
                    weight=path_w,
                    entry_index=idx,
                    raw_value=path,
                ))

        # ── Header match ──────────────────────────────────────────────────
        for hdr in req_headers:
            if hdr in headers and hdr not in matched_headers:
                matched_headers.add(hdr)
                raw_score += header_w
                evidence.append(EvidenceItem(
                    category="header",
                    description=f"Matched header: {hdr}",
                    weight=header_w,
                    entry_index=idx,
                    raw_value=headers[hdr][:120],
                ))

        # ── Cookie match ──────────────────────────────────────────────────
        for ck in cookies_keys:
            if ck in cookies and ck not in matched_cookies:
                matched_cookies.add(ck)
                raw_score += cookie_w
                evidence.append(EvidenceItem(
                    category="cookie",
                    description=f"Matched cookie: {ck}",
                    weight=cookie_w,
                    entry_index=idx,
                    raw_value=cookies[ck][:80],
                ))

        # ── Response marker match ─────────────────────────────────────────
        combined_resp = resp_txt + post_txt
        for marker in resp_markers:
            if marker.lower() in combined_resp.lower() and marker not in matched_markers:
                matched_markers.add(marker)
                raw_score += resp_w
                evidence.append(EvidenceItem(
                    category="response",
                    description=f"Matched response marker: {marker}",
                    weight=resp_w,
                    entry_index=idx,
                    raw_value=marker,
                ))

        # ── SSE pattern match ─────────────────────────────────────────────
        for ssekey in sse_patterns:
            if ssekey.lower() in combined_resp.lower() and ssekey not in matched_sse:
                matched_sse.add(ssekey)
                raw_score += sse_w
                evidence.append(EvidenceItem(
                    category="sse",
                    description=f"Matched SSE pattern: {ssekey}",
                    weight=sse_w,
                    entry_index=idx,
                    raw_value=ssekey,
                ))

        # ── WebSocket match ───────────────────────────────────────────────
        is_ws = (
            entry.get("request", {}).get("headers", [])
            and any(
                h.get("name", "").lower() == "upgrade"
                and h.get("value", "").lower() == "websocket"
                for h in entry.get("request", {}).get("headers", [])
            )
        ) or bool(entry.get("_webSocketMessages"))

        if is_ws and ws_paths:
            for wsp in ws_paths:
                if wsp in url:
                    raw_score += ws_w
                    evidence.append(EvidenceItem(
                        category="websocket",
                        description=f"WebSocket upgrade to: {wsp}",
                        weight=ws_w,
                        entry_index=idx,
                        raw_value=url,
                    ))
                    break

        # ── WebSocket frame content ───────────────────────────────────────
        for frame in ws_msgs:
            for marker in resp_markers:
                if marker.lower() in frame.lower() and f"ws:{marker}" not in matched_markers:
                    matched_markers.add(f"ws:{marker}")
                    raw_score += resp_w
                    evidence.append(EvidenceItem(
                        category="websocket_frame",
                        description=f"Matched marker in WebSocket frame: {marker}",
                        weight=resp_w,
                        entry_index=idx,
                        raw_value=frame[:120],
                    ))

    # ── Compute confidence ────────────────────────────────────────────────
    # max_possible: domain_w*3 + path_w*4 + header_w*3 + cookie_w*3 + resp_w*3 + sse_w*2
    max_possible = (
        domain_w * min(3, len(domains)) +
        path_w   * min(4, len(paths)) +
        header_w * min(3, len(req_headers)) +
        cookie_w * min(3, len(cookies_keys)) +
        resp_w   * min(3, len(resp_markers)) +
        sse_w    * min(2, len(sse_patterns)) +
        ws_w     * min(1, len(ws_paths))
    ) or 1

    confidence = _normalize_confidence(raw_score, max_possible)

    return PlatformMatch(
        platform_id=pid,
        platform_name=pname,
        provider=provider,
        confidence=confidence,
        raw_score=raw_score,
        evidence=evidence,
    )


# ─── SDK detector ────────────────────────────────────────────────────────────

def detect_sdks(entries: List[Dict]) -> List[SDKMatch]:
    """
    Detect SDK and framework fingerprints present in the HAR.
    Returns a list of SDKMatch objects sorted by confidence.
    """
    results: List[SDKMatch] = []

    for sdk_id, cfg in _SDK_CONFIGS.items():
        evidence: List[str] = []
        raw_score = 0
        weight = cfg.get("weight", 5)

        hdr_keys = [h.lower() for h in cfg.get("headers", [])]
        sdk_paths = [p.lower() for p in cfg.get("paths", [])]
        sdk_domains = [d.lower() for d in cfg.get("domains", [])]

        for entry in entries:
            url     = _get_url(entry)
            headers = _get_headers(entry)

            for hdr in hdr_keys:
                if hdr in headers:
                    desc = f"Header '{hdr}' present"
                    if desc not in evidence:
                        evidence.append(desc)
                        raw_score += weight

            for path in sdk_paths:
                if path in url:
                    desc = f"Endpoint '{path}' matched"
                    if desc not in evidence:
                        evidence.append(desc)
                        raw_score += weight // 2

            for domain in sdk_domains:
                if domain in url:
                    desc = f"Domain '{domain}' matched"
                    if desc not in evidence:
                        evidence.append(desc)
                        raw_score += weight

        if raw_score > 0:
            confidence = min(int(raw_score / (weight * 3) * 100), 100)
            results.append(SDKMatch(
                sdk_id=sdk_id,
                description=cfg.get("description", sdk_id),
                confidence=confidence,
                evidence=evidence,
            ))

    results.sort(key=lambda x: -x.confidence)
    return results


# ─── Model extractor ─────────────────────────────────────────────────────────

def extract_models(entries: List[Dict]) -> List[ModelDetection]:
    """
    Extract AI model identifiers from all HAR entries.
    Deduplicates and returns sorted list.
    """
    seen: set = set()
    models: List[ModelDetection] = []

    for idx, entry in enumerate(entries):
        texts = [
            _get_resp_text(entry),
            _get_post_text(entry),
        ]

        for raw_text in texts:
            if not raw_text:
                continue

            for pattern, provider in _MODEL_PATTERNS:
                for match in pattern.finditer(raw_text):
                    model_name = match.group(1)
                    key = model_name.lower()
                    if key not in seen:
                        seen.add(key)
                        src = "response_body" if raw_text == _get_resp_text(entry) else "request_body"
                        models.append(ModelDetection(
                            model=model_name,
                            provider=provider,
                            source=src,
                            entry_index=idx,
                        ))

    # Sort: known providers first, then alphabetically
    known = ["OpenAI", "Anthropic", "Google", "xAI", "Mistral AI", "DeepSeek"]
    models.sort(key=lambda m: (
        known.index(m.provider) if m.provider in known else 99,
        m.model.lower()
    ))
    return models


# ─── Streaming detector ──────────────────────────────────────────────────────

def detect_streaming_artifacts(entries: List[Dict]) -> Dict[str, Any]:
    """
    Detect streaming patterns and return forensic indicators.
    """
    sse_count     = 0
    ws_count      = 0
    chunked_count = 0
    regen_count   = 0
    stream_urls: List[str] = []
    regen_urls: List[str]  = []

    for entry in entries:
        url      = _get_url(entry)
        resp     = entry.get("response", {})
        headers  = {h["name"].lower(): h.get("value", "")
                    for h in resp.get("headers", [])}
        mime     = resp.get("content", {}).get("mimeType", "")

        if "event-stream" in mime:
            sse_count += 1
            stream_urls.append(url[:120])

        if headers.get("transfer-encoding", "").lower() == "chunked":
            chunked_count += 1

        if entry.get("_webSocketMessages"):
            ws_count += 1

        # Regeneration: second POST to same conversation endpoint
        if any(p in url for p in ["/completion", "/generate", "/chat"]):
            if "regenerate" in url or "retry" in url:
                regen_count += 1
                regen_urls.append(url[:120])

    return {
        "sse_stream_count": sse_count,
        "websocket_stream_count": ws_count,
        "chunked_transfer_count": chunked_count,
        "regeneration_requests": regen_count,
        "stream_endpoints": stream_urls[:10],
        "regeneration_endpoints": regen_urls[:5],
    }


# ─── Unknown platform extractor ──────────────────────────────────────────────

def extract_unknown_platform_artifacts(entries: List[Dict]) -> Dict[str, Any]:
    """
    For unknown platforms: extract as much forensic data as possible.
    """
    domains: set = set()
    endpoints: set = set()
    auth_tokens: List[str] = []
    models: List[str] = []
    ws_paths: set = set()

    for entry in entries:
        url     = _get_url(entry)
        headers = _get_headers(entry)

        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.netloc:
            domains.add(parsed.netloc)
        if parsed.path:
            endpoints.add(parsed.path[:100])

        # Auth tokens
        for hdr in ["authorization", "x-api-key", "bearer", "api-key"]:
            if hdr in headers and headers[hdr]:
                val = headers[hdr]
                token_repr = val[:20] + "..." if len(val) > 20 else val
                if token_repr not in auth_tokens:
                    auth_tokens.append(token_repr)

        # WebSocket
        if any(h.get("name", "").lower() == "upgrade"
               and h.get("value", "").lower() == "websocket"
               for h in entry.get("request", {}).get("headers", [])):
            ws_paths.add(url[:100])

        # Models from response
        resp_txt  = _get_resp_text(entry)
        post_txt  = _get_post_text(entry)
        for text in [resp_txt, post_txt]:
            for pattern, _ in _MODEL_PATTERNS[:10]:  # first 10 patterns cover most
                for m in pattern.finditer(text):
                    mn = m.group(1)
                    if mn not in models:
                        models.append(mn)

    return {
        "unique_domains": sorted(domains),
        "unique_endpoints": sorted(endpoints)[:30],
        "auth_tokens_found": len(auth_tokens),
        "auth_token_hints": auth_tokens[:5],
        "detected_models": models[:10],
        "websocket_paths": sorted(ws_paths),
    }


# ─── Session/artifact extractor ─────────────────────────────────────────────

def extract_session_artifacts(entries: List[Dict]) -> Dict[str, List[str]]:
    """
    Extract session IDs, conversation IDs, org IDs, trace IDs, etc.
    Returns dict of artifact_type -> list of values found.
    """
    artifacts: Dict[str, set] = {
        "session_ids":      set(),
        "conversation_ids": set(),
        "organization_ids": set(),
        "user_ids":         set(),
        "tenant_ids":       set(),
        "trace_ids":        set(),
        "request_ids":      set(),
        "model_ids":        set(),
        "feature_flags":    set(),
    }

    _ID_PATTERNS = {
        "session_ids":      re.compile(r'(?:session[_-]?id|sessionId)["\s:=]+([a-zA-Z0-9_\-\.]{8,80})', re.I),
        "conversation_ids": re.compile(r'(?:conv(?:ersation)?[_-]?id|chatId|threadId)["\s:=]+([a-zA-Z0-9_\-]{8,80})', re.I),
        "organization_ids": re.compile(r'(?:org(?:anization)?[_-]?id|orgId|org_uuid)["\s:=]+([a-zA-Z0-9_\-]{8,80})', re.I),
        "user_ids":         re.compile(r'(?:user[_-]?id|userId|uid)["\s:=]+([a-zA-Z0-9_\-]{6,80})', re.I),
        "tenant_ids":       re.compile(r'(?:tenant[_-]?id|tenantId)["\s:=]+([a-zA-Z0-9_\-]{8,80})', re.I),
        "trace_ids":        re.compile(r'(?:trace[_-]?id|traceId|x-b3-traceid)["\s:=]+([a-zA-Z0-9_\-]{8,80})', re.I),
        "request_ids":      re.compile(r'(?:request[_-]?id|requestId|x-request-id)["\s:=]+([a-zA-Z0-9_\-]{8,80})', re.I),
    }

    _URL_UUID = re.compile(r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', re.I)

    for entry in entries:
        url      = entry.get("request", {}).get("url", "")
        headers  = _get_headers(entry)
        post_txt = _get_post_text(entry)
        resp_txt = _get_resp_text(entry)
        combined = url + " " + post_txt + " " + resp_txt

        for art_type, pattern in _ID_PATTERNS.items():
            for m in pattern.finditer(combined):
                val = m.group(1).strip('"\'')
                if len(val) >= 6:
                    artifacts[art_type].add(val[:80])

        # Extract UUIDs from URL path segments
        for m in _URL_UUID.finditer(url):
            artifacts["conversation_ids"].add(m.group(1))

        # Header-based IDs
        for hdr_name, art_type in [
            ("x-request-id",      "request_ids"),
            ("x-trace-id",        "trace_ids"),
            ("x-correlation-id",  "request_ids"),
            ("x-session-id",      "session_ids"),
            ("x-conversation-id", "conversation_ids"),
        ]:
            if hdr_name in headers:
                artifacts[art_type].add(headers[hdr_name][:80])

    return {k: sorted(v) for k, v in artifacts.items()}


# ─── Main multi-platform detection ──────────────────────────────────────────

def detect_all_platforms(entries: List[Dict]) -> List[PlatformMatch]:
    """
    Run detection for all configured platforms.
    Returns list sorted by confidence (highest first).
    Filters out platforms with zero score.
    """
    matches: List[PlatformMatch] = []

    for config in _PLATFORM_CONFIGS:
        try:
            match = _score_platform(config, entries)
            if match.raw_score > 0:
                matches.append(match)
        except Exception as exc:
            logger.warning("Detection failed for platform %s: %s", config.get("id"), exc)

    matches.sort(key=lambda m: (-m.confidence, -m.raw_score))
    return matches


def build_detection_log(
    entries: List[Dict],
    matches: List[PlatformMatch],
    sdks: List[SDKMatch],
    models: List[ModelDetection],
    streaming: Dict[str, Any],
    har_path: str = "",
    output_dir: str = "exports",
) -> Dict[str, Any]:
    """
    Build and write detection_log.json explaining all detection decisions.
    Returns the log dict.
    """
    log: Dict[str, Any] = {
        "tool": "HARensic",
        "version": "2.0",
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        "source_file": os.path.basename(har_path),
        "entries_analyzed": len(entries),
        "detection_engine": "MultiPlatformDetectionEngine-v2",
        "detected_platforms": [m.to_dict() for m in matches],
        "detected_sdks": [s.to_dict() for s in sdks],
        "detected_models": [m.to_dict() for m in models],
        "streaming_artifacts": streaming,
        "rules_source": "platform_rules.json",
        "detection_notes": [],
    }

    if not matches:
        log["detection_notes"].append(
            "No known platform matched. HAR may contain an unsupported or novel AI service."
        )
    elif len(matches) == 1:
        log["detection_notes"].append(
            f"Single platform detected with {matches[0].confidence}% confidence: {matches[0].platform_name}"
        )
    else:
        note = (
            f"Multi-platform HAR: {len(matches)} platforms detected. "
            f"Primary: {matches[0].platform_name} ({matches[0].confidence}%). "
            f"This may indicate multiple AI services, browser extensions, or embedded integrations."
        )
        log["detection_notes"].append(note)

    if sdks:
        log["detection_notes"].append(
            "SDK/Framework fingerprints detected: " + ", ".join(s.sdk_id for s in sdks)
        )

    os.makedirs(output_dir, exist_ok=True)
    log_path = os.path.join(output_dir, "detection_log.json")
    try:
        with open(log_path, "w", encoding="utf-8") as f:
            json.dump(log, f, indent=2, ensure_ascii=False)
        logger.info("Detection log written: %s", log_path)
    except Exception as exc:
        logger.error("Failed to write detection_log.json: %s", exc)

    return log


# ─── Backward-compatible API ─────────────────────────────────────────────────
# These functions preserve the EXACT signature of the original detection.py
# so that existing callers in main.py, cli/display.py, etc. are unaffected.

def detect_platform(entries: List[Dict]) -> str:
    """
    Backward-compatible: return the single best-match platform ID.
    Maps new platform IDs to legacy IDs where needed.
    """
    matches = detect_all_platforms(entries)
    if not matches:
        return "unknown"

    pid = matches[0].platform_id
    # Map extended IDs back to legacy names the router understands
    _LEGACY_MAP = {
        "chatgpt":           "chatgpt",
        "claude":            "claude",
        "gemini":            "gemini",
        "anthropic_console": "claude",       # falls through to generic
        "openai_playground": "chatgpt",      # falls through to generic
        "google_ai_studio":  "gemini",       # falls through to generic
    }
    return _LEGACY_MAP.get(pid, pid)


def detect_platform_with_scores(
    entries: List[Dict],
) -> Tuple[str, int, int, int]:
    """
    Backward-compatible: return (platform, chatgpt_score, gemini_score, claude_score).

    The three legacy scores are extracted from the new detection results
    so that existing display/export code continues to work unchanged.
    """
    matches = detect_all_platforms(entries)

    cg = gm = cl = 0
    primary_platform = "unknown"

    score_map: Dict[str, int] = {m.platform_id: m.raw_score for m in matches}
    conf_map:  Dict[str, int] = {m.platform_id: m.confidence for m in matches}

    # Map to legacy triple
    cg = max(
        score_map.get("chatgpt", 0),
        score_map.get("openai_playground", 0),
    )
    gm = max(
        score_map.get("gemini", 0),
        score_map.get("google_ai_studio", 0),
    )
    cl = max(
        score_map.get("claude", 0),
        score_map.get("anthropic_console", 0),
    )

    if not matches:
        return "unknown", 0, 0, 0

    best = matches[0]
    pid  = best.platform_id

    _LEGACY_MAP = {
        "chatgpt":           "chatgpt",
        "claude":            "claude",
        "gemini":            "gemini",
        "anthropic_console": "claude",
        "openai_playground": "chatgpt",
        "google_ai_studio":  "gemini",
    }
    primary_platform = _LEGACY_MAP.get(pid, pid)

    # For legacy display: if new platform isn't one of the big 3,
    # use its raw_score as the "cg" slot so the bar shows something
    if primary_platform not in ("chatgpt", "gemini", "claude"):
        primary_platform = pid  # pass through new ID

    return primary_platform, cg, gm, cl


# ─── Convenience: full extended result ──────────────────────────────────────

def full_detection(
    entries: List[Dict],
    har_path: str = "",
    output_dir: str = "exports",
) -> Dict[str, Any]:
    """
    Run complete detection and return a comprehensive result dict.
    Also writes detection_log.json.
    """
    matches   = detect_all_platforms(entries)
    sdks      = detect_sdks(entries)
    models    = extract_models(entries)
    streaming = detect_streaming_artifacts(entries)
    sessions  = extract_session_artifacts(entries)

    unknown_artifacts: Dict = {}
    if not matches:
        unknown_artifacts = extract_unknown_platform_artifacts(entries)

    log = build_detection_log(
        entries=entries,
        matches=matches,
        sdks=sdks,
        models=models,
        streaming=streaming,
        har_path=har_path,
        output_dir=output_dir,
    )

    return {
        "platforms":          matches,
        "sdks":               sdks,
        "models":             models,
        "streaming":          streaming,
        "session_artifacts":  sessions,
        "unknown_artifacts":  unknown_artifacts,
        "detection_log":      log,
    }
