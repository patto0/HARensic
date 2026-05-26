"""Parsers package for HAR Parser For Conversational AI — v2.0."""
from .loader import load_har, get_entries
from .detection import (
    detect_platform,
    detect_platform_with_scores,
    detect_all_platforms,
    detect_sdks,
    extract_models,
    detect_streaming_artifacts,
    extract_session_artifacts,
    full_detection,
    PlatformMatch,
    SDKMatch,
    ModelDetection,
)
from .chatgpt import parse_chatgpt
from .gemini import parse_gemini
from .claude import parse_claude
from .generic_parser import parse_generic
from .router import run_analysis
from .category_labels import (
    SECTION_LABELS,
    SECTION_ORDER,
    LEGACY_KEY_MAP,
    normalize_key,
    normalize_results,
    normalize_prefix,
    section_label,
    section_description,
    ordered_results,
)

__all__ = [
    "load_har", "get_entries",
    "detect_platform", "detect_platform_with_scores",
    "detect_all_platforms", "detect_sdks", "extract_models",
    "detect_streaming_artifacts", "extract_session_artifacts",
    "full_detection",
    "PlatformMatch", "SDKMatch", "ModelDetection",
    "parse_chatgpt", "parse_gemini", "parse_claude", "parse_generic",
    "run_analysis",
    # Category label helpers
    "SECTION_LABELS", "SECTION_ORDER", "LEGACY_KEY_MAP",
    "normalize_key", "normalize_results", "normalize_prefix",
    "section_label", "section_description", "ordered_results",
]
