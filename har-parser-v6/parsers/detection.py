"""
Platform detection — backward-compatible facade over detection_engine.py
========================================================================
This module preserves the EXACT public API of the original detection.py
so that main.py, cli/display.py, and utils/export.py continue to work
without any changes.

All real detection logic lives in parsers/detection_engine.py.
"""

from typing import Dict, List, Tuple

from .detection_engine import (  # noqa: F401  (re-export for legacy imports)
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

__all__ = [
    "detect_platform",
    "detect_platform_with_scores",
    # Extended API
    "detect_all_platforms",
    "detect_sdks",
    "extract_models",
    "detect_streaming_artifacts",
    "extract_session_artifacts",
    "full_detection",
    "PlatformMatch",
    "SDKMatch",
    "ModelDetection",
]
