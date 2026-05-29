"""
Logging configuration for HARensic.
Creates logs/app.log with structured timestamps and stages.
"""

import logging
import os
from datetime import datetime

LOG_DIR  = "logs"
LOG_FILE = os.path.join(LOG_DIR, "app.log")

_initialized = False


def get_logger(name: str = "har_parser") -> logging.Logger:
    """Return a configured logger, initializing the log file on first call."""
    global _initialized

    logger = logging.getLogger(name)
    if _initialized:
        return logger

    logger.setLevel(logging.DEBUG)

    os.makedirs(LOG_DIR, exist_ok=True)

    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        "%(asctime)s  [%(levelname)-8s]  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    _initialized = True

    logger.info("=" * 72)
    logger.info("HARensic — Session started")
    logger.info(f"Timestamp: {datetime.now().isoformat()}")
    logger.info("=" * 72)

    return logger
