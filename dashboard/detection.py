"""Compatibility wrapper for the moved realtime detection module."""

from src.realtime_detect import (  # noqa: F401
    DATA_DIR,
    DB_PATH,
    LIVE_FLOWS_PATH,
    DetectionResult,
    FlowDetector,
    next_batch_no,
)
