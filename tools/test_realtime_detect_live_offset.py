"""Regression checks for restarting the live sensor while the dashboard stays up."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd

from src.realtime_detect import FlowDetector


class LiveOffsetResetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = FlowDetector.__new__(FlowDetector)
        self.detector.live_offset = 50

    def test_empty_replacement_resets_old_offset(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            path = Path(directory) / "live_flows.csv"
            path.write_text("", encoding="utf-8")
            with patch("src.realtime_detect.LIVE_FLOWS_PATH", path):
                self.assertIsNone(self.detector._read_live_batch())
            self.assertEqual(self.detector.live_offset, 0)

    def test_shorter_replacement_is_read_from_start(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            path = Path(directory) / "live_flows.csv"
            pd.DataFrame({"Destination Port": [22, 22], "Protocol": [6, 6]}).to_csv(path, index=False)
            with patch("src.realtime_detect.LIVE_FLOWS_PATH", path):
                batch = self.detector._read_live_batch()
            self.assertIsNotNone(batch)
            self.assertEqual(len(batch), 2)
            self.assertEqual(self.detector.live_offset, 2)


if __name__ == "__main__":
    unittest.main()
