from __future__ import annotations

import unittest

import pandas as pd

from src.prepare_ssh_port22_dataset import prepare_frame


class PrepareSshPort22Tests(unittest.TestCase):
    def test_uses_only_ssh_service_and_removes_conflicting_labels(self) -> None:
        source = pd.DataFrame(
            [
                {"Destination Port": 22, "Packet Count": 10, "Label": "BENIGN"},
                {"Destination Port": 22, "Packet Count": 20, "Label": "SSH-Patator"},
                {"Destination Port": 80, "Packet Count": 30, "Label": "BENIGN"},
                {"Destination Port": 22, "Packet Count": 40, "Label": "FTP-Patator"},
                {"Destination Port": 22, "Packet Count": 50, "Label": "BENIGN"},
                {"Destination Port": 22, "Packet Count": 50, "Label": "SSH-Patator"},
            ]
        )
        prepared, report = prepare_frame(source, ["Packet Count"])
        self.assertEqual(prepared["Packet Count"].tolist(), [10, 20])
        self.assertEqual(report["conflicting_label_rows"], 2)
        self.assertEqual(report["final_counts"], {"BENIGN": 1, "SSH-Patator": 1})


if __name__ == "__main__":
    unittest.main()
