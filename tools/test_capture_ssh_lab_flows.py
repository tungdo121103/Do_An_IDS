from __future__ import annotations

import unittest

from tools.capture_ssh_lab_flows import new_ssh_flows


class CaptureSshLabFlowsTests(unittest.TestCase):
    def test_keeps_only_new_ssh_rows_and_ignores_ddos(self) -> None:
        old = {"Source IP": "192.168.247.10", "Destination IP": "192.168.247.20", "Destination Port": "22", "Protocol": "6"}
        ddos = {**old, "Destination Port": "80"}
        ssh = dict(old)
        self.assertEqual(
            new_ssh_flows(1, [old, ddos, ssh], "192.168.247.10", "192.168.247.20"),
            [ssh],
        )

    def test_rejects_reset_during_capture(self) -> None:
        with self.assertRaises(ValueError):
            new_ssh_flows(3, [], "192.168.247.10", "192.168.247.20")


if __name__ == "__main__":
    unittest.main()
