"""Unit checks for SSH connection aggregation without packet-capture privileges."""

import json
import sys
import types
import unittest
from pathlib import Path


scapy = types.ModuleType("scapy")
scapy_all = types.ModuleType("scapy.all")
for name in ("IP", "TCP", "UDP", "AsyncSniffer"):
    setattr(scapy_all, name, type(name, (), {}))
sys.modules["scapy"] = scapy
sys.modules["scapy.all"] = scapy_all

from src.live_sensor import FlowStat, PacketStat, build_row, pop_ready_flows


def make_flow(port: int, timestamp: float = 100.0) -> FlowStat:
    flow = FlowStat("192.168.247.10", 40000, "192.168.247.20", port, 6)
    flow.add_packet(PacketStat(timestamp, 100, "fwd", flags=0x02))
    flow.add_packet(PacketStat(timestamp + 0.1, 120, "bwd", flags=0x12))
    return flow


class SSHFlowAggregationTests(unittest.TestCase):
    def test_ssh_connection_survives_two_second_window(self) -> None:
        ssh = make_flow(22)
        flows = {("ssh",): ssh}
        ready = pop_ready_flows(flows, now=103.0, flush_non_ssh=True, ssh_idle_timeout=10.0)
        self.assertFalse(ready)
        self.assertIs(flows[("ssh",)], ssh)

        ssh.add_packet(PacketStat(104.0, 200, "fwd", flags=0x18))
        row = build_row(ssh, ["Total Fwd Packets", "Total Backward Packets"])
        self.assertEqual((row["Total Fwd Packets"], row["Total Backward Packets"]), (2, 1))

    def test_ssh_connection_flushes_after_both_fin_directions(self) -> None:
        ssh = make_flow(22)
        ssh.add_packet(PacketStat(104.0, 60, "fwd", flags=0x11))
        ssh.add_packet(PacketStat(104.1, 60, "bwd", flags=0x11))
        flows = {("ssh",): ssh}
        ready = pop_ready_flows(flows, now=104.2, flush_non_ssh=False, ssh_idle_timeout=10.0)
        self.assertEqual(ready, {("ssh",): ssh})
        self.assertFalse(flows)

    def test_ssh_connection_flushes_on_rst_or_idle(self) -> None:
        ssh = make_flow(22)
        ssh.add_packet(PacketStat(101.0, 60, "bwd", flags=0x14))
        flows = {("rst",): ssh}
        self.assertEqual(len(pop_ready_flows(flows, 101.1, False, 10.0)), 1)

        idle = make_flow(22)
        flows = {("idle",): idle}
        self.assertFalse(pop_ready_flows(flows, 110.09, False, 10.0))
        self.assertEqual(len(pop_ready_flows(flows, 110.1, False, 10.0)), 1)

    def test_non_ssh_keeps_short_window_behavior(self) -> None:
        http = make_flow(80)
        flows = {("http",): http}
        self.assertFalse(pop_ready_flows(flows, 103.0, False, 10.0))
        self.assertEqual(len(pop_ready_flows(flows, 103.0, True, 10.0)), 1)

    def test_ssh_packet_lengths_use_tcp_payload(self) -> None:
        ssh = FlowStat("192.168.247.10", 40000, "192.168.247.20", 22, 6)
        ssh.add_packet(PacketStat(100.0, 66, "fwd", payload_length=0))
        ssh.add_packet(PacketStat(100.1, 146, "fwd", payload_length=80))
        ssh.add_packet(PacketStat(100.2, 166, "bwd", payload_length=100))
        row = build_row(ssh, [
            "Total Length of Fwd Packets", "Total Length of Bwd Packets",
            "Fwd Packet Length Min", "Bwd Packet Length Max",
            "Min Packet Length", "Max Packet Length", "Flow Bytes/s",
        ])
        self.assertEqual(row["Total Length of Fwd Packets"], 80)
        self.assertEqual(row["Total Length of Bwd Packets"], 100)
        self.assertEqual(row["Fwd Packet Length Min"], 0)
        self.assertEqual(row["Bwd Packet Length Max"], 100)
        self.assertEqual(row["Min Packet Length"], 0)
        self.assertEqual(row["Max Packet Length"], 100)
        self.assertAlmostEqual(row["Flow Bytes/s"], 900)

    def test_ddos_packet_lengths_ignore_payload_field(self) -> None:
        ddos = FlowStat("192.168.247.10", 40000, "192.168.247.20", 80, 6)
        ddos.add_packet(PacketStat(100.0, 66, "fwd", payload_length=0))
        ddos.add_packet(PacketStat(100.1, 146, "fwd", payload_length=80))
        ddos.add_packet(PacketStat(100.2, 166, "bwd", payload_length=100))
        manifest_path = Path(__file__).resolve().parents[1] / "models/ddos_v2/ddos_feature_manifest_v2.json"
        columns = json.loads(manifest_path.read_text(encoding="utf-8"))["features_in_order"]
        row_with_payload = build_row(ddos, columns)
        for packet in ddos.packets:
            packet.payload_length = None
        self.assertEqual(row_with_payload, build_row(ddos, columns))
        self.assertEqual(row_with_payload["Total Length of Fwd Packets"], 212)
        self.assertEqual(row_with_payload["Min Packet Length"], 66)


if __name__ == "__main__":
    unittest.main()
