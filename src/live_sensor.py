from __future__ import annotations

import argparse
import csv
import statistics
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import joblib
from scapy.all import IP, TCP, UDP, sniff


PROJECT_DIR = Path(__file__).resolve().parents[1]
FEATURE_COLUMNS_PATH = PROJECT_DIR / "models" / "feature_columns.joblib"
LIVE_FLOWS_PATH = PROJECT_DIR / "data" / "live_flows.csv"


@dataclass
class PacketStat:
    timestamp: float
    length: int
    direction: str
    flags: int = 0
    window: int = 0


@dataclass
class FlowStat:
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: int
    packets: list[PacketStat] = field(default_factory=list)

    def add_packet(self, packet_stat: PacketStat) -> None:
        self.packets.append(packet_stat)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Realtime packet sensor for IDS dashboard.")
    parser.add_argument("--interface", default="ens33", help="Interface connected to lab network.")
    parser.add_argument("--victim-ip", default="192.168.247.20", help="Victim server IP.")
    parser.add_argument("--attacker-ip", action="append", default=None, help="Attacker IP. Repeat for multiple attackers.")
    parser.add_argument("--attacker-ips", default="192.168.247.10", help="Comma-separated attacker IPs.")
    parser.add_argument("--window", type=float, default=2.0, help="Aggregation window in seconds.")
    parser.add_argument("--output", type=Path, default=LIVE_FLOWS_PATH, help="live_flows.csv output path.")
    parser.add_argument("--reset", action="store_true", help="Clear live_flows.csv before capture.")
    args = parser.parse_args()
    attacker_ips = []
    if args.attacker_ips:
        attacker_ips.extend(ip.strip() for ip in args.attacker_ips.split(",") if ip.strip())
    if args.attacker_ip:
        attacker_ips.extend(ip.strip() for ip in args.attacker_ip if ip.strip())
    args.attacker_ips = sorted(set(attacker_ips))
    return args


def flow_key(packet, victim_ip: str) -> tuple[str, int, str, int, int]:
    ip_layer = packet[IP]
    protocol = int(ip_layer.proto)
    src_port = 0
    dst_port = 0

    if TCP in packet:
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
    elif UDP in packet:
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)

    if ip_layer.dst == victim_ip:
        return ip_layer.src, src_port, ip_layer.dst, dst_port, protocol

    return ip_layer.dst, dst_port, ip_layer.src, src_port, protocol


def packet_direction(packet, victim_ip: str) -> str:
    return "fwd" if packet[IP].dst == victim_ip else "bwd"


def tcp_flags(packet) -> int:
    return int(packet[TCP].flags) if TCP in packet else 0


def tcp_window(packet) -> int:
    return int(packet[TCP].window) if TCP in packet else 0


def mean(values: list[float]) -> float:
    return statistics.fmean(values) if values else 0.0


def stdev(values: list[float]) -> float:
    return statistics.pstdev(values) if len(values) > 1 else 0.0


def iat_values(timestamps: list[float]) -> list[float]:
    if len(timestamps) < 2:
        return []
    return [(timestamps[index] - timestamps[index - 1]) * 1_000_000 for index in range(1, len(timestamps))]


def flag_count(packets: list[PacketStat], mask: int) -> int:
    return sum(1 for packet in packets if packet.flags & mask)


def build_row(flow: FlowStat, feature_columns: list[str]) -> dict[str, float | int | str]:
    packets = sorted(flow.packets, key=lambda item: item.timestamp)
    fwd_packets = [packet for packet in packets if packet.direction == "fwd"]
    bwd_packets = [packet for packet in packets if packet.direction == "bwd"]

    lengths = [packet.length for packet in packets]
    fwd_lengths = [packet.length for packet in fwd_packets]
    bwd_lengths = [packet.length for packet in bwd_packets]
    timestamps = [packet.timestamp for packet in packets]
    fwd_timestamps = [packet.timestamp for packet in fwd_packets]
    bwd_timestamps = [packet.timestamp for packet in bwd_packets]

    duration = max((timestamps[-1] - timestamps[0]) * 1_000_000, 1.0) if timestamps else 1.0
    flow_iat = iat_values(timestamps)
    fwd_iat = iat_values(fwd_timestamps)
    bwd_iat = iat_values(bwd_timestamps)
    total_bytes = sum(lengths)
    fwd_bytes = sum(fwd_lengths)
    bwd_bytes = sum(bwd_lengths)

    metrics = {
        "Protocol": flow.protocol,
        "Flow Duration": duration,
        "Total Fwd Packets": len(fwd_packets),
        "Total Backward Packets": len(bwd_packets),
        "Total Length of Fwd Packets": fwd_bytes,
        "Total Length of Bwd Packets": bwd_bytes,
        "Fwd Packet Length Max": max(fwd_lengths, default=0),
        "Fwd Packet Length Min": min(fwd_lengths, default=0),
        "Fwd Packet Length Mean": mean(fwd_lengths),
        "Fwd Packet Length Std": stdev(fwd_lengths),
        "Bwd Packet Length Max": max(bwd_lengths, default=0),
        "Bwd Packet Length Min": min(bwd_lengths, default=0),
        "Bwd Packet Length Mean": mean(bwd_lengths),
        "Bwd Packet Length Std": stdev(bwd_lengths),
        "Flow Bytes/s": total_bytes / (duration / 1_000_000),
        "Flow Packets/s": len(packets) / (duration / 1_000_000),
        "Flow IAT Mean": mean(flow_iat),
        "Flow IAT Std": stdev(flow_iat),
        "Flow IAT Max": max(flow_iat, default=0),
        "Flow IAT Min": min(flow_iat, default=0),
        "Fwd IAT Total": sum(fwd_iat),
        "Fwd IAT Mean": mean(fwd_iat),
        "Fwd IAT Std": stdev(fwd_iat),
        "Fwd IAT Max": max(fwd_iat, default=0),
        "Fwd IAT Min": min(fwd_iat, default=0),
        "Bwd IAT Total": sum(bwd_iat),
        "Bwd IAT Mean": mean(bwd_iat),
        "Bwd IAT Std": stdev(bwd_iat),
        "Bwd IAT Max": max(bwd_iat, default=0),
        "Bwd IAT Min": min(bwd_iat, default=0),
        "Fwd PSH Flags": sum(1 for packet in fwd_packets if packet.flags & 0x08),
        "Bwd PSH Flags": sum(1 for packet in bwd_packets if packet.flags & 0x08),
        "Fwd URG Flags": sum(1 for packet in fwd_packets if packet.flags & 0x20),
        "Bwd URG Flags": sum(1 for packet in bwd_packets if packet.flags & 0x20),
        "Fwd Header Length": len(fwd_packets) * 20,
        "Bwd Header Length": len(bwd_packets) * 20,
        "Fwd Packets/s": len(fwd_packets) / (duration / 1_000_000),
        "Bwd Packets/s": len(bwd_packets) / (duration / 1_000_000),
        "Min Packet Length": min(lengths, default=0),
        "Max Packet Length": max(lengths, default=0),
        "Packet Length Mean": mean(lengths),
        "Packet Length Std": stdev(lengths),
        "Packet Length Variance": stdev(lengths) ** 2,
        "FIN Flag Count": flag_count(packets, 0x01),
        "SYN Flag Count": flag_count(packets, 0x02),
        "RST Flag Count": flag_count(packets, 0x04),
        "PSH Flag Count": flag_count(packets, 0x08),
        "ACK Flag Count": flag_count(packets, 0x10),
        "URG Flag Count": flag_count(packets, 0x20),
        "CWE Flag Count": flag_count(packets, 0x80),
        "ECE Flag Count": flag_count(packets, 0x40),
        "Down/Up Ratio": len(bwd_packets) / len(fwd_packets) if fwd_packets else 0,
        "Average Packet Size": mean(lengths),
        "Avg Fwd Segment Size": mean(fwd_lengths),
        "Avg Bwd Segment Size": mean(bwd_lengths),
        "Fwd Header Length.1": len(fwd_packets) * 20,
        "Subflow Fwd Packets": len(fwd_packets),
        "Subflow Fwd Bytes": fwd_bytes,
        "Subflow Bwd Packets": len(bwd_packets),
        "Subflow Bwd Bytes": bwd_bytes,
        "Init_Win_bytes_forward": fwd_packets[0].window if fwd_packets else 0,
        "Init_Win_bytes_backward": bwd_packets[0].window if bwd_packets else 0,
        "act_data_pkt_fwd": sum(1 for packet in fwd_packets if packet.length > 0),
        "min_seg_size_forward": 20 if fwd_packets else 0,
        "Inbound": 1,
    }

    row = {column: metrics.get(column, 0) for column in feature_columns}
    row.update(
        {
            "Source IP": flow.source_ip,
            "Source Port": flow.source_port,
            "Destination IP": flow.destination_ip,
            "Destination Port": flow.destination_port,
            "Label": "LIVE",
        }
    )
    return row


def flush_flows(flows: dict, feature_columns: list[str], output_path: Path) -> None:
    if not flows:
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "Source IP",
        "Source Port",
        "Destination IP",
        "Destination Port",
        *feature_columns,
        "Label",
    ]
    exists = output_path.exists() and output_path.stat().st_size > 0

    with output_path.open("a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        if not exists:
            writer.writeheader()
        for flow in flows.values():
            writer.writerow(build_row(flow, feature_columns))

    print(f"[{time.strftime('%H:%M:%S')}] wrote {len(flows)} flows to {output_path}")
    flows.clear()


def main() -> None:
    args = parse_args()
    feature_columns = joblib.load(FEATURE_COLUMNS_PATH)
    flows: dict[tuple[str, int, str, int, int], FlowStat] = {}
    last_flush = time.time()

    if args.reset:
        args.output.write_text("", encoding="utf-8")

    def handle_packet(packet) -> None:
        nonlocal last_flush

        if IP not in packet:
            return

        ip_layer = packet[IP]
        if args.victim_ip not in {ip_layer.src, ip_layer.dst}:
            return
        if not ({ip_layer.src, ip_layer.dst} & set(args.attacker_ips)):
            return

        key = flow_key(packet, args.victim_ip)
        if key not in flows:
            flows[key] = FlowStat(*key)
        flows[key].add_packet(
            PacketStat(
                timestamp=float(packet.time),
                length=len(packet),
                direction=packet_direction(packet, args.victim_ip),
                flags=tcp_flags(packet),
                window=tcp_window(packet),
            )
        )

        now = time.time()
        if now - last_flush >= args.window:
            flush_flows(flows, feature_columns, args.output)
            last_flush = now

    print(f"Listening on {args.interface} for victim {args.victim_ip} and attackers {', '.join(args.attacker_ips)}")
    print(f"Writing realtime flows to {args.output}")
    print("Press Ctrl+C to stop.")

    try:
        sniff(iface=args.interface, prn=handle_packet, store=False)
    except KeyboardInterrupt:
        flush_flows(flows, feature_columns, args.output)
        print("Stopped live sensor.")


if __name__ == "__main__":
    main()
