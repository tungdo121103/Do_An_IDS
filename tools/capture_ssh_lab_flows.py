"""Save only the new TCP/22 flows from a controlled lab run.

Run on the IDS while the live sensor is active. Start this command before the
lab activity, perform only the named SSH scenario, wait for the sensor's SSH
idle timeout, then press Enter. It never clears or edits live_flows.csv.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]


def read_flows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    if not path.exists() or path.stat().st_size == 0:
        return [], []
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        return list(reader.fieldnames or []), list(reader)


def new_ssh_flows(
    previous_count: int,
    rows: list[dict[str, str]],
    source_ip: str,
    destination_ip: str,
) -> list[dict[str, str]]:
    if len(rows) < previous_count:
        raise ValueError("live_flows.csv was reset during capture; start again without resetting it")
    return [
        row
        for row in rows[previous_count:]
        if row.get("Source IP") == source_ip
        and row.get("Destination IP") == destination_ip
        and row.get("Destination Port") == "22"
        and row.get("Protocol") == "6"
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="Capture one labelled SSH lab scenario without resetting DDoS data.")
    parser.add_argument("--input", type=Path, default=PROJECT_DIR / "data" / "live_flows.csv")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-ip", default="192.168.247.10")
    parser.add_argument("--destination-ip", default="192.168.247.20")
    args = parser.parse_args()
    if args.output.exists():
        parser.error(f"Output already exists: {args.output}")

    _, before = read_flows(args.input)
    print(f"Starting after {len(before)} existing flows in {args.input}.")
    input("Run one controlled SSH scenario now. Finish it, wait 12 seconds, then press Enter here...")
    columns, after = read_flows(args.input)
    if not columns:
        parser.error("No live flow CSV header found; is the sensor running?")
    try:
        captured = new_ssh_flows(len(before), after, args.source_ip, args.destination_ip)
    except ValueError as error:
        parser.error(str(error))
    if not captured:
        parser.error("No new TCP/22 flow for this source and destination was captured")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, fieldnames=columns)
        writer.writeheader()
        writer.writerows(captured)
    print(f"Saved {len(captured)} SSH flows to {args.output}; live_flows.csv is unchanged.")


if __name__ == "__main__":
    main()
