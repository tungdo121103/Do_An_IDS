from __future__ import annotations

import argparse
import math
from pathlib import Path

import pandas as pd


PROJECT_DIR = Path(r"D:\DoAn_IDS_DDoS")
DATASET_DIR = PROJECT_DIR / "dataset" / "CSV-01-12" / "01-12"
OUTPUT_PATH = PROJECT_DIR / "data" / "demo_flows_3_1.csv"

DEFAULT_CSV_FILES = [
    "Syn.csv",
    "UDPLag.csv",
    "DrDoS_DNS.csv",
    "DrDoS_LDAP.csv",
    "DrDoS_MSSQL.csv",
    "DrDoS_NTP.csv",
    "DrDoS_NetBIOS.csv",
    "DrDoS_SNMP.csv",
    "DrDoS_SSDP.csv",
    "DrDoS_UDP.csv",
]


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = df.columns.str.strip()
    return df


def read_label_samples(
    path: Path,
    label_kind: str,
    target: int,
    chunk_size: int,
) -> pd.DataFrame:
    parts: list[pd.DataFrame] = []
    count = 0

    for chunk in pd.read_csv(path, chunksize=chunk_size, low_memory=False):
        chunk = normalize_columns(chunk)
        if "Label" not in chunk.columns:
            raise ValueError(f"Khong tim thay cot Label trong {path}")

        labels = chunk["Label"].astype(str).str.strip()
        if label_kind == "benign":
            sample = chunk[labels.str.upper() == "BENIGN"]
        else:
            sample = chunk[labels.str.upper() != "BENIGN"]

        if sample.empty:
            continue

        need = target - count
        sample = sample.head(need)
        parts.append(sample)
        count += len(sample)

        if count >= target:
            break

    if not parts:
        return pd.DataFrame()

    return pd.concat(parts, ignore_index=True)


def collect_benign(csv_files: list[str], target: int, chunk_size: int) -> pd.DataFrame:
    parts: list[pd.DataFrame] = []
    count = 0

    for csv_file in csv_files:
        path = DATASET_DIR / csv_file
        if not path.exists():
            print(f"Skip missing file: {path}", flush=True)
            continue

        need = target - count
        if need <= 0:
            break

        print(f"Collect BENIGN from: {path.name}", flush=True)
        sample = read_label_samples(path, "benign", need, chunk_size)
        if sample.empty:
            continue

        parts.append(sample)
        count += len(sample)
        print(f"  BENIGN: {count}/{target}", flush=True)

    if count < target:
        raise RuntimeError(f"Khong du BENIGN: {count}/{target}")

    return pd.concat(parts, ignore_index=True).head(target)


def collect_ddos_balanced(csv_files: list[str], target: int, chunk_size: int) -> pd.DataFrame:
    existing_files = [csv_file for csv_file in csv_files if (DATASET_DIR / csv_file).exists()]
    if not existing_files:
        raise FileNotFoundError("Khong tim thay file CSV tan cong nao.")

    per_file = math.ceil(target / len(existing_files))
    parts: list[pd.DataFrame] = []

    for csv_file in existing_files:
        path = DATASET_DIR / csv_file
        print(f"Collect DDoS from: {path.name} target={per_file}", flush=True)
        sample = read_label_samples(path, "ddos", per_file, chunk_size)
        if sample.empty:
            print(f"  No DDoS rows found in {path.name}", flush=True)
            continue

        sample = sample.copy()
        sample["Attack Source File"] = path.name
        parts.append(sample)
        print(f"  DDoS from {path.name}: {len(sample)}", flush=True)

    if not parts:
        raise RuntimeError("Khong gom duoc mau DDoS nao.")

    ddos_df = pd.concat(parts, ignore_index=True)
    if len(ddos_df) < target:
        raise RuntimeError(f"Khong du DDoS: {len(ddos_df)}/{target}")

    return ddos_df.sample(n=target, random_state=42).reset_index(drop=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create 3:1 BENIGN:DDoS demo flow CSV for dashboard.")
    parser.add_argument("--benign", type=int, default=7500)
    parser.add_argument("--ddos", type=int, default=2500)
    parser.add_argument("--chunk-size", type=int, default=100_000)
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH)
    parser.add_argument("--csv-files", nargs="*", default=DEFAULT_CSV_FILES)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    benign_df = collect_benign(args.csv_files, args.benign, args.chunk_size)
    ddos_df = collect_ddos_balanced(args.csv_files, args.ddos, args.chunk_size)

    demo_df = pd.concat([benign_df, ddos_df], ignore_index=True)
    demo_df = demo_df.sample(frac=1, random_state=42).reset_index(drop=True)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    demo_df.to_csv(args.output, index=False)

    labels = demo_df["Label"].astype(str).str.strip()
    benign_count = int((labels.str.upper() == "BENIGN").sum())
    ddos_count = int(len(demo_df) - benign_count)

    print(f"Saved: {args.output}")
    print(f"Rows: {len(demo_df)}")
    print(f"BENIGN: {benign_count}")
    print(f"DDoS: {ddos_count}")
    if "Attack Source File" in demo_df.columns:
        print("DDoS source distribution:")
        print(demo_df.loc[labels.str.upper() != "BENIGN", "Attack Source File"].value_counts())


if __name__ == "__main__":
    main()


