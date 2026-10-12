from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


PROJECT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = PROJECT_DIR / "dataset" / "ssh" / "raw" / "Tuesday-WorkingHours.pcap_ISCX.csv"
DEFAULT_OUTPUT = PROJECT_DIR / "dataset" / "ssh" / "processed" / "ssh_benign_clean.csv"
KEEP_LABELS = {"BENIGN", "SSH-Patator"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Filter and clean CICIDS2017 Tuesday data for binary SSH Brute Force detection."
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not args.input.exists():
        raise FileNotFoundError(f"Khong tim thay file dau vao: {args.input}")

    frame = pd.read_csv(args.input, low_memory=False)
    original_rows = len(frame)
    frame.columns = frame.columns.str.strip()

    if "Label" not in frame.columns:
        raise ValueError("Dataset khong co cot Label")

    frame["Label"] = frame["Label"].astype(str).str.strip()
    source_counts = frame["Label"].value_counts(dropna=False).to_dict()
    frame = frame.loc[frame["Label"].isin(KEEP_LABELS)].copy()
    filtered_rows = len(frame)

    feature_columns = [column for column in frame.columns if column != "Label"]
    frame[feature_columns] = frame[feature_columns].apply(pd.to_numeric, errors="coerce")
    frame[feature_columns] = frame[feature_columns].replace([np.inf, -np.inf], np.nan)
    invalid_rows = int(frame[feature_columns].isna().any(axis=1).sum())
    frame = frame.dropna(subset=feature_columns).reset_index(drop=True)
    duplicate_rows = int(frame.duplicated().sum())
    frame = frame.drop_duplicates().reset_index(drop=True)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(args.output, index=False)

    final_counts = frame["Label"].value_counts().to_dict()
    print(f"Input: {args.input}")
    print(f"Output: {args.output}")
    print(f"Original rows: {original_rows}")
    print(f"Source labels: {source_counts}")
    print(f"Rows after selecting BENIGN and SSH-Patator: {filtered_rows}")
    print(f"Rows removed because of NaN/Infinity: {invalid_rows}")
    print(f"Exact duplicate rows removed: {duplicate_rows}")
    print(f"Final rows: {len(frame)}")
    print(f"Final labels: {final_counts}")
    print(f"Columns: {len(frame.columns)}")


if __name__ == "__main__":
    main()
