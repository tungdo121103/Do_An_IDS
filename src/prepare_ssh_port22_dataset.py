"""Build a destination-port-22 training set for the SSH classifier.

The existing v1 training set contains benign traffic from other services.  At
runtime the SSH classifier only receives TCP/22 flows, so those other benign
flows are not an appropriate negative class for this task.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd


PROJECT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = PROJECT_DIR / "dataset" / "Tuesday-WorkingHours.pcap_ISCX.csv"
DEFAULT_OUTPUT = PROJECT_DIR / "dataset" / "ssh" / "processed" / "ssh_port22_train_ready.csv"
FEATURE_MANIFEST = PROJECT_DIR / "models" / "ssh_v1_artifacts" / "ssh_feature_manifest_v1.json"
LABELS = {"BENIGN", "SSH-Patator"}


def prepare_frame(frame: pd.DataFrame, features: list[str]) -> tuple[pd.DataFrame, dict]:
    frame = frame.copy()
    frame.columns = frame.columns.str.strip()
    required = {"Destination Port", "Label", *features}
    missing = sorted(required.difference(frame.columns))
    if missing:
        raise ValueError(f"SSH source data is missing columns: {missing}")

    frame["Label"] = frame["Label"].astype(str).str.strip()
    ports = pd.to_numeric(frame["Destination Port"], errors="coerce")
    frame = frame.loc[ports.eq(22) & frame["Label"].isin(LABELS), features + ["Label"]].copy()
    selected_counts = frame["Label"].value_counts().to_dict()

    frame[features] = frame[features].apply(pd.to_numeric, errors="coerce")
    frame[features] = frame[features].replace([np.inf, -np.inf], np.nan)
    invalid_rows = int(frame[features].isna().any(axis=1).sum())
    frame = frame.dropna(subset=features)

    # Remove contradictory feature vectors: a flow with identical model input
    # cannot legitimately have both labels in this training set.
    conflicting = frame.groupby(features, dropna=False)["Label"].transform("nunique").gt(1)
    conflicting_rows = int(conflicting.sum())
    frame = frame.loc[~conflicting].drop_duplicates(subset=features + ["Label"]).reset_index(drop=True)
    final_counts = frame["Label"].value_counts().to_dict()
    if not LABELS.issubset(final_counts):
        raise ValueError(f"Both SSH classes are required after cleaning: {final_counts}")

    report = {
        "destination_port": 22,
        "protocol_note": "The CICIDS2017 Tuesday CSV has no Protocol column; runtime routing also requires TCP.",
        "selected_counts_before_cleaning": {key: int(value) for key, value in selected_counts.items()},
        "invalid_numeric_rows": invalid_rows,
        "conflicting_label_rows": conflicting_rows,
        "final_counts": {key: int(value) for key, value in final_counts.items()},
        "feature_count": len(features),
    }
    return frame, report


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare SSH-only CICIDS2017 flows for candidate model training.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    features = json.loads(FEATURE_MANIFEST.read_text(encoding="utf-8"))["features_in_order"]
    frame = pd.read_csv(args.input, low_memory=False)
    prepared, report = prepare_frame(frame, features)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    prepared.to_csv(args.output, index=False)
    print(json.dumps({"output": str(args.output), **report}, indent=2))


if __name__ == "__main__":
    main()
