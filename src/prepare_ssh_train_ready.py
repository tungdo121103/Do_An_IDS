from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd


PROJECT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = PROJECT_DIR / "dataset" / "ssh" / "processed" / "ssh_benign_clean.csv"
DEFAULT_OUTPUT = PROJECT_DIR / "dataset" / "ssh" / "processed" / "ssh_train_ready.csv"
DEFAULT_MANIFEST = PROJECT_DIR / "dataset" / "ssh" / "processed" / "ssh_feature_manifest.json"

# Conservative set whose names, direction, aggregation and units are supported
# by src/live_sensor.py. Identity/service columns are routing metadata, not ML
# features. Ambiguous CICFlowMeter fields are deliberately excluded.
TRAIN_FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "ECE Flag Count",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "Label",
]

EXCLUSION_GROUPS = {
    "routing_metadata": ["Destination Port"],
    "sensor_not_implemented": [
        "Fwd Avg Bytes/Bulk",
        "Fwd Avg Packets/Bulk",
        "Fwd Avg Bulk Rate",
        "Bwd Avg Bytes/Bulk",
        "Bwd Avg Packets/Bulk",
        "Bwd Avg Bulk Rate",
        "Active Mean",
        "Active Std",
        "Active Max",
        "Active Min",
        "Idle Mean",
        "Idle Std",
        "Idle Max",
        "Idle Min",
    ],
    "ambiguous_or_approximated_by_sensor": [
        "Fwd PSH Flags",
        "Bwd PSH Flags",
        "Fwd URG Flags",
        "Bwd URG Flags",
        "Fwd Header Length",
        "Bwd Header Length",
        "Down/Up Ratio",
        "Average Packet Size",
        "Avg Fwd Segment Size",
        "Avg Bwd Segment Size",
        "Fwd Header Length.1",
        "Subflow Fwd Packets",
        "Subflow Fwd Bytes",
        "Subflow Bwd Packets",
        "Subflow Bwd Bytes",
        "act_data_pkt_fwd",
        "min_seg_size_forward",
    ],
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create sensor-compatible SSH training data.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    frame = pd.read_csv(args.input, low_memory=False)
    frame.columns = frame.columns.str.strip()

    missing = [column for column in TRAIN_FEATURES if column not in frame.columns]
    if missing:
        raise ValueError(f"Dataset thieu feature bat buoc: {missing}")

    output = frame[TRAIN_FEATURES].copy()
    numeric_columns = [column for column in TRAIN_FEATURES if column != "Label"]
    output[numeric_columns] = output[numeric_columns].apply(pd.to_numeric, errors="coerce")
    output[numeric_columns] = output[numeric_columns].replace([np.inf, -np.inf], np.nan)
    invalid_rows = int(output[numeric_columns].isna().any(axis=1).sum())
    if invalid_rows:
        raise ValueError(f"Phat hien {invalid_rows} dong NaN/Infinity trong dataset dau vao")

    duplicate_rows = int(output.duplicated().sum())
    output = output.drop_duplicates().reset_index(drop=True)
    label_counts = {str(key): int(value) for key, value in output["Label"].value_counts().items()}

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    output.to_csv(args.output, index=False)

    excluded_columns = [column for column in frame.columns if column not in TRAIN_FEATURES]
    manifest = {
        "source_file": str(args.input),
        "output_file": str(args.output),
        "task": "binary_classification",
        "labels": {"BENIGN": 0, "SSH-Patator": 1},
        "routing_rule": "Only send flows involving the configured SSH service port to this model.",
        "feature_count": len(numeric_columns),
        "features_in_order": numeric_columns,
        "rows": int(len(output)),
        "label_counts": label_counts,
        "duplicates_removed_after_feature_selection": duplicate_rows,
        "excluded_columns": excluded_columns,
        "exclusion_groups": EXCLUSION_GROUPS,
        "sensor_contract": {
            "duration_and_iat_unit": "microseconds",
            "direction": "forward means packets sent to the protected server",
            "feature_source": "src/live_sensor.py build_row",
        },
    }
    args.manifest.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Input rows: {len(frame)}")
    print(f"Output rows: {len(output)}")
    print(f"Feature count: {len(numeric_columns)}")
    print(f"Duplicates removed after selecting features: {duplicate_rows}")
    print(f"Labels: {label_counts}")
    print(f"CSV: {args.output}")
    print(f"Manifest: {args.manifest}")


if __name__ == "__main__":
    main()
