from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split


PROJECT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_DATASET_PATH = PROJECT_DIR / "dataset" / "Tuesday-WorkingHours.pcap_ISCX.csv"
DEFAULT_MODEL_PATH = PROJECT_DIR / "models" / "ssh_random_forest.joblib"
DEFAULT_FEATURE_PATH = PROJECT_DIR / "models" / "ssh_feature_columns.joblib"
DEFAULT_REPORT_PATH = PROJECT_DIR / "models" / "ssh_training_report.json"

# Network identity and service columns are excluded so that the model learns
# traffic behaviour instead of memorising the lab IP addresses or TCP port 22.
DROP_COLUMNS = [
    "Unnamed: 0",
    "Flow ID",
    "Source IP",
    "Source Port",
    "Destination IP",
    "Destination Port",
    "Timestamp",
]


def load_ssh_dataset(path: Path, sample_rows: int | None) -> tuple[pd.DataFrame, pd.Series]:
    if not path.exists():
        raise FileNotFoundError(
            f"Khong tim thay dataset SSH: {path}\n"
            "Hay dat file Tuesday-WorkingHours.pcap_ISCX.csv vao thu muc dataset/."
        )

    frame = pd.read_csv(path, nrows=sample_rows, low_memory=False)
    frame.columns = frame.columns.str.strip()
    if "Label" not in frame.columns:
        raise ValueError("Dataset khong co cot Label")

    labels = frame["Label"].astype(str).str.strip()
    frame = frame.loc[labels.isin(["BENIGN", "SSH-Patator"])].copy()
    labels = frame["Label"].astype(str).str.strip()
    if frame.empty or labels.nunique() < 2:
        raise ValueError("Can co ca hai nhan BENIGN va SSH-Patator de train model")

    y = labels.map({"BENIGN": 0, "SSH-Patator": 1}).astype(int)
    x = frame.drop(columns=["Label", *DROP_COLUMNS], errors="ignore")
    x = x.apply(pd.to_numeric, errors="coerce")
    x = x.replace([np.inf, -np.inf], np.nan).fillna(0)

    # Exact duplicates can otherwise appear in both train and test and inflate
    # the reported score. Keep one copy together with its label.
    combined = x.copy()
    combined["__target"] = y.to_numpy()
    combined = combined.drop_duplicates().reset_index(drop=True)
    y = combined.pop("__target").astype(int)
    return combined, y


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train SSH Brute Force detector from CICIDS2017 Tuesday data.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_PATH)
    parser.add_argument("--sample-rows", type=int, default=None)
    parser.add_argument("--model-path", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--feature-path", type=Path, default=DEFAULT_FEATURE_PATH)
    parser.add_argument("--report-path", type=Path, default=DEFAULT_REPORT_PATH)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    x, y = load_ssh_dataset(args.dataset, args.sample_rows)
    print("Data shape:", x.shape)
    print(y.value_counts().rename(index={0: "BENIGN", 1: "SSH-Patator"}))

    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )
    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample",
    )
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)

    report = {
        "dataset": str(args.dataset),
        "rows_after_filter_and_deduplication": int(len(x)),
        "train_rows": int(len(x_train)),
        "test_rows": int(len(x_test)),
        "class_counts": {
            "BENIGN": int((y == 0).sum()),
            "SSH-Patator": int((y == 1).sum()),
        },
        "accuracy": float(accuracy_score(y_test, predictions)),
        "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
        "classification_report": classification_report(
            y_test,
            predictions,
            target_names=["BENIGN", "SSH-Patator"],
            output_dict=True,
            zero_division=0,
        ),
    }

    args.model_path.parent.mkdir(parents=True, exist_ok=True)
    args.report_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.model_path)
    joblib.dump(x.columns.tolist(), args.feature_path)
    args.report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("Accuracy:", report["accuracy"])
    print("Confusion matrix:", report["confusion_matrix"])
    print(f"Saved model: {args.model_path}")
    print(f"Saved feature columns: {args.feature_path}")
    print(f"Saved report: {args.report_path}")


if __name__ == "__main__":
    main()
