"""Train and evaluate SSH-only candidate models without changing the live IDS.

This script writes candidate artifacts to a separate directory. It deliberately
does not replace the model files used by src/realtime_detect.py.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split


PROJECT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_DATA = PROJECT_DIR / "dataset" / "ssh" / "processed" / "ssh_port22_train_ready.csv"
DEFAULT_OUTPUT = PROJECT_DIR / "models" / "ssh_port22_candidate"
FEATURE_MANIFEST = PROJECT_DIR / "models" / "ssh_v1_artifacts" / "ssh_feature_manifest_v1.json"
LABELS = {"BENIGN": 0, "SSH-Patator": 1}


def load_lab_flows(paths: list[Path], features: list[str]) -> pd.DataFrame:
    frames = []
    for path in paths:
        frame = pd.read_csv(path, low_memory=False)
        frame.columns = frame.columns.str.strip()
        missing = sorted(set(features + ["Destination Port", "Protocol"]).difference(frame.columns))
        if missing:
            raise ValueError(f"{path} is missing columns: {missing}")
        port = pd.to_numeric(frame["Destination Port"], errors="coerce")
        protocol = pd.to_numeric(frame["Protocol"], errors="coerce")
        if not (port.eq(22) & protocol.eq(6)).all():
            raise ValueError(f"{path} must contain only TCP/22 flows")
        numeric = frame[features].apply(pd.to_numeric, errors="coerce")
        numeric = numeric.replace([np.inf, -np.inf], np.nan)
        if numeric.isna().any().any():
            raise ValueError(f"{path} contains missing or non-finite SSH features")
        frames.append(numeric)
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(columns=features)


def evaluate_lab(model, flows: pd.DataFrame, expected_label: int) -> dict | None:
    if flows.empty:
        return None
    predictions = model.predict(flows)
    probabilities = model.predict_proba(flows)[:, 1]
    return {
        "flows": int(len(flows)),
        "flagged_ssh_attack": int(np.sum(predictions == 1)),
        "rate_for_expected_label": float(np.mean(predictions == expected_label)),
        "median_attack_probability": float(np.median(probabilities)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Train SSH model candidates on TCP/22-only flow data.")
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--lab-attack", type=Path, action="append", default=[])
    parser.add_argument("--lab-benign", type=Path, action="append", default=[])
    args = parser.parse_args()

    features = json.loads(FEATURE_MANIFEST.read_text(encoding="utf-8"))["features_in_order"]
    training = pd.read_csv(args.data, low_memory=False)
    training.columns = training.columns.str.strip()
    missing = sorted(set(features + ["Label"]).difference(training.columns))
    if missing:
        raise ValueError(f"Training data is missing columns: {missing}")
    training["Label"] = training["Label"].astype(str).str.strip()
    if not set(training["Label"]).issubset(LABELS):
        raise ValueError("Training labels must be BENIGN or SSH-Patator")
    x = training[features].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    if x.isna().any().any():
        raise ValueError("Training features contain missing or non-finite values")
    y = training["Label"].map(LABELS)
    if set(y) != {0, 1}:
        raise ValueError("Training data must contain both SSH classes")

    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=0.2, stratify=y, random_state=42
    )
    lab_attack = load_lab_flows(args.lab_attack, features)
    lab_benign = load_lab_flows(args.lab_benign, features)
    models = {
        "random_forest": RandomForestClassifier(
            n_estimators=200, class_weight="balanced_subsample", random_state=42, n_jobs=-1
        ),
        "lightgbm": LGBMClassifier(
            n_estimators=200, class_weight="balanced", random_state=42, verbosity=-1
        ),
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "purpose": "SSH-only TCP/22 candidate; existing live IDS models are unchanged",
        "training_file": str(args.data),
        "training_rows": int(len(x_train)),
        "offline_test_rows": int(len(x_test)),
        "class_counts": {key: int((training["Label"] == key).sum()) for key in LABELS},
        "feature_count": len(features),
        "lab_attack_files": [str(path) for path in args.lab_attack],
        "lab_benign_files": [str(path) for path in args.lab_benign],
        "models": {},
        "limitations": (
            "The random CICIDS2017 holdout is from the same capture. Lab attack and benign "
            "runs must both be checked before deployment; one demo run cannot establish live accuracy."
        ),
    }
    for name, model in models.items():
        model.fit(x_train, y_train)
        predicted = model.predict(x_test)
        report["models"][name] = {
            "confusion_matrix_tn_fp_fn_tp": confusion_matrix(y_test, predicted, labels=[0, 1]).ravel().tolist(),
            "precision_ssh": float(precision_score(y_test, predicted, zero_division=0)),
            "recall_ssh": float(recall_score(y_test, predicted, zero_division=0)),
            "f1_ssh": float(f1_score(y_test, predicted, zero_division=0)),
            "lab_attack": evaluate_lab(model, lab_attack, 1),
            "lab_benign": evaluate_lab(model, lab_benign, 0),
        }
        joblib.dump(model, args.output_dir / f"ssh_{name}_candidate.joblib")

    (args.output_dir / "ssh_feature_manifest_candidate.json").write_text(
        json.dumps({"features_in_order": features, "labels": LABELS}, indent=2), encoding="utf-8"
    )
    (args.output_dir / "training_report_candidate.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
