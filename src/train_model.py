from __future__ import annotations

import argparse
import gc
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split


PROJECT_DIR = Path(r"D:\DoAn_IDS_DDoS")
DEFAULT_DATASET_DIR = PROJECT_DIR / "dataset" / "CSV-01-12" / "01-12"
DEFAULT_MODEL_PATH = PROJECT_DIR / "models" / "ddos_random_forest.joblib"
DEFAULT_FEATURE_PATH = PROJECT_DIR / "models" / "feature_columns.joblib"

DROP_COLUMNS = [
    "Unnamed: 0",
    "Flow ID",
    "Source IP",
    "Source Port",
    "Destination IP",
    "Destination Port",
    "Timestamp",
    "SimillarHTTP",
]

DEFAULT_CSV_FILES = [
    "UDPLag.csv",
    "DrDoS_UDP.csv",
    "Syn.csv",
    "DrDoS_DNS.csv",
]


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = df.columns.str.strip()
    return df


def clean_frame(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    df = normalize_columns(df)
    df = df.drop(columns=[col for col in DROP_COLUMNS if col in df.columns], errors="ignore")

    if "Label" not in df.columns:
        raise ValueError(f"Khong tim thay cot Label. Columns: {df.columns.tolist()}")

    labels = df["Label"].astype(str).str.strip()
    y = labels.apply(lambda value: 0 if value.upper() == "BENIGN" else 1)

    x = df.drop(columns=["Label"], errors="ignore")
    x = x.apply(pd.to_numeric, errors="coerce")
    x = x.replace([np.inf, -np.inf], np.nan)
    x = x.fillna(0)

    return x, y


def read_csv_sample(path: Path, sample_rows: int | None) -> tuple[pd.DataFrame, pd.Series]:
    print(f"Reading: {path}")
    df = pd.read_csv(path, nrows=sample_rows, low_memory=False)
    return clean_frame(df)


def load_dataset(dataset_dir: Path, csv_files: list[str], sample_rows: int | None) -> tuple[pd.DataFrame, pd.Series]:
    x_parts = []
    y_parts = []

    for csv_file in csv_files:
        path = dataset_dir / csv_file
        if not path.exists():
            print(f"Skip missing file: {path}")
            continue

        x_part, y_part = read_csv_sample(path, sample_rows)
        x_parts.append(x_part)
        y_parts.append(y_part)

    if not x_parts:
        raise FileNotFoundError(f"Khong tim thay file CSV nao trong: {dataset_dir}")

    x = pd.concat(x_parts, ignore_index=True)
    y = pd.concat(y_parts, ignore_index=True)

    del x_parts, y_parts
    gc.collect()

    return x, y


def train_model(x: pd.DataFrame, y: pd.Series) -> RandomForestClassifier:
    print("Data shape:", x.shape)
    print("Label counts:")
    print(y.value_counts().rename(index={0: "BENIGN", 1: "DDoS"}))

    if y.nunique() < 2:
        raise ValueError(
            "Dataset chi co 1 class. Can co ca BENIGN va DDoS de train model phan loai."
        )

    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )
    model.fit(x_train, y_train)

    y_pred = model.predict(x_test)
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("Confusion matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("Classification report:")
    print(classification_report(y_test, y_pred, target_names=["BENIGN", "DDoS"]))

    return model


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train ML model for realtime DDoS IDS.")
    parser.add_argument("--dataset-dir", type=Path, default=DEFAULT_DATASET_DIR)
    parser.add_argument("--sample-rows", type=int, default=50_000)
    parser.add_argument("--model-path", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--feature-path", type=Path, default=DEFAULT_FEATURE_PATH)
    parser.add_argument("--csv-files", nargs="*", default=DEFAULT_CSV_FILES)
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    x, y = load_dataset(args.dataset_dir, args.csv_files, args.sample_rows)
    feature_columns = x.columns.tolist()
    model = train_model(x, y)

    args.model_path.parent.mkdir(parents=True, exist_ok=True)
    args.feature_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.model_path)
    joblib.dump(feature_columns, args.feature_path)

    print(f"Saved model: {args.model_path}")
    print(f"Saved feature columns: {args.feature_path}")


if __name__ == "__main__":
    main()
