from pathlib import Path

import joblib
import numpy as np
import pandas as pd


PROJECT_DIR = Path(r"D:\DoAn_IDS_DDoS")
MODEL_PATH = PROJECT_DIR / "models" / "ddos_random_forest.joblib"
FEATURE_COLUMNS_PATH = PROJECT_DIR / "models" / "feature_columns.joblib"
CSV_PATH = PROJECT_DIR / "dataset" / "CSV-01-12" / "01-12" / "UDPLag.csv"

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


def load_sample(nrows: int = 20) -> pd.DataFrame:
    df = pd.read_csv(CSV_PATH, nrows=nrows, low_memory=False)
    df.columns = df.columns.str.strip()
    return df


def preprocess(df: pd.DataFrame, feature_columns: list[str]) -> pd.DataFrame:
    df = df.copy()
    df = df.drop(columns=[col for col in DROP_COLUMNS if col in df.columns], errors="ignore")
    df = df.drop(columns=["Label"], errors="ignore")

    for column in feature_columns:
        if column not in df.columns:
            df[column] = 0

    x = df[feature_columns]
    x = x.apply(pd.to_numeric, errors="coerce")
    x = x.replace([np.inf, -np.inf], np.nan)
    x = x.fillna(0)
    return x


def main() -> None:
    model = joblib.load(MODEL_PATH)
    feature_columns = joblib.load(FEATURE_COLUMNS_PATH)

    df = load_sample()
    x = preprocess(df, feature_columns)
    predictions = model.predict(x)

    labels = ["BENIGN" if value == 0 else "DDoS" for value in predictions]

    print("Model:", MODEL_PATH)
    print("Features:", len(feature_columns))
    print("Sample shape:", x.shape)
    print("Predictions:")
    for index, label in enumerate(labels, start=1):
        print(f"{index:02d}. {label}")


if __name__ == "__main__":
    main()
