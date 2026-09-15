from pathlib import Path

import pandas as pd


DATASET_PATH = Path(r"D:\DoAn_IDS_DDoS\dataset\CSV-01-12\01-12\UDPLag.csv")
SAMPLE_ROWS = 10_000


def main() -> None:
    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Khong tim thay file dataset: {DATASET_PATH}\n"
            "Hay giai nen CSV-01-12.zip vao thu muc dataset\\CSV-01-12 truoc."
        )

    df = pd.read_csv(DATASET_PATH, nrows=SAMPLE_ROWS)
    print("Shape:", df.shape)
    print("Columns:")
    print(df.columns.tolist())

    label_column = " Label" if " Label" in df.columns else "Label"
    if label_column not in df.columns:
        raise KeyError(
            "Khong tim thay cot label. Cac cot hien co:\n"
            f"{df.columns.tolist()}"
        )

    print("Label counts:")
    print(df[label_column].value_counts())


if __name__ == "__main__":
    main()
