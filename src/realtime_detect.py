from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


PROJECT_DIR = Path(__file__).resolve().parents[1]
MODELS_DIR = PROJECT_DIR / "models"
FEATURE_COLUMNS_PATH = MODELS_DIR / "feature_columns.joblib"
DATA_DIR = PROJECT_DIR / "data"
DB_PATH = DATA_DIR / "ids_logs.db"
LIVE_FLOWS_PATH = DATA_DIR / "live_flows.csv"

MODEL_REGISTRY = {
    "random_forest": {
        "label": "Random Forest",
        "path": MODELS_DIR / "ddos_random_forest.joblib",
    },
    "lightgbm": {
        "label": "LightGBM",
        "path": MODELS_DIR / "ddos_lightgbm.joblib",
    },
}
DEFAULT_MODEL_KEY = "random_forest"
BATCH_SIZE = 250

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


@dataclass
class DetectionResult:
    processed: bool
    finished: bool = False
    message: str = ""


class FlowDetector:
    def __init__(self) -> None:
        self.feature_columns: list[str] = joblib.load(FEATURE_COLUMNS_PATH)
        self.models = {
            key: joblib.load(config["path"])
            for key, config in MODEL_REGISTRY.items()
            if config["path"].exists()
        }
        if DEFAULT_MODEL_KEY not in self.models:
            raise FileNotFoundError(f"Missing default model: {MODEL_REGISTRY[DEFAULT_MODEL_KEY]['path']}")

        self.active_model_key = DEFAULT_MODEL_KEY
        self.live_offset = 0
        self.running = False
        self.finished = False

    @property
    def model(self):
        return self.models[self.active_model_key]

    @property
    def active_model_label(self) -> str:
        return MODEL_REGISTRY[self.active_model_key]["label"]

    def available_models(self) -> list[dict]:
        return [
            {
                "key": key,
                "label": config["label"],
                "active": key == self.active_model_key,
            }
            for key, config in MODEL_REGISTRY.items()
            if key in self.models
        ]

    def set_model(self, model_key: str) -> None:
        if model_key not in self.models:
            raise ValueError(f"Unknown or unloaded model: {model_key}")
        self.active_model_key = model_key

    def start(self) -> None:
        if not self.finished:
            self.running = True

    def pause(self) -> None:
        self.running = False

    def reset(self) -> None:
        self.live_offset = 0
        self.running = False
        self.finished = False

    def tick(self, connection: sqlite3.Connection) -> DetectionResult:
        if not self.running:
            return DetectionResult(processed=False, message="Detector paused")

        raw_df, input_source = self._next_batch()
        if raw_df is None:
            return DetectionResult(processed=False, finished=self.finished, message="No new flows")

        self._save_batch_log(connection, raw_df, input_source)
        return DetectionResult(processed=True)

    def _next_batch(self) -> tuple[pd.DataFrame | None, str]:
        live_df = self._read_live_batch()
        if live_df is not None:
            return live_df, "live_sensor"

        return None, "live_sensor"

    def _read_live_batch(self) -> pd.DataFrame | None:
        if not LIVE_FLOWS_PATH.exists() or LIVE_FLOWS_PATH.stat().st_size == 0:
            return None

        df = pd.read_csv(LIVE_FLOWS_PATH, low_memory=False)
        if self.live_offset >= len(df):
            return None

        end = min(self.live_offset + BATCH_SIZE, len(df))
        batch = df.iloc[self.live_offset:end].copy()
        self.live_offset = end
        return batch

    def _preprocess(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        df.columns = df.columns.str.strip()
        df = df.drop(columns=[col for col in DROP_COLUMNS if col in df.columns], errors="ignore")
        df = df.drop(columns=["Label"], errors="ignore")

        for column in self.feature_columns:
            if column not in df.columns:
                df[column] = 0

        x = df[self.feature_columns]
        x = x.apply(pd.to_numeric, errors="coerce")
        x = x.replace([np.inf, -np.inf], np.nan)
        return x.fillna(0)

    def _save_batch_log(
        self,
        connection: sqlite3.Connection,
        raw_df: pd.DataFrame,
        input_source: str,
    ) -> None:
        raw_df.columns = raw_df.columns.str.strip()
        predictions = self.model.predict(self._preprocess(raw_df))

        attack_count = int((predictions == 1).sum())
        benign_count = int((predictions == 0).sum())
        batch_total = int(len(predictions))
        attack_rate = round((attack_count / batch_total) * 100, 2) if batch_total else 0
        source_ip = raw_df.get("Source IP", pd.Series(["unknown"])).astype(str).mode().iloc[0]
        destination_ip = raw_df.get("Destination IP", pd.Series(["unknown"])).astype(str).mode().iloc[0]
        status = "DDoS Detected" if attack_count else "Normal"
        level = "HIGH" if attack_rate >= 70 else "MEDIUM" if attack_count else "LOW"
        message = (
            f"Detected {attack_count} suspicious DDoS flows"
            if attack_count
            else "No suspicious flow detected"
        )
        batch_no = next_batch_no(connection)

        connection.execute(
            """
            INSERT INTO flow_logs (
                created_at, batch_no, input_source, model_name, batch_total,
                attack_count, benign_count, attack_rate, status, level,
                source_ip, destination_ip, message
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                time.strftime("%Y-%m-%d %H:%M:%S"),
                batch_no,
                input_source,
                self.active_model_label,
                batch_total,
                attack_count,
                benign_count,
                attack_rate,
                status,
                level,
                source_ip,
                destination_ip,
                message,
            ),
        )


def next_batch_no(connection: sqlite3.Connection) -> int:
    row = connection.execute("SELECT COALESCE(MAX(batch_no), 0) + 1 AS batch_no FROM flow_logs").fetchone()
    return int(row["batch_no"])

