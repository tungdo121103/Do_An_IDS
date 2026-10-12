from __future__ import annotations

import sqlite3
import json
import time
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


PROJECT_DIR = Path(__file__).resolve().parents[1]
MODELS_DIR = PROJECT_DIR / "models"
FEATURE_MANIFEST_PATHS = {
    "ddos": MODELS_DIR / "ddos_v2" / "ddos_feature_manifest_v2.json",
    "ssh": MODELS_DIR / "ssh_v1_artifacts" / "ssh_feature_manifest_v1.json",
}
DATA_DIR = PROJECT_DIR / "data"
DB_PATH = DATA_DIR / "ids_logs.db"
LIVE_FLOWS_PATH = DATA_DIR / "live_flows.csv"

MODEL_REGISTRY = {
    "random_forest": {
        "label": "Random Forest",
        "ddos": MODELS_DIR / "ddos_v2" / "ddos_random_forest_v2.joblib",
        "ssh": MODELS_DIR / "ssh_v1_artifacts" / "ssh_random_forest_v1.joblib",
    },
    "lightgbm": {
        "label": "LightGBM",
        "ddos": MODELS_DIR / "ddos_v2" / "ddos_lightgbm_v2.joblib",
        "ssh": MODELS_DIR / "ssh_v1_artifacts" / "ssh_lightgbm_v1.joblib",
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
        self.feature_columns = {
            attack_type: json.loads(path.read_text(encoding="utf-8"))["features_in_order"]
            for attack_type, path in FEATURE_MANIFEST_PATHS.items()
        }
        if not set(self.feature_columns["ssh"]).issubset(self.feature_columns["ddos"]):
            raise ValueError("SSH manifest has features unavailable in the shared live sensor")
        self.models = {
            key: {attack_type: joblib.load(config[attack_type]) for attack_type in FEATURE_MANIFEST_PATHS}
            for key, config in MODEL_REGISTRY.items()
            if all(config[attack_type].exists() for attack_type in FEATURE_MANIFEST_PATHS)
        }
        if DEFAULT_MODEL_KEY not in self.models:
            raise FileNotFoundError("Missing DDoS or SSH Random Forest model; copy both model families to models/")

        self.active_model_key = DEFAULT_MODEL_KEY
        self.live_offset = 0
        self.running = False
        self.finished = False

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

    def _preprocess(self, df: pd.DataFrame, attack_type: str) -> pd.DataFrame:
        df = df.copy()
        df.columns = df.columns.str.strip()
        df = df.drop(columns=[col for col in DROP_COLUMNS if col in df.columns], errors="ignore")
        df = df.drop(columns=["Label"], errors="ignore")

        feature_columns = self.feature_columns[attack_type]
        missing = [column for column in feature_columns if column not in df.columns]
        if missing:
            raise ValueError(f"Live flow thieu feature: {missing}")

        x = df[feature_columns]
        x = x.apply(pd.to_numeric, errors="coerce")
        x = x.replace([np.inf, -np.inf], np.nan)
        if x.isna().any().any():
            raise ValueError("Live flow co gia tri NaN/Infinity sau khi tien xu ly")
        return x

    def _save_batch_log(
        self,
        connection: sqlite3.Connection,
        raw_df: pd.DataFrame,
        input_source: str,
    ) -> None:
        raw_df.columns = raw_df.columns.str.strip()
        if "Destination Port" not in raw_df.columns or "Protocol" not in raw_df.columns:
            raise ValueError("Live flow requires Destination Port and Protocol for SSH/DDoS routing")
        destination_ports = pd.to_numeric(raw_df["Destination Port"], errors="coerce")
        protocols = pd.to_numeric(raw_df["Protocol"], errors="coerce")
        ssh_mask = (destination_ports == 22) & (protocols == 6)
        for attack_type, group in (("ssh", raw_df.loc[ssh_mask]), ("ddos", raw_df.loc[~ssh_mask])):
            if not group.empty:
                self._save_group_log(connection, group, input_source, attack_type)

    def _save_group_log(
        self,
        connection: sqlite3.Connection,
        raw_df: pd.DataFrame,
        input_source: str,
        attack_type: str,
    ) -> None:
        predictions = self.models[self.active_model_key][attack_type].predict(
            self._preprocess(raw_df, attack_type)
        )

        attack_count = int((predictions == 1).sum())
        benign_count = int((predictions == 0).sum())
        batch_total = int(len(predictions))
        attack_rate = round((attack_count / batch_total) * 100, 2) if batch_total else 0
        source_ip = raw_df.get("Source IP", pd.Series(["unknown"])).astype(str).mode().iloc[0]
        destination_ip = raw_df.get("Destination IP", pd.Series(["unknown"])).astype(str).mode().iloc[0]
        attack_name = "SSH Brute Force" if attack_type == "ssh" else "DDoS"
        status = f"{attack_name} Detected" if attack_count else "Normal"
        level = "HIGH" if attack_rate >= 70 else "MEDIUM" if attack_count else "LOW"
        message = (
            f"Detected {attack_count} suspicious {attack_name} flows"
            if attack_count
            else "No suspicious flow detected"
        )
        batch_no = next_batch_no(connection)

        connection.execute(
            """
            INSERT INTO flow_logs (
                created_at, batch_no, input_source, model_name, attack_type, batch_total,
                attack_count, benign_count, attack_rate, status, level,
                source_ip, destination_ip, message
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                time.strftime("%Y-%m-%d %H:%M:%S"),
                batch_no,
                input_source,
                self.active_model_label,
                attack_type,
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

