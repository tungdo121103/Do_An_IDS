"""Offline smoke test for the shared DDoS/SSH flow router and saved models."""

from __future__ import annotations

import sqlite3
import sys
import tempfile
import importlib
from pathlib import Path

import pandas as pd

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

from src.realtime_detect import FlowDetector
import src.realtime_detect as detector_module


def main() -> None:
    dataset = PROJECT_DIR / "dataset" / "ssh" / "processed" / "ssh_train_ready.csv"
    benign = pd.read_csv(dataset, nrows=1)
    attack = None
    for chunk in pd.read_csv(dataset, chunksize=20_000):
        matching = chunk.loc[chunk["Label"] == "SSH-Patator"]
        if not matching.empty:
            attack = matching.head(100)
            break
    if attack is None:
        raise ValueError("No SSH-Patator row found in SSH train-ready dataset")
    sample = pd.concat([attack, benign], ignore_index=True)
    detector = FlowDetector()
    assert len(detector.feature_columns["ddos"]) == 46
    assert len(detector.feature_columns["ssh"]) == 45

    sample["Protocol"] = 6
    sample["Destination Port"] = [22] * len(attack) + [80]
    sample["Source IP"] = ["192.168.247.10"] * len(sample)
    sample["Destination IP"] = ["192.168.247.20"] * len(sample)

    for model_key in ("random_forest", "lightgbm"):
        detector.set_model(model_key)
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.execute(
            """CREATE TABLE flow_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT, batch_no INTEGER, input_source TEXT,
                model_name TEXT, attack_type TEXT, batch_total INTEGER,
                attack_count INTEGER, benign_count INTEGER, attack_rate REAL,
                status TEXT, level TEXT, source_ip TEXT,
                destination_ip TEXT, message TEXT
            )"""
        )
        detector._save_batch_log(connection, sample.copy(), "smoke_test")
        rows = connection.execute(
            "SELECT attack_type, batch_total, attack_count, benign_count FROM flow_logs"
        ).fetchall()
        assert {row["attack_type"] for row in rows} == {"ssh", "ddos"}
        assert sum(row["batch_total"] for row in rows) == len(sample)
        assert all(row["attack_count"] + row["benign_count"] == row["batch_total"] for row in rows)
        assert next(row for row in rows if row["attack_type"] == "ssh")["attack_count"] > 0
        print(model_key, [dict(row) for row in rows])
        connection.close()

    with tempfile.TemporaryDirectory() as temp_dir:
        detector_module.DB_PATH = Path(temp_dir) / "ids_logs.db"
        detector_module.LIVE_FLOWS_PATH = Path(temp_dir) / "live_flows.csv"
        dashboard = importlib.import_module("dashboard.app")
        with dashboard.get_db() as connection:
            dashboard.detector._save_batch_log(connection, sample.copy(), "smoke_test")
        response = dashboard.app.test_client().get("/api/stats")
        assert response.status_code == 200
        stats = response.get_json()
        assert stats["total_flows"] == len(sample)
        assert stats["total_ssh"] > 0
        assert stats["total_ddos"] == 0
        assert len(stats["available_models"]) == 2
        print("dashboard API", {key: stats[key] for key in ("total_flows", "total_ddos", "total_ssh")})


if __name__ == "__main__":
    main()
