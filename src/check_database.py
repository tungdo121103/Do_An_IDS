from pathlib import Path
import sqlite3


DB_PATH = Path(r"D:\DoAn_IDS_DDoS\data\ids_logs.db")


def main() -> None:
    if not DB_PATH.exists():
        raise FileNotFoundError(f"Khong tim thay database: {DB_PATH}")

    with sqlite3.connect(DB_PATH) as connection:
        connection.row_factory = sqlite3.Row
        totals = connection.execute(
            """
            SELECT
                COUNT(*) AS batches,
                COALESCE(SUM(batch_total), 0) AS total_flows,
                COALESCE(SUM(attack_count), 0) AS total_attacks,
                COALESCE(SUM(benign_count), 0) AS total_benign
            FROM flow_logs
            """
        ).fetchone()
        latest = connection.execute(
            """
            SELECT created_at, status, level, message, source_ip, destination_ip
            FROM flow_logs
            ORDER BY id DESC
            LIMIT 5
            """
        ).fetchall()

    print("Database:", DB_PATH)
    print("Batches:", totals["batches"])
    print("Total flows:", totals["total_flows"])
    print("Total DDoS:", totals["total_attacks"])
    print("Total BENIGN:", totals["total_benign"])
    print("Latest logs:")
    for row in latest:
        print(
            f'- {row["created_at"]} | {row["level"]} | {row["status"]} | '
            f'{row["source_ip"]} -> {row["destination_ip"]} | {row["message"]}'
        )


if __name__ == "__main__":
    main()
