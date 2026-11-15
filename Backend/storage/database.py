import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "cyber_trek.db"
DB_PATH = Path(os.getenv("CYBER_TREK_DB_PATH", str(DEFAULT_DB_PATH))).resolve()
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
_DB_LOCK = threading.RLock()


@contextmanager
def _connect():
    connection = sqlite3.connect(str(DB_PATH), timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database() -> None:
    with _DB_LOCK, _connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS traffic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                destination TEXT NOT NULL,
                protocol TEXT NOT NULL,
                source_port INTEGER,
                destination_port INTEGER,
                packet_length INTEGER NOT NULL DEFAULT 0,
                flags TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic(timestamp);
            CREATE INDEX IF NOT EXISTS idx_traffic_source ON traffic(source);

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                destination TEXT NOT NULL DEFAULT 'N/A',
                description TEXT NOT NULL,
                evidence TEXT NOT NULL DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(type);
            """
        )


def insert_traffic(packet: dict[str, Any]) -> int:
    with _DB_LOCK, _connect() as connection:
        cursor = connection.execute(
            """INSERT INTO traffic
            (timestamp, source, destination, protocol, source_port,
             destination_port, packet_length, flags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                packet["timestamp"], packet["source"], packet["destination"],
                packet["protocol"], packet.get("source_port"),
                packet.get("destination_port"), int(packet.get("length", 0)),
                packet.get("flags", ""),
            ),
        )
        return int(cursor.lastrowid)


def insert_alert(alert: dict[str, Any]) -> dict[str, Any]:
    import json

    with _DB_LOCK, _connect() as connection:
        cursor = connection.execute(
            """INSERT INTO alerts
            (timestamp, type, severity, source, destination, description, evidence)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                alert["timestamp"], alert["type"], alert["severity"],
                alert["source"], alert.get("destination", "N/A"),
                alert["description"], json.dumps(alert.get("evidence", {})),
            ),
        )
        result = dict(alert)
        result["id"] = int(cursor.lastrowid)
        return result


def fetch_traffic(limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 5000))
    offset = max(0, int(offset))
    with _DB_LOCK, _connect() as connection:
        rows = connection.execute(
            "SELECT * FROM traffic ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [dict(row) for row in rows]


def fetch_alerts(limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    import json

    limit = max(1, min(int(limit), 5000))
    offset = max(0, int(offset))
    with _DB_LOCK, _connect() as connection:
        rows = connection.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    results = []
    for row in rows:
        item = dict(row)
        try:
            item["evidence"] = json.loads(item.get("evidence") or "{}")
        except json.JSONDecodeError:
            item["evidence"] = {}
        results.append(item)
    return results


def get_counts() -> dict[str, int]:
    with _DB_LOCK, _connect() as connection:
        traffic_count = connection.execute("SELECT COUNT(*) FROM traffic").fetchone()[0]
        alert_count = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    return {"total_packets": int(traffic_count), "total_alerts": int(alert_count)}


def query_all(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with _DB_LOCK, _connect() as connection:
        rows = connection.execute(sql, params).fetchall()
    return [dict(row) for row in rows]
