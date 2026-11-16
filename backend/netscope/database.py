from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


class DatabaseRepository:
    def __init__(self) -> None:
        self.db_path = Path(__file__).resolve().parent.parent / "data" / "netscope.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL DEFAULT (strftime('%s','now'))
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS hosts (
                    host TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )

    async def add_alert(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO alerts (payload) VALUES (?)",
                (json.dumps(payload, sort_keys=True),),
            )
        return payload

    async def list_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM alerts ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    async def upsert_host(self, host: str, data: dict[str, Any]) -> dict[str, Any]:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO hosts (host, payload) VALUES (?, ?) ON CONFLICT(host) DO UPDATE SET payload = excluded.payload",
                (host, json.dumps(data, sort_keys=True)),
            )
        return data

    async def list_hosts(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT host, payload FROM hosts ORDER BY host ASC"
            ).fetchall()
        records = []
        for row in rows:
            content = json.loads(row["payload"])
            records.append({"host": row["host"], **content})
        return records

    async def save_settings(self, values: dict[str, Any]) -> dict[str, Any]:
        if not values:
            return {}
        with self._connect() as connection:
            for key, value in values.items():
                connection.execute(
                    "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, json.dumps(value, sort_keys=True)),
                )
        return values

    async def clear_alerts(self) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM alerts")

    async def get_settings(self) -> dict[str, Any]:
        with self._connect() as connection:
            rows = connection.execute("SELECT key, value FROM settings").fetchall()
        settings: dict[str, Any] = {}
        for row in rows:
            try:
                settings[row["key"]] = json.loads(row["value"])
            except json.JSONDecodeError:
                settings[row["key"]] = row["value"]
        return settings
