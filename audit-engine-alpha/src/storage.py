"""SQLite persistence for policy violations and anomaly reports."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from models import AnomalyReportRecord, PolicyViolationRecord


class AuditStorage:
    """Thin sqlite3 wrapper used by the middleware."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        parent = Path(db_path).expanduser().resolve().parent
        parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS policy_violations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time TEXT NOT NULL,
                event_name TEXT NOT NULL,
                user_name TEXT NOT NULL,
                policy_path TEXT NOT NULL,
                message TEXT NOT NULL,
                latency_ms REAL NOT NULL,
                raw_event_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_policy_violations_event_time
                ON policy_violations(event_time);
            CREATE INDEX IF NOT EXISTS idx_policy_violations_user_name
                ON policy_violations(user_name);

            CREATE TABLE IF NOT EXISTS anomaly_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                window_size INTEGER NOT NULL,
                is_anomalous INTEGER NOT NULL,
                risk_score REAL NOT NULL,
                anomaly_type TEXT NOT NULL,
                incident_summary TEXT NOT NULL,
                fallback_used INTEGER NOT NULL,
                window_event_names TEXT NOT NULL,
                window_user_names TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_anomaly_reports_created_at
                ON anomaly_reports(created_at);
            CREATE INDEX IF NOT EXISTS idx_anomaly_reports_is_anomalous
                ON anomaly_reports(is_anomalous);
            """
        )
        self._conn.commit()

    def record_violation(self, record: PolicyViolationRecord) -> int:
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO policy_violations (
                event_time, event_name, user_name, policy_path,
                message, latency_ms, raw_event_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.event_time,
                record.event_name,
                record.user_name,
                record.policy_path,
                record.message,
                record.latency_ms,
                record.raw_event_json,
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def record_anomaly_report(self, record: AnomalyReportRecord) -> int:
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO anomaly_reports (
                created_at, window_size, is_anomalous, risk_score,
                anomaly_type, incident_summary, fallback_used,
                window_event_names, window_user_names
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.created_at,
                record.window_size,
                1 if record.is_anomalous else 0,
                record.risk_score,
                record.anomaly_type,
                record.incident_summary,
                1 if record.fallback_used else 0,
                record.window_event_names,
                record.window_user_names,
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def get_recent_summary(self, limit: int = 20) -> dict[str, Any]:
        cur = self._conn.cursor()
        violation_count = cur.execute(
            "SELECT COUNT(*) FROM policy_violations"
        ).fetchone()[0]
        anomaly_count = cur.execute(
            "SELECT COUNT(*) FROM anomaly_reports"
        ).fetchone()[0]
        anomalous_count = cur.execute(
            "SELECT COUNT(*) FROM anomaly_reports WHERE is_anomalous = 1"
        ).fetchone()[0]
        recent_violations = [
            dict(row)
            for row in cur.execute(
                """
                SELECT id, event_time, event_name, user_name, policy_path, message, latency_ms
                FROM policy_violations
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        ]
        recent_anomalies = [
            dict(row)
            for row in cur.execute(
                """
                SELECT id, created_at, is_anomalous, risk_score, anomaly_type,
                       incident_summary, fallback_used
                FROM anomaly_reports
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        ]
        return {
            "violation_count": int(violation_count),
            "anomaly_report_count": int(anomaly_count),
            "anomalous_count": int(anomalous_count),
            "recent_violations": recent_violations,
            "recent_anomalies": recent_anomalies,
        }

    def close(self) -> None:
        self._conn.close()
