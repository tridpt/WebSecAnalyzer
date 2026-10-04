"""SQLite storage for scan history.

Stores the full serialized report as JSON plus a few indexed columns for the
history list. No external dependencies - uses the stdlib sqlite3 module.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .report import to_dict
from .scanner import ScanReport
from .targets import InvalidTarget
from .waivers import MAX_WAIVERS, Waiver

DEFAULT_DB = Path(__file__).resolve().parent.parent / "history.db"


@dataclass
class HistoryEntry:
    id: int
    url: str
    final_url: str
    overall_score: int
    created_at: str


@contextmanager
def _connect(db_path: Path) -> Iterator[sqlite3.Connection]:
    """Open a connection, ensure schema, commit on success, always close."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                url           TEXT NOT NULL,
                final_url     TEXT NOT NULL,
                overall_score INTEGER NOT NULL,
                created_at    TEXT NOT NULL,
                report_json   TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS waivers (
                fingerprint TEXT PRIMARY KEY,
                target_url  TEXT NOT NULL,
                surface     TEXT NOT NULL,
                url         TEXT NOT NULL,
                category    TEXT NOT NULL,
                check_id    TEXT NOT NULL,
                title       TEXT NOT NULL,
                reason      TEXT NOT NULL,
                expires_on  TEXT NOT NULL,
                created_at  TEXT NOT NULL
            )
            """
        )
        yield conn
        conn.commit()
    finally:
        conn.close()


def save_report(report: ScanReport, db_path: Path = DEFAULT_DB) -> int:
    """Persist a report and return its new row id."""
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    payload = json.dumps(to_dict(report), ensure_ascii=False)
    with _connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO scans (url, final_url, overall_score, created_at, "
            "report_json) VALUES (?, ?, ?, ?, ?)",
            (report.url, report.final_url, report.overall_score, created_at, payload),
        )
        return int(cur.lastrowid)


def list_history(
    limit: int = 100, db_path: Path = DEFAULT_DB
) -> list[HistoryEntry]:
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT id, url, final_url, overall_score, created_at "
            "FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [HistoryEntry(**dict(r)) for r in rows]


def get_report(scan_id: int, db_path: Path = DEFAULT_DB) -> ScanReport | None:
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT report_json FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    if row is None:
        return None
    return ScanReport.from_dict(json.loads(row["report_json"]))


def score_trend(
    url: str, limit: int = 30, db_path: Path = DEFAULT_DB
) -> list[tuple[str, int]]:
    """Return (created_at, score) points for a URL, oldest first."""
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT created_at, overall_score FROM scans WHERE url = ? "
            "ORDER BY id DESC LIMIT ?",
            (url, limit),
        ).fetchall()
    return [(r["created_at"], r["overall_score"]) for r in reversed(rows)]


def previous_scan_id(url: str, scan_id: int, db_path: Path = DEFAULT_DB) -> int | None:
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT id FROM scans WHERE url = ? AND id < ? ORDER BY id DESC LIMIT 1",
            (url, scan_id),
        ).fetchone()
    return int(row["id"]) if row else None


def save_waiver(waiver: Waiver, db_path: Path = DEFAULT_DB) -> None:
    with _connect(db_path) as conn:
        existing = conn.execute(
            "SELECT 1 FROM waivers WHERE fingerprint = ?", (waiver.fingerprint,)
        ).fetchone()
        if existing is None:
            count = conn.execute("SELECT COUNT(*) FROM waivers").fetchone()[0]
            if count >= MAX_WAIVERS:
                raise InvalidTarget("Đã đạt giới hạn 1000 ngoại lệ.")
        conn.execute(
            """INSERT INTO waivers
               (fingerprint, target_url, surface, url, category, check_id,
                title, reason, expires_on, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(fingerprint) DO UPDATE SET
                   reason = excluded.reason, expires_on = excluded.expires_on""",
            (
                waiver.fingerprint, waiver.target_url, waiver.surface, waiver.url,
                waiver.category, waiver.check, waiver.title, waiver.reason,
                waiver.expires_on, waiver.created_at,
            ),
        )


def delete_waiver(fingerprint: str, db_path: Path = DEFAULT_DB) -> None:
    with _connect(db_path) as conn:
        conn.execute("DELETE FROM waivers WHERE fingerprint = ?", (fingerprint,))


def list_waivers(db_path: Path = DEFAULT_DB) -> list[Waiver]:
    with _connect(db_path) as conn:
        rows = conn.execute(
            """SELECT fingerprint, target_url, surface, url, category,
                      check_id AS 'check', title, reason, expires_on, created_at
               FROM waivers ORDER BY expires_on, created_at"""
        ).fetchall()
    return [Waiver.from_dict(dict(row)) for row in rows]
