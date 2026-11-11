"""SQLite persistence for assessments and results."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from config.settings import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL DEFAULT 'running',
    target_json TEXT NOT NULL,
    score_json TEXT,
    total_cases INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    case_id TEXT, category TEXT, name TEXT, severity TEXT, severity_declared TEXT,
    status TEXT, finding_type TEXT, title TEXT, prompt TEXT, document TEXT, response TEXT,
    evidence_json TEXT, refused INTEGER, canary_json TEXT, marker_found INTEGER, overlap INTEGER,
    confidence REAL, rationale TEXT, recommendation TEXT, latency_ms REAL, is_control INTEGER,
    targets_canary INTEGER, techniques_json TEXT, error TEXT, created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_results_assessment ON results(assessment_id);
"""

_JSON_COLS = {"evidence_json": "evidence", "canary_json": "canary_hits", "techniques_json": "techniques"}
_BOOL_COLS = ("refused", "marker_found", "is_control", "targets_canary")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: str | Path = DB_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.init()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init(self) -> None:
        with self._conn() as c:
            c.executescript(SCHEMA)

    # ---------------------------------------------------------------- writes
    def create_assessment(self, name: str, target: dict, total_cases: int) -> int:
        with self._conn() as c:
            cur = c.execute("INSERT INTO assessments(name, created_at, target_json, total_cases) VALUES (?,?,?,?)",
                            (name.strip() or "Untitled assessment", _now(), json.dumps(target), total_cases))
            return int(cur.lastrowid)

    def add_result(self, assessment_id: int, r: dict) -> int:
        with self._conn() as c:
            cur = c.execute(
                """INSERT INTO results(assessment_id, case_id, category, name, severity, severity_declared, status,
                   finding_type, title, prompt, document, response, evidence_json, refused, canary_json, marker_found,
                   overlap, confidence, rationale, recommendation, latency_ms, is_control, targets_canary,
                   techniques_json, error, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (assessment_id, r["case_id"], r["category"], r["name"], r["severity"], r.get("severity_declared", r["severity"]),
                 r["status"], r.get("finding_type", "none"), r.get("title", ""), r.get("prompt", ""), r.get("document"),
                 r.get("response", ""), json.dumps(r.get("evidence", [])), int(bool(r.get("refused"))),
                 json.dumps(r.get("canary_hits", [])), int(bool(r.get("marker_found"))), int(r.get("overlap", 0)),
                 float(r.get("confidence", 0.0)), r.get("rationale", ""), r.get("recommendation", ""),
                 float(r.get("latency_ms", 0.0)), int(bool(r.get("is_control"))), int(bool(r.get("targets_canary"))),
                 json.dumps(r.get("techniques", [])), r.get("error"), r.get("created_at") or _now()))
            return int(cur.lastrowid)

    def finish_assessment(self, assessment_id: int, score: dict) -> None:
        with self._conn() as c:
            c.execute("UPDATE assessments SET finished_at=?, status='complete', score_json=? WHERE id=?",
                      (_now(), json.dumps(score), assessment_id))

    def delete_assessment(self, assessment_id: int) -> bool:
        with self._conn() as c:
            return c.execute("DELETE FROM assessments WHERE id=?", (assessment_id,)).rowcount > 0

    def delete_all(self) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM results")
            c.execute("DELETE FROM assessments")

    # ----------------------------------------------------------------- reads
    @staticmethod
    def _assessment(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["target"] = json.loads(d.pop("target_json") or "{}")
        d["score"] = json.loads(d.pop("score_json")) if d.get("score_json") else None
        return d

    def list_assessments(self) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM assessments ORDER BY id DESC").fetchall()
        return [self._assessment(r) for r in rows]

    def get_assessment(self, assessment_id: int) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM assessments WHERE id=?", (assessment_id,)).fetchone()
        return self._assessment(row) if row else None

    def get_results(self, assessment_id: int) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM results WHERE assessment_id=? ORDER BY id", (assessment_id,)).fetchall()
        out = []
        for row in rows:
            d = dict(row)
            for col, key in _JSON_COLS.items():
                d[key] = json.loads(d.pop(col) or "[]")
            for b in _BOOL_COLS:
                d[b] = bool(d[b])
            out.append(d)
        return out

    def all_results(self) -> list[dict]:
        """Every result joined with its assessment id/name/date, for analytics."""
        out = []
        for a in self.list_assessments():
            for r in self.get_results(a["id"]):
                r["assessment_name"], r["assessment_date"] = a["name"], a["created_at"]
                r["defense"] = a["target"].get("defense") or a["target"].get("model", "external")
                out.append(r)
        return out
