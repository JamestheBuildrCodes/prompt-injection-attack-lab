"""Run a full assessment against the mock target without the UI. Useful for CI and smoke tests.

    python scripts/run_headless.py --defense basic --export exports/
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from attacks.library import get_cases  # noqa: E402
from config.settings import DEFAULT_SYSTEM_PROMPT  # noqa: E402
from database.db import Database  # noqa: E402
from engine.clients import MockClient  # noqa: E402
from engine.runner import AssessmentRunner  # noqa: E402
from reports.exporters import build_report, report_to_json, report_to_pdf, results_to_csv  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--defense", default="basic", choices=["vulnerable", "basic", "hardened"])
    ap.add_argument("--db", default=None, help="SQLite path (default: configured DB)")
    ap.add_argument("--export", default=None, help="Directory for JSON/CSV/PDF output")
    a = ap.parse_args()
    db = Database(a.db) if a.db else Database()
    out = AssessmentRunner(MockClient(a.defense), DEFAULT_SYSTEM_PROMPT, db).run(get_cases(), f"Headless {a.defense}")
    s = out["score"]
    print(f"{a.defense}: score {s['overall_score']} ({s['grade']}), statuses {s['status_counts']}, ASR {s['attack_success_rate']:.0%}")
    if a.export:
        d = Path(a.export)
        d.mkdir(parents=True, exist_ok=True)
        rep = build_report(db.get_assessment(out["assessment_id"]), db.get_results(out["assessment_id"]))
        (d / "report.json").write_text(report_to_json(rep), encoding="utf-8")
        (d / "results.csv").write_text(results_to_csv(db.get_results(out["assessment_id"])), encoding="utf-8")
        (d / "report.pdf").write_bytes(report_to_pdf(rep))
        print(f"exported to {d}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
