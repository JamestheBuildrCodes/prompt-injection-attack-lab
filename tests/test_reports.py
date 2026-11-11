import csv
import io
import json

from attacks.library import get_cases
from config.settings import DEFAULT_SYSTEM_PROMPT as SP
from database.db import Database
from engine.clients import MockClient
from engine.runner import AssessmentRunner
from reports.exporters import build_report, report_to_json, report_to_pdf, results_to_csv
from tests.helpers import fake_result as fr


def _run(tmp_path, defense="basic"):
    db = Database(tmp_path / "r.db")
    out = AssessmentRunner(MockClient(defense), SP, db).run(get_cases(), f"{defense} run")
    return db.get_assessment(out["assessment_id"]), db.get_results(out["assessment_id"])


def test_report_has_required_sections(tmp_path):
    a, rs = _run(tmp_path)
    rep = build_report(a, rs)
    for key in ("report", "assessment", "target_configuration", "summary", "findings", "test_cases", "recommendations", "disclaimer"):
        assert key in rep
    assert rep["assessment"]["test_date"] and rep["target_configuration"]["defense"] == "basic"
    f = rep["findings"][0]
    assert f["status"] == "confirmed" and f["evidence"] and f["recommendation"] and f["severity"]
    assert len(rep["test_cases"]) == len(rs) and rep["recommendations"]


def test_findings_sorted_by_status_then_severity(tmp_path):
    a, rs = _run(tmp_path)
    order = {"confirmed": 3, "suspected": 2, "inconclusive": 1}
    f = build_report(a, rs)["findings"]
    assert [order[x["status"]] for x in f] == sorted([order[x["status"]] for x in f], reverse=True)


def test_json_round_trips(tmp_path):
    a, rs = _run(tmp_path)
    rep = build_report(a, rs)
    assert json.loads(report_to_json(rep))["summary"]["overall_score"] == rep["summary"]["overall_score"]


def test_csv_has_all_rows_and_columns(tmp_path):
    a, rs = _run(tmp_path)
    rows = list(csv.DictReader(io.StringIO(results_to_csv(rs))))
    assert len(rows) == len(rs) and {"case_id", "status", "severity", "evidence", "recommendation"} <= set(rows[0])


def test_csv_neutralises_formula_injection():
    r = fr(response="=HYPERLINK(\"http://evil\",\"x\")", title="+cmd|' /C calc'!A0", evidence=["@SUM(1+1)"])
    row = next(csv.DictReader(io.StringIO(results_to_csv([r]))))
    assert row["response"].startswith("'=") and row["title"].startswith("'+") and row["evidence"].startswith("'@")


def test_pdf_is_valid_and_survives_hostile_text(tmp_path):
    a, rs = _run(tmp_path)
    rs[0]["response"] = "<b>unclosed <script>alert(1)</script> & \x00 \u202e \u4e2d\u6587 " * 20
    rs[0]["evidence"] = ["<para>broken</para>"]
    pdf = report_to_pdf(build_report(a, rs))
    assert pdf.startswith(b"%PDF") and len(pdf) > 2000


def test_pdf_for_clean_assessment(tmp_path):
    a, rs = _run(tmp_path, "hardened")
    assert report_to_pdf(build_report(a, rs)).startswith(b"%PDF")


def test_reports_never_contain_secrets(tmp_path):
    secret = "sk-SUPERSECRET-123"
    a, rs = _run(tmp_path)
    a["target"]["api_key"] = secret  # even if one leaked into the target dict
    rep = build_report(a, rs)
    assert secret not in report_to_json(rep) and secret not in results_to_csv(rs)
