import sqlite3

import pytest

from database.db import Database
from tests.helpers import fake_result as fr


def test_create_and_read_assessment(tmp_path):
    db = Database(tmp_path / "a.db")
    aid = db.create_assessment("My run", {"type": "mock", "defense": "basic"}, 3)
    a = db.get_assessment(aid)
    assert a["name"] == "My run" and a["target"]["defense"] == "basic" and a["status"] == "running" and a["score"] is None


def test_results_round_trip_with_json_and_bools(tmp_path):
    db = Database(tmp_path / "a.db")
    aid = db.create_assessment("r", {}, 1)
    db.add_result(aid, fr("confirmed", canary_hits=[{"name": "api_key", "value": "v", "method": "exact"}],
                          evidence=["x", "y"], refused=False, targets_canary=True))
    r = db.get_results(aid)[0]
    assert r["canary_hits"][0]["name"] == "api_key" and r["evidence"] == ["x", "y"]
    assert r["refused"] is False and r["targets_canary"] is True and r["status"] == "confirmed"


def test_finish_assessment_stores_score(tmp_path):
    db = Database(tmp_path / "a.db")
    aid = db.create_assessment("r", {}, 1)
    db.finish_assessment(aid, {"overall_score": 42.0})
    a = db.get_assessment(aid)
    assert a["status"] == "complete" and a["score"]["overall_score"] == 42.0 and a["finished_at"]


def test_list_orders_newest_first_and_blank_name_defaulted(tmp_path):
    db = Database(tmp_path / "a.db")
    first = db.create_assessment("one", {}, 0)
    second = db.create_assessment("  ", {}, 0)
    ids = [a["id"] for a in db.list_assessments()]
    assert ids == [second, first] and db.get_assessment(second)["name"] == "Untitled assessment"


def test_delete_cascades_to_results(tmp_path):
    db = Database(tmp_path / "a.db")
    aid = db.create_assessment("r", {}, 1)
    db.add_result(aid, fr())
    assert db.delete_assessment(aid) is True and db.get_results(aid) == [] and db.get_assessment(aid) is None
    assert db.delete_assessment(aid) is False


def test_delete_all_and_all_results(tmp_path):
    db = Database(tmp_path / "a.db")
    for n in ("a", "b"):
        aid = db.create_assessment(n, {"defense": "basic"}, 1)
        db.add_result(aid, fr())
    rows = db.all_results()
    assert len(rows) == 2 and rows[0]["defense"] == "basic" and "assessment_name" in rows[0]
    db.delete_all()
    assert db.list_assessments() == [] and db.all_results() == []


def test_missing_assessment_returns_none(tmp_path):
    assert Database(tmp_path / "a.db").get_assessment(999) is None


def test_foreign_key_enforced(tmp_path):
    db = Database(tmp_path / "a.db")
    with pytest.raises(sqlite3.IntegrityError):
        db.add_result(12345, fr())


def test_creates_parent_directory(tmp_path):
    db = Database(tmp_path / "nested" / "dir" / "a.db")
    assert db.path.exists()
