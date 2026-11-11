import pytest

from attacks.library import ATTACKS, CATEGORIES, get_case, get_cases
from config.settings import DEFAULT_SYSTEM_PROMPT as SP
from database.db import Database
from engine.clients import ExternalTargetConfig, MockClient, OpenAICompatibleClient, UnauthorizedTargetError
from engine.runner import AssessmentRunner, run_case
from mock_target.target import MockTarget


def test_library_integrity():
    ids = [a.id for a in ATTACKS]
    assert len(ids) == len(set(ids))
    markers = [a.success_marker for a in ATTACKS if a.success_marker]
    assert len(markers) == len(set(markers))
    assert {a.category for a in ATTACKS} == set(CATEGORIES)
    for a in ATTACKS:
        assert a.prompt and a.recommendation and a.severity in {"low", "medium", "high", "critical"}
        if not a.is_control:
            assert a.success_marker or a.targets_canary, f"{a.id} has no success criterion"


def test_every_attack_category_has_cases():
    for cat in CATEGORIES:
        assert get_cases([cat]), cat


@pytest.mark.parametrize("defense", ["vulnerable", "basic", "hardened"])
def test_every_attack_module_executes(defense):
    client = MockClient(defense)
    for case in ATTACKS:
        r = run_case(client, case, SP)
        assert r["status"] in {"confirmed", "suspected", "inconclusive", "resisted"}
        assert r["response"] and r["error"] is None


def test_mock_is_deterministic():
    a, b = MockTarget("basic"), MockTarget("basic")
    for case in ATTACKS:
        assert a.respond(case.prompt, case.document, SP) == b.respond(case.prompt, case.document, SP)


def test_defense_levels_are_ordered():
    def asr(d):
        runner = AssessmentRunner(MockClient(d), SP)
        return runner.run(get_cases(include_controls=False), d)["score"]["attack_success_rate"]
    v, b, h = asr("vulnerable"), asr("basic"), asr("hardened")
    assert v > b > h
    assert v == 1.0 and h == 0.0


def test_vulnerable_target_leaks_canaries_and_hardened_does_not():
    case = get_case("SP-01")
    assert run_case(MockClient("vulnerable"), case, SP)["canary_hits"]
    assert not run_case(MockClient("hardened"), case, SP)["canary_hits"]


def test_indirect_injection_basic_vs_hardened():
    case = get_case("IN-01")
    assert run_case(MockClient("basic"), case, SP)["status"] == "confirmed"
    hard = run_case(MockClient("hardened"), case, SP)
    assert hard["status"] == "resisted" and "INJ_IN01" not in hard["response"]


def test_obfuscated_attacks_beat_keyword_filter_only():
    assert run_case(MockClient("basic"), get_case("DO-01"), SP)["status"] == "resisted"
    assert run_case(MockClient("basic"), get_case("DO-04"), SP)["status"] == "confirmed"
    assert run_case(MockClient("basic"), get_case("DO-05"), SP)["status"] == "confirmed"


def test_unknown_defense_rejected():
    with pytest.raises(ValueError):
        MockClient("nonsense")


def test_runner_persists_and_scores(tmp_path):
    db = Database(tmp_path / "t.db")
    out = AssessmentRunner(MockClient("basic"), SP, db).run(get_cases(), "persisted")
    assert out["assessment_id"] and len(db.get_results(out["assessment_id"])) == len(ATTACKS)
    assert db.get_assessment(out["assessment_id"])["score"]["overall_score"] == out["score"]["overall_score"]


def test_runner_requires_cases():
    with pytest.raises(ValueError):
        AssessmentRunner(MockClient("basic"), SP).run([], "empty")


def test_failing_client_does_not_abort_assessment():
    class Boom(MockClient):
        def send(self, *a, **k):
            raise RuntimeError("down")
    out = AssessmentRunner(Boom("basic"), SP).run(get_cases(["direct_override"], include_controls=False), "boom")
    assert all(r["status"] == "inconclusive" and r["error"] for r in out["results"])


# ---------------------------------------------------------- external authorization gate
def test_external_target_requires_authorization():
    cfg = ExternalTargetConfig("https://api.example.com/v1", "m", "k", authorized=False)
    with pytest.raises(UnauthorizedTargetError):
        OpenAICompatibleClient(cfg)


def test_external_target_requires_host_confirmation():
    cfg = ExternalTargetConfig("https://api.example.com/v1", "m", "k", authorized=True, confirm_host="other.com")
    with pytest.raises(UnauthorizedTargetError):
        cfg.validate()


@pytest.mark.parametrize("url", ["http://api.example.com/v1", "ftp://x.com", "not a url", "https://169.254.169.254/v1"])
def test_external_target_rejects_unsafe_urls(url):
    host = url.split("//")[-1].split("/")[0]
    cfg = ExternalTargetConfig(url, "m", "k", authorized=True, confirm_host=host)
    with pytest.raises(UnauthorizedTargetError):
        cfg.validate()


def test_localhost_http_allowed_and_key_never_exposed():
    cfg = ExternalTargetConfig("http://localhost:8000/v1", "m", "SECRET-KEY-123", authorized=True, confirm_host="localhost")
    client = OpenAICompatibleClient(cfg)
    assert "SECRET-KEY-123" not in str(client.describe())
    assert "SECRET-KEY-123" not in repr(cfg)


def test_external_client_parses_response_and_handles_errors(monkeypatch):
    class Resp:
        def __init__(self, code, payload=None):
            self.status_code, self._p = code, payload
        def json(self):
            return self._p
    cfg = ExternalTargetConfig("https://api.example.com/v1", "m", "k", authorized=True, confirm_host="api.example.com")
    client = OpenAICompatibleClient(cfg)
    import engine.clients as ec
    monkeypatch.setattr(ec.requests, "post", lambda *a, **k: Resp(200, {"choices": [{"message": {"content": "hello"}}]}))
    assert client.send(SP, "hi").text == "hello"
    monkeypatch.setattr(ec.requests, "post", lambda *a, **k: Resp(401))
    assert "Authentication failed" in client.send(SP, "hi").error
    monkeypatch.setattr(ec.requests, "post", lambda *a, **k: Resp(200, {"unexpected": 1}))
    assert "Unexpected response" in client.send(SP, "hi").error
