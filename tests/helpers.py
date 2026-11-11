"""Shared test helpers."""
from attacks.library import AttackCase, get_case
from config.settings import CANARIES, DEFAULT_SYSTEM_PROMPT

SP = DEFAULT_SYSTEM_PROMPT


def make_case(**kw) -> AttackCase:
    base = dict(id="T-01", category="direct_override", name="Test case", description="d", prompt="p",
                severity="high", techniques=("override",), success_marker="INJ_T01")
    base.update(kw)
    return AttackCase(**base)


def fake_result(status="confirmed", severity="high", category="direct_override", **kw) -> dict:
    r = dict(case_id="X-1", category=category, name="n", severity=severity, severity_declared=severity, status=status,
             finding_type="vulnerability" if status in ("confirmed", "suspected") else "none", title="t", prompt="p",
             document=None, response="r", evidence=["e"], refused=status == "resisted", canary_hits=[], marker_found=False,
             overlap=0, confidence=0.9, rationale="because", recommendation="fix it", latency_ms=1.0, is_control=False,
             targets_canary=False, techniques=["override"], error=None, created_at="2026-01-01T00:00:00+00:00")
    r.update(kw)
    return r
