"""Assessment runner: executes cases against a client, evaluates, scores and stores results."""
from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone
from typing import Callable

from attacks.library import AttackCase
from config.settings import CANARIES, DEFAULT_SYSTEM_PROMPT
from database.db import Database
from detectors.evaluate import evaluate
from engine.clients import BaseClient
from engine.scoring import compute_score

ProgressFn = Callable[[int, int, dict], None]


def describe_target(client: BaseClient, system_prompt: str) -> dict:
    info = dict(client.describe())
    info["system_prompt_sha256"] = hashlib.sha256(system_prompt.encode()).hexdigest()[:16]
    info["system_prompt_chars"] = len(system_prompt)
    info["canaries"] = sorted(CANARIES)
    return info


def run_case(client: BaseClient, case: AttackCase, system_prompt: str) -> dict:
    """Execute a single case and return a flat, serialisable result dict."""
    try:
        resp = client.send(system_prompt, case.prompt, case.document)
        text, latency, error = resp.text, resp.latency_ms, resp.error
    except Exception as exc:  # noqa: BLE001 - one failing case must never abort the assessment
        text, latency, error = "", 0.0, f"client error: {type(exc).__name__}: {exc}"
    ev = evaluate(case, text, system_prompt, error)
    return {
        "case_id": case.id,
        "category": case.category,
        "name": case.name,
        "severity": ev.severity,
        "severity_declared": case.severity,
        "status": ev.status,
        "finding_type": ev.finding_type,
        "title": ev.title,
        "prompt": case.prompt,
        "document": case.document,
        "response": text,
        "evidence": ev.evidence,
        "refused": ev.refused,
        "canary_hits": ev.canary_hits,
        "marker_found": ev.marker_found,
        "overlap": ev.overlap,
        "confidence": ev.confidence,
        "rationale": ev.rationale,
        "recommendation": case.recommendation if ev.status in ("confirmed", "suspected", "inconclusive") else "",
        "latency_ms": round(latency, 1),
        "is_control": case.is_control,
        "targets_canary": case.targets_canary,
        "techniques": list(case.techniques),
        "error": error,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


class AssessmentRunner:
    def __init__(self, client: BaseClient, system_prompt: str = DEFAULT_SYSTEM_PROMPT,
                 database: Database | None = None, delay_s: float = 0.0, progress: ProgressFn | None = None):
        self.client, self.system_prompt = client, system_prompt
        self.db, self.delay_s, self.progress = database, delay_s, progress

    def run(self, cases: list[AttackCase], name: str = "Assessment") -> dict:
        if not cases:
            raise ValueError("Select at least one test case.")
        target = describe_target(self.client, self.system_prompt)
        aid = self.db.create_assessment(name, target, len(cases)) if self.db else None
        results: list[dict] = []
        for i, case in enumerate(cases, 1):
            res = run_case(self.client, case, self.system_prompt)
            results.append(res)
            if self.db and aid is not None:
                self.db.add_result(aid, res)
            if self.progress:
                self.progress(i, len(cases), res)
            if self.delay_s and self.client.kind == "external" and i < len(cases):
                time.sleep(self.delay_s)
        score = compute_score(results)
        if self.db and aid is not None:
            self.db.finish_assessment(aid, score)
        return {"assessment_id": aid, "name": name, "target": target, "results": results, "score": score}
