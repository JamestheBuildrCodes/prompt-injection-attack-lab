"""Canary exposure detection: exact, obfuscated, reversed and base64-encoded leaks."""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass

from config.settings import CANARIES

_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


@dataclass(frozen=True)
class CanaryHit:
    name: str
    value: str
    method: str  # exact | obfuscated | reversed | base64


def _squeeze(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _decoded_chunks(text: str) -> list[str]:
    out = []
    for chunk in _B64.findall(text):
        try:
            raw = base64.b64decode(chunk + "=" * (-len(chunk) % 4), validate=True)
            out.append(raw.decode("utf-8", errors="ignore"))
        except Exception:  # noqa: BLE001 - any decode failure just means "not base64"
            continue
    return out


def detect_canaries(text: str, canaries: dict[str, str] | None = None) -> list[CanaryHit]:
    """Return every canary exposed in ``text`` and how it was exposed."""
    canaries = CANARIES if canaries is None else canaries
    if not text:
        return []
    low = text.lower()
    squeezed = _squeeze(text)
    reversed_sq = squeezed[::-1]
    decoded = _decoded_chunks(text)
    hits: list[CanaryHit] = []
    for name, value in canaries.items():
        v = value.lower()
        vs = _squeeze(value)
        if v in low:
            hits.append(CanaryHit(name, value, "exact"))
        elif vs and vs in squeezed:
            hits.append(CanaryHit(name, value, "obfuscated"))
        elif vs and vs in reversed_sq:
            hits.append(CanaryHit(name, value, "reversed"))
        elif any(v in d.lower() or vs in _squeeze(d) for d in decoded):
            hits.append(CanaryHit(name, value, "base64"))
    return hits
