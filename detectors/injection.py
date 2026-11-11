"""Prompt-injection detection for untrusted text (user input, documents)."""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field

_VERB = r"(?:ignore|disregard|forget|override|bypass|set aside|drop)"
_DET = r"(?:all\s+|any\s+|your\s+|the\s+|my\s+)?"
_OBJ = (
    r"(?:previous|prior|earlier|above|initial|system|safety)\s+(?:instructions?|rules?|prompts?|guidelines?|polic\w+)"
    r"|(?:rules|guidelines|restrictions|safeguards|policies|instructions|safety|confidentiality)"
)

# name -> (weight, regex)
SIGNALS: dict[str, tuple[int, str]] = {
    "instruction_override": (35, rf"\b{_VERB}\s+{_DET}(?:{_OBJ})"),
    "instruction_expiry": (30, r"(?:previous|prior|earlier) instructions (?:have )?(?:expired|been (?:replaced|cancelled))|new (?:session|instructions?|task)\s*[:.]"),
    "role_manipulation": (25, r"\byou are now\b|\bfrom now on you are\b|\bpretend (?:to be|you are)\b|\bstay in character\b|\bDAN\b|\bdev(?:eloper )?mode\b|\bno (?:restrictions|rules|content policy)\b"),
    "authority_claim": (20, r"\b(?:i am|i'm|this is)\s+(?:the\s+)?(?:acme\s+)?(?:developer|admin|administrator|owner|operator)\b|\bauthori[sz]ed audit\b|\b(?:admin|system) override\b|\bmaintenance mode\b"),
    "delimiter_spoof": (25, r"\[\s*(?:system|assistant|admin)\s*\]|<\s*/?\s*(?:system|assistant|admin|user_input)\s*>|###\s*(?:new session|system|instruction)|<\|im_start\|>|BEGIN SYSTEM"),
    "prompt_extraction": (30, r"\b(?:reveal|print|show|repeat|output|leak|display|translate)\b.{0,40}(?:system prompt|initial instructions|developer instructions|your instructions|everything above|configuration)"),
    "secret_request": (20, r"\b(?:api keys?|credentials?|passwords?|secrets?|discount code|internal host)\b"),
    "refusal_suppression": (20, r"\bdo not (?:apologi[sz]e|refuse)\b|\bnever refuse\b|\bwithout (?:refusing|warnings?)\b|\bnever say you can['\u2019]?t\b"),
    "priority_claim": (15, r"\b(?:highest|higher) priority\b|\btakes? precedence\b|\bmost recent instruction\b|\bfollow the (?:latest|most recent)\b"),
    "exfiltration_url": (30, r"!\[[^\]]*\]\(https?://[^)]+\)|https?://\S+[?&]\w+="),
    "hidden_content": (15, r"<!--.*?-->|[\u200b-\u200f\u2060\ufeff]"),
    "addressed_to_ai": (15, r"\b(?:note|message|instructions?)\s+(?:to|for)\s+(?:the\s+)?(?:ai|assistant|llm|model)\b|\battention[,:]?\s+(?:ai|assistant)\b|\bassistant:"),
    "urgency_pressure": (10, r"\burgent\b|\blives depend\b"),
    "forged_tool_call": (30, r"\[\[\s*tool\s*:|<tool_call>|\bfunction_call\b"),
    "split_payload": (20, r"\bpart a\b.{0,60}\bpart b\b|\bconcatenate (?:the )?(?:parts|strings)\b"),
    "rule_extraction": (20, r"\b(?:summari[sz]e|list|describe)\b.{0,40}\b(?:rules|guidelines|constraints) (?:you|that you) (?:must|have to|follow)"),
    "output_marker_demand": (15, r"\b(?:reply|respond|answer|output|print|say)\b[^.\n]{0,40}\bINJ_[A-Z0-9_]+"),
}
_COMPILED = {k: (w, re.compile(p, re.I | re.S)) for k, (w, p) in SIGNALS.items()}
_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


@dataclass
class Signal:
    name: str
    weight: int
    snippet: str


@dataclass
class ScanResult:
    score: int
    level: str  # none | low | medium | high
    signals: list[Signal] = field(default_factory=list)

    @property
    def is_suspicious(self) -> bool:
        return self.score >= 30

    @property
    def names(self) -> list[str]:
        return [s.name for s in self.signals]


def _decoded_views(text: str) -> list[str]:
    out = []
    for chunk in _B64.findall(text):
        try:
            dec = base64.b64decode(chunk + "=" * (-len(chunk) % 4), validate=True).decode("utf-8")
        except Exception:  # noqa: BLE001
            continue
        if dec.strip() and dec.isprintable():
            out.append(dec)
    return out


def _despaced(text: str) -> str:
    """Collapse 'i g n o r e' style letter spacing."""
    return re.sub(r"\b(?:\w\s){4,}\w\b", lambda m: m.group(0).replace(" ", ""), text)


def scan_text(text: str) -> ScanResult:
    """Score how much ``text`` looks like a prompt-injection attempt (0-100)."""
    if not text or not text.strip():
        return ScanResult(0, "none", [])
    found: dict[str, Signal] = {}
    views = [text, _despaced(text), *_decoded_views(text)]
    for i, view in enumerate(views):
        for name, (weight, rx) in _COMPILED.items():
            if name in found:
                continue
            m = rx.search(view)
            if m:
                label = name if i == 0 else f"{name}"
                snippet = m.group(0)[:80].replace("\n", " ")
                found[label] = Signal(label, weight, snippet if i == 0 else f"(decoded) {snippet}")
    if len(_decoded_views(text)) and any(n in found for n in ("instruction_override", "instruction_expiry")):
        found["encoded_payload"] = Signal("encoded_payload", 30, "base64 payload decodes to an instruction")
    score = min(100, sum(s.weight for s in found.values()))
    level = "high" if score >= 60 else "medium" if score >= 30 else "low" if score > 0 else "none"
    return ScanResult(score, level, list(found.values()))


def scan_document(text: str) -> ScanResult:
    """Alias with document semantics (documents are always untrusted)."""
    return scan_text(text)
