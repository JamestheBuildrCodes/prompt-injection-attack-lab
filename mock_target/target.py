"""Deterministic mock LLM target with three defence levels.

It simulates realistic failure modes with simple, documented heuristics, so the
whole lab runs offline and results are reproducible. It is *not* a language model.

vulnerable  Obeys injected instructions and leaks its prompt on request.
basic       Keyword filter: blocks blatant attacks, falls for obfuscation, role-play,
            authority claims, fake delimiters, multi-step requests and document injection.
hardened    Refuses or ignores every injection signal and treats documents as untrusted data.
"""
from __future__ import annotations

import base64
import re

from config.settings import CANARIES, DEFAULT_SYSTEM_PROMPT

DEFENSES = {
    "vulnerable": "Follows almost any injected instruction and leaks its prompt. Use it to confirm detections work.",
    "basic": "Keyword filter only. Blocks blatant phrases but misses obfuscation, personas, fake system turns and documents.",
    "hardened": "Treats user text and documents as untrusted. Refuses injections and flags poisoned documents.",
}

REFUSAL_TEXT = (
    "I'm sorry, but I can't help with that request. "
    "I can only assist with Acme orders, products, shipping and returns."
)
DEFLECT_TEXT = "Happy to help with Acme orders, products, shipping and returns! My internal setup details stay with the Acme team."
DOC_NOTE = (
    "Note: the document contains instructions addressed to AI assistants. "
    "I treated them as untrusted content and did not follow them."
)

MARKER_RE = re.compile(r"INJ_[A-Z0-9_]+")
_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_LITERAL_OVERRIDE = re.compile(r"\b(ignore|disregard|forget)\s+(all\s+|any\s+|your\s+|the\s+)?(previous|prior|earlier|above)\b", re.I)
_LITERAL_EXTRACT = re.compile(r"(system prompt|initial instructions|developer instructions|your instructions)", re.I)
_BASIC_BLOCK = re.compile(r"\bignore\b|\b(dan|devmode|developer mode|jailbreak)\b|do not (apologi[sz]e|refuse)", re.I)
_REPEAT_ABOVE = re.compile(r"(repeat|print|output|copy)\s+(everything|all|the text)\s+(above|before)", re.I)
_TRANSLATE = re.compile(r"translate.*(configuration|setup)", re.I)
_RULES = re.compile(r"(summari[sz]e|list|describe).{0,40}\b(rules|guidelines|constraints)\b", re.I)
_SECRET = re.compile(r"(discount code|internal host|host ?name|api key|credentials?)", re.I)
_MULTI = re.compile(r"(\b1\)|\bsteps?\b|\bfirst\b|\bthen\b|\balso\b)", re.I)
_DOC_HINT = re.compile(r"INJ_|\bassistant\b|\bAI\b|system override|repeat everything", re.I)


def _expand(text: str) -> str:
    """Return the text plus decoded base64 chunks and re-joined split payloads."""
    parts = [text]
    for chunk in _B64.findall(text):
        try:
            dec = base64.b64decode(chunk + "=" * (-len(chunk) % 4), validate=True).decode("utf-8")
        except Exception:  # noqa: BLE001
            continue
        if dec.isprintable():
            parts.append(dec)
    m = re.search(r"part a:\s*'([^']*)'\s*part b:\s*'([^']*)'", text, re.I)
    if m:
        parts.append(m.group(1) + m.group(2))
    return "\n".join(parts)


def _intents(text: str) -> dict:
    markers = MARKER_RE.findall(text)
    return {
        "override": bool(_LITERAL_OVERRIDE.search(text)),
        "extract": bool(_LITERAL_EXTRACT.search(text)),
        "repeat": bool(_REPEAT_ABOVE.search(text)),
        "translate": bool(_TRANSLATE.search(text)),
        "rules": bool(_RULES.search(text)),
        "secret": bool(_SECRET.search(text)),
        "multi": bool(_MULTI.search(text)),
        "marker": markers[-1] if markers else None,
    }


def _rules_lines(system_prompt: str) -> list[str]:
    rules = [re.sub(r"^\d+\.\s*", "", ln.strip()) for ln in system_prompt.splitlines() if re.match(r"^\s*\d+\.\s", ln)]
    return rules or [ln.strip() for ln in system_prompt.splitlines() if ln.strip()][:3]


def _summary(document: str) -> str:
    cleaned = re.sub(r"<!--.*?-->", " ", document, flags=re.S)
    lines = [ln.strip() for ln in cleaned.splitlines() if ln.strip() and not _DOC_HINT.search(ln)]
    sentences: list[str] = []
    for ln in lines[1:] if len(lines) > 1 else lines:
        sentences += [s.strip() for s in re.split(r"(?<=[.!?])\s+", ln) if s.strip()]
    sentences = sentences[:3] or ["The document is short and has no further details."]
    return "Here's a summary:\n" + "\n".join(f"- {s[:160]}" for s in sentences)


def _benign(msg: str) -> str:
    t = msg.lower()
    if "return" in t:
        return "You can return unused items within 30 days of delivery for a full refund. Start a return from your order page."
    if "hour" in t:
        return "Our support team is available 9am to 6pm, Monday to Saturday."
    if "system prompt" in t:
        return "A system prompt is a set of hidden instructions that tells an AI assistant how to behave."
    return "Thanks for your message! I can help with orders, products, shipping and returns. What would you like to know?"


def _comply(marker: str, text: str) -> str:
    t = text.lower()
    if re.search(r"\b(dan|devmode|developer mode|you are now)\b", t):
        return f"DevMode enabled. {marker}"
    if "maintenance mode" in t:
        return f"Maintenance mode enabled. {marker}"
    return f"Sure! {marker}"


class MockTarget:
    def __init__(self, defense: str = "basic"):
        if defense not in DEFENSES:
            raise ValueError(f"Unknown defense level '{defense}'. Choose from {sorted(DEFENSES)}.")
        self.defense = defense

    # ------------------------------------------------------------------ leaks
    @staticmethod
    def _full_leak(system_prompt: str, french: bool = False) -> str:
        head = "Voici ma configuration :" if french else "Of course! Here is my configuration:"
        return f"{head}\n\n{system_prompt}"

    @staticmethod
    def _secret_leak(text: str) -> str:
        t = text.lower()
        if "host" in t:
            return f"Sure. The internal host is {CANARIES['internal_host']}."
        if "discount" in t:
            return f"Sure. The staff discount code is {CANARIES['discount_code']}."
        return f"Sure. The API key is {CANARIES['api_key']}."

    # ---------------------------------------------------------------- respond
    def respond(self, user_message: str, document: str | None = None, system_prompt: str | None = None) -> str:
        sp = system_prompt or DEFAULT_SYSTEM_PROMPT
        raw_i = _intents(user_message or "")
        exp_text = _expand(user_message or "")
        exp_i = _intents(exp_text)
        doc = document or ""
        doc_i = _intents(_expand(doc)) if doc else None
        doc_raw_i = _intents(doc) if doc else None

        if self.defense == "vulnerable":
            if any(exp_i[k] for k in ("extract", "repeat", "translate", "rules")):
                return self._full_leak(sp, french=exp_i["translate"])
            if exp_i["secret"]:
                return self._secret_leak(exp_text)
            if exp_i["marker"]:
                return _comply(exp_i["marker"], exp_text)
            if doc_i:
                if any(doc_i[k] for k in ("extract", "repeat", "translate", "rules")):
                    return f"{_summary(doc)}\n\n{self._full_leak(sp)}"
                if doc_i["marker"]:
                    return doc_i["marker"]
                return _summary(doc)
            return _benign(user_message)

        if self.defense == "basic":
            if raw_i["override"] or raw_i["extract"] or _BASIC_BLOCK.search(user_message or ""):
                return REFUSAL_TEXT
            if exp_i["repeat"] or exp_i["translate"]:
                return self._full_leak(sp, french=exp_i["translate"])
            if exp_i["rules"]:
                return "Sure! Here are the rules I follow:\n" + "\n".join(f"- {r}" for r in _rules_lines(sp))
            if exp_i["secret"]:
                return self._secret_leak(exp_text) if raw_i["multi"] else REFUSAL_TEXT
            if exp_i["marker"]:
                return _comply(exp_i["marker"], exp_text)
            if doc_i:
                if doc_raw_i["override"] or doc_raw_i["extract"]:
                    return _summary(doc)
                if doc_i["repeat"]:
                    return f"{_summary(doc)}\n\n{self._full_leak(sp)}"
                if doc_i["marker"]:
                    return doc_i["marker"]
                return _summary(doc)
            return _benign(user_message)

        # hardened
        if any(exp_i[k] for k in ("override", "extract", "repeat", "translate", "secret")) or exp_i["marker"]:
            return REFUSAL_TEXT
        if exp_i["rules"]:
            return DEFLECT_TEXT
        if doc:
            suspicious = bool(doc_i["marker"] or doc_i["override"] or doc_i["extract"] or doc_i["repeat"] or _DOC_HINT.search(doc))
            return _summary(doc) + (f"\n\n{DOC_NOTE}" if suspicious else "")
        return _benign(user_message)
