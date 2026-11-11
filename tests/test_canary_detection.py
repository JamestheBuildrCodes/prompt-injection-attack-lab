import base64

import pytest

from config.settings import CANARIES
from detectors.canary import detect_canaries


def test_exact_and_case_insensitive():
    hits = detect_canaries(f"the key is {CANARIES['api_key'].lower()} ok")
    assert [h.name for h in hits] == ["api_key"] and hits[0].method == "exact"


def test_multiple_canaries():
    text = f"{CANARIES['api_key']} and {CANARIES['discount_code']} and {CANARIES['internal_host']}"
    assert {h.name for h in detect_canaries(text)} == set(CANARIES)


def test_obfuscated_spaced_and_hyphen_stripped():
    spaced = " ".join(CANARIES["discount_code"])
    assert detect_canaries(spaced)[0].method == "obfuscated"


def test_reversed():
    assert detect_canaries(CANARIES["api_key"][::-1])[0].method == "reversed"


def test_base64():
    enc = base64.b64encode(CANARIES["api_key"].encode()).decode()
    hits = detect_canaries(f"data: {enc}")
    assert hits and hits[0].method == "base64"


@pytest.mark.parametrize("text", ["", "nothing secret here", "PIAL is an app", "CANARY birds sing"])
def test_no_false_positives(text):
    assert detect_canaries(text) == []


def test_custom_canaries():
    assert detect_canaries("token ZX-99", {"t": "ZX-99"})[0].name == "t"
