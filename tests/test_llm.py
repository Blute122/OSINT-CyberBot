"""
Tests for the LLM extraction layer (schema validation + retry/backoff + fallback).

The network call (_call_groq) is injected via monkeypatch so these run offline
and deterministically. time.sleep is stubbed so backoff doesn't slow the suite.
"""
import json
import pytest

import cyber_agent as ca
from cyber_agent import ExtractionResult


VALID = {
    "skip": False, "severity_icon": "🔴", "cve": "CVE-2026-4020",
    "threat_actor": "LockBit", "target": "AcmeOS",
    "tweet": "🔴 Critical breach at AcmeOS via Source #infosec",
    "card_context": "ctx", "card_impact": "impact", "simply_put": "plain",
}


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(ca.time, "sleep", lambda *_: None)


# ── schema validation ─────────────────────────────────────────────
def test_parse_and_validate_valid():
    r = ca._parse_and_validate(json.dumps(VALID))
    assert isinstance(r, ExtractionResult)
    assert r.cve == "CVE-2026-4020" and r.skip is False

def test_parse_and_validate_fills_defaults():
    r = ca._parse_and_validate('{"tweet": "hi"}')
    assert r.severity_icon == "🟡"      # default
    assert r.cve == "" and r.skip is False

def test_parse_and_validate_raises_on_bad_json():
    with pytest.raises(json.JSONDecodeError):
        ca._parse_and_validate("{not valid")

def test_parse_and_validate_raises_on_wrong_type():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        ca._parse_and_validate('{"skip": "definitely-not-a-bool"}')


# ── generate_content happy paths ──────────────────────────────────
def _stub_call(monkeypatch, side_effect):
    """side_effect: callable(model, prompt) -> raw str (or raises)."""
    monkeypatch.setattr(ca, "_call_groq", side_effect)

def test_generate_content_success(monkeypatch):
    _stub_call(monkeypatch, lambda m, p: json.dumps(VALID))
    data = ca.generate_content("t", "s", "Source")
    assert data["cve"] == "CVE-2026-4020"
    assert data["tweet"].startswith("🔴")
    assert data["severity_icon"] == "🔴"

def test_generate_content_skip_returns_none(monkeypatch):
    _stub_call(monkeypatch, lambda m, p: '{"skip": true}')
    assert ca.generate_content("t", "s", "Source") is None

def test_generate_content_rejects_invalid_cve(monkeypatch):
    bad = dict(VALID, cve="CVE-XXXX-XXXX")
    _stub_call(monkeypatch, lambda m, p: json.dumps(bad))
    data = ca.generate_content("t", "s", "Source")
    assert data["cve"] == ""        # placeholder rejected

def test_generate_content_normalizes_null_fields(monkeypatch):
    nulls = dict(VALID, threat_actor=None, target=None, simply_put=None)
    _stub_call(monkeypatch, lambda m, p: json.dumps(nulls))
    data = ca.generate_content("t", "s", "Source")
    assert data["threat_actor"] == "" and data["simply_put"] == ""


# ── retry / fallback behavior ─────────────────────────────────────
def test_retries_then_succeeds(monkeypatch):
    calls = {"n": 0}
    def flaky(model, prompt):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient 503")
        return json.dumps(VALID)
    _stub_call(monkeypatch, flaky)
    data = ca.generate_content("t", "s", "Source")
    assert data["cve"] == "CVE-2026-4020"
    assert calls["n"] == 2           # failed once, retried, succeeded

def test_falls_back_to_second_model(monkeypatch):
    monkeypatch.setattr(ca, "GROQ_MODELS", ["m1", "m2"])
    monkeypatch.setattr(ca, "GROQ_MAX_ATTEMPTS", 1)
    seen = []
    def by_model(model, prompt):
        seen.append(model)
        if model == "m1":
            raise RuntimeError("m1 down")
        return json.dumps(VALID)
    _stub_call(monkeypatch, by_model)
    data = ca.generate_content("t", "s", "Source")
    assert data is not None
    assert seen == ["m1", "m2"]      # tried primary, then fallback

def test_invalid_json_then_valid_on_retry(monkeypatch):
    calls = {"n": 0}
    def maybe_bad(model, prompt):
        calls["n"] += 1
        return "{garbage" if calls["n"] == 1 else json.dumps(VALID)
    _stub_call(monkeypatch, maybe_bad)
    data = ca.generate_content("t", "s", "Source")
    assert data["cve"] == "CVE-2026-4020"

def test_returns_none_when_all_attempts_fail(monkeypatch):
    monkeypatch.setattr(ca, "GROQ_MODELS", ["m1", "m2"])
    monkeypatch.setattr(ca, "GROQ_MAX_ATTEMPTS", 2)
    def always_fail(model, prompt):
        raise RuntimeError("down")
    _stub_call(monkeypatch, always_fail)
    assert ca.generate_content("t", "s", "Source") is None
