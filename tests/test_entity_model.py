"""
Unit tests for entity_model: status resolution, atomic persistence, and the
CVE/actor upsert lifecycle. File paths are redirected to a tmp dir so tests
never touch the real vulnerabilities.json / actors.json.
"""
import json
import pytest

import entity_model as em


@pytest.fixture(autouse=True)
def redirect_files(tmp_path, monkeypatch):
    """Point the module's data files at a throwaway temp directory."""
    monkeypatch.setattr(em, "VULN_FILE", str(tmp_path / "vulnerabilities.json"))
    monkeypatch.setattr(em, "ACTOR_FILE", str(tmp_path / "actors.json"))
    yield


# ── load/save atomic round-trip ───────────────────────────────────
def test_save_and_load_round_trip(tmp_path):
    p = str(tmp_path / "data.json")
    em.save_json_safe(p, {"k": [1, 2, 3]})
    assert em.load_json_safe(p) == {"k": [1, 2, 3]}

def test_load_missing_returns_empty(tmp_path):
    assert em.load_json_safe(str(tmp_path / "nope.json")) == {}

def test_load_corrupt_returns_empty(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not valid json")
    assert em.load_json_safe(str(p)) == {}

def test_save_leaves_no_temp_files(tmp_path):
    p = str(tmp_path / "data.json")
    em.save_json_safe(p, {"x": 1})
    assert list(tmp_path.glob(".tmp_*")) == []


# ── resolve_status ────────────────────────────────────────────────
def test_resolve_status_kev_flip_forces_exploited():
    assert em.resolve_status("disclosed", "title", kev_flag=True, was_kev_before=False) == "actively_exploited"

def test_resolve_status_trusts_valid_groq_value():
    assert em.resolve_status("patched", "title", kev_flag=False, was_kev_before=False) == "patched"

def test_resolve_status_regex_patch_fallback():
    assert em.resolve_status("", "Vendor releases patch for flaw", False, False) == "patched"

def test_resolve_status_regex_exploit_fallback():
    assert em.resolve_status("garbage", "Zero-day exploited in the wild", False, False) == "actively_exploited"

def test_resolve_status_defaults_to_disclosed():
    assert em.resolve_status("", "A new vulnerability was found", False, False) == "disclosed"


# ── upsert_vulnerability lifecycle ────────────────────────────────
def test_upsert_vulnerability_creates_new():
    res = em.upsert_vulnerability(
        cve="CVE-2026-4020", title="Disclosed flaw", cvss=7.5,
        kev_flag=False, epss_score=0.03, source_url="https://x/1",
        vuln_status="disclosed", product="WidgetServer",
    )
    assert res["_is_new"] is True
    assert res["_status_changed"] is True
    assert len(res["status_timeline"]) == 1
    stored = em.load_json_safe(em.VULN_FILE)
    assert "CVE-2026-4020" in stored
    # transient flags must never be persisted to disk
    assert "_is_new" not in stored["CVE-2026-4020"]

def test_upsert_vulnerability_status_change_detection():
    em.upsert_vulnerability("CVE-2026-1", "Disclosed", 5.0, False, 0.01,
                            "https://x/1", vuln_status="disclosed")
    same = em.upsert_vulnerability("CVE-2026-1", "Still disclosed", 5.0, False, 0.01,
                                   "https://x/2", vuln_status="disclosed")
    assert same["_is_new"] is False
    assert same["_status_changed"] is False

    escalated = em.upsert_vulnerability("CVE-2026-1", "Now exploited", 5.0, True, 0.5,
                                        "https://x/3", vuln_status="actively_exploited")
    assert escalated["_status_changed"] is True
    assert escalated["status_timeline"][-1]["status"] == "actively_exploited"

def test_upsert_vulnerability_empty_cve_noop():
    assert em.upsert_vulnerability("", "t", 1.0, False, None, "u") == {}


# ── cve_already_covered ───────────────────────────────────────────
def test_cve_already_covered_true_after_recent_upsert():
    em.upsert_vulnerability("CVE-2026-9", "t", 5.0, False, 0.1, "u", vuln_status="disclosed")
    assert em.cve_already_covered("CVE-2026-9", days=7) is True

def test_cve_already_covered_false_for_unknown():
    assert em.cve_already_covered("CVE-2026-0000", days=7) is False


# ── upsert_actor ──────────────────────────────────────────────────
def test_upsert_actor_creates_and_appends_campaign():
    em.upsert_actor("LockBit", "Acme Corp", "LockBit hits Acme", "https://x/1")
    res = em.upsert_actor("LockBit", "Beta Inc", "LockBit hits Beta", "https://x/2")
    assert len(res["campaigns"]) == 2
    stored = em.load_json_safe(em.ACTOR_FILE)
    assert "lockbit" in stored   # keyed lowercase

def test_upsert_actor_same_name_does_not_duplicate_alias():
    em.upsert_actor("APT-X", "t", "first", "https://x/3")
    res = em.upsert_actor("APT-X", "t", "second", "https://x/4")
    assert res["aliases"] == ["APT-X"]

def test_upsert_actor_accumulates_alias_for_same_key():
    # Same lowercase key, different surface form => alias is tracked.
    em.upsert_actor("LockBit", "t", "first", "https://x/1")
    res = em.upsert_actor("lockbit", "t", "second", "https://x/2")
    assert "LockBit" in res["aliases"] and "lockbit" in res["aliases"]

def test_upsert_actor_empty_noop():
    assert em.upsert_actor("", "t", "x", "u") == {}
