"""Unit tests for the risk-prioritization scoring model."""
import scoring as s


# ── bounds & basic behavior ───────────────────────────────────────
def test_score_is_bounded_0_100():
    assert s.compute_risk_score(cvss=10, epss=1.0, kev=True, age_days=0) <= 100
    assert s.compute_risk_score(cvss=0, epss=0, kev=False, age_days=999) >= 0

def test_max_inputs_score_100():
    assert s.compute_risk_score(cvss=10, epss=1.0, kev=True, age_days=0) == 100

def test_all_zero_inputs_score_0():
    # No CVSS-known, no epss, no kev, ancient => 0
    assert s.compute_risk_score(cvss=0.0, epss=0.0, kev=False, age_days=999) == 0


# ── KEV dominance ─────────────────────────────────────────────────
def test_kev_imposes_high_floor_even_with_weak_signals():
    score = s.compute_risk_score(cvss=2.0, epss=0.01, kev=True, age_days=10)
    assert score >= s.KEV_FLOOR

def test_kev_beats_equivalent_non_kev():
    with_kev = s.compute_risk_score(cvss=7.0, epss=0.2, kev=True, age_days=0)
    without  = s.compute_risk_score(cvss=7.0, epss=0.2, kev=False, age_days=0)
    assert with_kev > without


# ── monotonicity ──────────────────────────────────────────────────
def test_higher_cvss_increases_score():
    lo = s.compute_risk_score(cvss=4.0, epss=0.1, kev=False, age_days=0)
    hi = s.compute_risk_score(cvss=9.0, epss=0.1, kev=False, age_days=0)
    assert hi > lo

def test_higher_epss_increases_score():
    lo = s.compute_risk_score(cvss=7.0, epss=0.05, kev=False, age_days=0)
    hi = s.compute_risk_score(cvss=7.0, epss=0.95, kev=False, age_days=0)
    assert hi > lo

def test_recency_decreases_with_age():
    fresh = s.compute_risk_score(cvss=7.0, epss=0.1, kev=False, age_days=0)
    stale = s.compute_risk_score(cvss=7.0, epss=0.1, kev=False, age_days=60)
    assert fresh > stale


# ── missing / malformed CVSS ──────────────────────────────────────
def test_missing_cvss_not_penalized_to_zero():
    # 'N/A' CVSS but high EPSS should still produce a meaningful score
    score = s.compute_risk_score(cvss="N/A", epss=0.9, kev=False, age_days=0)
    assert score > 0

def test_missing_cvss_with_kev_still_floored():
    assert s.compute_risk_score(cvss="Score Pending", epss=None, kev=True, age_days=0) >= s.KEV_FLOOR

def test_none_inputs_do_not_crash():
    assert isinstance(s.compute_risk_score(cvss=None, epss=None, kev=False, age_days=None), int)


# ── bands ─────────────────────────────────────────────────────────
def test_risk_bands():
    assert s.risk_band(95) == "critical"
    assert s.risk_band(80) == "critical"
    assert s.risk_band(70) == "high"
    assert s.risk_band(40) == "medium"
    assert s.risk_band(10) == "low"


# ── realistic sample (mirrors a record in vulnerabilities.json) ────
def test_low_signal_cve_lands_low_band():
    # CVE-2026-4020: N/A CVSS, ~3% EPSS, not KEV, fresh -> low priority
    score = s.compute_risk_score(cvss="N/A", epss=0.0298, kev=False, age_days=0)
    assert s.risk_band(score) in ("low", "medium")
    assert score < 35
