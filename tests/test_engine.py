"""
Unit tests for the cyber_agent pipeline's pure logic and persistence helpers.

These cover the deterministic, network-free parts of the engine: dedup,
CVE validation, severity scoring, tweet composition, atomic writes, and the
pre-LLM filter stage. The network-bound stages (Groq, NVD, KEV, EPSS, X) are
intentionally not exercised here.
"""
import json
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import cyber_agent as ca


# ── CVE validation ────────────────────────────────────────────────
def test_cve_pattern_accepts_valid():
    assert ca.CVE_PATTERN.fullmatch("CVE-2026-4020")
    assert ca.CVE_PATTERN.fullmatch("CVE-2026-12345")

def test_cve_pattern_rejects_placeholders():
    assert not ca.CVE_PATTERN.fullmatch("CVE-XXXX-XXXXX")
    assert not ca.CVE_PATTERN.fullmatch("CVE-2026-12")   # too few digits
    assert not ca.CVE_PATTERN.fullmatch("not-a-cve")


# ── Keyword / entity extraction ───────────────────────────────────
def test_extract_keywords_drops_filler_keeps_entities():
    kw = ca.extract_keywords("Critical new attack on Fortinet via CVE-2026-4020")
    assert "fortinet" in kw
    assert "cve-2026-4020" in kw
    assert "critical" not in kw   # filler word

def test_extract_entities_capitalized_only():
    ents = ca.extract_entities("LockBit ransomware hits Acme Corp")
    assert "lockbit" in ents
    assert "acme" in ents
    assert "ransomware" not in ents   # lowercase generic / filler


# ── Duplicate detection ───────────────────────────────────────────
def _db_entry(headline, dt):
    return {"date": dt.strftime("%Y-%m-%d %H:%M UTC"), "content": headline}

def test_duplicate_cve_match_within_7d():
    now = datetime.now(timezone.utc)
    db = [_db_entry("Hackers exploit CVE-2026-4020 in the wild", now - timedelta(days=3))]
    assert ca.is_duplicate_story("New report on CVE-2026-4020 patching", db) is True

def test_not_duplicate_when_unrelated():
    now = datetime.now(timezone.utc)
    db = [_db_entry("LockBit ransomware hits Acme Corp", now - timedelta(hours=2))]
    assert ca.is_duplicate_story("Unrelated Cisco Talos research on phishing", db) is False

def test_duplicate_empty_db():
    assert ca.is_duplicate_story("anything", []) is False


# ── safe_trim ─────────────────────────────────────────────────────
def test_safe_trim_noop_when_short():
    assert ca.safe_trim("short text", limit=278) == "short text"

def test_safe_trim_cuts_on_word_boundary_and_appends_ellipsis():
    text = "word " * 100
    out = ca.safe_trim(text, limit=50)
    assert len(out) <= 51         # 50 + ellipsis
    assert out.endswith("…")
    assert not out.endswith(" …")  # trailing space stripped


# ── severity_from_cvss ────────────────────────────────────────────
def test_severity_from_cvss_buckets():
    assert ca.severity_from_cvss(9.5, "🟡", False) == "🔴"
    assert ca.severity_from_cvss(7.2, "🟡", False) == "🟠"
    assert ca.severity_from_cvss(5.0, "🟡", False) == "🟡"
    assert ca.severity_from_cvss(2.0, "🔴", False) == "🟢"

def test_severity_falls_back_to_current_icon_when_non_numeric():
    assert ca.severity_from_cvss("N/A", "🟠", False) == "🟠"
    assert ca.severity_from_cvss("Score Pending", "🟢", False) == "🟢"

def test_severity_kev_forces_critical():
    assert ca.severity_from_cvss(2.0, "🟢", True) == "🔴"
    assert ca.severity_from_cvss("N/A", "🟡", True) == "🔴"


# ── build_score_str ───────────────────────────────────────────────
def test_build_score_str_numeric():
    assert ca.build_score_str("CVE-2026-1", 9.1, False, None) == "CVE-2026-1 (CVSS: 9.1/10)"

def test_build_score_str_na_with_kev_and_epss():
    s = ca.build_score_str("CVE-2026-1", "N/A", True, 0.42)
    assert s == "CVE-2026-1 (CVSS: N/A) [CISA KEV: ACTIVELY EXPLOITED] [EPSS: 42.0%]"


# ── inject_score ──────────────────────────────────────────────────
def test_inject_score_splices_at_cve_position():
    out = ca.inject_score("🔴 Exploit CVE-2026-1 now", "CVE-2026-1",
                          "CVE-2026-1 (CVSS: 9.0/10)", limit=278)
    assert out == "🔴 Exploit CVE-2026-1 (CVSS: 9.0/10) now"

def test_inject_score_falls_back_to_trim_when_cve_absent():
    out = ca.inject_score("no cve here", "CVE-2026-1", "irrelevant", limit=278)
    assert out == "no cve here"

def test_inject_score_trims_trailing_text_not_the_warning():
    # Realistic case: short lead-in, long trailing prose. The trailing text
    # is trimmed so the CVSS/KEV suffix survives, and the result fits.
    score = "CVE-2026-1 (CVSS: 9.0/10) [CISA KEV: ACTIVELY EXPLOITED]"
    tweet = "🔴 Exploit CVE-2026-1 " + ("blah " * 80)
    out = ca.inject_score(tweet, "CVE-2026-1", score, limit=278)
    assert score in out          # the KEV warning is never the part cut
    assert len(out) <= 278

def test_inject_score_preserves_warning_in_before_overflow_edge():
    # When the text BEFORE the CVE alone exceeds budget, safe_trim's ellipsis
    # can push length to limit+1; the engine's unconditional final safe_trim
    # enforces the hard 278 cap afterward. We assert the warning is kept and
    # that the final trim brings it back under the cap.
    score = "CVE-2026-1 (CVSS: 9.0/10) [CISA KEV: ACTIVELY EXPLOITED]"
    out = ca.inject_score("x" * 400 + " CVE-2026-1 tail", "CVE-2026-1", score, limit=278)
    assert score in out
    assert len(out) <= 279
    assert len(ca.safe_trim(out, limit=ca.TWEET_CHAR_LIMIT)) <= ca.TWEET_CHAR_LIMIT


# ── ensure_leading_emoji ──────────────────────────────────────────
def test_ensure_leading_emoji_adds_when_missing():
    assert ca.ensure_leading_emoji("Breach reported", "🔴") == "🔴 Breach reported"

def test_ensure_leading_emoji_noop_when_present():
    assert ca.ensure_leading_emoji("🔴 Breach reported", "🔴") == "🔴 Breach reported"


# ── atomic_write_json ─────────────────────────────────────────────
def test_atomic_write_round_trip(tmp_path):
    p = tmp_path / "out.json"
    payload = [{"a": 1}, {"b": "two"}]
    ca.atomic_write_json(str(p), payload, indent=4)
    assert json.loads(p.read_text()) == payload
    # no stray temp files left behind
    assert list(tmp_path.glob(".tmp_*")) == []


# ── RunStats ──────────────────────────────────────────────────────
def test_runstats_counts_and_summary():
    s = ca.RunStats()
    s.skip("old")
    s.skip("old")
    s.skip("duplicate")
    s.posted += 1
    assert s.skipped == {"old": 2, "duplicate": 1}
    summary = s.summary()
    assert "posted: 1" in summary
    assert "old=2" in summary and "duplicate=1" in summary


# ── parse_article ─────────────────────────────────────────────────
def test_parse_article_extracts_fields_and_time():
    epoch = time.gmtime(1_700_000_000)
    entry = SimpleNamespace(
        link="https://example.com/a",
        title="Some breach",
        description="details here",
        published_parsed=epoch,
    )
    art = ca.parse_article(entry, "Test Source")
    assert art.url == "https://example.com/a"
    assert art.title == "Some breach"
    assert art.summary == "details here"
    assert art.source_name == "Test Source"
    assert art.published is not None and art.published.tzinfo == timezone.utc

def test_parse_article_handles_missing_fields():
    entry = SimpleNamespace(link="u", title="t")
    art = ca.parse_article(entry, "Src")
    assert art.summary == ""
    assert art.published is None


# ── pre_llm_skip_reason ───────────────────────────────────────────
def _article(url="https://x/a", title="LockBit hits Acme Corp", published=None):
    return ca.Article(url=url, title=title, summary="", source_name="Src", published=published)

def test_pre_llm_skip_url_seen():
    art = _article()
    assert ca.pre_llm_skip_reason(art, [art.url], []) == "url_seen"

def test_pre_llm_skip_old():
    art = _article(published=datetime.now(timezone.utc) - timedelta(hours=ca.ARTICLE_MAX_AGE_HOURS + 1))
    assert ca.pre_llm_skip_reason(art, [], []) == "old"

def test_pre_llm_skip_duplicate():
    now = datetime.now(timezone.utc)
    db = [_db_entry("LockBit hits Acme Corp", now - timedelta(hours=1))]
    art = _article(published=now)
    assert ca.pre_llm_skip_reason(art, [], db) == "duplicate"

def test_pre_llm_skip_none_when_fresh_and_unique():
    art = _article(title="Brand new Cisco Talos finding", published=datetime.now(timezone.utc))
    assert ca.pre_llm_skip_reason(art, [], []) is None
