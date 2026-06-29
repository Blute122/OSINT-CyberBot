"""Unit tests for the TF-IDF cosine near-duplicate detector."""
from datetime import datetime, timedelta, timezone

import semantic as sem
import cyber_agent as ca


# ── max_similarity ────────────────────────────────────────────────
def test_identical_text_is_max_similar():
    assert sem.max_similarity("LockBit ransomware hits Acme Corp",
                              ["LockBit ransomware hits Acme Corp"]) > 0.99

def test_unrelated_text_is_low():
    sim = sem.max_similarity(
        "Cisco Talos publishes phishing research report",
        ["Microsoft patches Windows kernel privilege escalation bug"],
    )
    assert sim < 0.3

def test_reworded_headline_is_high():
    # Same story, different wording — shares the distinctive rare terms.
    sim = sem.max_similarity(
        "Fortinet FortiOS zero-day exploited by attackers in the wild",
        ["Attackers actively exploit Fortinet FortiOS zero-day vulnerability"],
    )
    assert sim >= sem.DEFAULT_THRESHOLD

def test_empty_corpus_returns_zero():
    assert sem.max_similarity("anything at all", []) == 0.0

def test_picks_max_over_corpus():
    sim = sem.max_similarity(
        "LockBit ransomware strikes Acme Corporation",
        ["Unrelated CISA advisory on industrial control systems",
         "LockBit ransomware strikes Acme Corporation"],
    )
    assert sim > 0.9


# ── is_semantic_duplicate threshold ───────────────────────────────
def test_is_semantic_duplicate_respects_threshold():
    corpus = ["Attackers exploit Fortinet FortiOS zero-day vulnerability"]
    cand = "Fortinet FortiOS zero-day exploited in the wild"
    assert sem.is_semantic_duplicate(cand, corpus, threshold=0.3) is True
    assert sem.is_semantic_duplicate(cand, corpus, threshold=0.99) is False


# ── integration: is_duplicate_story uses the semantic fallback ─────
def _entry(headline, dt):
    return {"date": dt.strftime("%Y-%m-%d %H:%M UTC"), "content": headline}

def test_duplicate_story_catches_reworded_via_semantics():
    now = datetime.now(timezone.utc)
    db = [_entry("Attackers actively exploit Fortinet FortiOS zero-day flaw",
                 now - timedelta(days=2))]
    # Reworded headline; should be caught by the TF-IDF fallback.
    assert ca.is_duplicate_story(
        "Fortinet FortiOS zero-day under active exploitation by attackers", db
    ) is True

def test_duplicate_story_allows_genuinely_different_story():
    now = datetime.now(timezone.utc)
    db = [_entry("Attackers exploit Fortinet FortiOS zero-day flaw",
                 now - timedelta(days=2))]
    assert ca.is_duplicate_story(
        "Microsoft announces new Azure identity governance features", db
    ) is False
