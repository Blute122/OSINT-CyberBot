"""
Tests for the threat-card text fitting — guarantees no ellipsis is ever shown
and overflowing text is trimmed to complete sentences.
"""
import textwrap

import cyber_agent as ca


def _lines(text, width):
    return len(textwrap.TextWrapper(width=width).wrap(text))


# ── fit_to_lines ──────────────────────────────────────────────────
def test_short_text_unchanged():
    t = "A short complete sentence."
    assert ca.fit_to_lines(t, width_chars=40, max_lines=3) == t

def test_never_appends_ellipsis():
    t = ("Alpha breach hit Acme servers today. Beta flaw exposed user data "
         "widely. Gamma worm spreads via email fast and silently.")
    out = ca.fit_to_lines(t, width_chars=40, max_lines=2)
    assert "…" not in out and "..." not in out

def test_trims_to_complete_sentences():
    t = ("Alpha breach hit Acme servers today. Beta flaw exposed user data "
         "widely. Gamma worm spreads via email fast and silently.")
    out = ca.fit_to_lines(t, width_chars=40, max_lines=2)
    assert out.endswith(".")                 # ends on a finished sentence
    assert "Gamma" not in out                # the overflowing sentence is dropped
    assert _lines(out, 40) <= 2              # fits the line budget

def test_keeps_first_sentence_when_only_one_fits():
    t = "First sentence stays. Second sentence is dropped because no room left."
    out = ca.fit_to_lines(t, width_chars=24, max_lines=1)
    assert out == "First sentence stays."

def test_single_overlong_sentence_clean_cut_no_ellipsis():
    t = "This single sentence is definitely far too long to fit on one short line."
    out = ca.fit_to_lines(t, width_chars=20, max_lines=1)
    assert "…" not in out
    assert _lines(out, 20) <= 1
    assert out and t.startswith(out.split()[0])   # a clean prefix

def test_empty_text():
    assert ca.fit_to_lines("", width_chars=40, max_lines=3) == ""


# ── fit_single_line ───────────────────────────────────────────────
def test_single_line_short_unchanged():
    assert ca.fit_single_line("AcmeOS", 40) == "AcmeOS"

def test_single_line_long_cut_no_ellipsis():
    out = ca.fit_single_line("Cisco Unified Communications Manager Platform", 20)
    assert "…" not in out
    assert len(out) <= 20
    assert out == "Cisco Unified"
