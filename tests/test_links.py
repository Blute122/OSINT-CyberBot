"""
Tests for strip_links — the safety net that keeps URLs out of posted tweets
(X charges ~13x more for posts that contain a link). It must remove real links
while preserving dotted technical terms common in CTI (Node.js, asp.net, .io)
and the injected CVSS/EPSS suffix.
"""
import cyber_agent as ca


# ── real links are removed ────────────────────────────────────────
def test_strips_https_url():
    out = ca.strip_links("Flaw exploited. Read more at https://krebsonsecurity.com/2026/05/foo via Krebs")
    assert "http" not in out and "krebsonsecurity.com" not in out
    assert out.endswith("via Krebs")

def test_strips_www_url():
    out = ca.strip_links("Patch now. More: www.bleepingcomputer.com/news/x via BleepingComputer")
    assert "www." not in out and ".com" not in out
    assert out.endswith("via BleepingComputer")

def test_strips_bracketed_hallucinated_domain():
    out = ca.strip_links("Bug disclosed via <securityweek.com/new-controller-flaw> via SecurityWeek")
    assert "securityweek.com" not in out and "<" not in out and ">" not in out
    assert out.endswith("via SecurityWeek")

def test_strips_bare_source_domain():
    out = ca.strip_links("Source: thehackernews.com via The Hacker News")
    assert "thehackernews.com" not in out
    assert out.endswith("via The Hacker News")


# ── legitimate content is preserved ───────────────────────────────
def test_preserves_nodejs():
    t = "Node.js prototype pollution flaw patched. via The Hacker News"
    assert ca.strip_links(t) == t

def test_preserves_aspnet_and_files():
    for t in ["asp.net deserialization bug exploited. via Dark Reading",
              "Malicious config.php uploaded to servers. via CyberScoop",
              "New .io domain abuse campaign. via Unit 42"]:
        assert ca.strip_links(t) == t

def test_preserves_cvss_suffix():
    t = "CVE-2026-4020 (CVSS: 9.8/10) [CISA KEV: ACTIVELY EXPLOITED]. via The Hacker News"
    assert ca.strip_links(t) == t

def test_preserves_abbreviations():
    t = "Affects U.S. agencies and e.g. banks. via SecurityWeek"
    assert ca.strip_links(t) == t

def test_no_link_tweet_unchanged():
    t = "🔴 Critical RCE in AcmeOS lets attackers run code. via SecurityWeek #infosec"
    assert ca.strip_links(t) == t
