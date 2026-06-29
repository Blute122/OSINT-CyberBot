"""
Vulnerability risk-prioritization scoring.

Collapses the verified enrichment signals into a single 0-100 priority score,
mirroring how modern vulnerability-management programs triage: base severity
(CVSS) + exploit likelihood (EPSS) + confirmed active exploitation (CISA KEV)
+ recency. This is the kind of weighted model real CTI / vuln-management teams
use to decide "what do we patch first."

The SAME formula is mirrored in index.html (computeRiskScore) so the engine
and the dashboard always agree on a score. If you change the weights here,
change them there too.
"""

# Weights — chosen to sum to 100 at maximum inputs.
W_CVSS    = 35   # base technical severity
W_EPSS    = 30   # probability of exploitation in the next 30 days
W_KEV     = 25   # confirmed active exploitation (hardest external signal)
W_RECENCY = 10   # urgency decays as an item ages

RECENCY_WINDOW_DAYS = 30   # linear decay to zero over this window
KEV_FLOOR = 85             # KEV (actively exploited) is always near-top priority


def _coerce_cvss(cvss):
    """Return a 0-10 float, or None if the score is unknown (e.g. 'N/A',
    'Score Pending', None)."""
    try:
        return max(0.0, min(float(cvss), 10.0))
    except (ValueError, TypeError):
        return None


def _coerce_epss(epss):
    try:
        return max(0.0, min(float(epss), 1.0))
    except (ValueError, TypeError):
        return 0.0


def _recency_factor(age_days):
    """1.0 for a brand-new item, decaying linearly to 0.0 at RECENCY_WINDOW_DAYS."""
    try:
        age = max(0.0, float(age_days))
    except (ValueError, TypeError):
        age = 0.0
    return max(0.0, 1.0 - (age / RECENCY_WINDOW_DAYS))


def compute_risk_score(cvss=None, epss=None, kev=False, age_days=0.0):
    """
    Return an integer 0-100 priority score.

    cvss:     0-10 CVSS base score, or 'N/A'/None if unknown
    epss:     0-1 exploit-prediction probability, or None
    kev:      bool — present in CISA's Known Exploited Vulnerabilities catalog
    age_days: days since the item was first seen / disclosed

    A missing CVSS does NOT zero the score: its weight is redistributed across
    the remaining signals so an unscored-but-actively-exploited CVE still ranks
    appropriately. KEV imposes a hard floor (KEV_FLOOR).
    """
    cvss_v = _coerce_cvss(cvss)
    epss_v = _coerce_epss(epss)
    kev_v = 1.0 if kev else 0.0
    recency = _recency_factor(age_days)

    if cvss_v is None:
        # Redistribute the CVSS weight proportionally so missing data is not
        # penalized — the score is computed from the signals we actually have.
        total = W_EPSS + W_KEV + W_RECENCY
        score = (
            (W_EPSS / total) * epss_v
            + (W_KEV / total) * kev_v
            + (W_RECENCY / total) * recency
        ) * 100.0
    else:
        score = (
            W_CVSS * (cvss_v / 10.0)
            + W_EPSS * epss_v
            + W_KEV * kev_v
            + W_RECENCY * recency
        )

    if kev:
        score = max(score, KEV_FLOOR)

    return int(round(max(0.0, min(score, 100.0))))


def risk_band(score):
    """Map a 0-100 score to a qualitative band (matches dashboard colors)."""
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"
