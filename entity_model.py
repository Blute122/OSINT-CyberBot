import os
import re
import json
import tempfile
from datetime import datetime, timezone

from scoring import compute_risk_score, risk_band

VULN_FILE  = "vulnerabilities.json"
ACTOR_FILE = "actors.json"

VALID_STATUSES = {"disclosed", "actively_exploited", "patched", "poc_released"}

# Fallback only — used if Groq's vuln_status is missing/malformed, NOT the
# primary path anymore. Groq has full article context; this regex only sees
# the headline, so it's strictly worse and exists purely as a safety net.
_PATCH_PATTERN = re.compile(
    r"\b(patch(es|ed)?|fix(es|ed)?|update(s|d)?\s+(released|available)|addressed)\b",
    re.IGNORECASE,
)
_EXPLOIT_PATTERN = re.compile(
    r"\b(actively exploit|exploited in the wild|active(ly)? attack|under attack|zero.?day)\b",
    re.IGNORECASE,
)


def load_json_safe(path: str) -> dict:
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}


def _age_days(date_str: str) -> float:
    """Days between a 'YYYY-MM-DD HH:MM UTC' timestamp and now. 0 on parse error."""
    try:
        seen = datetime.strptime(
            date_str.replace(" UTC", ""), "%Y-%m-%d %H:%M"
        ).replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError, TypeError):
        return 0.0
    return max(0.0, (datetime.now(timezone.utc) - seen).total_seconds() / 86400)


def save_json_safe(path: str, data):
    """
    Atomic write: serialize to a temp file in the same directory, then
    os.replace() over the target. os.replace is atomic on the same
    filesystem, so a crash mid-write can never leave a truncated or
    half-written database behind — readers always see either the old
    file or the fully-written new one.
    """
    dir_name = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix=".tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def resolve_status(vuln_status: str, title: str, kev_flag: bool, was_kev_before: bool) -> str:
    """
    Primary signal: Groq's own vuln_status field (has full article context).
    Falls back to cheap regex/KEV inference only if Groq's value is missing
    or not one of the expected labels. KEV flipping true always forces
    actively_exploited regardless of source, since that's a harder external
    signal than anything in article text.
    """
    if kev_flag and not was_kev_before:
        return "actively_exploited"

    if vuln_status in VALID_STATUSES:
        return vuln_status

    if _PATCH_PATTERN.search(title):
        return "patched"
    if kev_flag or _EXPLOIT_PATTERN.search(title):
        return "actively_exploited"
    return "disclosed"


def upsert_vulnerability(cve: str, title: str, cvss, kev_flag: bool,
                          epss_score, source_url: str, vuln_status: str = "",
                          product: str = "") -> dict:
    """
    Inserts or updates a CVE record in vulnerabilities.json.
    vuln_status should come directly from Groq's extraction (full article
    context) — title/regex fallback only kicks in if that's missing.
    """
    if not cve:
        return {}

    vulns = load_json_safe(VULN_FILE)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    is_new = cve not in vulns
    was_kev_before = vulns.get(cve, {}).get("kev", False)
    status = resolve_status(vuln_status, title, kev_flag, was_kev_before)

    if is_new:
        vulns[cve] = {
            "first_seen": now_str,
            "product": product,
            "status_timeline": [],
            "related_posts": [],
        }

    entry = vulns[cve]
    entry["last_updated"] = now_str
    if product and not entry.get("product"):
        entry["product"] = product
    entry["cvss"] = cvss
    entry["kev"] = kev_flag
    entry["epss"] = epss_score

    # Risk prioritization score — recomputed on every update from the latest
    # verified signals. Recency is measured from first_seen.
    score = compute_risk_score(
        cvss=cvss, epss=epss_score, kev=kev_flag,
        age_days=_age_days(entry.get("first_seen", now_str)),
    )
    entry["risk_score"] = score
    entry["risk_band"] = risk_band(score)

    last_status = entry["status_timeline"][-1]["status"] if entry["status_timeline"] else None
    status_changed = (status != last_status)

    entry["status_timeline"].append({
        "date": now_str,
        "status": status,
        "summary": title[:200],
        "source_url": source_url,
    })
    if source_url not in entry["related_posts"]:
        entry["related_posts"].append(source_url)

    # Persist BEFORE attaching transient flags — these must never be
    # written into vulnerabilities.json itself.
    save_json_safe(VULN_FILE, vulns)

    result = dict(entry)
    result["_is_new"] = is_new
    result["_status_changed"] = status_changed
    return result


def upsert_actor(actor_name: str, target: str, title: str, source_url: str) -> dict:
    """Inserts or updates a threat-actor record in actors.json."""
    if not actor_name:
        return {}

    actors = load_json_safe(ACTOR_FILE)
    key = actor_name.strip().lower()
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    if key not in actors:
        actors[key] = {
            "aliases": [actor_name.strip()],
            "first_seen": now_str,
            "campaigns": [],
        }

    entry = actors[key]
    if actor_name.strip() not in entry["aliases"]:
        entry["aliases"].append(actor_name.strip())

    entry["campaigns"].append({
        "target": target or "unspecified",
        "date": now_str,
        "summary": title[:200],
        "source_url": source_url,
    })

    save_json_safe(ACTOR_FILE, actors)
    return entry


def cve_already_covered(cve: str, days: int = 7) -> bool:
    """
    Exact-match CVE dedup. Returns True if this CVE was already posted
    about within `days`. Call AFTER Groq returns a CVE, BEFORE spending
    NVD/KEV/EPSS calls.
    """
    vulns = load_json_safe(VULN_FILE)
    if cve not in vulns:
        return False

    entry = vulns[cve]
    timeline = entry.get("status_timeline", [])
    if not timeline:
        return False

    last_entry = timeline[-1]
    try:
        last_time = datetime.strptime(
            last_entry["date"].replace(" UTC", ""), "%Y-%m-%d %H:%M"
        ).replace(tzinfo=timezone.utc)
    except (ValueError, KeyError):
        return False

    now = datetime.now(timezone.utc)
    age_days = (now - last_time).total_seconds() / 86400

    if age_days < days:
        return True

    return False