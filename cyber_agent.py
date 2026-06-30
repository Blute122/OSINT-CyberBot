
import os
import random
import re
import time
import logging
import tempfile
import feedparser
import tweepy
import requests
import traceback
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from calendar import timegm
from groq import Groq
from pydantic import BaseModel, ValidationError
from PIL import Image, ImageDraw, ImageFont
import textwrap
from entity_model import (
    upsert_vulnerability, upsert_actor, cve_already_covered,
)
from scoring import compute_risk_score, risk_band
from semantic import max_similarity as max_semantic_similarity

# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("cyber_agent")


# ─────────────────────────────────────────────
# RUN METRICS
# ─────────────────────────────────────────────
@dataclass
class RunStats:
    """Per-run observability counters. Surfaced in the end-of-run summary
    and a natural source for a future dashboard 'system health' panel."""
    feeds_scanned: int = 0
    articles_seen: int = 0
    posted: int = 0
    skipped: dict = field(default_factory=dict)

    def skip(self, reason: str):
        self.skipped[reason] = self.skipped.get(reason, 0) + 1

    def summary(self) -> str:
        skip_detail = ", ".join(f"{k}={v}" for k, v in sorted(self.skipped.items())) or "none"
        return (
            f"Run summary — feeds: {self.feeds_scanned}, articles: {self.articles_seen}, "
            f"posted: {self.posted}, skipped: [{skip_detail}]"
        )


# ─────────────────────────────────────────────
# ARTICLE
# ─────────────────────────────────────────────
@dataclass
class Article:
    """Normalized view of one RSS entry flowing through the pipeline."""
    url: str
    title: str
    summary: str
    source_name: str
    published: datetime | None = None


def atomic_write_json(path: str, data, indent: int = 4):
    """Crash-safe JSON write (temp file + os.replace). See entity_model
    for rationale; this variant keeps the dashboard's indent=4 format."""
    dir_name = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix=".tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=indent)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
X_API_KEY             = os.environ.get("X_API_KEY")
X_API_SECRET          = os.environ.get("X_API_SECRET")
X_ACCESS_TOKEN        = os.environ.get("X_ACCESS_TOKEN")
X_ACCESS_TOKEN_SECRET = os.environ.get("X_ACCESS_TOKEN_SECRET")
GROQ_API_KEY          = os.environ.get("GROQ_API_KEY")
DISCORD_WEBHOOK_URL   = os.environ.get("DISCORD_WEBHOOK_URL")

DAILY_POST_CAP        = 7   # Max tweets per day (UTC)
ARTICLE_MAX_AGE_HOURS = 6   # Skip articles older than this
TWEET_CHAR_LIMIT      = 278 # X free/Basic tier hard caps posts at 280 chars.
                             # Raise to ~24900 if/when back on X Premium.

# LLM extraction resilience: try the primary model, fall back to a larger one;
# each model gets a few attempts with exponential backoff on transient errors.
GROQ_MODELS        = ["llama-3.1-8b-instant", "llama-3.3-70b-versatile"]
GROQ_MAX_ATTEMPTS  = 2   # attempts per model before falling back
GROQ_BACKOFF_BASE  = 2   # seconds; doubles each retry

RSS_FEEDS = [
    # ── Tier 1: Breaking news ────────────────────────────────────────
    {"url": "https://feeds.feedburner.com/TheHackersNews",               "name": "The Hacker News"},
    {"url": "https://www.bleepingcomputer.com/feed/",                    "name": "BleepingComputer"},
    {"url": "https://www.darkreading.com/rss.xml",                       "name": "Dark Reading"},
    {"url": "https://cyberscoop.com/feed/",                              "name": "CyberScoop"},
    {"url": "https://krebsonsecurity.com/feed/",                         "name": "Krebs on Security"},
    {"url": "https://feeds.feedburner.com/securityweek",                 "name": "SecurityWeek"},
    {"url": "https://www.cisa.gov/feeds/alerts.xml",                     "name": "CISA"},
    # ── Tier 2: Threat research ──────────────────────────────────────
    {"url": "https://blog.talosintelligence.com/rss",                    "name": "Cisco Talos"},
    {"url": "https://unit42.paloaltonetworks.com/feed/",                 "name": "Unit 42"},
    {"url": "https://www.recordedfuture.com/feed",                       "name": "Recorded Future"},
    {"url": "https://googleprojectzero.blogspot.com/feeds/posts/default","name": "Google Project Zero"},
    {"url": "https://isc.sans.edu/rssfeed.xml",                          "name": "SANS ISC"},
]

HISTORY_FILE = "posted_urls.txt"
DB_FILE      = "database.json"

COLOR_MAP = {
    "🔴": "#ff4757",
    "🟠": "#ffa502",
    "🟡": "#eccc68",
    "🟢": "#2ed573",
}

# Strict CVE pattern — rejects placeholders like CVE-XXXX-XXXXX
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# ─────────────────────────────────────────────
# DUPLICATE DETECTION
# ─────────────────────────────────────────────

# Words that appear in almost every security headline — skip for matching
_FILLER_WORDS = {
    "a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "is", "are", "was", "were", "be", "been",
    "has", "have", "had", "its", "it", "this", "that", "as", "via",
    "new", "critical", "high", "severity", "security", "cyber", "attack",
    "attacks", "flaw", "flaws", "bug", "bugs", "vulnerability", "vulnerabilities",
    "exploit", "exploits", "exploited", "exploitation", "hacker", "hackers",
    "hacking", "breach", "breached", "leak", "leaked", "warns", "warning",
    "alert", "patch", "patches", "patched", "update", "updated", "fix",
    "researcher", "researchers", "discovers", "discovered", "report", "reports",
    "active", "actively", "campaign", "campaigns", "threat", "threats",
    "malicious", "details", "latest", "major", "multiple", "using", "used",
    "could", "allow", "allows", "data", "user", "users", "system", "systems",
    "network", "networks", "access", "remote", "code", "execution",
}

DUPLICATE_WINDOW_HOURS_GENERAL = 24    # same-day keyword overlap (unchanged)
DUPLICATE_WINDOW_HOURS_LONG    = 168   # 7 days — for CVE/named-entity recurrence
DUPLICATE_MIN_MATCHES          = 2     # general tier threshold (unchanged)
DUPLICATE_MIN_ENTITY_MATCHES   = 2     # long-window tier needs 2+ shared proper nouns
SEMANTIC_DUP_THRESHOLD         = 0.6   # TF-IDF cosine similarity over the 7-day window


def extract_keywords(title: str) -> set:
    """Extract meaningful entity tokens — CVE IDs, proper nouns, words >4 chars."""
    cves = set(re.findall(r"CVE-\d{4}-\d+", title, re.IGNORECASE))
    raw_tokens = re.findall(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", title)
    meaningful = set()
    for tok in raw_tokens:
        lower = tok.lower()
        if lower in _FILLER_WORDS:
            continue
        if tok[0].isupper() or len(tok) > 4:
            meaningful.add(lower)
    return meaningful | {c.lower() for c in cves}


def extract_entities(title: str) -> set:
    """Proper-noun-only subset of keywords — used for the longer-window
    recurrence check. Capitalized tokens only, so generic lowercase words
    ('breach', 'critical') never count toward long-window matches."""
    raw_tokens = re.findall(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", title)
    return {
        t.lower() for t in raw_tokens
        if t[0].isupper() and len(t) >= 4 and t.lower() not in _FILLER_WORDS
    }


def is_duplicate_story(title: str, db_data: list) -> bool:
    """
    Two-tier check:
      1. CVE match OR 2+ shared proper-noun entities within 7 days — catches
         the same CVE/threat-actor/org resurfacing under a different headline
         days later (e.g. "breach claimed" -> "breach confirmed, N orgs affected").
      2. General keyword overlap within 24h — original same-day logic, unchanged.
    """
    if not db_data:
        return False

    now = datetime.now(timezone.utc)
    candidate_kw = extract_keywords(title)
    if not candidate_kw:
        return False
    candidate_cves = {k for k in candidate_kw if k.lower().startswith("cve-")}
    candidate_entities = extract_entities(title)

    cutoff_general = now - timedelta(hours=DUPLICATE_WINDOW_HOURS_GENERAL)
    cutoff_long     = now - timedelta(hours=DUPLICATE_WINDOW_HOURS_LONG)

    recent_headlines = []   # 7-day window, for the semantic fallback pass

    for entry in db_data:
        raw_date = entry.get("date", "").replace(" UTC", "").strip()
        try:
            entry_time = datetime.strptime(raw_date, "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
        except ValueError:
            continue

        stored_headline = entry.get("content", "").split("\n")[0]
        stored_kw = extract_keywords(stored_headline)

        if entry_time >= cutoff_long:
            recent_headlines.append(stored_headline)
            stored_cves = {k for k in stored_kw if k.lower().startswith("cve-")}
            if candidate_cves and (candidate_cves & stored_cves):
                log.info("Duplicate (CVE match, 7d): %s", candidate_cves & stored_cves)
                return True

            stored_entities = extract_entities(stored_headline)
            ent_overlap = candidate_entities & stored_entities
            if len(ent_overlap) >= DUPLICATE_MIN_ENTITY_MATCHES:
                log.info("Duplicate (entity match, 7d): %s", ent_overlap)
                return True

        if entry_time >= cutoff_general:
            overlap = candidate_kw & stored_kw
            if len(overlap) >= DUPLICATE_MIN_MATCHES:
                log.info("Duplicate (keyword overlap, 24h): %s", overlap)
                return True

    # ── Semantic fallback: TF-IDF cosine over the 7-day window ──
    # Catches reworded headlines that share distinctive terms but slipped
    # past the lexical thresholds above.
    sim = max_semantic_similarity(title, recent_headlines)
    if sim >= SEMANTIC_DUP_THRESHOLD:
        log.info("Duplicate (semantic similarity %.2f, 7d)", sim)
        return True

    return False


# ─────────────────────────────────────────────
# DAILY CAP
# ─────────────────────────────────────────────
def get_todays_post_count() -> int:
    if not os.path.exists(DB_FILE) or os.path.getsize(DB_FILE) == 0:
        return 0
    try:
        with open(DB_FILE, "r") as f:
            db_data = json.load(f)
    except json.JSONDecodeError:
        return 0
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return sum(1 for item in db_data if item.get("date", "").startswith(today_str))


# ─────────────────────────────────────────────
# URL HISTORY & DATABASE
# ─────────────────────────────────────────────
def get_posted_urls() -> list:
    if not os.path.exists(HISTORY_FILE):
        return []
    with open(HISTORY_FILE, "r") as f:
        return f.read().splitlines()

def save_posted_url(url: str):
    with open(HISTORY_FILE, "a") as f:
        f.write(url + "\n")

def load_db() -> list:
    if not os.path.exists(DB_FILE) or os.path.getsize(DB_FILE) == 0:
        return []
    try:
        with open(DB_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []

def save_db(db_data: list):
    atomic_write_json(DB_FILE, db_data, indent=4)


# ─────────────────────────────────────────────
# NVD CVSS LOOKUP
# ─────────────────────────────────────────────
def get_nvd_cvss(cve_id: str):
    time.sleep(1)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data  = response.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                metrics = vulns[0].get("cve", {}).get("metrics", {})
                if "cvssMetricV31" in metrics:
                    return metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV3" in metrics:
                    return metrics["cvssMetricV3"][0]["cvssData"]["baseScore"]
                return "Score Pending"
    except Exception as e:
        log.error("NVD API Error: %s", e)
    return "N/A"


# ─────────────────────────────────────────────
# KEV + EPSS ENRICHMENT
# ─────────────────────────────────────────────
KEV_CACHE = {"data": None, "fetched_at": 0}
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_TTL_SECONDS = 6 * 60 * 60  # refetch at most every 6 hours


def get_kev_catalog() -> set:
    """Returns a set of CVE IDs in CISA's Known Exploited Vulnerabilities catalog."""
    now = time.time()
    if KEV_CACHE["data"] is not None and (now - KEV_CACHE["fetched_at"]) < KEV_TTL_SECONDS:
        return KEV_CACHE["data"]
    try:
        resp = requests.get(KEV_URL, timeout=15)
        if resp.status_code == 200:
            vulns = resp.json().get("vulnerabilities", [])
            cve_set = {v["cveID"].upper() for v in vulns if "cveID" in v}
            KEV_CACHE["data"] = cve_set
            KEV_CACHE["fetched_at"] = now
            return cve_set
    except Exception as e:
        log.error("KEV fetch error: %s", e)
    return KEV_CACHE["data"] or set()


def is_in_kev(cve_id: str) -> bool:
    if not cve_id:
        return False
    return cve_id.upper() in get_kev_catalog()


def get_epss_score(cve_id: str):
    """Returns (probability, percentile) floats 0-1, or (None, None)."""
    if not cve_id:
        return None, None
    try:
        resp = requests.get(
            "https://api.first.org/data/v1/epss",
            params={"cve": cve_id}, timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", [])
            if data:
                return float(data[0]["epss"]), float(data[0]["percentile"])
    except Exception as e:
        log.error("EPSS fetch error: %s", e)
    return None, None


# ─────────────────────────────────────────────
# GROQ — EXTRACTION  (schema-validated, retried, with model fallback)
# ─────────────────────────────────────────────
class ExtractionResult(BaseModel):
    """Schema the LLM must satisfy. Structural validation stops malformed
    output from ever reaching the pipeline; missing fields fall back to
    sensible defaults."""
    skip: bool = False
    severity_icon: str = "🟡"
    cve: str | None = ""
    threat_actor: str | None = ""
    target: str | None = ""
    tweet: str | None = ""
    card_context: str | None = ""
    card_impact: str | None = ""
    simply_put: str | None = ""


def _call_groq(model: str, prompt: str) -> str:
    """One Groq completion → raw content string. Raises on API error."""
    client = Groq(api_key=GROQ_API_KEY)
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"},
    )
    return response.choices[0].message.content.strip()


def _parse_and_validate(raw: str) -> ExtractionResult:
    """Parse JSON and validate against ExtractionResult. Raises
    JSONDecodeError or ValidationError on malformed output."""
    return ExtractionResult.model_validate(json.loads(raw))


def generate_content(title: str, summary: str, source_name: str) -> dict | None:
    """
    One Groq call. Each output field serves a DISTINCT purpose:
      tweet        — short hook for Twitter, what happened + who
      card_context — EXPANDED background for the card: history, scale, how
                     the attack works, scope. Richer than the tweet.
      card_impact  — who is at risk right now, real-world consequences
      simply_put   — one plain-English sentence for non-technical readers
    Validates the output against a schema and retries with exponential backoff,
    falling back to a second model. Returns a normalized dict, or None if the
    article should be skipped or extraction ultimately fails.
    """
    prompt = f"""You are a cyber threat intelligence analyst. Analyze the article below and return a JSON object.

CONTENT FILTER — return exactly {{"skip": true}} if the article is ANY of:
- A podcast, interview, webinar, or recorded conversation
- A contest, giveaway, or advertisement
- A sponsored post or vendor marketing piece
- An opinion/editorial with no specific incident
- A "how a story went viral" or human-interest piece
- An industry award, job posting, funding round, M&A, hiring/personnel announcement, or event announcement
- A legal proceeding, court sentencing, extradition, or policy/regulatory memo that does NOT describe an active technical compromise (e.g. lawsuits, government policy debate, legislation, sentence commutations)
- A product launch, feature release, or general software update with no security vulnerability or incident attached
- A criminal case involving harm to a person that is not itself a cybersecurity incident (e.g. an arrest unrelated to hacking, network intrusion, or digital fraud)
- Content with no identifiable technical attack vector, vulnerability, or breach mechanism described anywhere in the source
Only proceed if the article reports a SPECIFIC, REAL security incident, vulnerability, breach, exploit, or malware campaign with an identifiable technical mechanism.

SEVERITY (pick ONE emoji based strictly on the content):
🔴 CRITICAL — confirmed data breach, ransomware deployed, active zero-day exploitation, state-sponsored APT
🟠 HIGH     — CVSS 7.0–8.9, new malware variant, large-scale phishing campaign
🟡 MEDIUM   — vulnerability discovered but not yet exploited, security research finding
🟢 LOW      — policy update, industry news, minor bug with no active exploitation

OUTPUT: Return ONLY a valid JSON object. No markdown, no backticks, no preamble.

{{
  "skip": false,
  "severity_icon": "<one emoji>",
  "cve": "<exact CVE-YYYY-NNNNN only if explicitly stated in article, else empty string>",
  "threat_actor": "<attacker name/group if named in article, else empty string>",
  "target": "<specific affected software, product, or organization, else empty string>",

  "tweet": "<Twitter hook. Lead with severity emoji. State WHAT happened and WHO is affected in plain language. End with 'via {source_name}' and 1-2 hashtags. MAX 210 CHARS — count carefully.>",

  "card_context": "<MAIN BODY of the threat card image — DIFFERENT and RICHER than the tweet. Cover: background on the affected product/org, how the attack vector works (e.g. unauthenticated RCE, supply chain, phishing lure type), and the scale/scope (users or systems at risk if stated). 1-2 COMPLETE sentences, each ending with a period. HARD LIMIT 200 characters — be concise so nothing is cut off. Never repeat the tweet text.>",

  "card_impact": "<Real-world impact for the card: what an attacker can DO if this is exploited and who is concretely affected (enterprises, consumers, a specific sector). ONE COMPLETE sentence ending with a period. HARD LIMIT 120 characters. No speculation — only what the article states.>",

  "simply_put": "<One sentence a non-technical person fully understands. Avoid all jargon. Max 110 chars.>"
}}

RULES:
- cve: real CVE IDs only (format CVE-YYYY-NNNNN). Empty string if not in article. Never invent.
- When mentioning a CVE ID inside the tweet field, write it as a bare token (e.g. "...exploit CVE-2026-4020 to..."), never wrapped in your own parentheses or brackets — CVSS/KEV/EPSS detail is appended separately and already uses parentheses/brackets, so double-wrapping creates nested punctuation.
- tweet: 210 chars MAX before any post-processing. Complete sentence, not truncated.
- card_context and card_impact must ADD information the tweet does not contain.
- card_context and card_impact MUST be complete sentences that each end with a period, and MUST stay within their character limits so the threat-card text is never cut off mid-sentence. Prefer fewer words over an unfinished thought.
- NEVER state a specific CVSS score, numeric severity rating, or percentage inside card_context or card_impact. CVSS/EPSS/KEV data is injected separately from verified sources — stating your own number risks contradicting it. Describe severity only in qualitative terms (e.g. "a high-severity flaw") if needed.
- No mitigation advice anywhere.
- NEVER include a URL, link, domain name, or "http"/"www" in ANY field. The tweet must end with "via {source_name}" using the PLAIN source NAME only (e.g. "via SecurityWeek") — never a web address. Do not invent or append article URLs; the post carries no link.
- All fields strictly factual, sourced only from the article.

ARTICLE:
Title: {title}
Summary: {summary}"""

    last_err = None
    for model in GROQ_MODELS:
        for attempt in range(1, GROQ_MAX_ATTEMPTS + 1):
            try:
                result = _parse_and_validate(_call_groq(model, prompt))
            except (json.JSONDecodeError, ValidationError) as e:
                # Bad/malformed content — a retry (often on the fallback model)
                # may produce valid output.
                last_err = e
                log.warning("Groq output invalid (model=%s, attempt=%d): %s", model, attempt, e)
                time.sleep(1)
                continue
            except Exception as e:
                # Transient API / network / rate-limit error — back off and retry.
                last_err = e
                wait = GROQ_BACKOFF_BASE * (2 ** (attempt - 1))
                log.warning("Groq call failed (model=%s, attempt=%d): %s — retrying in %ds",
                            model, attempt, e, wait)
                time.sleep(wait)
                continue

            # ── Success: normalize and return ──
            if result.skip:
                return None
            cve = (result.cve or "").strip()
            if cve and not CVE_PATTERN.fullmatch(cve):
                log.warning("Rejected invalid CVE: '%s'", cve)
                cve = ""
            return {
                "severity_icon": result.severity_icon or "🟡",
                "cve": cve,
                "threat_actor": (result.threat_actor or "").strip(),
                "target": (result.target or "").strip(),
                "tweet": (result.tweet or "").strip(),
                "card_context": (result.card_context or "").strip(),
                "card_impact": (result.card_impact or "").strip(),
                "simply_put": (result.simply_put or "").strip(),
            }
        log.warning("Model '%s' exhausted after %d attempts; trying fallback.", model, GROQ_MAX_ATTEMPTS)

    log.error("All Groq models/attempts failed: %s", last_err)
    return None


# ─────────────────────────────────────────────
# THREAT CARD
# ─────────────────────────────────────────────
def fit_to_lines(text: str, width_chars: int, max_lines: int) -> str:
    """Fit text within max_lines WITHOUT ever showing an ellipsis: keep the
    longest run of COMPLETE sentences that fits. Enforced in code because LLMs
    don't reliably obey character-count instructions. Only if the very first
    sentence is itself too long does it fall back to a clean word-boundary cut
    (still no '…')."""
    if not text:
        return text
    wrapper = textwrap.TextWrapper(width=width_chars)
    if len(wrapper.wrap(text)) <= max_lines:
        return text
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    kept = ""
    for s in sentences:
        candidate = f"{kept} {s}".strip() if kept else s
        if len(wrapper.wrap(candidate)) <= max_lines:
            kept = candidate
        else:
            break
    if kept:
        return kept
    return " ".join(wrapper.wrap(text)[:max_lines])


def fit_single_line(text: str, max_chars: int) -> str:
    """Single-line fit for fields like TARGET — clean word-boundary cut,
    no ellipsis."""
    if not text or len(text) <= max_chars:
        return text
    return text[:max_chars].rsplit(" ", 1)[0].rstrip(".,;:—-")


def generate_threat_card(severity_icon: str, title: str,
                         card_context: str, card_impact: str,
                         cve: str, target: str,
                         simply_put: str, source_site: str,
                         kev_flag: bool = False, epss_score: float = None) -> str:
    """
    Card layout (top → bottom):
      ┌─ accent bar ──────────────────────────────┐
      │ THREAT INTELLIGENCE ALERT                 │
      │ <Article title>                           │
      │ CONTEXT: <card_context — richer than tweet│
      │ IMPACT:  <card_impact>                    │
      │ Source: <source>                          │
      ├───────────────────────────────────────────┤  ← dynamic divider
      │ THREAT: <cve>   TARGET: <target>          │  ← pinned meta zone
      ├───────────────────────────────────────────┤
      │ SIMPLY PUT: <plain english>               │  ← pinned footer
      └───────────────────────────────────────────┘

    The meta zone and footer are pinned from the bottom so they
    ALWAYS render regardless of how much context text there is.
    The divider is placed at the actual end of content, eliminating gaps.
    """
    W, H       = 1024, 512
    FOOTER_H   = 90
    META_H     = 115
    FOOTER_TOP = H - FOOTER_H
    META_TOP   = FOOTER_TOP - META_H
    HEADER_MAX = META_TOP - 12   # Content must not cross this line

    bg_color     = "#0d1117"
    footer_color = "#161b22"
    accent_color = COLOR_MAP.get(severity_icon, "#ff4757")
    text_primary   = "#ffffff"
    text_secondary = "#8b949e"
    text_body      = "#c9d1d9"

    image = Image.new("RGB", (W, H), color=bg_color)
    draw  = ImageDraw.Draw(image)

    try:
        f_label    = ImageFont.truetype("Roboto-Bold.ttf",   17)
        f_title    = ImageFont.truetype("Roboto-Bold.ttf",   28)
        f_tag      = ImageFont.truetype("Roboto-Bold.ttf",   17)   # "CONTEXT:" / "IMPACT:"
        f_body     = ImageFont.truetype("Roboto-Medium.ttf", 18)
        f_source   = ImageFont.truetype("Roboto-Medium.ttf", 17)
        f_meta_l   = ImageFont.truetype("Roboto-Bold.ttf",   18)
        f_meta_v   = ImageFont.truetype("Roboto-Medium.ttf", 19)
        f_foot_l   = ImageFont.truetype("Roboto-Bold.ttf",   15)
        f_foot_v   = ImageFont.truetype("Roboto-Medium.ttf", 19)
    except OSError:
        f_label = f_title = f_tag = f_body = f_source = \
        f_meta_l = f_meta_v = f_foot_l = f_foot_v = ImageFont.load_default()

    MX = 45

    def lh(font) -> int:
        b = font.getbbox("Ag")
        return b[3] - b[1]

    def draw_wrapped(text: str, font, x: int, y: int, fill,
                     width_chars: int = 85, padding: int = 4,
                     max_lines: int = 99, max_y: int = 9999) -> int:
        """Draw wrapped text within optional max_y boundary. Returns y after last line."""
        lines = textwrap.TextWrapper(width=width_chars).wrap(text)[:max_lines]
        for line in lines:
            if y + lh(font) > max_y:
                break
            draw.text((x, y), line, font=font, fill=fill)
            y += lh(font) + padding
        return y

    def draw_inline_tag(tag: str, text: str, x: int, y: int,
                        tag_font, body_font, tag_color, body_color,
                        width_chars: int = 75, padding: int = 4,
                        max_lines: int = 2, max_y: int = 9999) -> int:
        """Draw a bold coloured tag then wrapped body text on same/next lines.
        Assumes text has already been pre-fitted via fit_to_lines() before
        this is called — no truncation logic needed here."""
        tag_w = tag_font.getlength(tag + " ") if hasattr(tag_font, "getlength") else 80
        first_line_x = x + int(tag_w)
        draw.text((x, y), tag, font=tag_font, fill=tag_color)
        lines = textwrap.TextWrapper(width=width_chars).wrap(text)[:max_lines]
        for i, line in enumerate(lines):
            tx = first_line_x if i == 0 else x + 8
            draw.text((tx, y), line, font=body_font, fill=body_color)
            y += lh(body_font) + padding
        return y

    # ── Top accent bar ───────────────────────────────────
    draw.rectangle([(0, 0), (W, 10)], fill=accent_color)

    # ── HEADER ───────────────────────────────────────────
    y = 20
    draw.text((MX, y), "THREAT INTELLIGENCE ALERT", font=f_label, fill=accent_color)
    y += lh(f_label) + 8

    # Title — max 2 lines
    y = draw_wrapped(title, f_title, MX, y, text_primary,
                     width_chars=50, padding=6, max_lines=2, max_y=HEADER_MAX)
    y += 6

    # Context block — richer background info
    if card_context:
        card_context = fit_to_lines(card_context, width_chars=78, max_lines=3)
        y = draw_inline_tag(
            "CONTEXT  ", card_context,
            MX, y,
            f_tag, f_body,
            accent_color, text_body,
            width_chars=78, padding=3, max_lines=3, max_y=HEADER_MAX - 30,
        )
        y += 4

    # Impact block
    if card_impact:
        card_impact = fit_to_lines(card_impact, width_chars=78, max_lines=2)
        y = draw_inline_tag(
            "IMPACT   ", card_impact,
            MX, y,
            f_tag, f_body,
            "#ffa502", text_body,
            width_chars=78, padding=3, max_lines=2, max_y=HEADER_MAX - 10,
        )
        y += 4

    # Source — drawn before divider
    if source_site and y + lh(f_source) + 10 < HEADER_MAX:
        y += 4
        draw.text((MX, y), f"Source: {source_site}", font=f_source, fill=text_secondary)
        y += lh(f_source) + 10

    # ── Dynamic divider ──────────────────────────────────
    div_y = min(y, HEADER_MAX)
    draw.line([(MX, div_y), (W - MX, div_y)], fill="#30363d", width=2)

    # ── META ZONE — always pinned ────────────────────────
    meta_col2_x = MX + 120
    row_y       = META_TOP + 10

    if cve:
        draw.text((MX, row_y), "THREAT:", font=f_meta_l, fill=text_secondary)
        cve_text = cve if len(cve) <= 62 else cve[:62]
        if epss_score is not None:
            cve_text += f"  (EPSS: {epss_score*100:.1f}%)"
        draw.text((meta_col2_x, row_y), cve_text, font=f_meta_v, fill=accent_color)
        row_y += lh(f_meta_l) + 12

    if target:
        draw.text((MX, row_y), "TARGET:", font=f_meta_l, fill=text_secondary)
        target_text = fit_single_line(target, max_chars=62)
        draw.text((meta_col2_x, row_y), target_text, font=f_meta_v, fill=text_primary)
        row_y += lh(f_meta_l) + 12

    if kev_flag:
        draw.text((MX, row_y), "KEV:", font=f_meta_l, fill=text_secondary)
        draw.text((meta_col2_x, row_y), "ACTIVELY EXPLOITED", font=f_meta_v, fill="#ff4757")
        row_y += lh(f_meta_l) + 12

    # If neither CVE nor target, show a "No CVE identified" note
    if not cve and not target:
        draw.text((MX, row_y), "No CVE or specific target identified for this incident.",
                  font=f_source, fill=text_secondary)

    # ── FOOTER — pinned ──────────────────────────────────
    draw.rectangle([(0, FOOTER_TOP), (W, H)], fill=footer_color)
    draw.line([(0, FOOTER_TOP), (W, FOOTER_TOP)], fill="#30363d", width=2)
    draw.text((MX, FOOTER_TOP + 10), "SIMPLY PUT:", font=f_foot_l, fill=text_secondary)
    draw_wrapped(simply_put, f_foot_v, MX, FOOTER_TOP + 30,
                 text_primary, width_chars=92, padding=3, max_lines=2)

    output_filename = "threat_card.png"
    image.save(output_filename, "PNG")
    return output_filename


# ─────────────────────────────────────────────
# TWITTER — SINGLE TWEET ($0.01 per run)
# ─────────────────────────────────────────────
def post_tweet(text: str, media_path: str = None):
    client_v2 = tweepy.Client(
        consumer_key=X_API_KEY,
        consumer_secret=X_API_SECRET,
        access_token=X_ACCESS_TOKEN,
        access_token_secret=X_ACCESS_TOKEN_SECRET,
    )

    media_id = None
    if media_path and os.path.exists(media_path):
        auth   = tweepy.OAuth1UserHandler(
            X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_TOKEN_SECRET
        )
        api_v1 = tweepy.API(auth)
        media  = api_v1.media_upload(filename=media_path)
        media_id = media.media_id

    kwargs = {"text": text}
    if media_id:
        kwargs["media_ids"] = [media_id]

    response = client_v2.create_tweet(**kwargs)
    log.info("Tweet posted. ID: %s", response.data['id'])


# ─────────────────────────────────────────────
# SAFE TWEET TRIMMER
# ─────────────────────────────────────────────
def safe_trim(text: str, limit: int = 278) -> str:
    """
    Trim to limit chars at a word boundary. Append '…' only if trimmed.
    278 chars is safe — Twitter's t.co URL shortener adds ~23 chars
    but that's counted separately by the API.
    """
    if len(text) <= limit:
        return text
    trimmed = text[:limit].rsplit(" ", 1)[0]
    return trimmed.rstrip(".,;:—-") + "…"


# ─────────────────────────────────────────────
# TWEET COMPOSITION  (pure — unit tested)
# ─────────────────────────────────────────────
def severity_from_cvss(cvss_score, current_icon: str, kev_flag: bool) -> str:
    """Derive the severity emoji from the verified CVSS base score, falling
    back to the LLM-provided icon if the score is non-numeric. KEV always
    forces critical (CISA BOD 22-01 rationale): an actively-exploited vuln
    is critical regardless of its base score."""
    icon = current_icon
    try:
        score_float = float(cvss_score)
        if score_float >= 9.0:   icon = "🔴"
        elif score_float >= 7.0: icon = "🟠"
        elif score_float >= 4.0: icon = "🟡"
        else:                    icon = "🟢"
    except (ValueError, TypeError):
        pass
    if kev_flag:
        icon = "🔴"
    return icon


def build_score_str(cve: str, cvss_score, kev_flag: bool, epss_score) -> str:
    """Assemble the verified-enrichment suffix appended into the tweet:
    CVE id + CVSS, plus KEV and EPSS flags when present."""
    score_str = (f"{cve} (CVSS: {cvss_score}/10)"
                 if cvss_score not in ["N/A", "Score Pending"]
                 else f"{cve} (CVSS: {cvss_score})")
    if kev_flag:
        score_str += " [CISA KEV: ACTIVELY EXPLOITED]"
    if epss_score is not None:
        score_str += f" [EPSS: {epss_score*100:.1f}%]"
    return score_str


def inject_score(tweet_text: str, cve: str, score_str: str, limit: int = 278) -> str:
    """Splice the enrichment suffix in at the CVE's position, trimming the
    surrounding prose so the KEV/EPSS warning is never the part cut off.
    Falls back to a plain trim if the CVE token isn't present in the text."""
    if cve in tweet_text:
        cve_pos = tweet_text.find(cve)
        before  = tweet_text[:cve_pos]
        after   = tweet_text[cve_pos + len(cve):]
        remaining_budget = limit - len(score_str)
        if len(before) > remaining_budget:
            before, after = safe_trim(before, limit=remaining_budget), ""
        else:
            after = safe_trim(after, limit=max(0, remaining_budget - len(before)))
        return before + score_str + after
    return safe_trim(tweet_text, limit=limit)


# Match only ACTUAL links X would turn into a billable t.co link, while leaving
# dotted tech terms (Node.js, asp.net, config.php, ".io") intact. A bare
# domain is stripped only for the common source TLDs (com/org/gov/edu/info);
# anything with a scheme, "www.", or a /path is always stripped.
_URL_RE = re.compile(
    r"""<?\s*
        (?:
            https?://[^\s<>]+                       # scheme URL
          | www\.[^\s<>]+                           # www URL
          | (?:[a-z0-9-]+\.)+[a-z]{2,}/[^\s<>]*     # any domain WITH a path
          | (?:[a-z0-9-]+\.)+(?:com|org|gov|edu|info)\b   # bare common source domain
        )
        \s*>?
    """,
    re.IGNORECASE | re.VERBOSE,
)


def strip_links(tweet_text: str) -> str:
    """Remove any URL / domain the model slipped in despite the prompt rule.

    Safety net for the 'no links in posts' requirement: the LLM occasionally
    appends a (often hallucinated) article URL after 'via', e.g.
    'via <securityweek.com/new-controller...>'. We strip any web address and
    tidy up the dangling 'via', brackets, and whitespace it leaves behind.
    """
    cleaned = _URL_RE.sub(" ", tweet_text)
    # Collapse a now-empty "via <>" / "via" tail and stray brackets/punctuation.
    cleaned = re.sub(r"\bvia\s*<\s*>", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\bvia\s*(?=$|\s+via\b)", "", cleaned, flags=re.IGNORECASE)
    # Drop an orphaned link-intro connector left dangling before the 'via'
    # attribution, so 'Read at <url> via Krebs' becomes a clean 'via Krebs'.
    cleaned = re.sub(
        r"(?:\b(?:read(?:ing)?|see|more|details?|story|info|learn|view|full|here|at|on|the)\b[\s,:.\-–—]*)+(?=via\b)",
        "",
        cleaned,
        flags=re.IGNORECASE,
    )
    cleaned = re.sub(r"[<>]", "", cleaned)
    cleaned = re.sub(r"\s{2,}", " ", cleaned)
    # Tidy a space before sentence punctuation, but only at a word boundary so
    # leading-dot tech terms (".io", ".NET", ".env") keep their space.
    cleaned = re.sub(r"\s+([.,;:])(?=\s|$)", r"\1", cleaned)
    return cleaned.strip()


def ensure_leading_emoji(tweet_text: str, severity_icon: str) -> str:
    """Guarantee the tweet opens with the severity emoji."""
    if not tweet_text.startswith(severity_icon):
        return f"{severity_icon} {tweet_text.lstrip()}"
    return tweet_text


# ─────────────────────────────────────────────
# DISCORD ERROR ALERTS
# ─────────────────────────────────────────────
def send_discord_alert(error_message: str):
    if not DISCORD_WEBHOOK_URL:
        return
    data = {
        "content": (
            f"🚨 **CyberNewsBot Crash Report** 🚨\n"
            f"```python\n{error_message}\n```"
        )
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=data)
    except Exception as e:
        log.error("Failed to send Discord alert: %s", e)


# ─────────────────────────────────────────────
# PIPELINE STAGES
# ─────────────────────────────────────────────
def parse_article(entry, source_name: str) -> Article:
    """INGEST — normalize a raw feedparser entry into an Article."""
    published = None
    if getattr(entry, "published_parsed", None):
        published = datetime.fromtimestamp(timegm(entry.published_parsed), timezone.utc)
    return Article(
        url=entry.link,
        title=entry.title,
        summary=getattr(entry, "description", ""),
        source_name=source_name,
        published=published,
    )


def pre_llm_skip_reason(article: Article, posted_urls: list, db_data: list) -> str | None:
    """DEDUP/FILTER — decide whether to skip a candidate BEFORE spending a
    Groq call. Returns a reason code ('url_seen' | 'old' | 'duplicate') or
    None if the article should proceed. Pure decision logic, no side effects."""
    if article.url in posted_urls:
        return "url_seen"
    if article.published is not None:
        age = datetime.now(timezone.utc) - article.published
        if age > timedelta(hours=ARTICLE_MAX_AGE_HOURS):
            return "old"
    if is_duplicate_story(article.title, db_data):
        return "duplicate"
    return None


def enrich_cve(cve: str) -> dict:
    """ENRICH — gather verified external signals for a CVE: NVD CVSS,
    CISA KEV status, and FIRST EPSS score."""
    log.info("Fetching CVSS for %s...", cve)
    cvss_score = get_nvd_cvss(cve)
    kev_flag = is_in_kev(cve)
    epss_score, epss_pct = get_epss_score(cve)
    log.info("KEV: %s  EPSS: %s", kev_flag, epss_score)
    return {"cvss": cvss_score, "kev": kev_flag, "epss": epss_score, "epss_pct": epss_pct}


def process_article(article: Article, db_data: list, stats: RunStats) -> bool:
    """EXTRACT → ENRICH → SCORE → PERSIST → DISTRIBUTE for one candidate.
    Returns True if it resulted in a published post, False if skipped.
    Raises on hard errors (fail-fast, mirroring the original loop)."""
    # ── EXTRACT (single Groq call) ───────────────────────
    log.info("Calling Groq...")
    data = generate_content(article.title, article.summary, article.source_name)
    if data is None:
        save_posted_url(article.url)
        stats.skip("filtered")
        log.info("Skipped (non-threat / filtered content).")
        return False

    severity_icon = data.get("severity_icon", "🟡")
    cve           = data.get("cve", "").strip()
    threat_actor  = data.get("threat_actor", "").strip()
    target        = data.get("target", "").strip()
    tweet_text    = data.get("tweet", "").strip()
    card_context  = data.get("card_context", "").strip()
    card_impact   = data.get("card_impact", "").strip()
    simply_put    = data.get("simply_put", "").strip()

    if not tweet_text or len(tweet_text.strip()) < 20:
        log.warning("Skipped — tweet_text too short or empty: '%s'", tweet_text)
        save_posted_url(article.url)
        stats.skip("short_tweet")
        return False

    # Exact-CVE dedup catches what title-keyword dedup misses
    if cve and cve_already_covered(cve, days=7):
        log.info("Skipped — %s already covered recently with no status change.", cve)
        save_posted_url(article.url)
        stats.skip("cve_recent")
        return False

    # ── ENRICH + SCORE ───────────────────────────────────
    cvss_score = None
    kev_flag   = False
    epss_score = None
    if cve:
        enrichment = enrich_cve(cve)
        cvss_score = enrichment["cvss"]
        kev_flag   = enrichment["kev"]
        epss_score = enrichment["epss"]

        severity_icon = severity_from_cvss(cvss_score, severity_icon, kev_flag)
        score_str = build_score_str(cve, cvss_score, kev_flag, epss_score)
        tweet_text = inject_score(tweet_text, cve, score_str, limit=278)

    # ── PERSIST entities (vulnerabilities.json / actors.json) ──
    if cve:
        upsert_vulnerability(
            cve=cve,
            title=article.title,
            cvss=cvss_score,
            kev_flag=kev_flag,
            epss_score=epss_score,
            source_url=article.url,
            product=target,
        )
    if threat_actor:
        upsert_actor(
            actor_name=threat_actor,
            target=target,
            title=article.title,
            source_url=article.url,
        )

    # ── Finalize tweet text ──────────────────────────────
    # Hard safety net: strip any URL/domain the model slipped in (posts carry
    # no link). Runs AFTER score injection so we don't touch CVSS/EPSS suffixes.
    tweet_text = strip_links(tweet_text)
    tweet_text = ensure_leading_emoji(tweet_text, severity_icon)
    # Final safety trim — UNCONDITIONAL. X's free/Basic API tier hard-caps
    # posts at 280 chars. If you resubscribe to X Premium, raise the limit
    # in CONFIG instead of removing this line.
    tweet_text = safe_trim(tweet_text, limit=TWEET_CHAR_LIMIT)

    log.info("Severity: %s | CVE: %s | Target: %s",
             severity_icon, cve or "N/A", target or "N/A")
    log.info("Tweet (%d chars): %s", len(tweet_text), tweet_text)

    # ── Threat card ──────────────────────────────────────
    card_filename = None
    try:
        # Only pass a target if it adds info beyond the malware/actor name
        # already implied by the title — avoids a TARGET row that just
        # restates the headline.
        display_target = target or threat_actor
        if display_target and display_target.lower() in article.title.lower():
            display_target = target if target and target != display_target else ""

        card_filename = generate_threat_card(
            severity_icon,
            article.title,
            card_context,
            card_impact,
            cve,
            display_target,
            simply_put,
            article.source_name,
            kev_flag,
            epss_score,
        )
        log.info("Threat card generated: %s", card_filename)
    except Exception as img_e:
        log.error("Threat card failed: %s", img_e)

    # Priority score for the feed record (fresh item => recency factor 1.0)
    risk = compute_risk_score(cvss=cvss_score, epss=epss_score, kev=kev_flag) if cve else None

    # ── DISTRIBUTE + persist feed record ─────────────────
    log.info("Posting to X...")
    post_tweet(tweet_text, media_path=card_filename)
    save_posted_url(article.url)
    db_data.append({
        "date":    datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "content": tweet_text,
        "url":     article.url,
        "cve":     cve or None,
        "kev":     kev_flag if cve else None,
        "epss":    epss_score if cve else None,
        "risk_score": risk,
        "risk_band":  risk_band(risk) if risk is not None else None,
    })
    save_db(db_data)
    stats.posted += 1
    return True


# ─────────────────────────────────────────────
# MAIN AGENT  (orchestration)
# ─────────────────────────────────────────────
def run_agent() -> RunStats:
    log.info("Agent waking up. Checking for new cybersecurity news...")
    stats = RunStats()

    # ── Daily cap ────────────────────────────────────────
    todays_count = get_todays_post_count()
    if todays_count >= DAILY_POST_CAP:
        log.info("Daily cap of %d reached (%d today). Exiting.", DAILY_POST_CAP, todays_count)
        return stats

    random.shuffle(RSS_FEEDS)
    posted_urls = get_posted_urls()
    db_data     = load_db()   # Loaded once, reused for duplicate check

    for feed_info in RSS_FEEDS:
        log.info("Checking feed: %s", feed_info["name"])
        stats.feeds_scanned += 1
        feed = feedparser.parse(feed_info["url"])

        for entry in feed.entries:
            article = parse_article(entry, feed_info["name"])

            # URL dedup — already posted, skip silently
            if article.url in posted_urls:
                continue

            stats.articles_seen += 1
            log.info("New article found: %s", article.title)

            reason = pre_llm_skip_reason(article, posted_urls, db_data)
            if reason == "old":
                log.info("Skipping old article.")
                stats.skip("old")
                continue
            if reason == "duplicate":
                save_posted_url(article.url)   # Mark URL so we don't recheck it
                log.info("Skipping duplicate story.")
                stats.skip("duplicate")
                continue

            try:
                posted = process_article(article, db_data, stats)
            except Exception as e:
                log.error("Error processing article: %s", e)
                traceback.print_exc()
                log.info(stats.summary())
                return stats

            if posted:
                log.info("Agent finished successfully. Exiting.")
                log.info(stats.summary())
                return stats  # One tweet per GitHub Actions run

    log.info("No new articles found. Exiting.")
    log.info(stats.summary())
    return stats


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    try:
        run_agent()
    except Exception as e:
        error_details = traceback.format_exc()
        log.critical("CRITICAL ERROR: %s", e)
        send_discord_alert(error_details)
        raise e
