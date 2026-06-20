
import os
import random
import re
import time
import feedparser
import tweepy
import requests
import traceback
import json
from datetime import datetime, timedelta, timezone
from calendar import timegm
from groq import Groq
from PIL import Image, ImageDraw, ImageFont
import textwrap
from entity_model import (
    upsert_vulnerability, upsert_actor, cve_already_covered,
)

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

    for entry in db_data:
        raw_date = entry.get("date", "").replace(" UTC", "").strip()
        try:
            entry_time = datetime.strptime(raw_date, "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
        except ValueError:
            continue

        stored_headline = entry.get("content", "").split("\n")[0]
        stored_kw = extract_keywords(stored_headline)

        if entry_time >= cutoff_long:
            stored_cves = {k for k in stored_kw if k.lower().startswith("cve-")}
            if candidate_cves and (candidate_cves & stored_cves):
                print(f"Duplicate (CVE match, 7d): {candidate_cves & stored_cves}")
                return True

            stored_entities = extract_entities(stored_headline)
            ent_overlap = candidate_entities & stored_entities
            if len(ent_overlap) >= DUPLICATE_MIN_ENTITY_MATCHES:
                print(f"Duplicate (entity match, 7d): {ent_overlap}")
                return True

        if entry_time >= cutoff_general:
            overlap = candidate_kw & stored_kw
            if len(overlap) >= DUPLICATE_MIN_MATCHES:
                print(f"Duplicate (keyword overlap, 24h): {overlap}")
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
    with open(DB_FILE, "w") as f:
        json.dump(db_data, f, indent=4)


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
        print(f"NVD API Error: {e}")
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
        print(f"KEV fetch error: {e}")
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
        print(f"EPSS fetch error: {e}")
    return None, None


# ─────────────────────────────────────────────
# GROQ — SINGLE CALL
# ─────────────────────────────────────────────
def generate_content(title: str, summary: str, source_name: str) -> dict | None:
    """
    One Groq call. Each output field serves a DISTINCT purpose:
      tweet        — short hook for Twitter, what happened + who
      card_context — EXPANDED background for the card: history, scale, how
                     the attack works, scope. Richer than the tweet.
      card_impact  — who is at risk right now, real-world consequences
      simply_put   — one plain-English sentence for non-technical readers
    Returns None if the article should be skipped.
    """
    client = Groq(api_key=GROQ_API_KEY)

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

  "tweet": "<A comprehensive, long-form X post formatted with line breaks. Lead with the severity emoji and a strong headline. Include three sections: 1. The Breakdown (what happened), 2. The Technical Vector (how the attack/vuln works), and 3. The Impact (who is at risk). Use bullet points (•) where appropriate. End with 'via {source_name}'. ALWAYS include the hashtag #cybersecurity, followed by 2-3 highly specific hashtags related to the threat actor, malware, or targeted software. Target length: 150 to 250 words.>",  "card_context": "<This is the MAIN BODY of the threat card image — it must contain DIFFERENT and RICHER information than the tweet. Include: background on the affected product/org, how the attack vector works (e.g. unauthenticated RCE, supply chain, phishing lure type), known exploitation timeline, and the scale or scope (number of users/systems at risk if stated). 2-3 sentences max. Never repeat the tweet text.>",

  "card_impact": "<Real-world impact statement for the card. What can an attacker DO if this is exploited? What data or access is at stake? Who is concretely affected (enterprises, consumers, specific sectors)? 1-2 sentences. No speculation — only what the article states.>",

  "simply_put": "<One sentence a non-technical person fully understands. Avoid all jargon. Max 110 chars.>"
}}

RULES:
- cve: real CVE IDs only (format CVE-YYYY-NNNNN). Empty string if not in article. Never invent.
- tweet: 210 chars MAX before any post-processing. Complete sentence, not truncated.
- card_context and card_impact must ADD information the tweet does not contain.
- No mitigation advice anywhere.
- All fields strictly factual, sourced only from the article.

ARTICLE:
Title: {title}
Summary: {summary}"""

    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"},
    )

    raw = response.choices[0].message.content.strip()

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        print(f"Failed to parse Groq JSON:\n{raw}")
        return None

    if data.get("skip"):
        return None

    # Validate CVE — reject placeholders
    cve = data.get("cve", "").strip()
    if cve and not CVE_PATTERN.fullmatch(cve):
        print(f"Rejected invalid CVE: '{cve}'")
        data["cve"] = ""

    return data


# ─────────────────────────────────────────────
# THREAT CARD
# ─────────────────────────────────────────────
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
        """Draw a bold coloured tag then wrapped body text on same/next lines."""
        tag_w = tag_font.getlength(tag + " ") if hasattr(tag_font, "getlength") else 80
        # First line: tag + start of text inline
        first_line_x = x + int(tag_w)
        draw.text((x, y), tag, font=tag_font, fill=tag_color)
        # Wrap remaining text starting after the tag
        lines = textwrap.TextWrapper(width=width_chars).wrap(text)[:max_lines]
        for i, line in enumerate(lines):
            if y + lh(body_font) > max_y:
                break
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
        cve_text = cve if len(cve) <= 62 else cve[:59] + "…"
        if epss_score is not None:
            cve_text += f"  (EPSS: {epss_score*100:.1f}%)"
        draw.text((meta_col2_x, row_y), cve_text, font=f_meta_v, fill=accent_color)
        row_y += lh(f_meta_l) + 12

    if target:
        draw.text((MX, row_y), "TARGET:", font=f_meta_l, fill=text_secondary)
        target_text = target if len(target) <= 62 else target[:59] + "…"
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
    print(f"Tweet posted. ID: {response.data['id']}")


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
        print(f"Failed to send Discord alert: {e}")


# ─────────────────────────────────────────────
# MAIN AGENT
# ─────────────────────────────────────────────
def run_agent():
    print("Agent waking up. Checking for new cybersecurity news...")

    # ── Daily cap ────────────────────────────────────────
    todays_count = get_todays_post_count()
    if todays_count >= DAILY_POST_CAP:
        print(f"Daily cap of {DAILY_POST_CAP} reached ({todays_count} today). Exiting.")
        return

    random.shuffle(RSS_FEEDS)
    posted_urls = get_posted_urls()
    db_data     = load_db()   # Loaded once, reused for duplicate check

    for feed_info in RSS_FEEDS:
        print(f"Checking feed: {feed_info['name']}")
        feed = feedparser.parse(feed_info["url"])

        for entry in feed.entries:

            # ── URL dedup ─────────────────────────────────
            if entry.link in posted_urls:
                continue

            print(f"New article found: {entry.title}")

            # ── Age filter ────────────────────────────────
            if hasattr(entry, "published_parsed") and entry.published_parsed:
                article_time = datetime.fromtimestamp(timegm(entry.published_parsed), timezone.utc)
                if datetime.now(timezone.utc) - article_time > timedelta(hours=ARTICLE_MAX_AGE_HOURS):
                    print("Skipping old article.")
                    continue

            # ── Duplicate story check (before Groq call) ──
            if is_duplicate_story(entry.title, db_data):
                save_posted_url(entry.link)   # Mark URL so we don't recheck it
                print("Skipping duplicate story.")
                continue

            try:
                # ── Single Groq call ──────────────────────
                print("Calling Groq...")
                data = generate_content(entry.title, entry.description, feed_info["name"])

                if data is None:
                    save_posted_url(entry.link)
                    print("Skipped (non-threat / filtered content).")
                    continue

                severity_icon = data.get("severity_icon", "🟡")
                cve           = data.get("cve", "").strip()
                threat_actor  = data.get("threat_actor", "").strip()
                target        = data.get("target", "").strip()
                tweet_text    = data.get("tweet", "").strip()
                card_context  = data.get("card_context", "").strip()
                card_impact   = data.get("card_impact", "").strip()
                simply_put    = data.get("simply_put", "").strip()

                # ── Guard against empty/garbage Groq output ──
                if not tweet_text or len(tweet_text.strip()) < 20:
                    print(f"Skipped — tweet_text too short or empty: '{tweet_text}'")
                    save_posted_url(entry.link)
                    continue

                # ── Exact-CVE dedup (catches what title-keyword dedup misses) ──
                if cve and cve_already_covered(cve, days=7):
                    print(f"Skipped — {cve} already covered recently with no status change.")
                    save_posted_url(entry.link)
                    continue

                # ── NVD + KEV + EPSS enrichment ───────────
                kev_flag    = False
                epss_score  = None
                if cve:
                    print(f"Fetching CVSS for {cve}...")
                    cvss_score = get_nvd_cvss(cve)
                    kev_flag = is_in_kev(cve)
                    epss_score, epss_pct = get_epss_score(cve)
                    print(f"KEV: {kev_flag}  EPSS: {epss_score}")

                    try:
                        score_float = float(cvss_score)
                        if score_float >= 9.0:   severity_icon = "🔴"
                        elif score_float >= 7.0: severity_icon = "🟠"
                        elif score_float >= 4.0: severity_icon = "🟡"
                        else:                    severity_icon = "🟢"
                    except ValueError:
                        pass

                    # KEV overrides CVSS-based severity: actively-exploited
                    # vulns are critical regardless of base score (this is
                    # the actual rationale behind CISA BOD 22-01).
                    if kev_flag:
                        severity_icon = "🔴"

                    score_str = (f"{cve} (CVSS: {cvss_score}/10)"
                                 if cvss_score not in ["N/A", "Score Pending"]
                                 else f"{cve} (CVSS: {cvss_score})")
                    if kev_flag:
                        score_str += " [CISA KEV: ACTIVELY EXPLOITED]"
                    if epss_score is not None:
                        score_str += f" [EPSS: {epss_score*100:.1f}%]"

                    # Position-aware trim: score_str (which carries the
                    # KEV/EPSS warning) must never be the part that gets
                    # cut off. Trim the surrounding text instead, splitting
                    # the remaining budget around wherever the CVE sits.
                    if cve in tweet_text:
                        cve_pos = tweet_text.find(cve)
                        before  = tweet_text[:cve_pos]
                        after   = tweet_text[cve_pos + len(cve):]
                        remaining_budget = 278 - len(score_str)
                        if len(before) > remaining_budget:
                            before, after = safe_trim(before, limit=remaining_budget), ""
                        else:
                            after = safe_trim(after, limit=max(0, remaining_budget - len(before)))
                        tweet_text = before + score_str + after
                    else:
                        tweet_text = safe_trim(tweet_text, limit=278)

                # ── Upsert into entity model (vulnerabilities.json / actors.json) ──
                if cve:
                    upsert_vulnerability(
                        cve=cve,
                        title=entry.title,
                        cvss=cvss_score,
                        kev_flag=kev_flag,
                        epss_score=epss_score,
                        source_url=entry.link,
                        product=target,
                    )
                if threat_actor:
                    upsert_actor(
                        actor_name=threat_actor,
                        target=target,
                        title=entry.title,
                        source_url=entry.link,
                    )

                # ── Guarantee emoji leads tweet ───────────
                if not tweet_text.startswith(severity_icon):
                    tweet_text = f"{severity_icon} {tweet_text.lstrip()}"
                    # Re-trim only if adding the emoji pushed us over —
                    # the CVE branch above already protected the score_str,
                    # this is just a final length safety net.
                    tweet_text = safe_trim(tweet_text, limit=278)

                print(f"\nSeverity : {severity_icon}")
                print(f"CVE      : {cve or 'N/A'}")
                print(f"Target   : {target or 'N/A'}")
                print(f"Tweet    : {tweet_text}  [{len(tweet_text)} chars]\n")

                # ── Threat card ───────────────────────────
                card_filename = None
                try:
                    card_filename = generate_threat_card(
                        severity_icon,
                        entry.title,
                        card_context,
                        card_impact,
                        cve,
                        target or threat_actor,
                        simply_put,
                        feed_info["name"],
                        kev_flag,
                        epss_score
                    )
                    print(f"Threat card generated: {card_filename}")
                except Exception as img_e:
                    print(f"Threat card failed: {img_e}")

                # ── Post ──────────────────────────────────
                print("Posting to X...")
                post_tweet(tweet_text, media_path=card_filename)

                # ── Persist ───────────────────────────────
                save_posted_url(entry.link)

                db_data.append({
                    "date":    datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                    "content": tweet_text,
                    "url":     entry.link,
                    "cve":     cve or None,
                    "kev":     kev_flag if cve else None,
                    "epss":    epss_score if cve else None,
                })
                save_db(db_data)

                print("Agent finished successfully. Exiting.")
                return  # One tweet per GitHub Actions run

            except Exception as e:
                print(f"Error processing article: {e}")
                traceback.print_exc()
                return

    print("No new articles found. Exiting.")


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    try:
        run_agent()
    except Exception as e:
        error_details = traceback.format_exc()
        print(f"CRITICAL ERROR: {e}")
        send_discord_alert(error_details)
        raise e
