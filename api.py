"""
CyberNews Auto — read-only REST API.

A FastAPI service that exposes the threat-intelligence data the agent produces
(database.json / vulnerabilities.json / actors.json) over a clean HTTP API.
It is read-only and stateless: it reads the same JSON the static dashboard
uses and reuses scoring.py so risk values match the engine and the dashboard
exactly. No database required.

Run locally:
    uvicorn api:app --reload
Interactive docs:
    http://127.0.0.1:8000/docs

The data directory defaults to this file's folder and can be overridden with
the DATA_DIR environment variable (used by the tests).
"""
import json
import os

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from scoring import compute_risk_score, risk_band
from entity_model import _age_days

DATA_DIR = os.environ.get("DATA_DIR", os.path.dirname(os.path.abspath(__file__)))

app = FastAPI(
    title="CyberNews Auto API",
    version="1.0.0",
    description=(
        "Read-only threat-intelligence API: CVEs (with risk scores), threat "
        "actors, the live feed, unified search, and summary stats. Backed by "
        "the same data as the dashboard."
    ),
)

# Public read-only data — allow any origin (e.g. the GitHub Pages dashboard).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────
# DATA ACCESS (mtime-cached JSON reads)
# ─────────────────────────────────────────────
_cache = {}


def _load(name, default):
    """Load a JSON file from DATA_DIR, cached and invalidated by mtime."""
    path = os.path.join(DATA_DIR, name)
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return default
    hit = _cache.get(name)
    if hit and hit[0] == mtime:
        return hit[1]
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return default
    _cache[name] = (mtime, data)
    return data


def load_feed():
    data = _load("database.json", [])
    return data if isinstance(data, list) else []


def load_vulns():
    data = _load("vulnerabilities.json", {})
    return data if isinstance(data, dict) else {}


def load_actors():
    data = _load("actors.json", {})
    return data if isinstance(data, dict) else {}


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def risk_for_vuln(v):
    """Prefer the engine-persisted score; otherwise compute it live so older
    records (written before scoring existed) still rank consistently."""
    rs = v.get("risk_score")
    if isinstance(rs, int):
        return rs
    return compute_risk_score(
        cvss=v.get("cvss"), epss=v.get("epss"), kev=bool(v.get("kev")),
        age_days=_age_days(v.get("first_seen") or v.get("last_updated") or ""),
    )


def severity_from_content(content):
    c = content or ""
    if "🔴" in c: return "critical"
    if "🟠" in c: return "high"
    if "🟡" in c: return "medium"
    if "🟢" in c: return "low"
    return "unknown"


def cve_model(cve_id, v):
    timeline = v.get("status_timeline", []) or []
    risk = risk_for_vuln(v)
    return {
        "id": cve_id,
        "product": v.get("product"),
        "cvss": v.get("cvss"),
        "kev": bool(v.get("kev")),
        "epss": v.get("epss"),
        "risk_score": risk,
        "risk_band": risk_band(risk),
        "status": timeline[-1]["status"] if timeline else None,
        "first_seen": v.get("first_seen"),
        "last_updated": v.get("last_updated"),
        "status_timeline": timeline,
    }


def actor_model(key, a):
    campaigns = a.get("campaigns", []) or []
    aliases = a.get("aliases", []) or []
    return {
        "name": aliases[0] if aliases else key,
        "aliases": aliases,
        "first_seen": a.get("first_seen"),
        "campaign_count": len(campaigns),
        "campaigns": campaigns,
    }


def paginate(items, limit, offset):
    return {"total": len(items), "limit": limit, "offset": offset,
            "items": items[offset:offset + limit]}


# ─────────────────────────────────────────────
# RESPONSE MODELS
# ─────────────────────────────────────────────
class TimelineEvent(BaseModel):
    date: str | None = None
    status: str | None = None
    summary: str | None = None
    source_url: str | None = None


class CVE(BaseModel):
    id: str
    product: str | None = None
    cvss: float | str | None = None
    kev: bool = False
    epss: float | None = None
    risk_score: int
    risk_band: str
    status: str | None = None
    first_seen: str | None = None
    last_updated: str | None = None
    status_timeline: list[TimelineEvent] = []


class Campaign(BaseModel):
    target: str | None = None
    date: str | None = None
    summary: str | None = None
    source_url: str | None = None


class Actor(BaseModel):
    name: str
    aliases: list[str] = []
    first_seen: str | None = None
    campaign_count: int = 0
    campaigns: list[Campaign] = []


class FeedItem(BaseModel):
    date: str | None = None
    content: str | None = None
    url: str | None = None
    cve: str | None = None
    kev: bool | None = None
    epss: float | None = None
    risk_score: int | None = None
    risk_band: str | None = None


class CVEPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[CVE]


class ActorPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[Actor]


class FeedPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[FeedItem]


class SearchResponse(BaseModel):
    query: str
    total: int
    cves: list[CVE] = []
    actors: list[Actor] = []
    feed: list[FeedItem] = []


# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────
@app.get("/", tags=["meta"])
def root():
    return {
        "name": "CyberNews Auto API",
        "version": app.version,
        "docs": "/docs",
        "endpoints": ["/health", "/api/cves", "/api/cves/{cve_id}",
                      "/api/actors", "/api/actors/{name}", "/api/feed",
                      "/api/search", "/api/stats"],
    }


@app.get("/health", tags=["meta"])
def health():
    return {
        "status": "ok",
        "cves": len(load_vulns()),
        "actors": len(load_actors()),
        "feed": len(load_feed()),
    }


@app.get("/api/cves", response_model=CVEPage, tags=["cves"])
def list_cves(
    kev: bool | None = Query(None, description="Filter to CISA KEV (actively exploited)"),
    min_risk: int = Query(0, ge=0, le=100, description="Minimum risk score"),
    status: str | None = Query(None, description="Latest lifecycle status, e.g. actively_exploited"),
    sort: str = Query("risk", pattern="^(risk|recent)$", description="risk | recent"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    items = [cve_model(cid, v) for cid, v in load_vulns().items()]
    if kev is not None:
        items = [c for c in items if c["kev"] == kev]
    if status:
        items = [c for c in items if c["status"] == status]
    items = [c for c in items if c["risk_score"] >= min_risk]
    if sort == "recent":
        items.sort(key=lambda c: c["last_updated"] or "", reverse=True)
    else:
        items.sort(key=lambda c: c["risk_score"], reverse=True)
    return paginate(items, limit, offset)


@app.get("/api/cves/{cve_id}", response_model=CVE, tags=["cves"])
def get_cve(cve_id: str):
    vulns = load_vulns()
    key = next((k for k in vulns if k.upper() == cve_id.upper()), None)
    if key is None:
        raise HTTPException(status_code=404, detail=f"CVE '{cve_id}' not found")
    return cve_model(key, vulns[key])


@app.get("/api/actors", response_model=ActorPage, tags=["actors"])
def list_actors(
    sort: str = Query("campaigns", pattern="^(campaigns|recent)$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    items = [actor_model(k, a) for k, a in load_actors().items()]
    if sort == "recent":
        items.sort(key=lambda a: a["first_seen"] or "", reverse=True)
    else:
        items.sort(key=lambda a: a["campaign_count"], reverse=True)
    return paginate(items, limit, offset)


@app.get("/api/actors/{name}", response_model=Actor, tags=["actors"])
def get_actor(name: str):
    actors = load_actors()
    key = next((k for k in actors if k.lower() == name.lower()), None)
    if key is None:
        # also match by alias
        for k, a in actors.items():
            if any(al.lower() == name.lower() for al in a.get("aliases", [])):
                key = k
                break
    if key is None:
        raise HTTPException(status_code=404, detail=f"Actor '{name}' not found")
    return actor_model(key, actors[key])


@app.get("/api/feed", response_model=FeedPage, tags=["feed"])
def get_feed(
    kev: bool | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    items = list(reversed(load_feed()))   # newest first
    if kev is not None:
        items = [f for f in items if bool(f.get("kev")) == kev]
    return paginate(items, limit, offset)


@app.get("/api/search", response_model=SearchResponse, tags=["search"])
def search(
    q: str = Query(..., min_length=1, description="CVE id, actor, malware, or vendor"),
    limit: int = Query(20, ge=1, le=100),
):
    ql = q.lower()

    cves = [cve_model(cid, v) for cid, v in load_vulns().items()
            if ql in cid.lower()
            or ql in (v.get("product") or "").lower()
            or any(ql in (e.get("summary") or "").lower() for e in v.get("status_timeline", []) or [])]
    cves.sort(key=lambda c: c["risk_score"], reverse=True)

    actors = [actor_model(k, a) for k, a in load_actors().items()
              if ql in k.lower()
              or any(ql in al.lower() for al in a.get("aliases", []) or [])
              or any(ql in (c.get("summary") or "").lower() or ql in (c.get("target") or "").lower()
                     for c in a.get("campaigns", []) or [])]

    feed = [f for f in reversed(load_feed())
            if ql in (f.get("content") or "").lower() or ql in (f.get("cve") or "").lower()]

    return {
        "query": q,
        "total": len(cves) + len(actors) + len(feed),
        "cves": cves[:limit],
        "actors": actors[:limit],
        "feed": feed[:limit],
    }


@app.get("/api/stats", tags=["stats"])
def stats():
    feed = load_feed()
    vulns = load_vulns()
    actors = load_actors()

    sev = {}
    for f in feed:
        s = severity_from_content(f.get("content"))
        sev[s] = sev.get(s, 0) + 1

    bands = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    products = {}
    for v in vulns.values():
        bands[risk_band(risk_for_vuln(v))] += 1
        p = (v.get("product") or "").strip()
        if p:
            products[p] = products.get(p, 0) + 1

    top = lambda d, n: [{"label": k, "count": c}
                        for k, c in sorted(d.items(), key=lambda kv: kv[1], reverse=True)[:n]]
    actor_counts = {(a.get("aliases") or [k])[0]: len(a.get("campaigns", []) or [])
                    for k, a in actors.items()}

    return {
        "totals": {
            "feed": len(feed),
            "cves": len(vulns),
            "kev": sum(1 for v in vulns.values() if v.get("kev")),
            "actors": len(actors),
        },
        "severity_breakdown": sev,
        "risk_band_breakdown": bands,
        "top_products": top(products, 6),
        "top_actors": top(actor_counts, 6),
    }
