"""
Lightweight, dependency-free near-duplicate detection.

Scores how similar a candidate headline is to a corpus of recently-seen
headlines using the classic vector-space model: each headline becomes a
sparse term vector and similarity is the cosine between vectors. No heavy
dependencies (no PyTorch, no models) — it runs instantly in CI.

Two refinements make it robust for short security headlines:

  * **Stop-word filtering** removes generic English + boilerplate security
    words ("the", "attack", "vulnerability") so only distinctive terms
    (product names, CVE ids, actor names) drive similarity.
  * **TF-IDF weighting with a small-corpus fallback.** When the 7-day window
    holds enough headlines, terms are weighted by inverse document frequency
    so rare/distinctive words count more and common ones less. For a tiny
    corpus (where IDF is statistically meaningless and can even invert), it
    falls back to plain term-frequency cosine.

This is not synonym-level semantics (that needs embeddings) — it is a fast,
free statistical near-duplicate detector that catches reworded headlines.
"""
import math
import re
from collections import Counter

_TOKEN_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")

DEFAULT_THRESHOLD = 0.6
MIN_CORPUS_FOR_IDF = 5   # below this, IDF is unreliable -> plain TF cosine

# Generic words that carry no distinguishing signal in security headlines.
STOPWORDS = {
    "a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "is", "are", "was", "were", "be", "been",
    "has", "have", "had", "its", "it", "this", "that", "as", "via", "into",
    "under", "over", "after", "before", "new", "now", "more", "amid",
    "security", "cyber", "attack", "attacks", "flaw", "flaws", "bug", "bugs",
    "vulnerability", "vulnerabilities", "exploit", "exploits", "threat",
    "threats", "hacker", "hackers", "report", "reports", "warns", "warning",
}


def tokenize(text: str) -> list:
    """Lowercase tokens with stop-words removed (CVE ids and product-style
    tokens with internal punctuation are preserved)."""
    return [t for t in (tok.lower() for tok in _TOKEN_RE.findall(text or ""))
            if t not in STOPWORDS]


def _cosine(a: dict, b: dict) -> float:
    if not a or not b:
        return 0.0
    if len(a) > len(b):
        a, b = b, a
    dot = sum(weight * b.get(term, 0.0) for term, weight in a.items())
    na = math.sqrt(sum(w * w for w in a.values()))
    nb = math.sqrt(sum(w * w for w in b.values()))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


def max_similarity(candidate: str, corpus: list) -> float:
    """Maximum cosine similarity between `candidate` and any string in
    `corpus`. Returns 0.0 for an empty corpus."""
    if not corpus:
        return 0.0

    cand_tokens = tokenize(candidate)
    corpus_tokens = [tokenize(c) for c in corpus]
    n = len(corpus_tokens)

    idf = None
    default_idf = 1.0
    if n >= MIN_CORPUS_FOR_IDF:
        df = Counter()
        for toks in corpus_tokens:
            for t in set(toks):
                df[t] += 1
        idf = {t: math.log(n / (1 + df_t)) + 1.0 for t, df_t in df.items()}
        default_idf = math.log(n) + 1.0   # for terms unseen in the corpus

    def vec(tokens):
        tf = Counter(tokens)
        if idf is None:                    # small-corpus fallback: plain TF
            return dict(tf)
        return {t: c * idf.get(t, default_idf) for t, c in tf.items()}

    cand_vec = vec(cand_tokens)
    return max((_cosine(cand_vec, vec(toks)) for toks in corpus_tokens), default=0.0)


def is_semantic_duplicate(candidate: str, corpus: list,
                          threshold: float = DEFAULT_THRESHOLD) -> bool:
    """True if `candidate` is at least `threshold` cosine-similar to any item
    in `corpus`."""
    return max_similarity(candidate, corpus) >= threshold
