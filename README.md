# 🎯 SkillMatch — Job Recommendation Engine

A job search engine that ranks live listings against a user's skills using **BM25** — the ranking function behind Elasticsearch and Lucene — with **Jaccard similarity** computed alongside it for comparison.

**Live demo:** https://skillmatch-vyva.onrender.com

> The demo runs on a free tier that sleeps when idle. The first request after a quiet period takes ~30–60s to wake the container; everything after that is fast.

---

## What it does

Enter your skills as free text or a comma-separated list. The engine scores every indexed job listing, ranks them by relevance, and returns the top matches with matched terms highlighted.

```
Skills in  →  BM25 scores the corpus  →  Jaccard re-scores the candidates  →  Ranked jobs out
```

---

## The interesting part: why the ranking works

### Why BM25 over TF-IDF

BM25 refines TF-IDF in two ways that matter for this data:

- **Term-frequency saturation.** A listing mentioning "Python" ten times isn't ten times more relevant than one mentioning it once. TF-IDF scales linearly; BM25 flattens the curve.
- **Length normalisation.** A verbose listing shouldn't outrank a focused one purely because it has more text to match against.

### Why Jaccard is still here

The original approach to this problem used Jaccard similarity — plain set overlap. It's kept because the comparison is instructive rather than decorative.

Searching `java spring boot`, a listing whose skills are exactly `["Java", "Spring Boot"]` scores a **perfect 1.0 Jaccard** — total overlap. BM25 ranks fuller, more specific listings above it. Jaccard rewards *brevity*: a short skill list is mathematically easier to fully overlap with. Both scores are returned by the API so the difference is observable, not theoretical.

### The background corpus

This is the part I'd point at in a review.

BM25's IDF component measures how rare a term is across the collection — it's what stops a generic tag from outweighing a distinctive skill. But the live corpus is only ~3,800 listings, which makes those statistics noisy. There isn't enough evidence to tell a rare skill apart from a common one.

So IDF is estimated from a **much larger archived corpus of 31,970 listings** and those values are applied when ranking the live set. Using a large background collection to obtain reliable term statistics for a smaller target collection is standard practice in information retrieval.

The scale of the problem it solves: in the archive, the generic tag `"IT Skills"` appears in **6,323 of 31,970 listings**. Without reliable IDF, it would carry the same weight as `"Kubernetes"`.

The IDF formula matches `rank_bm25`'s `BM25Okapi._calc_idf` exactly — using a different formula would put the background values on a different scale to the ones they replace.

---

## Architecture

```
Jooble API  ─┐
             ├─→  fetch_jobs.py  →  dedupe  →  Supabase (jobs table)
Adzuna API  ─┘                                       │
                                                     ▼
archived corpus (31,970)  ──→  IDF estimation  ──→  BM25 index  ──→  FastAPI  ──→  browser
       (local JSON)                                                      │
                                                                    Jaccard
                                                                  re-scoring
```

**Two-stage search.** BM25 scores the full corpus and selects a candidate pool; Jaccard re-scores only that pool. This mirrors how production recommenders separate candidate generation from re-ranking — cheap ranking across everything, more expensive scoring on a shortlist.

**Graceful degradation.** If Supabase is unreachable or unconfigured, the app falls back to a committed local JSON snapshot and still starts. `GET /api/health` reports which path was taken, so a silent fallback in production is visible rather than mysterious.

**The archive stays on disk deliberately.** It's static reference data used only for IDF estimation — putting it behind a network call would add latency and a failure mode for no benefit.

---

## Data

| | |
|---|---|
| Live listings | ~3,800 (Jooble + Adzuna, India) |
| Background corpus | 31,970 archived listings |
| Storage | Supabase (Postgres), local JSON fallback |

### Sourcing

Listings come from **Adzuna** and **Jooble**, both of which offer free public APIs. LinkedIn, Wellfound and Internshala were evaluated and ruled out — none offers public API access, and the only routes to their data are paid third-party scrapers operating against those platforms' terms of service. Everything here uses officially sanctioned access.

Adzuna contributes the large majority of records: it returns up to 50 results per page against Jooble's ~20, and full descriptions rather than truncated snippets.

### Cleaning

The archived corpus had real quality problems worth documenting:

| Issue | Scale | Handling |
|---|---|---|
| Duplicate listings (same job scraped under multiple search terms) | 21,190 of 53,160 (~40%) | Deduplicated by URL |
| `>` prefix artifacts in skill strings | 43 records | Stripped |
| Case-inconsistent duplicate skills within a listing | Widespread | Normalised |

Deduplication matters beyond tidiness. IDF measures how rare a term is *across the collection* — leaving 21,190 duplicates in would have systematically distorted those statistics.

Live records are deduplicated on both URL and a normalised `(title, company)` key, since the same listing appears on both aggregators under different URLs.

---

## Tech stack

| Layer | Tech |
|---|---|
| Backend | Python, FastAPI |
| Ranking | rank-bm25 (BM25Okapi), custom Jaccard implementation |
| Database | Supabase (Postgres) with row-level security |
| Data sources | Adzuna API, Jooble API |
| Frontend | Vanilla HTML/CSS/JS — no framework, no build step |
| Testing | pytest |
| Hosting | Render |

---

## API

| Endpoint | Description |
|---|---|
| `GET /api/search?q=<skills>&top_k=20` | Ranked results with BM25 and Jaccard scores |
| `GET /api/health` | Index status, corpus sizes, and active data source |
| `GET /docs` | Interactive documentation (auto-generated) |

---

## Setup

```bash
git clone https://github.com/meowddler/skillmatch.git
cd skillmatch

python -m venv venv
venv\Scripts\Activate.ps1      # Windows
# source venv/bin/activate     # macOS/Linux

pip install -r requirements.txt
uvicorn backend.app:app --reload
```

Open **http://127.0.0.1:8000**

> The app must run through uvicorn — FastAPI serves both the API and the frontend. Opening `index.html` directly, or via a static server, will fail because `/api/search` won't exist.

### Environment

Create a `.env` at the project root. All values are optional — the app falls back to the local snapshot without them.

```
SUPABASE_URL=...
SUPABASE_KEY=...        # publishable/anon key, not the service role key
JOOBLE_API_KEY=...      # only needed to refresh data
ADZUNA_APP_ID=...
ADZUNA_APP_KEY=...
```

### Refreshing the data

```bash
python backend/fetch_jobs.py          # pull from both APIs into data/jobs_live.json
python backend/upload_to_supabase.py  # push to Supabase
```

The `jobs` table has row-level security enabled with a select-only policy, so the publishable key can read but not write. Seeding requires a temporary insert policy, dropped immediately afterwards.

---

## Tests

```bash
python -m pytest tests/ -v
```

Covers tokenisation (including `C++`, `C#`, `.NET`), Jaccard arithmetic, ranking behaviour, background-corpus IDF, Supabase loading and fallback, and every API endpoint.

One test documents a genuine BM25 edge case: a term appearing in *every* document of a corpus gets an IDF at or near zero, so a single-document corpus scores everything zero and returns nothing. That's BM25 behaving correctly, and it's precisely the small-corpus problem the background corpus exists to solve.

---

## Known limitations

- **Exact-token matching.** "ML" won't match "Machine Learning" — BM25 operates on tokens, not meaning. A semantic embedding layer would address this.
- **No formal evaluation.** Ranking quality is assessed qualitatively. A labelled query set with Precision@K would make this rigorous.
- **Source imbalance.** Adzuna's fuller descriptions give it more terms to match on, so it dominates results even where Jooble holds comparable listings.
- **India-scoped.** Both fetchers are configured for the Indian market.
- **Cold starts.** Free-tier hosting sleeps when idle.

---

## Attribution

Job listing data is retrieved from the Adzuna and Jooble public APIs. The archived corpus originates from a publicly available scraped dataset. The search engine, ranking pipeline, data pipeline, API and interface were built independently.