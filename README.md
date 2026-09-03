# AI Compliance Engine

A multi-tenant compliance evaluation platform. It ingests infrastructure
evidence, evaluates it against versioned controls mapped to regulatory clauses,
and produces findings that remain reproducible and auditable months later.

Deterministic rules decide compliance. An AI layer explains findings and drafts
controls, but never assigns a status.

> **Status:** in active development. Phases 0–5 of an eight-phase plan are
> implemented. Not production-certified — see [Limitations](#limitations).

---

## What it does

```
Evidence upload
      │  stored + SHA-256 hashed, never discarded
      ▼
Deterministic rule engine ──► PASS / FAIL / ERROR / INSUFFICIENT_EVIDENCE
      │
      ├─► Findings ──► lifecycle workflow (OPEN → … → CLOSED)
      ├─► Anomaly detection (fitted on tenant history)
      ├─► Posture score (controls passing / controls evaluated)
      └─► AI layer ──► explanations, drafted controls (human-approved)
```

Every finding links to the exact evidence file and the exact control **version**
that produced it, so it can be re-derived and defended later.

---

## Design principles

**Fail closed.** When something cannot be done safely, the system stops and says
so rather than guessing. Missing configuration prevents startup. A control that
cannot be evaluated returns `INSUFFICIENT_EVIDENCE`, never `PASS`. A failed scan
saves nothing.

**AI proposes, deterministic rules decide.** No model output can set a
compliance status. AI explains verdicts the engine already reached and drafts
controls that a human must approve. Proven by a prompt-injection test suite:
even a fully hijacked model cannot change a verdict.

**Evidence over assertion.** Uploaded files are retained and hashed at ingest.
Any finding can be traced to its source, and tampering is detectable.

**Versioned truth.** Editing a control creates a new version; prior versions are
never mutated, so historical findings stay tied to what was actually evaluated.

**Tenant isolation.** Every tenant-owned query filters on organisation, proven
by an automated isolation suite.

---

## Stack

FastAPI · SQLAlchemy · PostgreSQL · Alembic · scikit-learn · ReportLab ·
NVIDIA NIM (Nemotron) · vanilla HTML/CSS/JS

---

## Setup

```bash
git clone https://github.com/meowddler/ai-compliance-engine.git
cd ai-compliance-engine

python -m venv venv
venv\Scripts\Activate.ps1        # Windows
# source venv/bin/activate       # macOS/Linux

pip install -r requirements.txt
```

Create a PostgreSQL database:

```bash
psql -U postgres -c "CREATE DATABASE compliance;"
```

Create `.env` in the project root (see `.env.example`):

```
SECRET_KEY=<python -c "import secrets; print(secrets.token_hex(32))">
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
DATABASE_URL=postgresql+psycopg2://postgres:PASSWORD@localhost:5432/compliance
CORS_ORIGINS=http://127.0.0.1:8000,http://localhost:8000
EVIDENCE_FRESHNESS_DAYS=90

# AI layer (optional — omit to run without live inference)
AI_PROVIDER=nvidia
NVIDIA_API_KEY=
AI_BASE_URL=https://integrate.api.nvidia.com/v1
AI_MODEL=nvidia/nemotron-3-ultra-550b-a55b
```

`SECRET_KEY` and `DATABASE_URL` are required; the application refuses to start
without them.

Create the schema and seed reference data:

```bash
alembic upgrade head
python -m backend.seed_users
python -m backend.seed_rules
python -m backend.seed_frameworks
```

Run:

```bash
uvicorn backend.app:app --reload
```

Open **http://127.0.0.1:8000/login.html**. The backend serves the frontend, so
both share one origin — opening the HTML files directly will not work.

Development accounts: `admin` / `admin123`, `auditor1` / `auditor123`,
`analyst1` / `analyst123`. Override via `ADMIN_PASSWORD` etc. before exposing
the service to a network.

Interactive API docs: **http://127.0.0.1:8000/docs**

---

## Tests

```bash
python -m pytest tests/ -q
```

Covers rule evaluation and its failure modes, API behaviour, tenant isolation,
and prompt-injection resistance. Some tests make live AI calls, so a full run
takes 1–3 minutes.

---

## Development history

Built against an independent audit that scored the original prototype 21/100
with 31 defects.

| Phase | Focus | State |
|---|---|---|
| 0 | Security containment — all 4 critical and 7 high findings | Complete |
| 1 | Domain model — PostgreSQL, Alembic, tenancy, control versioning, frameworks | Complete |
| 2 | Evidence — persistence, hashing, tamper detection, provenance, freshness | Complete |
| 3 | AI layer — provider abstraction, prompt registry, audit trail, injection defence | Complete |
| 4 | Risk and findings — denominator-based posture, finding lifecycle | Complete |
| 5 | Continuous compliance — freshness monitoring, change detection | Core complete |
| 6–8 | Audit hardening, enterprise concerns, deployment | Not started |

Notable fixes: hardcoded JWT secret; four tenant-isolation defects; stored XSS
across four render sites; controls silently passing when a rule could not run or
a data cell was blank; anomaly detection fitted per-batch rather than per-tenant;
a compliance score with no denominator that fell when unchanged data was
re-scanned.

---

## Limitations

Stated plainly rather than discovered later:

- **No background job queue.** Evaluation runs inside the HTTP request. Fine at
  current scale; a queue is required before it is not.
- **No notifications.** Requires SMTP or Slack credentials.
- **No cloud connectors.** Evidence is uploaded manually; automated collection
  from AWS/Azure/Okta requires accounts not available here.
- **No scheduler.** Freshness and re-evaluation logic exists and is side-effect
  free, but is invoked on demand rather than on a timer.
- **Audit log is append-only by convention, not cryptographically chained.**
  Hash chaining is Phase 6.
- **Not penetration tested**, and not certified against any framework.

---

## Disclaimer

A learning and portfolio project. Not a certified compliance product; do not
rely on it for regulatory attestation.