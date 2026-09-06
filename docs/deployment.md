# Deployment

How to run this system, and what must be true before it is exposed to a network.

---

## 1. Before anything else

The application refuses to start without `SECRET_KEY` and `DATABASE_URL`. That
is deliberate: a service that boots with a missing secret is more dangerous than
one that will not boot at all.

**Generate real secrets. Do not reuse the development values.**

```bash
# Signing key — minimum 32 characters, enforced at startup
python -c "import secrets; print(secrets.token_hex(32))"

# Encryption keys — two, so rotation can be exercised before it is needed
python -c "from cryptography.fernet import Fernet; print('k1:' + Fernet.generate_key().decode()); print('k2:' + Fernet.generate_key().decode())"
```

---

## 2. Environment

| Variable | Required | Notes |
|---|---|---|
| `SECRET_KEY` | **Yes** | ≥32 chars. Startup fails without it. |
| `DATABASE_URL` | **Yes** | No default — a silent fallback to SQLite would let the app appear to work against an empty local file. |
| `ALGORITHM` | No | `HS256`. Constrained to an allowlist; `none` is rejected. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | No | Default 60. Access tokens are stateless and cannot be revoked, so short lifetimes are what bound a compromise. |
| `CORS_ORIGINS` | No | Empty by default, which permits nothing. Set to the real front-end origin. |
| `EVIDENCE_FRESHNESS_DAYS` | No | Default 90. Evidence older than this degrades its controls. |
| `MAX_UPLOAD_BYTES` | No | Default 10 MB. |
| `MAX_UPLOAD_ROWS` | No | Default 100,000. |
| `ENCRYPTION_KEYS` | Recommended | `k1:<key>,k2:<key>`. Absent means values are stored as plaintext. |
| `ENCRYPTION_ACTIVE_KEY_ID` | With keys | Which key encrypts new writes. |
| `AI_PROVIDER` | No | `nvidia` or `stub`. `stub` returns clearly-labelled placeholder text. |
| `NVIDIA_API_KEY` | For AI | Omit to run without live inference. |
| `ADMIN_PASSWORD` etc. | **Before exposure** | Overrides the seeded development passwords. |

`.env.example` lists every key with empty values. `.env` is git-ignored and must
never be committed.

---

## 3. Docker (recommended)

```bash
cp .env.example .env        # then fill it in
docker compose up -d --build
```

Migrations are **not** run by the container on start. That is deliberate: during
a rolling deploy every replica would race to alter the schema. Run them as an
explicit step:

```bash
docker compose exec app alembic upgrade head
docker compose exec app python -m backend.seed_users
docker compose exec app python -m backend.seed_rules
docker compose exec app python -m backend.seed_frameworks
```

Then open `http://localhost:8000/login.html`.

### What the container does and does not do

- Runs as an unprivileged user. A container process running as root that is
  compromised is a host process running as root.
- Multi-stage build: compilers are used to build wheels and then discarded, so
  the runtime image carries neither the toolchain nor its attack surface.
- Health check hits the application's own endpoint rather than the TCP port — a
  process can hold a port open while being unable to serve a request.
- Evidence is a named volume. It must outlive the container; losing it destroys
  the proof behind every finding.
- **Single instance.** No load balancer, no replicas. See section 6.

---

## 4. Manual installation

```bash
python -m venv venv
venv\Scripts\Activate.ps1          # Windows
# source venv/bin/activate         # macOS/Linux
pip install -r requirements.txt

createdb compliance                # or: psql -U postgres -c "CREATE DATABASE compliance;"
alembic upgrade head
python -m backend.seed_users
python -m backend.seed_rules
python -m backend.seed_frameworks

uvicorn backend.app:app
```

The backend serves the frontend, so both share one origin. Opening the HTML
files directly from disk will not work — CORS will reject the API calls, which
is the allowlist behaving correctly.

---

## 5. Deployment sequence

Order matters. Migrating after replacing the application means the new code
briefly runs against an old schema.

```
1. Back up the database.            An untested backup is an assumption; take
                                    one you have restored from before.
2. Apply migrations.                alembic upgrade head — once, not per replica.
3. Deploy the new application.
4. Verify.                          /  → 200
                                    /version → expected version
                                    /audit/verify → valid: true
                                    /admin/scheduler → tasks healthy
5. Watch the logs.                  Correlation IDs tie a failing request to
                                    everything it touched.
```

### Rolling back

Application rollback is straightforward: deploy the previous image.

**Migration rollback is not.** `alembic downgrade` exists but has never been
exercised against production data here, and a downgrade that drops a column
destroys whatever was in it. Treat a forward fix as the default and a downgrade
as a last resort taken from a backup.

---

## 6. What is not production-ready

Stated here rather than discovered later.

**Single instance.** Rate limiting and metrics are both in-process. With N
instances you get N times the configured rate limit and N partial views of the
metrics. Both need a shared backend before horizontal scaling means anything.

**The scheduler runs in every instance.** Its two tasks are idempotent, so
duplicate execution is wasteful rather than harmful — but any task added later
needs a distributed lock first.

**No backup automation, and no tested restore.** The deployment sequence says
"back up the database"; nothing here does it for you, and no restore has been
rehearsed. An untested backup is a hope.

**No TLS termination.** Expected to sit behind a reverse proxy. Serving this
directly over HTTP would send tokens in clear text.

**MFA is not enforced at login.** Enrolment works; enforcement needs an
out-of-band recovery channel that does not exist here.

**Default passwords ship seeded.** `admin/admin123` and the rest. Override them
via environment variables before the service is reachable by anyone.

**No penetration test.** Nothing here has been challenged by an adversary.

**No monitoring or alerting.** Metrics are exposed; nothing consumes them.
Nobody is paged when something breaks.

---

## 7. Pre-exposure checklist

Before this service is reachable from a network other than your own machine:

- [ ] `SECRET_KEY` generated fresh, ≥32 characters
- [ ] `DATABASE_URL` points at a database with a strong password
- [ ] `ENCRYPTION_KEYS` set — otherwise sensitive values are plaintext
- [ ] `ADMIN_PASSWORD`, `AUDITOR_PASSWORD`, `ANALYST_PASSWORD` overridden
- [ ] `CORS_ORIGINS` set to the real origin, not a wildcard
- [ ] TLS terminated by a reverse proxy
- [ ] Database port not published to the host or the internet
- [ ] A backup taken, and a restore rehearsed at least once
- [ ] `/audit/verify` returns `valid: true`
- [ ] Full test suite green
- [ ] `docs/threat-model.md` read, and its residual risks accepted knowingly

The last item is the one most easily skipped and least safely skipped.