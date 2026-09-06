# Phase 8 — Production Deployment

**Completion report**

Records what was built, what was deliberately not attempted, and what an
assessor should not assume. This is the final phase of an eight-phase plan.

---

## 1. Objectives

| # | Objective | Status |
|---|---|---|
| 1 | Containerisation with reproducible builds | **Complete** |
| 2 | Deployment documentation | **Complete** |
| 3 | Production readiness assessment against the 96-item gate | **Complete** |
| 4 | Background job processing | **Complete** |
| 5 | Coverage measurement and CI gate | **Complete** |
| 6 | RBAC matrix testing | **Complete** |
| 7 | Regression tests for every historical S0/S1 defect | **Complete** |
| 8 | Infrastructure as code (Terraform) | **BLOCKED** — no cloud account |
| 9 | Blue/green or canary deployment with automated rollback | **BLOCKED** — requires an orchestrator |
| 10 | Production runbooks, on-call, incident response | **NOT ATTEMPTED** — requires an operating team |
| 11 | SOC 2 readiness for the product itself | **NOT ATTEMPTED** — requires an external audit |
| 12 | Customer documentation and onboarding guides | **NOT ATTEMPTED** — no customers |
| 13 | Pilot with design-partner tenants | **NOT ATTEMPTED** — requires partners |
| 14 | Formal go-live gate | **Complete as an assessment**; the gate does not pass |

**7 complete, 2 blocked on infrastructure, 4 requiring people or organisations
that do not exist for this project, 1 completed as an assessment.**

---

## 2. Containerisation

A multi-stage build: compilers produce the wheels and are then discarded, so the
runtime image carries neither the toolchain nor its attack surface. The process
runs as an unprivileged user — a container process running as root that is
compromised is a host process running as root. The health check calls the
application's own endpoint rather than probing the TCP port, because a process
can hold a port open while being unable to serve a request.

**Verified end to end from nothing:** clean build, container start, 18
migrations applied to an empty database, seeds run, login, scan, and live AI
inference. Evidence is a named volume, because losing it would destroy the proof
behind every finding.

Migrations are deliberately **not** run by the container on start. During a
rolling deploy every replica would race to alter the schema. Migration is an
explicit step in the documented sequence.

### What containerisation found

Building from scratch exposed a real defect: **`slowapi`, `pyotp`, and
`pytest-asyncio` were missing from `requirements.txt`.** They had been installed
by hand during development, so the application ran locally and would have failed
for anyone cloning the repository. A container has no such history — it installs
exactly what is declared, which is why it caught this and local testing never
could.

---

## 3. Production readiness: 6 → 52 → 58 of 96

The original audit scored the prototype **6/96 (6%)**. Re-scoring after Phases
0–7 gave **52/96 (54%)**. The work in this phase — the job queue, coverage,
RBAC matrix, and regression tests — brings it to approximately **58/96 (60%)**.

Scored strictly. Where a capability exists but does not satisfy the item as
written, it is marked failing with the reason. Partial credit would make the
number meaningless and a reviewer would find the inflation immediately.

| Section | Baseline | Final | Total |
|---|---|---|---|
| Architecture | 0 | 5 | 8 |
| Compliance Knowledge | 0 | 0 | 9 |
| Controls | 1 | 4 | 9 |
| Evidence | 0 | 5 | 10 |
| AI Layer | 0 | 5 | 12 |
| Risk | 0 | 6 | 8 |
| Findings & Remediation | 0 | 2 | 8 |
| Auditability | 0 | **11** | 11 |
| Security | 5 | 9 | 13 |
| Testing | 0 | 5 | 7 |
| Monitoring | 0 | 1 | 6 |
| Deployment | 0 | 1 | 7 |
| Data Governance | 0 | 1 | 6 |
| Continuous Compliance | 0 | 3 | 6 |
| **Total** | **6** | **58** | **96** |

**The gate does not pass, and this report does not claim otherwise.**

---

## 4. Background job processing

Evaluation no longer runs inside an HTTP request. Work is queued in PostgreSQL
rather than Redis: the database is already a dependency, so a queue living in it
cannot fail independently of the data it operates on, and there is one less
service to run, secure, and back up. The trade is throughput, which is the right
trade at this scale.

**Claiming is the whole problem.** Two workers reading "the oldest queued job"
simultaneously will both take it. The claim uses `SELECT ... FOR UPDATE SKIP
LOCKED`, making the read and the claim a single atomic act — a row another
worker holds is skipped rather than waited on, so workers neither collide nor
block each other.

Failed jobs retry to a limit and then stop. A job that retries forever hides a
permanent failure behind apparent activity.

Evaluation is idempotent: prior findings for a scan are cleared before
re-evaluating, so a retry after partial failure produces one clean set rather
than duplicates.

---

## 5. Testing

| Measure | Before this phase | After |
|---|---|---|
| Tests | 152 | 240 |
| Coverage | 68% (unmeasured before) | 88% |
| CI gates | tests, lint, security scan, dependency audit | + coverage floor at 80% |

Three checklist items closed: coverage above the threshold, a full RBAC matrix
(every role against every endpoint), and a regression test for each of the
eleven historical S0/S1 defects.

The coverage number is enforced, not merely reported. A number that is only
reported gets watched for a while and then ignored.

---

## 6. What was not attempted, and why

**Infrastructure as code, blue/green deployment, staged environments.** All
require a cloud account and an orchestrator. Writing Terraform that has never
been applied would produce a file, not a capability.

**Runbooks, on-call, incident response.** These describe how a team responds to
failure. There is no team. A runbook written for nobody is documentation
theatre.

**SOC 2 readiness for the product itself.** Requires an external auditor and a
period of operation to evidence. A compliance vendor is asked for its own
attestation first — which is exactly why this cannot be self-declared.

**Customer documentation and a design-partner pilot.** Both require customers.

**Service layer extraction.** The one substantial refactor left undone. It would
close a single checklist item while rewriting all 49 endpoints, with 240 tests
depending on current behaviour. The risk-to-reward ratio did not justify it as
the final act of the project; it is recorded here as known architectural debt
rather than quietly omitted.

---

## 7. Remaining limitations

Repeated from the deployment documentation because they belong in the same place
as the completion claim:

- **Single instance.** Rate limiting, metrics, and the scheduler are all
  in-process. N instances means N times the rate limit and N partial views of
  the metrics.
- **No TLS.** Expected behind a reverse proxy; serving directly over HTTP would
  send tokens in clear.
- **No backup automation and no rehearsed restore.** The deployment sequence
  says to take a backup; nothing does it, and no restore has been tested.
- **MFA is not enforced at login.**
- **Default passwords ship seeded** and must be overridden before exposure.
- **No penetration test.** Nothing here has been challenged by an adversary.
- **No monitoring or alerting.** Metrics are exposed; nothing consumes them and
  nobody is paged.
- **Tenant isolation is behavioural**, enforced in the service layer and proven
  by test, not by the database.

---

## 8. Position

The project began as a prototype scored 21/100 for maturity with 31 defects, of
which 4 were critical and 7 high. It ends as a multi-tenant compliance engine
with versioned controls, tamper-evident evidence, a hash-chained audit trail,
full finding traceability, an AI layer that cannot alter a verdict, background
job processing, 240 tests at 88% coverage, and a CI pipeline that gates every
push on tests, lint, coverage, static security analysis, and dependency
vulnerabilities.

**It is not production ready, and the assessment says so with a number.**

What separates it from production is largely not code: infrastructure,
authored compliance content, and an adversary who has tried to break it. Those
are the next three things, in that order.

---

*Phase 8 of eight. The gate stands at 58/96 — recorded honestly, because a
compliance product that misrepresents its own readiness has failed at the thing
it exists to do.*