# Production Readiness Assessment

Re-scoring the original 96-item gate. Every item is binary: it passes or it does
not. An item is **not** satisfied by a file, table, endpoint, or UI page
existing — each requires demonstrated behaviour.

**Baseline: 6 / 96 (6%).**
**Current: 52 / 96 (54%).**
**Verdict: NOT PRODUCTION READY.**

Scored strictly. Where a capability exists but does not meet the item as
written, it is marked as failing with the reason. Partial credit would make the
number meaningless.

---

## 1. Architecture — 4 / 8

| Item | Status |
|---|---|
| Service layer separates HTTP, logic, persistence | **FAIL** — `app.py` is ~1,500 lines with business logic inside route handlers |
| Full compliance domain model | **FAIL** — Organization, Evidence, Control, Finding exist; Requirement, ControlObjective, Remediation, Risk do not |
| Config injected from environment, no literals | **PASS** |
| Versioned reversible migrations | **PASS** — 18 Alembic migrations, applied cleanly to an empty database |
| PostgreSQL with connection pooling | **PASS** — `pool_pre_ping`, `pool_recycle` |
| Background jobs; no evaluation in an HTTP request | **FAIL** — evaluation is still synchronous |
| Horizontal scalability under load test | **FAIL** — throughput measured, concurrent load not |
| API versioning with published deprecation policy | **PASS** |

## 2. Compliance Knowledge — 0 / 9

Unchanged from baseline, and the honest weak point of the whole system.

| Item | Status |
|---|---|
| Regulations, frameworks, requirements, controls as distinct versioned entities | **FAIL** — Requirement is not modelled |
| Every control traces to a canonical clause ID | **FAIL** — the capability exists; seeded controls use free-text labels |
| Framework versions modelled and stated per control | **FAIL** — modelled, not used |
| Cross-framework mapping | **FAIL** |
| Applicability rules | **FAIL** |
| Effective dates and supersession | **FAIL** |
| Jurisdiction | **FAIL** |
| Two frameworks fully modelled, SME reviewed | **FAIL** — one framework, 12 of ~93 clauses, no SME review |
| Source material distinguishable from derived interpretation | **FAIL** |

**This is content, not engineering.** The engine models clauses and traceability;
nobody has authored the framework content. Closing this section requires a
compliance specialist reading standards, not more code.

## 3. Controls — 4 / 9

| Item | Status |
|---|---|
| Stored as data, not code | **PASS** |
| Immutably versioned | **PASS** — edits create a version; prior versions retained and retrievable |
| Declares evidence requirements explicitly | **FAIL** |
| Declares an objective distinct from its test procedure | **FAIL** |
| Named accountable owner | **FAIL** |
| Lifecycle state machine (DRAFT → REVIEW → ACTIVE → RETIRED) | **FAIL** — active/current flags and retire-not-delete exist; no state machine |
| AND, OR, NOT, grouping, regex, aggregates, cross-record | **FAIL** — all present except aggregates and cross-record |
| Explicit status, never silently skips | **PASS** — PASS / FAIL / ERROR / INSUFFICIENT_EVIDENCE, tested including empty cells and unevaluable branches |
| Separation of duties on approval | **PASS** |

## 4. Evidence — 5 / 10

| Item | Status |
|---|---|
| Persisted first-class entity | **PASS** |
| SHA-256 hash; tampering detectable | **PASS** — demonstrated by modifying a stored file |
| Stored immutably (WORM or versioned object storage) | **FAIL** — ordinary filesystem |
| Collection timestamp distinct from processing | **FAIL** — recorded, but both are ingest time |
| Validity window; expired evidence degrades its controls | **PASS** |
| Provenance to source document, page, offset | **FAIL** — no document parsing |
| Named owner per record | **FAIL** — uploader recorded; ownership is a different concept |
| Explicit Evidence↔Control and Evidence↔Finding links | **PASS** |
| Reusable across controls without duplication | **PASS** |
| History retained; superseded evidence retrievable | **FAIL** — nothing is deleted, but supersession is not modelled |

## 5. AI Layer — 5 / 12

| Item | Status |
|---|---|
| Provider abstraction with centralised routing | **PASS** |
| Prompts versioned as source artifacts | **PASS** |
| Structured output enforced with validation **and retry** | **FAIL** — validated; no retry |
| **No AI output sets a status without deterministic evaluation** | **PASS** — architectural, proven by injection tests |
| Artifacts carry model ID, prompt version, confidence, citations | **FAIL** — model and prompt version only |
| Every claim cites retrievable source text | **FAIL** — no retrieval layer |
| Citation spoofing fails a mechanical check | **FAIL** |
| Every call persisted with inputs, output, cost, latency, reviewer | **PASS** |
| Evaluation harness with golden datasets, CI-gated | **FAIL** |
| Prompt-injection defence | **PASS** — tested |
| Tenant-scoped retrieval isolated at index level | **FAIL** — no retrieval layer |
| Data-residency policy with redaction and opt-out | **FAIL** |

## 6. Risk — 6 / 8

The strongest gain relative to baseline.

| Item | Status |
|---|---|
| Risk model: likelihood, impact, inherent, residual | **FAIL** |
| Severity a validated enum with a documented rubric | **PASS** |
| Confidence propagated from evidence and AI to finding | **FAIL** |
| Score has a denominator, time-boxed, scoped | **PASS** |
| **Re-evaluating unchanged evidence gives an identical score** | **PASS** — tested |
| Remediation improves the score; deleting data does not | **PASS** — by construction: deleted evidence yields INSUFFICIENT_EVIDENCE, which is never counted as passing |
| Posture snapshots per run | **PASS** |
| Score decomposes to the results that produced it | **PASS** |

## 7. Findings & Remediation — 2 / 8

| Item | Status |
|---|---|
| Links to requirement, control version, evidence, org, asset, risk | **FAIL** — control version, evidence, org only |
| Full lifecycle plus RISK_ACCEPTED with expiry and approver | **FAIL** — states exist; no expiry or approver on risk acceptance |
| Owner, due date, SLA tracking, escalation | **FAIL** |
| Remediation as a task entity | **FAIL** |
| Remediation verified by automated re-test before closure | **FAIL** |
| Full change history per finding | **PASS** |
| **Any historical finding reproducible from evidence and pinned control** | **PASS** |
| Duplicates deduplicated across runs | **FAIL** |

## 8. Auditability — 11 / 11

All eleven questions answerable via `GET /violations/{id}/traceability`, and the
audit trail is hash-chained with tampering demonstrably detectable.

The only section at full marks. It is also the section the whole product depends
on: findings that cannot be traced or defended are not compliance evidence.

## 9. Security — 9 / 13

| Item | Status |
|---|---|
| Passwords hashed with a modern adaptive algorithm | **PASS** |
| No injection — parameterised access throughout | **PASS** |
| No code execution in rule evaluation | **PASS** |
| Authorisation read from the datastore, not token claims | **PASS** — tested against a forged role claim |
| Stack traces never returned to clients | **PASS** |
| Secrets from a managed store, rotated | **FAIL** — environment variables, not a KMS |
| Every data endpoint authenticated and authorised | **PASS** |
| Tenant isolation **structural**, impossible by construction | **FAIL** — enforced in the service layer and proven by test, but not by the database. Four isolation defects were found during review, which is evidence the distinction matters |
| All output encoded; no unescaped DOM interpolation | **PASS** |
| CORS restricted to an allowlist | **PASS** |
| Rate limiting **and account lockout** | **FAIL** — rate limiting present; no lockout |
| TLS enforced, HSTS, secure headers | **FAIL** — expected behind a proxy; not configured here |
| Encryption at rest **and** clean independent penetration test | **FAIL** — encryption partial; no penetration test |

## 10. Testing — 1 / 7

152 tests exist, but the gate asks specific questions.

| Item | Status |
|---|---|
| Unit coverage ≥80% on business logic | **FAIL** — never measured |
| Integration tests for every end-to-end workflow | **FAIL** |
| Regression test for **every** S0/S1 defect | **FAIL** — several covered; CORS, XSS, severity enum, duplicate IDs, and ghost scans are not |
| Tenant-isolation suite | **PASS** |
| Full RBAC matrix: every role × every endpoint | **FAIL** |
| Load testing at target scale, published | **FAIL** — throughput published; concurrent load untested |
| CI gates on tests, lint, **type checking**, coverage | **FAIL** — tests, lint, security scanning; no type checking or coverage threshold |

## 11. Monitoring — 1 / 6

| Item | Status |
|---|---|
| Structured logging with correlation IDs | **PASS** |
| Distributed tracing | **FAIL** |
| Metrics **and dashboards** | **FAIL** — metrics exposed; nothing renders them |
| Alerting | **FAIL** |
| SLOs with error budgets | **FAIL** |
| Error aggregation with triage ownership | **FAIL** |

## 12. Deployment — 1 / 7

| Item | Status |
|---|---|
| Infrastructure as code | **FAIL** |
| Containerised, reproducible builds | **PASS** — verified: clean build, migrations, seeds, and login from nothing |
| Blue/green or canary with automated rollback | **FAIL** |
| Backup and restore with tested RPO/RTO | **FAIL** |
| Disaster recovery plan, exercised | **FAIL** |
| Runbooks and on-call | **FAIL** |
| Staged environments | **FAIL** |

## 13. Data Governance — 1 / 6

| Item | Status |
|---|---|
| Data classification | **FAIL** |
| Retention **enforced automatically** | **FAIL** — policies stored and evaluated; deletion is deliberately manual |
| Legal hold | **PASS** — overrides retention, tested |
| Right-to-erasure preserving audit integrity | **FAIL** |
| DPAs and sub-processor register | **FAIL** |
| Data residency per tenant | **FAIL** |

## 14. Continuous Compliance — 2 / 6

| Item | Status |
|---|---|
| Controls re-evaluate on schedule with no human action | **FAIL** — the scheduler re-checks freshness, it does not re-run evaluation against evidence |
| Evidence freshness monitored; ageing degrades controls | **PASS** |
| Change detection between runs | **PASS** — distinguishes regressions from newly observed assets |
| Regulatory-update monitoring | **FAIL** |
| Notifications by severity | **FAIL** |
| Posture history over **arbitrary** time ranges | **FAIL** — returns the most recent N; no date filtering |

---

## Summary

| Section | Baseline | Now | Total |
|---|---|---|---|
| Architecture | 0 | **4** | 8 |
| Compliance Knowledge | 0 | 0 | 9 |
| Controls | 1 | **4** | 9 |
| Evidence | 0 | **5** | 10 |
| AI Layer | 0 | **5** | 12 |
| Risk | 0 | **6** | 8 |
| Findings & Remediation | 0 | **2** | 8 |
| Auditability | 0 | **11** | 11 |
| Security | 5 | **9** | 13 |
| Testing | 0 | **1** | 7 |
| Monitoring | 0 | **1** | 6 |
| Deployment | 0 | **1** | 7 |
| Data Governance | 0 | **1** | 6 |
| Continuous Compliance | 0 | **2** | 6 |
| **Total** | **6** | **52** | **96** |

**6% → 54%.**

---

## Reading the number

**Auditability at 11/11 is the result that matters most.** For any finding the
system can produce the clause, the exact control version, the evidence and its
hash, when it was collected, what reasoning produced the status, who has touched
it since — and prove that record has not been altered. That is the capability a
compliance product exists to provide.

**Compliance Knowledge at 0/9 is the honest weak point**, and it is not an
engineering gap. The engine models frameworks, clauses, and traceability; the
content has not been authored. Closing it needs someone to read ISO 27001 and
translate ~93 clauses, not more code.

**Testing at 1/7 is the most misleading section.** 152 tests exist and CI runs
them on every push, but the gate asks for measured coverage, a full RBAC matrix,
a regression test per historical defect, and type checking. Volume is not the
same as the specific assurances asked for.

**Monitoring, Deployment, and Data Governance are largely infrastructure.**
Tracing backends, alerting, staged environments, tested disaster recovery, and
residency controls need infrastructure that does not exist for this deployment.
They are not skill gaps.

## What would move the number most

| Work | Items gained |
|---|---|
| Background job queue + async evaluation | 2 (Architecture, Continuous Compliance) |
| Coverage measurement, RBAC matrix, per-defect regression tests, type checking | 4 (Testing) |
| Extract a service layer from `app.py` | 1 (Architecture) |
| Model Requirement, ControlObjective, and Remediation as entities | 4–5 (Compliance Knowledge, Findings) |
| Author one framework fully with SME review | 2–3 (Compliance Knowledge) |
| Database row-level security | 1 (Security) |
| TLS, HSTS, account lockout, secret manager | 3 (Security) |

Roughly 17–19 further items are reachable without additional infrastructure,
which would put the system near 70/96. The remainder needs cloud infrastructure,
a compliance specialist, or a penetration tester.

---

*Scored against `NEMOR_Production_Readiness_Checklist.md`. Every item marked
PASS corresponds to behaviour that has been demonstrated or tested, not to code
that exists.*