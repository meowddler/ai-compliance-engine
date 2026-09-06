# Phase 7 — Enterprise Hardening

**Completion report**

Records what was built, what was not, and what an assessor should not assume.
Items marked NOT IMPLEMENTED or BLOCKED are stated as such deliberately.

---

## 1. Objectives

| # | Objective | Status |
|---|---|---|
| 1 | Rate limiting per tenant | **Complete** |
| 2 | Upload size and row limits | **Complete** |
| 3 | Pagination on list endpoints | **Complete** |
| 4 | Structured logging with correlation IDs | **Complete** |
| 5 | Operational and business metrics | **Complete** |
| 6 | Performance benchmarking at target scale | **Complete** |
| 7 | Rule engine optimisation | **Complete** |
| 8 | API versioning and deprecation policy | **Complete** |
| 9 | Admin tooling: tenant and user management | **Complete** |
| 10 | Usage metering | **Complete** |
| 11 | Support impersonation with full audit | **Complete** |
| 12 | Connection pooling | **Complete** (Phase 6) |
| 13 | Read replicas | **BLOCKED** — requires infrastructure |
| 14 | Multi-region deployment and data residency | **BLOCKED** — requires cloud infrastructure |
| 15 | OpenTelemetry tracing | **NOT IMPLEMENTED** — requires a collector |
| 16 | SLOs and alerting | **NOT IMPLEMENTED** — requires a monitoring backend |
| 17 | Backup, restore, tested RPO/RTO | **NOT IMPLEMENTED** — requires infrastructure |
| 18 | Load and chaos testing | **NOT IMPLEMENTED** — requires a cluster |
| 19 | Caching layer | **NOT IMPLEMENTED** — not yet justified by measurement |

**11 complete, 2 blocked on infrastructure, 6 not implemented.**

---

## 2. Performance results

Measured on the development machine, five rules of mixed complexity including a
nested expression tree. Reproducible via `python -m benchmarks.benchmark_engine`.

| Rows | Evaluations | Time | Rows/sec |
|---|---|---|---|
| 100 | 500 | 0.01s | 9,645 |
| 1,000 | 5,000 | 0.03s | 36,516 |
| 10,000 | 50,000 | 0.26s | 38,854 |
| 50,000 | 250,000 | 1.32s | 37,852 |
| **100,000** | **500,000** | **2.46s** | **40,579** |

**The roadmap's 100,000-record target is met.**

Throughput at 100,000 rows is 1.11× throughput at 1,000 rows — scaling is
linear, with no hidden quadratic behaviour. That was the property worth
establishing; a design that degrades superlinearly fails only at customer scale,
where it is most expensive to discover.

### Optimisation

Profiling, not guesswork, identified two costs — neither in the rule logic:

| Cost | Share of runtime | Fix |
|---|---|---|
| `DataFrame.iterrows()` | ~34% | `to_dict("records")`; the engine needs mapping access, not a pandas Series per row |
| `json.loads` per rule **per row** | ~12% | Parse each condition once and cache it on the rule |

Result: **3.05× faster**, byte-identical output. The second finding is the more
instructive one — a 20,000-row file with five rules was parsing the same JSON
100,000 times to produce a value that never changed.

### The honest caveat

2.46 seconds is the *evaluation* time. Persisting 500,000 results adds more, and
the request is synchronous. **The engine is fast enough; the delivery mechanism
is the constraint.** Evaluation at this scale belongs in a background job, which
remains unimplemented — the benchmark prints this rather than leaving the
implication to a reader.

---

## 3. What was built

**Rate limiting.** Per-organisation rather than per-IP, because behind a proxy or
NAT many users share an address — IP limiting either punishes innocent users or
fails to constrain a determined one. Tiered by cost and risk: 10/min on auth,
20/hour on AI, 60/min on writes, 300/min on reads. The organisation is read from
the token without a database lookup, and the signature is verified first, so a
forged org id cannot borrow another tenant's allowance.

This closes the gap the Phase 6 threat model named as most serious: login
previously accepted unlimited password attempts.

**Upload limits.** 10 MB and 100,000 rows, enforced by reading in bounded chunks
and stopping at the limit — reading the whole body and checking afterwards would
mean the memory was already spent.

**Pagination.** 50 per page by default, capped server-side at 500. A client
asking for a million rows is mistaken or hostile; either way the server should
not comply.

**Structured logging.** JSON with a per-request correlation ID returned in
`X-Correlation-ID`, so a user reporting a problem can quote a value that locates
their logs. Secrets are redacted before emission, because logs are frequently
shipped to systems with weaker access controls than the database.

**Metrics.** Request volume with p50/p95/p99 latency, plus durable business
counts. The endpoint distinguishes in-process counters that reset on restart
from database aggregates that do not, so nobody reads a volatile number as a
lifetime total.

**API versioning.** A published contract stating what counts as a breaking
change and a 90-day minimum deprecation notice, with RFC 8594 headers. Prompted
by an actual incident: adding pagination changed three endpoints from returning
an array to `{items, pagination}`, which would have broken any integrator
without warning.

**Admin tooling.** Tenant and user management scoped to the caller's own
organisation, usage metering that reports units without inventing prices, and
support impersonation that requires a substantive reason, bounds the session,
records the real actor in the token, and is visible to auditors — a support
feature its own organisation cannot review is a backdoor.

---

## 4. What was not built, and why

**Read replicas, multi-region, data residency.** Require cloud infrastructure
that does not exist for this deployment.

**OpenTelemetry tracing.** Instrumentation is writable; a collector to receive
the spans is not. Correlation IDs provide a coarser equivalent — a request's
records can be tied together, but not its spans across services.

**SLOs and alerting.** Metrics are exposed but nothing consumes them. Defining
an SLO without a system that can alert on its breach is documentation, not
operations.

**Backup, restore, and tested RPO/RTO.** The roadmap is explicit that these must
be *tested*, and an untested backup is an assumption. Testing requires
infrastructure to restore into.

**Load and chaos testing.** Needs a cluster to disrupt. The single-process
benchmark measures throughput, not resilience.

**Caching.** Deliberately not added. Measurement shows dashboard queries at
3–40ms; caching would add invalidation complexity to solve a problem that does
not yet exist.

---

## 5. Known limitations

**In-process metrics do not survive a restart or span instances.** Behind a load
balancer each process would report its own slice. A shared store is required
before the numbers mean anything at scale.

**Rate limiting is also in-process.** Limits are per instance, so N instances
permit N times the configured rate. Correct behaviour needs a shared backend.

**Pagination uses offsets.** Deep pages get slower because the database counts
rows it will discard. Acceptable at target scale; cursor pagination is the
answer if result sets reach millions.

**Admin tooling is single-tenant.** An operator manages only their own
organisation. Cross-tenant administration would need a separate operator role
that does not exist, and adding one would need care — it is precisely the
capability that could defeat the isolation the rest of the system enforces.

**Usage metering has no cost model.** It reports consumption. Attaching prices
without invoice reconciliation would be fiction.

**The benchmark measures one machine.** Results will differ on other hardware,
and no measurement has been taken under concurrent load.

---

## 6. Position

Throughput is measured rather than assumed, the largest denial-of-service gap is
closed, requests are traceable end to end, and the operational surface —
metrics, versioning, admin tooling — exists.

What remains for Phase 7's full scope is infrastructure-dependent: replicas,
multi-region, tracing backends, tested disaster recovery, and load testing at
scale. Those are not skill gaps; they are deployment prerequisites, and they
belong with Phase 8.

**Test count: 141.** Every push runs the suite, lint, static security analysis,
and a dependency audit.

---

*Phase 7 of an eight-phase plan. Phase 8 covers production deployment.*