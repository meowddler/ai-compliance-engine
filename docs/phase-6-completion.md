# Phase 6 — Security and Auditability Hardening

**Completion report**

Records what was built, what was not, and what an assessor should not assume.
Items marked FOUNDATION ONLY or NOT IMPLEMENTED are stated as such deliberately;
a completion report that claims everything succeeded is not useful to anyone
deciding whether to trust the system.

---

## 1. Objectives

| # | Objective | Status |
|---|---|---|
| 1 | Tamper-evident audit trail | **Complete** |
| 2 | Audit verification API | **Complete** |
| 3 | Rich audit capture (before/after) | **Complete** |
| 4 | Traceability API — 11 auditability questions | **Complete** |
| 5 | Fine-grained permissions | **Complete** |
| 6 | Separation of duties | **Complete** |
| 7 | Token lifecycle: refresh, rotation, revocation | **Complete** |
| 8 | Session management | **Complete** |
| 9 | Encryption at rest with key rotation | **Complete** |
| 10 | Data retention policies | **Complete** |
| 11 | Legal hold | **Complete** |
| 12 | Security test suite | **Complete** |
| 13 | CI pipeline with security gates | **Complete** |
| 14 | Threat model | **Complete** |
| 15 | Security architecture documentation | **Complete** |
| 16 | Multi-factor authentication | **FOUNDATION ONLY** |
| 17 | SSO / OIDC / SAML | **NOT IMPLEMENTED** |
| 18 | Rate limiting | **NOT IMPLEMENTED** |
| 19 | Penetration test | **NOT PERFORMED** |
| 20 | Read-access auditing | **NOT IMPLEMENTED** |

---

## 2. Acceptance criteria

| # | Criterion | Met | Evidence |
|---|---|---|---|
| 1 | Every material mutation produces an audit event | Yes | 9 call sites; `AuditLog` rows for scans, control create/update/delete, finding lifecycle, reports, resets, holds |
| 2 | Audit entries are hash-chained | Yes | `backend/utils/audit_chain.py`; each entry hashes content + predecessor |
| 3 | Tampering is detectable | Yes | Demonstrated by direct database modification; `GET /audit/verify` returned `payload_modified` at the exact sequence |
| 4 | Verification is exposed via API | Yes | `GET /audit/verify`, `POST /audit/checkpoint` |
| 5 | All 11 auditability questions answerable | Yes | `GET /violations/{id}/traceability` |
| 6 | Before/after state captured | Yes | Controlled snapshots via `snapshot_rule`, `snapshot_finding` |
| 7 | Authorisation is capability-based | Yes | `backend/core/permissions.py`; endpoints check capabilities |
| 8 | Separation of duties enforced | Yes | Admin cannot approve; Auditor cannot author; tests assert both |
| 9 | Role claims cannot escalate privilege | Yes | Role read from database; test signs a valid Admin-claiming token for an Analyst and asserts 403 |
| 10 | Encryption supports key rotation without data loss | Yes | Ciphertext tagged with key id; test rotates and asserts old values remain readable |
| 11 | Refresh tokens rotate and can be revoked | Yes | Rotation on use; replay revokes the family; tests cover both |
| 12 | Retention and legal hold enforced | Yes | Hold overrides retention; audit log never deletable; tests assert precedence |
| 13 | Security regression suite exists | Yes | 91 tests, including forged tokens, `alg: none`, expiry, escalation, injection, isolation |
| 14 | CI enforces security gates | Yes | pytest, ruff, bandit, pip-audit on every push |
| 15 | Threat model documented | Yes | `docs/threat-model.md` — 22 threats with residual risk |
| 16 | MFA available | Partial | Enrolment works; **not enforced at login** |
| 17 | SSO available | No | Requires an identity provider |

**14 of 17 fully met, 1 partial, 2 not met.**

---

## 3. What was built

**Tamper-evident audit trail.** Entries are hash-chained, each covering its own
content and the previous entry's hash. Verification walks the chain and names
the exact sequence where a break occurs, distinguishing a modified payload from
a deleted or reordered entry. The canonical serialization is versioned, because
altering it would invalidate every existing hash.

**Traceability.** One endpoint answers the eleven auditability questions for any
finding, each answer carrying the data it was derived from so a reviewer can
check the reasoning rather than trust a summary.

**Capability-based authorisation with separation of duties.** Roles are bundles
of capabilities defined in one place; an unknown role receives the empty set.
Admin can author controls but not approve them, Auditor the reverse.

**Token lifecycle.** Refresh tokens are stored hashed and rotate on use. Replay
of a rotated token revokes the entire family, on the reasoning that it is
unknowable whether the legitimate user or a thief holds the newer token.

**Encryption with rotation.** Ciphertext carries the id of the key that produced
it, so changing the active key leaves historical data readable and a partial
rotation recoverable.

**Data governance.** Retention policies are stored, owned, and audited. Legal
holds override retention. Audit history is never deletable by retention.
Evaluation reports; it never deletes.

**CI with security gates.** Tests against a real PostgreSQL, defect-scoped lint,
`bandit`, and `pip-audit` on every push.

---

## 4. Defects found during this phase

CI and lint surfaced problems the test suite had not:

| Defect | Severity | Impact |
|---|---|---|
| `build_anomaly_map` called but never defined | **High** | Every scan upload returned 500. Missed by tests because none upload a CSV through the API |
| Naive `datetime.utcnow()` in `freshness.py` | Medium | Comparison against timezone-aware timestamps raised `TypeError` |
| Blocking file write inside an async handler | Medium | Stalls the event loop for the duration of every upload |
| `log_action` committing the caller's transaction | Medium | An audit call could commit unrelated pending work |
| Rule deletion orphaning findings | Medium | Would have destroyed traceability; now retires instead of deleting |
| Six unused imports, one unused variable | Low | Noise |

The first is the clearest argument for CI: a green test suite coexisted with a
completely broken upload path.

---

## 5. What was not built, and why

**MFA is not enforced at login.** Enrolment, encrypted secrets, and single-use
recovery codes all work. Enforcement requires an out-of-band recovery channel —
email or SMS — that this deployment does not have. Shipping enforcement without
recovery would permanently lock out any user who lost their device. The API
reports `enforced_at_login: false` rather than implying protection it does not
provide.

**SSO is not implemented.** OIDC and SAML require an identity provider to
integrate with and test against. None is available.

**Rate limiting is absent.** This is the largest open gap. Login and the AI
endpoints are both unprotected, and the AI endpoints are synchronous and can
hold a connection for up to a minute. On a network-exposed deployment this is
the first thing an attacker would reach for.

**No penetration test.** Nothing here has been validated by an adversary.

**Read access is not audited.** "Who viewed this finding" cannot be answered.

---

## 6. Known limitations of what was built

Stated because each is a real boundary, not a rough edge:

**The hash chain does not survive a database administrator.** An actor with
unrestricted write access can recompute the entire chain and leave it internally
consistent. Hash chaining detects ad-hoc tampering, not a wholesale rewrite.
Checkpoints narrow this only if the head hash is recorded outside the database —
and `GET /audit/verify` says so in its own response.

**Tenant isolation is behavioural, not structural.** Every query filters
correctly and tests prove it, but nothing prevents the next query from omitting
the filter. Four such defects were found during review, which is evidence the
risk is real. Database row-level security would make the guarantee structural.

**Evidence integrity is verified on demand, not continuously.** A file altered
today is not noticed until someone checks.

**Encryption covers evidence paths and MFA secrets only.** Findings, control
definitions, and audit entries are stored in plaintext. Keys live in environment
variables, not a key management service.

**91 tests is not comprehensive.** They cover the paths that were reasoned
about. The undefined-function defect existed precisely because no test exercised
the upload path end to end.

---

## 7. Position

The system can now demonstrate, for any finding, what caused it, what evidence
supported it, which control version produced it, who has touched it since, and
that the record of all of this has not been altered. That is the capability this
phase existed to build, and it works.

It is not production-ready. The absence of rate limiting alone makes it
unsuitable for network exposure, and nothing has been tested by an adversary.

**Recommended before any deployment:** rate limiting, upload size limits, MFA
enforcement with a recovery channel, and a penetration test.

---

*Phase 6 of an eight-phase plan. Phases 7 and 8 cover enterprise concerns and
deployment.*