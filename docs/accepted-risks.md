# Accepted Risks

Findings that are known, understood, and deliberately not fixed. Each records
why, and what would change the decision.

---

## PYSEC-2026-1325 — `ecdsa` 0.19.2

**Status:** Accepted
**Recorded:** 2026-09-05
**Component:** `ecdsa`, a transitive dependency of `python-jose`

**Finding.** `pip-audit` reports a vulnerability in `ecdsa` 0.19.2.

**Why it is not fixed.** No patched release exists. 0.19.2 is the latest
version published; there is nothing to upgrade to.

**Why the exposure is limited.** `ecdsa` implements elliptic-curve signing.
This application signs and verifies JWTs with **HS256**, a symmetric HMAC
algorithm, and `backend/config.py` restricts `ALGORITHM` to an allowlist of
`HS256`, `HS384`, `HS512`. No configuration reachable through environment
variables selects an ECDSA algorithm, so the vulnerable code path is not
executed.

**What would change this decision.**
- A patched `ecdsa` release becomes available → upgrade and remove this entry.
- The signing algorithm changes to ES256 or another EC algorithm → the exposure
  becomes real and this must be re-evaluated before that change ships.
- Migration away from `python-jose` (e.g. to `pyjwt`) → removes the dependency
  entirely.

**Review:** re-check on any dependency upgrade, and at minimum whenever the
authentication code is modified.