"""Compliance posture scoring.

Replaces the score removed in Phase 0 (S0-02), which had no denominator, only
ever decreased, and reported an empty database as 100% compliant.

This version:
  * has a real denominator — controls evaluated in the most recent scan
  * is scoped to the LATEST scan, so it reflects current posture and improves
    when problems are remediated
  * is deterministic — the same evidence and control set always produce the
    same score
  * refuses to invent a number when nothing has been evaluated
  * decomposes on demand into the counts that produced it

Statuses that count toward the denominator are those the engine actually
evaluated. INSUFFICIENT_EVIDENCE and ERROR are NOT counted as passes — a
control we could not verify must never inflate the score.
"""

RUBRIC_VERSION = "posture-v1"

# Severity weights: a failing HIGH control costs more than a failing LOW one.
SEVERITY_WEIGHTS = {"HIGH": 3.0, "MEDIUM": 2.0, "LOW": 1.0}
DEFAULT_WEIGHT = 1.0

# Statuses that represent a completed evaluation (they form the denominator).
EVALUATED_STATUSES = {"PASS", "FAIL"}
# Statuses that mean we could not conclude — surfaced separately, never a pass.
UNVERIFIED_STATUSES = {"INSUFFICIENT_EVIDENCE", "ERROR", "EVALUATION_ERROR"}


def compute_posture(results):
    """Compute posture from a list of evaluation results.

    results: iterable of dicts with 'status' and 'severity'.

    Returns a dict with the score, its inputs, and the rubric version, so any
    score can be decomposed into exactly the results that produced it.
    """
    counts = {}
    weighted_possible = 0.0
    weighted_passed = 0.0

    for r in results:
        status = (r.get("status") or "").upper()
        severity = (r.get("severity") or "").upper()
        counts[status] = counts.get(status, 0) + 1

        if status in EVALUATED_STATUSES:
            w = SEVERITY_WEIGHTS.get(severity, DEFAULT_WEIGHT)
            weighted_possible += w
            if status == "PASS":
                weighted_passed += w

    evaluated = counts.get("PASS", 0) + counts.get("FAIL", 0)
    unverified = sum(counts.get(s, 0) for s in UNVERIFIED_STATUSES)

    if evaluated == 0:
        # Nothing was evaluated. We do NOT return 100 — an unevaluated system
        # is not a compliant one. This was the original defect.
        return {
            "score": None,
            "scored": False,
            "reason": "No controls were evaluated; posture cannot be computed.",
            "controls_evaluated": 0,
            "controls_passed": 0,
            "controls_failed": 0,
            "controls_unverified": unverified,
            "status_counts": counts,
            "rubric_version": RUBRIC_VERSION,
        }

    score = round((weighted_passed / weighted_possible) * 100, 1) if weighted_possible else 0.0

    return {
        "score": score,
        "scored": True,
        "reason": None,
        "controls_evaluated": evaluated,
        "controls_passed": counts.get("PASS", 0),
        "controls_failed": counts.get("FAIL", 0),
        "controls_unverified": unverified,
        "weighted_passed": round(weighted_passed, 2),
        "weighted_possible": round(weighted_possible, 2),
        "status_counts": counts,
        "rubric_version": RUBRIC_VERSION,
    }