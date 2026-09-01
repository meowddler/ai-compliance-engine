"""Anomaly detection.

Fitted on an organization's HISTORY, with a threshold derived from that
history's own score distribution.

Why (audit finding S2-01): the previous implementation called fit() on each
uploaded batch, so "anomalous" meant "unusual compared to the other rows in
this file" — the same server was normal in a 5-row file and anomalous in a
30-row file. It also hardcoded contamination=0.2, which manufactured anomalies
on clean data.

This version:
  * fits the baseline on the organization's past observations
  * sets the anomaly threshold at a percentile of the HISTORY's scores, so the
    cutoff is explainable ("worse than 99% of what we have seen before")
  * refuses to score at all when there is too little history, instead of
    scoring a batch against itself
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

FEATURE_COLUMNS = ["port", "port_exposed", "mfa_enabled", "last_login_days", "failed_logins"]

DETECTOR_VERSION = "isolation-forest-v2-history-p1"

# Below this many historical observations a baseline is not meaningful.
MIN_BASELINE_ROWS = 20

# A row is anomalous if it scores lower than this percentile of the history's
# own scores. 1.0 => "worse than 99% of everything previously observed".
ANOMALY_PERCENTILE = 1.0

_MODEL_PARAMS = dict(n_estimators=200, contamination="auto", random_state=42)


def _prepare(df):
    data = df.copy()
    for col in FEATURE_COLUMNS:
        if col not in data.columns:
            data[col] = 0
    for boolcol in ("port_exposed", "mfa_enabled"):
        data[boolcol] = data[boolcol].astype(str).str.lower().isin(["true", "1", "yes"]).astype(int)
    for numcol in ("port", "last_login_days", "failed_logins"):
        data[numcol] = pd.to_numeric(data[numcol], errors="coerce").fillna(0)
    return data[FEATURE_COLUMNS]


def extract_features(row):
    """Feature snapshot for one row, stored as history for future baselines."""
    return {col: (row.get(col) if hasattr(row, "get") else None) for col in FEATURE_COLUMNS}


def detect_anomalies(df, history_df=None):
    """Score `df` against a baseline built from `history_df`.

    Returns (df_with_results, metadata).
    """
    result = df.copy()
    baseline_rows = 0 if history_df is None else len(history_df)

    if baseline_rows < MIN_BASELINE_ROWS:
        result["is_anomaly"] = False
        result["anomaly_score"] = None
        return result, {
            "scored": False,
            "reason": (f"Insufficient baseline: {baseline_rows} historical observations, "
                       f"{MIN_BASELINE_ROWS} required. Rows were not scored rather than "
                       f"scored against themselves."),
            "baseline_rows": baseline_rows,
            "threshold": None,
            "detector_version": DETECTOR_VERSION,
        }

    X_hist = _prepare(history_df)
    X_new = _prepare(df)

    model = IsolationForest(**_MODEL_PARAMS)
    model.fit(X_hist)

    # Threshold from the history's own distribution — explainable, and it does
    # not assume a fixed anomaly rate in the new batch.
    hist_scores = model.decision_function(X_hist)
    threshold = float(np.percentile(hist_scores, ANOMALY_PERCENTILE))

    new_scores = model.decision_function(X_new)
    result["is_anomaly"] = new_scores < threshold
    result["anomaly_score"] = np.round(new_scores, 3)

    return result, {
        "scored": True,
        "reason": None,
        "baseline_rows": baseline_rows,
        "threshold": round(threshold, 4),
        "detector_version": DETECTOR_VERSION,
    }