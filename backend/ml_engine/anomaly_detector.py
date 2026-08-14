from sklearn.ensemble import IsolationForest
import pandas as pd

FEATURE_COLUMNS = ["port", "port_exposed", "mfa_enabled", "last_login_days", "failed_logins"]

def detect_anomalies(df):
    """
    Runs Isolation Forest on numeric/boolean features.
    Returns the dataframe with an added 'is_anomaly' column (True/False)
    and an 'anomaly_score' (lower = more anomalous).
    """
    data = df.copy()

    # Convert booleans to 0/1 so the model can use them
    data["port_exposed"] = data["port_exposed"].astype(int)
    data["mfa_enabled"] = data["mfa_enabled"].astype(int)

    X = data[FEATURE_COLUMNS]

    model = IsolationForest(
        n_estimators=100,
        contamination=0.2,  # rough guess: assume ~20% of rows might be anomalous
        random_state=42
    )
    model.fit(X)

    predictions = model.predict(X)          # -1 = anomaly, 1 = normal
    scores = model.decision_function(X)     # lower = more anomalous

    df = df.copy()
    df["is_anomaly"] = predictions == -1
    df["anomaly_score"] = scores.round(3)

    return df