"""Rule engine performance benchmark.

Measures evaluation throughput against the roadmap's 100,000-record target.

Run:  python -m benchmarks.benchmark_engine

Kept as a script rather than a test: it takes tens of seconds and measures a
property that varies with hardware, so failing CI on a timing threshold would
produce flaky builds rather than useful signal.
"""

import json
import random
import time

import pandas as pd

from backend.rules.rule_engine import evaluate_dataframe

TARGET_ROWS = 100_000
SIZES = (100, 1_000, 10_000, 50_000, 100_000)


class BenchRule:
    """Stands in for a database Rule without needing a database."""

    def __init__(self, name, condition, severity="HIGH"):
        self.name = name
        self.severity = severity
        self.description = f"benchmark rule {name}"
        self.framework = "ISO 27001"
        self.remediation = "n/a"
        self.condition = json.dumps(condition)


def benchmark_rules():
    """A realistic mix: flat conditions, list membership, and a nested tree."""
    return [
        BenchRule("exposed_port_no_mfa", [
            {"field": "port_exposed", "operator": "==", "value": True},
            {"field": "mfa_enabled", "operator": "==", "value": False},
        ]),
        BenchRule("risky_port_open", [
            {"field": "port", "operator": "in", "value": [22, 3389]},
            {"field": "port_exposed", "operator": "==", "value": True},
        ]),
        BenchRule("excessive_failed_logins", [
            {"field": "failed_logins", "operator": ">", "value": 5},
        ], "MEDIUM"),
        BenchRule("stale_account", [
            {"field": "last_login_days", "operator": ">", "value": 60},
        ], "LOW"),
        BenchRule("prod_needs_protection", {"all": [
            {"field": "port_exposed", "operator": "==", "value": True},
            {"not": {"any": [
                {"field": "mfa_enabled", "operator": "==", "value": True},
                {"field": "vpn_only", "operator": "==", "value": True},
            ]}},
        ]}),
    ]


def make_dataset(n, seed=42):
    random.seed(seed)
    return pd.DataFrame([{
        "server_id": f"srv-{i:06d}",
        "port": random.choice([22, 80, 443, 3389, 8080]),
        "port_exposed": random.choice([True, False]),
        "mfa_enabled": random.choice([True, False]),
        "vpn_only": random.choice([True, False]),
        "last_login_days": random.randint(1, 200),
        "failed_logins": random.randint(0, 20),
    } for i in range(n)])


def main():
    rules = benchmark_rules()
    print(f"Rule engine benchmark — {len(rules)} rules\n")
    print(f"{'rows':>9} {'evaluations':>13} {'seconds':>9} {'rows/sec':>10} {'evals/sec':>11}")
    print("-" * 56)

    results = []
    for n in SIZES:
        df = make_dataset(n)
        started = time.perf_counter()
        evaluate_dataframe(df, benchmark_rules())      # fresh rules: no warm cache
        elapsed = time.perf_counter() - started
        evals = n * len(rules)
        results.append((n, elapsed))
        print(f"{n:>9,} {evals:>13,} {elapsed:>9.2f} {n / elapsed:>10,.0f} {evals / elapsed:>11,.0f}")

    print()

    # Linearity is the property that matters. Throughput holding steady as the
    # dataset grows means no hidden quadratic behaviour — the failure mode that
    # only appears at customer scale.
    small_rate = SIZES[1] / results[1][1]
    large_rate = results[-1][0] / results[-1][1]
    ratio = large_rate / small_rate

    print(f"Throughput at {SIZES[1]:,} rows : {small_rate:,.0f} rows/sec")
    print(f"Throughput at {SIZES[-1]:,} rows: {large_rate:,.0f} rows/sec")
    print(f"Ratio: {ratio:.2f}  ({'linear' if ratio > 0.5 else 'DEGRADING — investigate'})")

    target_time = next(t for n, t in results if n == TARGET_ROWS)
    print(f"\n{TARGET_ROWS:,}-record target: {target_time:.1f}s")
    print("\nNote: this exceeds any reasonable HTTP timeout. Evaluation at this")
    print("scale belongs in a background job, which is not yet implemented.")


if __name__ == "__main__":
    main()