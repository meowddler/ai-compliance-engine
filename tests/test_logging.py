"""Structured logging tests.

Two properties matter: a correlation ID ties a request's records together, and
secrets never reach a log. Logs are frequently shipped to systems with weaker
access controls than the database, so a token in a log line is a token in
someone else's storage.
"""
import json
import logging

from fastapi.testclient import TestClient

from backend.app import app
from backend.core.logging_config import (
    JsonFormatter, correlation_id, new_correlation_id,
)

client = TestClient(app)


def _format(record_kwargs=None, message="test", level=logging.INFO):
    """Run a record through the formatter and return the parsed JSON."""
    record = logging.LogRecord("test", level, __file__, 1, message, (), None)
    for k, v in (record_kwargs or {}).items():
        setattr(record, k, v)
    return json.loads(JsonFormatter().format(record))


def test_output_is_valid_json_with_expected_fields():
    """Line-delimited JSON is what aggregators consume; a malformed line is a
    lost record."""
    parsed = _format(message="hello")
    for field in ("timestamp", "level", "logger", "message", "correlation_id"):
        assert field in parsed, field
    assert parsed["message"] == "hello"


def test_extras_are_included():
    parsed = _format({"path": "/violations", "status": 200, "duration_ms": 12.3})
    assert parsed["path"] == "/violations"
    assert parsed["status"] == 200


def test_secrets_are_redacted_from_log_extras():
    parsed = _format({
        "password": "hunter2",
        "access_token": "eyJhbGciOi.secret.value",
        "api_key": "sk-live-123",
        "username": "amy",
    })
    assert parsed["password"] == "[REDACTED]"
    assert parsed["access_token"] == "[REDACTED]"
    assert parsed["api_key"] == "[REDACTED]"
    assert parsed["username"] == "amy"          # ordinary fields survive


def test_nested_secrets_are_redacted():
    parsed = _format({"body": {"user": "amy", "password": "hunter2",
                               "nested": {"refresh_token": "abc"}}})
    assert parsed["body"]["password"] == "[REDACTED]"
    assert parsed["body"]["nested"]["refresh_token"] == "[REDACTED]"
    assert parsed["body"]["user"] == "amy"


def test_correlation_id_appears_in_records():
    token = correlation_id.set("abc123")
    try:
        assert _format()["correlation_id"] == "abc123"
    finally:
        correlation_id.reset(token)


def test_exceptions_are_captured():
    try:
        raise ValueError("boom")
    except ValueError:
        import sys
        record = logging.LogRecord("test", logging.ERROR, __file__, 1,
                                   "failed", (), sys.exc_info())
        parsed = json.loads(JsonFormatter().format(record))
    assert "exception" in parsed
    assert "ValueError" in parsed["exception"]


# --- Middleware behaviour -------------------------------------------------

def test_response_carries_a_correlation_id():
    """A user reporting a problem can quote this value to locate their logs."""
    r = client.get("/")
    assert "x-correlation-id" in {k.lower() for k in r.headers}
    assert len(r.headers["x-correlation-id"]) > 0


def test_each_request_gets_a_distinct_id():
    a = client.get("/").headers["x-correlation-id"]
    b = client.get("/").headers["x-correlation-id"]
    assert a != b


def test_inbound_correlation_id_is_honoured():
    """Allows a trace to span a caller and this service."""
    r = client.get("/", headers={"X-Correlation-ID": "caller-supplied-id"})
    assert r.headers["x-correlation-id"] == "caller-supplied-id"


def test_inbound_correlation_id_is_length_capped():
    """An unbounded client-supplied value would appear in every log line the
    request produces."""
    r = client.get("/", headers={"X-Correlation-ID": "x" * 500})
    assert len(r.headers["x-correlation-id"]) <= 64


def test_generated_ids_are_unique():
    assert len({new_correlation_id() for _ in range(200)}) == 200