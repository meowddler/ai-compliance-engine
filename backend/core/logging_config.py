"""Structured logging with request correlation.

Logs are emitted as JSON so they can be queried rather than grepped. Each entry
carries a correlation ID that ties together everything a single request did —
the audit entry it wrote, the AI call it made, the error it raised. Without
that, diagnosing a production incident means guessing which lines belong
together from their timestamps.

The correlation ID is generated per request and returned in the
`X-Correlation-ID` header, so a user reporting a problem can quote it and the
matching logs can be found directly.

Sensitive values are redacted before emission. Logs are frequently shipped to
third-party systems with weaker access controls than the database, so a token
in a log line is a token in someone else's storage.
"""

import json
import logging
import sys
import uuid
from contextvars import ContextVar

# A ContextVar rather than a global: each concurrent request needs its own
# value, and a module-level variable would leak between them.
correlation_id: ContextVar[str] = ContextVar("correlation_id", default="-")

REDACTED_KEYS = {
    "password", "token", "access_token", "refresh_token", "secret",
    "api_key", "authorization", "cookie", "mfa_secret", "secret_key",
}
REDACTION = "[REDACTED]"


def new_correlation_id() -> str:
    return uuid.uuid4().hex[:16]


def _redact(value, depth=0):
    if depth > 8:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        return {k: (REDACTION if str(k).lower() in REDACTED_KEYS else _redact(v, depth + 1))
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(v, depth + 1) for v in value]
    return value


class JsonFormatter(logging.Formatter):
    """Emit one JSON object per line.

    Line-delimited JSON is what log aggregators expect, and it survives being
    concatenated from multiple processes without needing a parser that
    understands multi-line records.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": correlation_id.get(),
        }

        # Anything passed via extra={...}, minus the standard LogRecord fields.
        standard = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__)
        standard |= {"message", "asctime", "taskName"}
        extras = {k: v for k, v in record.__dict__.items() if k not in standard}
        if extras:
            payload.update(_redact(extras))

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO"):
    """Install the JSON formatter on the root logger.

    Existing handlers are replaced rather than added to, so uvicorn's default
    plain-text handler does not duplicate every line in a second format.
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())

    # uvicorn installs its own handlers; route them through the root logger so
    # access logs share the same format and correlation id.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers.clear()
        lg.propagate = True

    return root


def get_logger(name: str) -> logging.LoggerAdapter:
    return logging.getLogger(name)