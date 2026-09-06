"""Request middleware: correlation, timing, and access logging."""

import time

from starlette.middleware.base import BaseHTTPMiddleware

from backend.core.logging_config import correlation_id, get_logger, new_correlation_id

from backend.core.metrics import record_request

logger = get_logger("request")

# Endpoints whose bodies contain credentials. Their paths are logged; nothing
# else about them is.
SENSITIVE_PATHS = {"/auth/login", "/auth/refresh", "/auth/mfa/verify", "/auth/mfa/disable"}


class CorrelationMiddleware(BaseHTTPMiddleware):
    """Assign a correlation ID to every request and log its outcome.

    An inbound X-Correlation-ID is honoured so a trace can span a caller and
    this service, but it is length-capped: an unbounded value from a client
    ends up in every log line the request produces.
    """

    async def dispatch(self, request, call_next):
        incoming = request.headers.get("x-correlation-id", "")
        cid = incoming[:64] if incoming else new_correlation_id()
        token = correlation_id.set(cid)

        started = time.perf_counter()
        status = 500                     # assume failure until proven otherwise

        try:
            response = await call_next(request)
            status = response.status_code
            response.headers["X-Correlation-ID"] = cid
            return response
        finally:
            duration_ms = round((time.perf_counter() - started) * 1000, 1)
            logger.info(
                "request",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "status": status,
                    "duration_ms": duration_ms,
                    # Query strings can carry identifiers; paths alone are safer.
                    "sensitive": request.url.path in SENSITIVE_PATHS,
                },
            )
            correlation_id.reset(token)
            # The route template rather than the concrete path, so
            # /violations/1 and /violations/2 aggregate instead of producing
            # one metric series per id.
            route = request.scope.get("route")
            template = getattr(route, "path", request.url.path)
            record_request(request.method, template, status, duration_ms)