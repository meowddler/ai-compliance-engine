# Multi-stage build. The final image carries the application and its runtime
# dependencies, not the toolchain used to compile them — a smaller image is
# also a smaller attack surface.

FROM python:3.12-slim AS builder

WORKDIR /build

# Build tools are needed for packages with C extensions (psycopg2, bcrypt,
# scikit-learn) and are discarded with this stage.
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


FROM python:3.12-slim

# Run as an unprivileged user. A container process running as root that is
# compromised is a host process running as root.
RUN groupadd --system app && useradd --system --gid app --create-home app

# libpq is the runtime half of libpq-dev; the compiler is not carried forward.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

WORKDIR /app
COPY --chown=app:app backend/ ./backend/
COPY --chown=app:app frontend/ ./frontend/
COPY --chown=app:app alembic/ ./alembic/
COPY --chown=app:app alembic.ini ./

# Evidence is written at runtime and must survive a container restart, so this
# path is expected to be a mounted volume. Created here so the directory exists
# and is writable even when no volume is attached.
RUN mkdir -p /app/evidence_store && chown -R app:app /app/evidence_store

USER app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

# Uses the application's own liveness endpoint rather than a TCP check: a
# process can hold the port open while being unable to serve a request.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/ || exit 1

# Migrations are NOT run here. An image that migrates on start would have every
# replica racing to alter the schema during a rolling deploy. Migration is a
# deliberate step in the deployment sequence — see docs/deployment.md.
CMD ["uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "8000"]