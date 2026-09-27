# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Stage 1: build a wheel cache in an isolated layer so the runtime image never
# carries compilers, headers, or pip's build cache.
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2: slim runtime — just the interpreter, the installed packages, and
# the application code, running as a non-root user.
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

ARG APP_UID=10001
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --gid ${APP_UID} sentinelai \
    && useradd --uid ${APP_UID} --gid sentinelai --shell /bin/false --no-create-home sentinelai \
    && apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local
COPY app ./app

# SQLite fallback data directory — writable by the app user when no
# DATABASE_URL is supplied and the platform runs entirely offline.
RUN mkdir -p /app/data && chown -R sentinelai:sentinelai /app

USER sentinelai
ENV SQLITE_PATH=/app/data/sentinel_ai.db

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/liveness || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
