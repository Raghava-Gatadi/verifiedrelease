# Refresh this reviewed multi-platform digest through a pull request.
FROM python:3.13-alpine@sha256:7984cf56ceaddebe4fefeb75d64000b9f45d8b77b11a09b24524da6cdc3af0c8 AS dependencies
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv/ledger
COPY requirements.lock .
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --require-hashes --only-binary=:all: -r requirements.lock

FROM python:3.13-alpine@sha256:7984cf56ceaddebe4fefeb75d64000b9f45d8b77b11a09b24524da6cdc3af0c8 AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PATH="/opt/venv/bin:$PATH"
WORKDIR /srv/ledger
COPY --from=dependencies /opt/venv /opt/venv
COPY pyproject.toml alembic.ini ./
COPY app ./app
COPY alembic ./alembic
RUN addgroup -g 10001 ledger && adduser -D -H -u 10001 -G ledger -s /sbin/nologin ledger
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]

FROM base AS test
USER root
COPY requirements-test.lock .
RUN pip install --require-hashes --only-binary=:all: -r requirements-test.lock
COPY tests ./tests
COPY lab ./lab
COPY scripts ./scripts
USER 10001:10001
ENV PYTEST_ADDOPTS="-p no:cacheprovider" HYPOTHESIS_STORAGE_DIRECTORY=/tmp/hypothesis

FROM base AS runtime
