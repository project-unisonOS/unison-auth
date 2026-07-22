# syntax=docker/dockerfile:1

FROM python:3.14-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6 AS wheels

ARG REPO_PATH="."
WORKDIR /build
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends git gcc ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY ${REPO_PATH}/constraints.txt ${REPO_PATH}/requirements.txt ./
RUN pip wheel --no-cache-dir --wheel-dir /wheels \
    --constraint constraints.txt --requirement requirements.txt

FROM python:3.14-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

ARG REPO_PATH="."
WORKDIR /app
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=wheels /wheels /wheels
RUN pip install --no-cache-dir --no-index /wheels/*.whl \
    && pip uninstall -y pip setuptools wheel \
    && rm -rf /wheels

COPY ${REPO_PATH}/src/ ./src/
COPY ${REPO_PATH}/migrations/ ./migrations/
RUN groupadd -r unison && useradd -r -g unison -u 1000 unison \
    && mkdir -p /keys \
    && chown -R unison:unison /app /keys
USER unison

EXPOSE 8088
CMD ["python", "-m", "uvicorn", "auth_service:app", "--app-dir", "src", "--host", "0.0.0.0", "--port", "8088"]
