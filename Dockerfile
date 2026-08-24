# syntax=docker/dockerfile:1

FROM python:3.13-slim@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a AS wheels

ARG REPO_PATH="."
WORKDIR /build
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends git gcc ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY ${REPO_PATH}/constraints.txt ${REPO_PATH}/requirements.txt ./
RUN pip wheel --no-cache-dir --wheel-dir /wheels \
    --constraint constraints.txt --requirement requirements.txt

FROM python:3.13-slim@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a

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
