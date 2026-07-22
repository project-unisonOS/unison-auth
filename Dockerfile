# syntax=docker/dockerfile:1

FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS wheels

ARG REPO_PATH="."
WORKDIR /build
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends git gcc ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY ${REPO_PATH}/constraints.txt ${REPO_PATH}/requirements.txt ./
RUN pip wheel --no-cache-dir --wheel-dir /wheels \
    --constraint constraints.txt --requirement requirements.txt

FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

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
RUN groupadd -r unison && useradd -r -g unison -u 1000 unison \
    && mkdir -p /keys \
    && chown -R unison:unison /app /keys
USER unison

EXPOSE 8088
CMD ["python", "src/auth_service.py"]
