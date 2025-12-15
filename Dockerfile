FROM ghcr.io/project-unisonos/unison-common-wheel:latest AS common_wheel
FROM python:3.12-slim@sha256:fdab368dc2e04fab3180d04508b41732756cc442586f708021560ee1341f3d29

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

ARG REPO_PATH="."
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gcc curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY ${REPO_PATH}/constraints.txt ./constraints.txt
COPY ${REPO_PATH}/requirements.txt ./requirements.txt
COPY --from=common_wheel /tmp/wheels /tmp/wheels
RUN pip install --no-cache-dir -c ./constraints.txt /tmp/wheels/unison_common-*.whl \
    && pip install --no-cache-dir -c ./constraints.txt -r requirements.txt

COPY ${REPO_PATH}/src/ ./src/
COPY ${REPO_PATH}/tests/ ./tests/

RUN groupadd -r unison && useradd -r -g unison -u 1000 unison \
    && chown -R unison:unison /app
USER unison

EXPOSE 8088
CMD ["python", "src/auth_service.py"]
