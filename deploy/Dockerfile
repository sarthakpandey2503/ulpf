# syntax=docker/dockerfile:1
# Pin the base image by digest before a production/air-gap release, e.g.
#   docker pull python:3.12-slim-bookworm && docker inspect --format='{{index .RepoDigests 0}}' python:3.12-slim-bookworm
ARG BASE=python:3.12-slim-bookworm

FROM ${BASE} AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends build-essential && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
# Offline builds: place wheels in deploy/airgap/wheels and build with --build-arg PIP_ARGS="--no-index --find-links=/wheels"
ARG PIP_ARGS=""
COPY deploy/airgap/wheel[s] /wheels
RUN pip install --prefix=/install ${PIP_ARGS} -r requirements.txt
COPY pyproject.toml README.md ./
COPY ulpf ./ulpf
RUN pip install --prefix=/install --no-deps .

FROM ${BASE}
LABEL org.opencontainers.image.title="ULPF" \
      org.opencontainers.image.description="Universal Log Pre-processing Framework"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    ULPF_DATA_DIR=/var/lib/ulpf ULPF_KEYS_DIR=/var/lib/ulpf/keys ULPF_DRAFTS_DIR=/var/lib/ulpf/drafts
COPY --from=build /install /usr/local
COPY ui /opt/ulpf/ui
COPY samples /opt/ulpf/samples
ENV ULPF_UI_DIR=/opt/ulpf/ui ULPF_SAMPLES_DIR=/opt/ulpf/samples
# Unprivileged runtime user; no shell login, no home write outside the data volume.
RUN groupadd --system --gid 10001 ulpf && \
    useradd --system --uid 10001 --gid ulpf --no-create-home --shell /usr/sbin/nologin ulpf && \
    mkdir -p /var/lib/ulpf && chown -R ulpf:ulpf /var/lib/ulpf
USER 10001:10001
VOLUME ["/var/lib/ulpf"]
EXPOSE 8080 5514/udp 5514/tcp 6514/tcp
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health').status==200 else 1)"
ENTRYPOINT ["ulpf"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
