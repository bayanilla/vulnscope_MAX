# VulnScope MAX with Zeek: PCAP -> Zeek logs -> VulnScope, the same on Linux, macOS and Windows.
#
#   docker compose up -d            # upload page on http://127.0.0.1:8080/
#   docker compose run --rm vulnscope analyze /data/case1 -o /runs/case1
#
# Multi-arch (linux/amd64, linux/arm64): the Zeek base image and DuckDB wheels exist for both.
# Nothing is downloaded at run time; see "Air-gapped networks and enclaves" in ARCHITECTURE.md.
ARG ZEEK_IMAGE=zeek/zeek:9.0.1
# Must match the Python in the Zeek image (Debian trixie: 3.13), since DuckDB is a compiled wheel.
ARG PYTHON_IMAGE=python:3.13-slim-trixie

# DuckDB (the one Python dependency) is fetched in a throwaway stage, so the final image needs
# no package manager, pip or network.
FROM ${PYTHON_IMAGE} AS deps
COPY requirements.txt /tmp/requirements.txt
# Behind a TLS-inspecting proxy, pass its CA: docker build --secret id=ca,src=corp-ca.pem .
RUN --mount=type=secret,id=ca,required=false \
    if [ -s /run/secrets/ca ]; then export PIP_CERT=/run/secrets/ca; fi; \
    pip install --no-cache-dir --disable-pip-version-check --target /deps -r /tmp/requirements.txt

FROM ${ZEEK_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/usr/local/zeek/bin:$PATH
COPY --from=deps /deps /opt/vulnscope/deps
RUN python3 -c "import sys; sys.path.insert(0, '/opt/vulnscope/deps'); import duckdb; print('duckdb', duckdb.__version__)" \
 && groupadd --gid 1000 vulnscope \
 && useradd --uid 1000 --gid 1000 --home-dir /runs --no-create-home --shell /usr/sbin/nologin vulnscope \
 && mkdir -p /data /runs \
 && chown vulnscope:vulnscope /runs \
 && zeek --version

COPY vulnflow /opt/vulnscope/vulnflow
COPY samples /opt/vulnscope/samples
COPY docker/entrypoint.py /opt/vulnscope/entrypoint.py
COPY README.md METHODS.md ARCHITECTURE.md DEVELOPMENT.md API.md UPGRADE.md LICENSE THIRD_PARTY_NOTICES.md /opt/vulnscope/
COPY docs /opt/vulnscope/docs
RUN python3 -m compileall -q /opt/vulnscope/vulnflow

# /data  your logs, scans and captures (mount read-only)
# /runs  results, temporary Parquet/DuckDB/Zeek files and settings (mount a disk with room)
ENV PYTHONPATH=/opt/vulnscope:/opt/vulnscope/deps \
    VULNSCOPE_CONTAINER=1 \
    VULNSCOPE_DATA_ROOT=/data \
    VULNSCOPE_HOME=/runs/.vulnscope \
    VULNSCOPE_WORKDIR=/runs/.tmp \
    VULNSCOPE_ZEEK=/usr/local/zeek/bin/zeek \
    TMPDIR=/runs/.tmp \
    HOME=/runs
WORKDIR /runs
EXPOSE 8080
VOLUME ["/runs"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/', timeout=4)"]

ENTRYPOINT ["python3", "/opt/vulnscope/entrypoint.py"]
CMD ["serve"]
