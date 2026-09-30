# fw-diff worker image (ADR-0008): Ghidra 11.3.2 + pyghidra + fw-diff, nothing else.
# Build:  docker build -f docker/ghidra-worker.Dockerfile -t fw-diff-worker:11.3.2 .
# Supply-chain note (THREAT_MODEL 3.4): pin the Ghidra release URL; the version check in
# pyghidra's launcher is relaxed by the wheel bundled with this exact Ghidra.
FROM eclipse-temurin:21-jre-noble

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv python3-pip unzip curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /usr/lib/jvm && ln -s "$JAVA_HOME" /usr/lib/jvm/java-21-openjdk
# ^ Ghidra's LaunchSupport discovers JDKs by scanning /usr/lib/jvm; temurin installs to
#   /opt/java/openjdk, so expose it there (THREAT_MODEL supply-chain: same pinned image)

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir .

# Ghidra 11.3.2 (pinned release URL; wheel below pairs with this exact version)
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
RUN curl -sSL -o /tmp/ghidra.zip \
      https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.2_build/ghidra_11.3.2_PUBLIC_20250415.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_11.3.2_PUBLIC /opt/ghidra \
    && /opt/venv/bin/pip install --no-cache-dir /opt/ghidra/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-*.whl \
    && rm /tmp/ghidra.zip

ENV PATH="/opt/venv/bin:$PATH"
RUN useradd -m worker
USER worker
ENTRYPOINT ["python3", "-m", "fw_diff.worker"]