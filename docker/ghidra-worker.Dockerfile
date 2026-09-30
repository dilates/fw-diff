# fw-diff worker image (ADR-0008): Ghidra 11.3.2 + pyghidra + fw-diff, nothing else.
# Build:  docker build -f docker/ghidra-worker.Dockerfile -t fw-diff-worker:11.3.2 .
# Supply-chain note (THREAT_MODEL 3.4): pin the Ghidra release URL; the version check in
# pyghidra's launcher is relaxed by the wheel bundled with this exact Ghidra.
# full JDK required: Ghidra's LaunchSupport rejects JRE-only homes (no javac)
FROM eclipse-temurin:21-jdk-noble

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
ENV GHIDRA_INSTALL_DIR=/opt/ghidra \
    JAVA_HOME_OVERRIDE=/opt/java/openjdk
# ^ pyghidra skips LaunchSupport JDK discovery entirely when this is set (containers
#   confound its /usr/lib/jvm scan)
RUN curl -sSL -o /tmp/ghidra.zip \
      https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.2_build/ghidra_11.3.2_PUBLIC_20250415.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_11.3.2_PUBLIC /opt/ghidra \
    && /opt/venv/bin/pip install --no-cache-dir /opt/ghidra/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-*.whl \
    && rm /tmp/ghidra.zip

ENV PATH="/opt/venv/bin:$PATH"
RUN useradd -m worker
# Pre-seed Ghidra's JDK discovery (LaunchSupport's /usr/lib/jvm scan is unreliable in
# containers): the save file format is a single line containing the JDK home
RUN mkdir -p /home/worker/.config/ghidra/ghidra_11.3.2_PUBLIC \
    && echo "$JAVA_HOME" > /home/worker/.config/ghidra/ghidra_11.3.2_PUBLIC/java_home.save \
    && chown -R worker:worker /home/worker/.config
USER worker
ENTRYPOINT ["python3", "-m", "fw_diff.worker"]