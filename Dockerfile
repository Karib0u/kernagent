# Multi-stage Docker build that compiles the Ghidra decompiler so the image
# works on macOS ARM (and other platforms) where the native binaries are not
# shipped pre-built.

FROM eclipse-temurin:21-jdk-jammy AS ghidra-builder

ENV DEBIAN_FRONTEND=noninteractive
ENV GHIDRA_VERSION=11.4.2
ENV GHIDRA_BUILD=20250826
ENV GHIDRA_DIR=ghidra_${GHIDRA_VERSION}_PUBLIC
ENV GHIDRA_SHA=795a02076af16257bd6f3f4736c4fc152ce9ff1f95df35cd47e2adc086e037a6
ENV GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD}.zip
ENV GRADLE_VERSION=8.8

# Install native build tooling required for Ghidra's decompiler
RUN set -eux; \
    retries=5; \
    for attempt in $(seq 1 "${retries}"); do \
        if apt-get update; then \
            break; \
        elif [ "${attempt}" -lt "${retries}" ]; then \
            echo "apt-get update failed (attempt ${attempt}/${retries}); retrying..." >&2; \
            sleep 5; \
        else \
            exit 1; \
        fi; \
    done; \
    apt-get install -y \
        build-essential \
        bison \
        flex \
        git \
        unzip \
        wget; \
    rm -rf /var/lib/apt/lists/*

# Install a modern Gradle version (the apt one is too old for Ghidra)
RUN wget -q "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" -O /tmp/gradle.zip \
    && unzip -q /tmp/gradle.zip -d /opt \
    && mv "/opt/gradle-${GRADLE_VERSION}" /opt/gradle \
    && rm /tmp/gradle.zip
ENV PATH="/opt/gradle/bin:${PATH}"

# Download and verify Ghidra, then compile the native decompiler
WORKDIR /tmp
RUN wget -q "${GHIDRA_URL}" -O ghidra.zip \
    && echo "${GHIDRA_SHA} ghidra.zip" | sha256sum -c - \
    && unzip -q ghidra.zip \
    && mv "${GHIDRA_DIR}" /ghidra \
    && rm ghidra.zip

WORKDIR /ghidra/support/gradle
RUN gradle --no-daemon buildNatives

################################################################################

FROM eclipse-temurin:21-jdk-jammy

ENV DEBIAN_FRONTEND=noninteractive

# Install Python runtime and helpers
RUN set -eux; \
    retries=5; \
    for attempt in $(seq 1 "${retries}"); do \
        if apt-get update; then \
            break; \
        elif [ "${attempt}" -lt "${retries}" ]; then \
            echo "apt-get update failed (attempt ${attempt}/${retries}); retrying..." >&2; \
            sleep 5; \
        else \
            exit 1; \
        fi; \
    done; \
    apt-get install -y \
        python3 \
        python3-pip \
        wget \
        unzip \
        curl; \
    rm -rf /var/lib/apt/lists/*

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

# Download capa-rules once so every build has a deterministic rule pack
ENV CAPA_RULES_VERSION=9.2.1
ENV CAPA_RULES_URL=https://github.com/mandiant/capa-rules/archive/refs/tags/v${CAPA_RULES_VERSION}.zip
RUN rm -rf /opt/capa-rules \
    && wget -q "${CAPA_RULES_URL}" -O /tmp/capa-rules.zip \
    && unzip -q /tmp/capa-rules.zip -d /tmp \
    && mv "/tmp/capa-rules-${CAPA_RULES_VERSION}" /opt/capa-rules \
    && rm /tmp/capa-rules.zip
ENV CAPA_RULES_PATH=/opt/capa-rules

# Bring in the compiled Ghidra distribution (with native decompiler)
COPY --from=ghidra-builder /ghidra /opt/ghidra
ENV GHIDRA_INSTALL_DIR=/opt/ghidra

# Ensure the decompiler binaries are executable inside the image
RUN find "${GHIDRA_INSTALL_DIR}/Ghidra/Features/Decompiler/os" -type f -name "decompile" -exec chmod +x {} +

# Python configuration
ENV PYTHONUNBUFFERED=1

# Copy application sources and install dependencies with uv
WORKDIR /workspace/project

# First, copy pyproject.toml and README to the project root
COPY pyproject.toml uv.lock /workspace/project/
COPY README.md /workspace/project/README.md

# Create the kernagent package directory and copy Python sources
RUN mkdir -p /workspace/project/kernagent
COPY kernagent/__init__.py \
     kernagent/__main__.py \
     kernagent/agent.py \
     kernagent/capa_runner.py \
     kernagent/cli.py \
     kernagent/config.py \
     kernagent/llm_client.py \
     kernagent/log.py \
     kernagent/prompts.py \
     /workspace/project/kernagent/

# Copy subdirectories
COPY kernagent/oneshot /workspace/project/kernagent/oneshot
COPY kernagent/snapshot /workspace/project/kernagent/snapshot

# Pin Python version to 3.12 (python-flirt doesn't have wheels for 3.14 yet)
ENV UV_PYTHON=3.12

# Install dependencies using uv (including dev dependencies for testing)
RUN cd /workspace/project && uv sync --all-groups

# Default to the project virtual environment at runtime so we can invoke
# python modules directly without re-running `uv run` on every container start.
ENV VIRTUAL_ENV=/workspace/project/.venv
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

# Share binaries via mounted volume
VOLUME /data

# Run the CLI directly from the virtual environment
ENTRYPOINT ["python", "-m", "kernagent.cli"]
CMD ["--help"]
