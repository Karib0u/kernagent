<div align="center">

<pre>
     _                                            _
    | | _____ _ __ _ __   __ _  __ _  ___ _ __ | |_
    | |/ / _ \ '__| '_ \ / _` |/ _` |/ _ \ '_ \| __|
    |   <  __/ |  | | | | (_| | (_| |  __/ | | | |_
    |_|\_\___|_|  |_| |_|\__,_|\__, |\___|_| |_|\__|
                                |___/
</pre>

# kernagent

[![CI](https://github.com/Karib0u/kernagent/workflows/CI/badge.svg)](https://github.com/Karib0u/kernagent/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Karib0u/kernagent?include_prereleases)](https://github.com/Karib0u/kernagent/releases)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE)
[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?logo=docker\&logoColor=white)](https://github.com/Karib0u/kernagent/pkgs/container/kernagent)

**Turn binaries into conversations — deterministic, auditable, offline-capable.**

</div>

---

## Quick Start

```bash
# Install
bash <(curl -fsSL https://raw.githubusercontent.com/Karib0u/kernagent/main/install.sh)

# Configure
kernagent init

# Analyze
kernagent analyze /path/to/binary
```

That's it.

---

## What is kernagent?

`kernagent` converts a binary into a **portable static snapshot** and lets an LLM answer questions **with evidence**.

- **Headless** — runs in CI/Docker; no IDE or GUI required
- **Evidence-based** — every answer cites functions, xrefs, imports, strings, and decompilation
- **Deterministic** — same binary → same snapshot → same report
- **Model-agnostic** — works with any OpenAI-compatible endpoint (OpenAI, Gemini, Ollama, LM Studio)

---

## Commands

### `init`

Interactive configuration wizard. Sets up your LLM provider with model auto-discovery.

```bash
kernagent init
```

### `analyze`

One-click threat assessment. Produces a structured security report with streaming output.

```bash
kernagent analyze /path/to/binary

# Raw JSON for automation
kernagent analyze /path/to/binary --json
```

### `chat`

Interactive reverse engineering session. Ask questions, explore the binary, get cited answers.

```bash
kernagent chat /path/to/binary
```

Inside the session:
```
kernagent >> What does this binary do?
kernagent >> Show me the network functions
kernagent >> exit
```

### `snapshot`

Manual snapshot management.

```bash
# Build snapshot
kernagent snapshot /path/to/binary

# List snapshots in current directory
kernagent snapshot --list

# Force rebuild
kernagent snapshot /path/to/binary --force
```

### Global Options

```bash
kernagent -v --model gpt-4o \
  --base-url https://api.openai.com/v1 \
  --api-key sk-... \
  analyze /path/to/binary
```

---

## Installation

### Requirements

- Docker (Engine or Desktop)
- 64-bit OS (x86_64 or ARM64)
- 4 GB RAM (8+ GB recommended for large samples)

### Option 1 — Install Script (Recommended)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Karib0u/kernagent/main/install.sh)
```

Or clone first:

```bash
git clone https://github.com/Karib0u/kernagent.git
cd kernagent
bash install.sh
```

Then configure:

```bash
kernagent init
```

### Option 2 — Docker Compose

```bash
git clone https://github.com/Karib0u/kernagent.git
cd kernagent
docker compose pull
docker compose run --rm kernagent init
```

### Option 3 — Direct Docker

```bash
docker pull ghcr.io/karib0u/kernagent:latest

docker run -it --rm \
  -v /path/to/binaries:/data \
  -v ~/.config/kernagent/config.env:/config/config.env \
  ghcr.io/karib0u/kernagent:latest analyze /data/sample.exe
```

---

## How It Works

1. **Snapshot** — Ghidra extracts functions, strings, imports, call graph, and decompilation
2. **Prune** — Key artifacts are scored and selected for LLM context
3. **Analyze** — LLM produces cited findings; chat mode enables follow-up questions

```
binary.exe
    ↓
binary.snapshot/
├── meta.json
├── functions.jsonl
├── strings.jsonl
├── imports_exports.json
├── callgraph.jsonl
├── capa_summary.json
└── decomp/*.c
    ↓
Threat Report / Chat Session
```

---

## Configuration

### Quick Setup

```bash
kernagent init
```

### Manual Setup

```bash
mkdir -p ~/.config/kernagent
cat > ~/.config/kernagent/config.env << 'EOF'
OPENAI_API_KEY=your-key
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=gpt-4o
EOF
```

### Environment Variables

```bash
export OPENAI_API_KEY=...
export OPENAI_BASE_URL=https://api.openai.com/v1
export OPENAI_MODEL=gpt-4o
```

Any `/v1/chat/completions`-compatible endpoint works (OpenAI, Anthropic, Google, Ollama, LM Studio).

---

## Update & Uninstall

```bash
# Update to latest
kernagent-update

# Check for updates
kernagent-update --check

# Pin to specific version
kernagent-update --tag vX.Y.Z

# Uninstall
kernagent-uninstall
```

---

## License

Apache 2.0 — see [LICENSE](./LICENSE)
