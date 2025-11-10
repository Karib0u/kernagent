<div align="center">

<pre>
     _                                            _
    | | _____ _ __ _ __   __ _  __ _  ___ _ __ | |_
    | |/ / _ \ '__| '_ \ / _` |/ _` |/ _ \ '_ \| __|
    |   <  __/ |  | | | | (_| | (_| |  __/ | | | |_
    |_|\_\___|_|  |_| |_|\__,_|\__, |\___|_| |_|\__|
                                |___/
</pre>

# 🔍 kernagent

[![CI Status](https://github.com/Karib0u/kernagent/workflows/CI/badge.svg)](https://github.com/Karib0u/kernagent/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/Karib0u/kernagent/blob/main/LICENSE)
[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?logo=docker&logoColor=white)](https://github.com/Karib0u/kernagent/pkgs/container/kernagent)
[![GitHub release](https://img.shields.io/github/v/release/Karib0u/kernagent?include_prereleases)](https://github.com/Karib0u/kernagent/releases)
[![GitHub stars](https://img.shields.io/github/stars/Karib0u/kernagent?style=social)](https://github.com/Karib0u/kernagent/stargazers)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/Karib0u/kernagent/pulls)

**Turn binaries into conversations — offline, deterministic, and verifiable.**

Unlike existing **Model Context Protocol (MCP) plugins for IDA/Ghidra**, `kernagent` is a **fully headless, snapshot-based pipeline**:
no live disassembler, no GUI automation, no screen-scraping — just a portable static analysis bundle that any LLM or script can consume.

`kernagent` is an **AI-powered reverse-engineering copilot** built on top of **Ghidra snapshots**.

It converts a binary into a portable analysis bundle, then lets an LLM (or your scripts) answer questions about it.

Every answer is backed by **real evidence** (functions, strings, imports, xrefs, decomp, sections). No runtime execution. No patching. No blind guessing.

---

## 🛠️ Built With

![Python](https://img.shields.io/badge/python-3.12+-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)
![Ghidra](https://img.shields.io/badge/Ghidra-NSA-FF0000?style=for-the-badge)
![OpenAI](https://img.shields.io/badge/OpenAI-Compatible-412991?style=for-the-badge&logo=openai&logoColor=white)

**Core Technologies:** Ghidra 11.x • PyGhidra 2.2+ • OpenAI API • Docker • Python 3.12+

</div>

---

## 📑 Table of Contents

- [🔍 kernagent](#-kernagent)
  - [🛠️ Built With](#️-built-with)
  - [📑 Table of Contents](#-table-of-contents)
  - [🎯 What makes kernagent different?](#-what-makes-kernagent-different)
  - [🆚 How is this different from IDA / Ghidra MCP integrations?](#-how-is-this-different-from-ida--ghidra-mcp-integrations)
  - [🖼️ Screenshots](#️-screenshots)
    - [Summary Command](#summary-command)
    - [Ask Command](#ask-command)
  - [🚀 Quick Start](#-quick-start)
    - [Installation](#installation)
    - [Windows Installation](#windows-installation)
  - [⚙️ Model Configuration](#️-model-configuration)
  - [🧱 Commands](#-commands)
    - [`summary`](#summary)
    - [`ask`](#ask)
    - [`oneshot`](#oneshot)
  - [🧬 How It Works](#-how-it-works)
    - [1. Snapshot extraction (once per binary)](#1-snapshot-extraction-once-per-binary)
    - [2. Tool surface](#2-tool-surface)
    - [3. ReverseEngineeringAgent](#3-reverseengineeringagent)
  - [📚 Real-world usage guides](#-real-world-usage-guides)
    - [Guide 1 — Malware triage pipeline](#guide-1--malware-triage-pipeline)
    - [Guide 2 — Explaining legacy / vendor binaries](#guide-2--explaining-legacy--vendor-binaries)
  - [🛠️ Development](#️-development)
    - [Local dev with Docker Compose](#local-dev-with-docker-compose)
    - [Python library usage (advanced)](#python-library-usage-advanced)
  - [🏗️ Project Structure](#️-project-structure)
  - [🔒 Design principles](#-design-principles)
  - [🤝 Contributing](#-contributing)
  - [📜 License](#-license)

---

## 🎯 What makes kernagent different?

Most AI-assisted RE tooling today falls into two buckets:

* **IDE plugins / MCP for IDA & Ghidra** – require a running GUI or live project, often tightly coupled to a specific tool.
* **"Chat with your binary" toys** – stream random chunks into an LLM context window with little control or verifiability.

`kernagent` takes a different route:

1. 🚫 **Not an MCP plugin, not tied to an IDE**
   `kernagent` does **not** require an IDA or Ghidra GUI session, and does **not** drive your disassembler over MCP.
   It runs as a **headless pipeline** (Docker-friendly, CI-friendly) that emits a self-contained snapshot directory.

2. 📦 **Snapshot-first, tool-agnostic**
   A binary is processed **once** into a structured archive (`functions.jsonl`, `strings.jsonl`, `callgraph.jsonl`, `decomp/*.c`, etc.).
   Any LLM client, script, or service can work on that snapshot — locally, offline, or in another environment — without re-running Ghidra/IDA.

3. 🧪 **Evidence over vibes**
   All answers must map back to concrete artifacts: addresses, functions, imports, strings, sections, xrefs, decomp.
   No opaque embeddings, no hallucinated "guesses" you can't verify in a real RE tool.

4. 🔁 **Deterministic & portable**
   Same binary → same snapshot → same JSON → same report.
   Easy to archive, diff across versions, ship between teams, or attach to tickets.

5. 🧩 **Model-agnostic & self-hostable**
   Works with any `/v1/chat/completions`-compatible endpoint:
   OpenAI, Ollama, llama.cpp, LM Studio, your own gateway, etc.
   You decide where data lives.

6. 📏 **Designed for context-window efficiency (and getting better)**
   `kernagent` already prunes and structures data for LLM consumption.
   Roadmap includes additional tools to:
   - rank / filter high-signal functions & strings,
   - generate compact semantic indexes over snapshots,
   - stream targeted slices of evidence instead of dumping entire archives.
   Goal: **maximize analysis quality per token**, not just "stuff more JSON into the prompt".

---

## 🆚 How is this different from IDA / Ghidra MCP integrations?

Short version:

- **No live IDE requirement**
  MCP plugins for IDA/Ghidra typically assume:
  - an interactive disassembler instance,
  - an open database/project,
  - and often GUI or plugin APIs.

  `kernagent` instead:
  - runs headless in Docker or your CI,
  - produces a portable snapshot directory,
  - lets you analyze that snapshot anywhere (including air-gapped or cloud LLMs) without rerunning the disassembler.

- **Decoupled from specific vendors / UIs**
  You're not locked into a single RE UI or MCP server. The snapshot is just files: easy to inspect, grep, and integrate.

- **Inspired by modern static-export workflows**
  This project is heavily inspired by the static-export + LLM methodology described by Check Point Research in
  "Beating XLoader at Speed: Generative AI as a Force Multiplier for Reverse Engineering"
  (a.k.a. "Generative AI for Reverse Engineering").
  `kernagent` turns that idea into a reusable, open, production-ready toolchain with:
  - a standardized snapshot format,
  - a constrained evidence-backed agent,
  - and CLI/CI integration out of the box.

---

## 🖼️ Screenshots

Below are examples running `kernagent` against a **WannaCry** sample, using a local LLM (LM Studio) with the **qwen3-4b-thinkink-2507** model — one of the best models for its size.

### Summary Command

The `summary` command provides an executive overview of the binary's purpose, capabilities, and key artifacts:

![Summary Example](docs/images/summary.png)

### Ask Command

The `ask` command enables interactive Q&A, letting you drill down into specific behaviors with evidence-backed responses:

![Ask Example](docs/images/ask.png)

---

## 🚀 Quick Start

### Installation

**Linux / macOS / WSL2:**

```bash
curl -fsSL https://raw.githubusercontent.com/Karib0u/kernagent/main/install.sh | bash
```

**Or manual installation (all platforms):**

```bash
git clone https://github.com/Karib0u/kernagent.git
cd kernagent
bash install.sh  # Linux/macOS/WSL2
```

This will:

* Clone the repository (if using one-liner)
* Build or pull the `kernagent` Docker image (with Ghidra + PyGhidra)
* Install a `/usr/local/bin/kernagent` wrapper
* Optionally help configure your API settings

Then you can run, from anywhere:

```bash
kernagent summary /path/to/binary.exe
kernagent ask /path/to/binary.exe "What does this binary do?"
kernagent oneshot /path/to/binary.exe
```

> Requires Docker and Git. The wrapper mounts your binary directory into the container and forwards `OPENAI_*` env vars or anything inside `~/.config/kernagent/config.env` automatically.

### Windows Installation

**Option 1: Docker Desktop (Recommended)**

1. Install [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/)
2. Clone and use docker-compose directly:

```powershell
git clone https://github.com/Karib0u/kernagent.git
cd kernagent
# Configure once (see "Model Configuration" below for details)
New-Item -ItemType Directory -Force "$env:USERPROFILE\.config\kernagent" | Out-Null
Copy-Item -Force config.env.example "$env:USERPROFILE\.config\kernagent\config.env"
notepad "$env:USERPROFILE\.config\kernagent\config.env"
docker compose build
docker compose run --rm kernagent --help
```

3. To analyze binaries:

```powershell
# From the kernagent directory
docker compose run --rm kernagent summary /data/path/to/binary.exe
```

**Option 2: WSL2 (Ubuntu)**

If you have WSL2 installed, use the Linux installation method inside your WSL2 terminal:

```bash
curl -fsSL https://raw.githubusercontent.com/Karib0u/kernagent/main/install.sh | bash
```

**Windows Notes:**
- The Docker image itself is fully cross-platform
- All Python code works on any OS
- Currently, the `kernagent` CLI wrapper is bash-based (works in WSL2/Git Bash)
- For native PowerShell/CMD support, use `docker compose run` directly
- Paths in docker-compose: Use absolute Windows paths like `C:\binaries:/data`

---

## ⚙️ Model Configuration

All entrypoints (wrapper, docker compose, tests) load credentials from a single config file that lives outside the repo: `${XDG_CONFIG_HOME:-~/.config}/kernagent/config.env`. Create or edit it once and the file will be mounted into every container at `/config/config.env`.

```bash
mkdir -p ~/.config/kernagent
cp config.env.example ~/.config/kernagent/config.env
$EDITOR ~/.config/kernagent/config.env
```

PowerShell version:

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\.config\kernagent" | Out-Null
Copy-Item -Force config.env.example "$env:USERPROFILE\.config\kernagent\config.env"
notepad "$env:USERPROFILE\.config\kernagent\config.env"
```

Set `KERNAGENT_CONFIG=/path/to/your/config.env` if you want to override the default location.

You can still override any value via regular environment variables:

```bash
export OPENAI_API_KEY="sk-..."
export OPENAI_BASE_URL="https://api.openai.com/v1"     # or your gateway
export OPENAI_MODEL="gpt-4o"                          # or your local model name
```

Any `/v1/chat/completions`-compatible endpoint works.

---

## 🧱 Commands

All commands operate on a **snapshot** (see “How it works”).
If a `<name>_archive/` snapshot does not exist, `kernagent` builds it automatically.
That build orchestrates the bundled static analyzers (currently Ghidra-based
snapshotting plus flare-capa) and drops their artifacts alongside each other,
so capabilities and ATT&CK mappings are available without extra switches.

### `summary`

**Executive summary** of a binary.

```bash
kernagent summary /path/to/binary
```

Outputs:

* Purpose & behavior (human readable)
* Capabilities (network, filesystem, process, persistence, injection, etc.)
* Interesting functions, imports, strings
* Addresses and references so you can confirm manually

**[See screenshot example](#summary-command)** — WannaCry analysis using qwen3-4b-thinkink-2507 on LM Studio

### `ask`

**Interactive Q&A** over the snapshot using a tool-using agent.

```bash
kernagent ask /path/to/binary "Show me suspected C2 logic and supporting evidence."
```

The agent can (via tools):

* Search functions by name, size, complexity
* Read decompilation
* Follow call graphs up/down
* Search strings, imports, data, instructions
* Resolve xrefs between code, data, strings
* Return answers with concrete evidence (EAs, function names, APIs)

**[See screenshot example](#ask-command)** — WannaCry analysis using qwen3-4b-thinkink-2507 on LM Studio

### `oneshot`

**Deterministic triage mode** — for CI, bulk analysis, and pipelines.

```bash
kernagent oneshot /path/to/binary
```

Flow:

1. Build a compact JSON bundle (`build_oneshot_summary`) containing:

   * file metadata
   * suspicious / non-standard sections
   * imports grouped by capability (network, filesystem, memory_injection, persistence, etc.)
   * up to 150 high-signal strings
   * up to 40 key functions with metrics, caps, callers/callees
   * candidate embedded configs
   * boolean suspicion flags
   * CAPA rule highlights (namespaces, ATT&CK/MBC) when CAPA runs successfully
2. Feed that JSON to a strict malware-analyst prompt.
3. Emit a single Markdown report with:

   * behavior summary
   * capability assessment
   * classification: `MALICIOUS | GRAYWARE | BENIGN | UNKNOWN`
   * evidence map

You can also bypass the prompt and consume the JSON directly in your own tooling.

---

## 🧬 How It Works

`kernagent` packages the "export once, reason over structured data" approach into a headless pipeline.
It can orchestrate multiple static analysis backends; today that means
running Ghidra/PyGhidra to build a rich snapshot and flare-capa for rule
coverage, and the architecture leaves room to plug in other disassemblers or
specialized scanners without changing the CLI.

### 1. Snapshot extraction (once per binary)

`kernagent.snapshot.extractor` currently uses Ghidra/PyGhidra and emits:

```text
<name>_archive/
├── meta.json            # hashes, format, arch, image base
├── functions.jsonl      # functions, metrics, ranges, xrefs, decomp_path
├── strings.jsonl        # strings + xrefs
├── imports_exports.json # imports & exports
├── sections.json        # memory sections & perms
├── equates.json         # named constants (if any)
├── callgraph.jsonl      # caller → callee edges
├── data.jsonl           # globals / data items
├── index.json           # name ↔ ea map
├── data_index.json
├── capa_summary.json    # CAPA hits + ATT&CK/MBC mappings (auto-generated)
└── decomp/*.c           # decompiled functions
```

This snapshot is:

* **Immutable** — safe to store, diff, and serialize
* **Portable** — move it into air-gapped envs; no need to rerun Ghidra there

### 2. Tool surface

`kernagent.snapshot.SnapshotTools` + the `TOOLS` schema expose safe, read-only operations used by the agent (and you) across every static artifact the pipeline produces:

* `read_json` – meta/sections/imports/etc.
* `get_function_stats`
* `search_functions` / `get_function`
* `read_decompilation`
* `search_strings`
* `search_imports_exports`
* `search_by_instruction`
* `search_data`
* `search_equates`
* `trace_calls`
* `get_memory_section`
* `get_capa_summary`
* `resolve_symbol`
* `get_xrefs`
* `search_decomp`
* `list_files`

Everything is scoped to the snapshot directory; no arbitrary filesystem access.

### 3. ReverseEngineeringAgent

`ReverseEngineeringAgent` orchestrates:

* A bounded tool-calling loop using the above tools
* A strong system prompt that:

  * forbids hallucinating artifacts,
  * requires citing functions/addresses/strings,
  * enforces short, checkable explanations.

Result: answers that feel like an analyst walked the code, not like a chatbot guessing.

---

## 📚 Real-world usage guides

Here are two concrete patterns you can adopt immediately.

### Guide 1 — Malware triage pipeline

Use `kernagent` as a CI / sandbox post-processor for suspicious binaries.

1. Your sandbox or build system drops binaries into a directory.

2. For each file:

   ```bash
   kernagent oneshot /artifacts/sample.bin > reports/sample.md
   ```

3. Parse classification / capabilities to:

   * auto-route high-risk samples to analysts,
   * attach Markdown reports to tickets,
   * gate releases in your internal supply chain.

Because oneshot JSON/logic is deterministic and static-only, it’s safe to run at scale.

### Guide 2 — Explaining legacy / vendor binaries

You’ve got a closed-source driver, agent, or appliance binary and need to document it.

1. Run:

   ```bash
   kernagent summary legacy_driver.sys > legacy_driver_summary.md
   kernagent ask legacy_driver.sys "List key persistence mechanisms and config paths."
   ```

2. Use the report + cited addresses to:

   * verify claims inside Ghidra/IDA,
   * onboard new engineers quickly,
   * build internal docs for audits / reviews.

No code execution, no uploading binaries to random SaaS if you point it at your own model endpoint.

---

## 🛠️ Development

### Local dev with Docker Compose

**Linux / macOS / WSL2:**

```bash
git clone https://github.com/Karib0u/kernagent.git
cd kernagent
mkdir -p ~/.config/kernagent
cp config.env.example ~/.config/kernagent/config.env
docker compose build
docker compose run --rm kernagent --help
```

**Windows (PowerShell):**

```powershell
git clone https://github.com/Karib0u/kernagent.git
cd kernagent
New-Item -ItemType Directory -Force "$env:USERPROFILE\.config\kernagent" | Out-Null
Copy-Item -Force config.env.example "$env:USERPROFILE\.config\kernagent\config.env"
docker compose build
docker compose run --rm kernagent --help
```

### Python library usage (advanced)

If you already have Java + Ghidra + PyGhidra installed:

```bash
pip install kernagent
python -m kernagent summary /path/to/binary
```

Direct scripting:

```python
from pathlib import Path
from kernagent.snapshot import SnapshotTools

snapshot_root = Path("sample_archive")
tools = SnapshotTools(snapshot_root)

print(tools.get_function_stats())
print(tools.search_strings("http"))
print(tools.search_imports_exports(name_pattern="WinInet"))
```

---

## 🏗️ Project Structure

```text
kernagent/
  cli.py            # CLI: summary / ask / oneshot
  agent.py          # ReverseEngineeringAgent (tool loop)
  config.py         # Settings (env + global config file)
  llm_client.py     # OpenAI-compatible client
  prompts.py        # System prompts + tool schemas
  snapshot/
    extractor.py    # Ghidra/PyGhidra snapshot builder
    tools.py        # SnapshotTools + build_tool_map
  oneshot/
    pruner.py       # Deterministic pruning + triage JSON
tests/
  ...               # Agent, snapshot tools, oneshot tests
Dockerfile
docker-compose.yml
install.sh
Makefile
```

---

## 🔒 Design principles

* **Read-only** — never mutates your binaries.
* **Static-only** — no execution of untrusted code.
* **Deterministic** — same inputs → same outputs.
* **Model-neutral** — bring your own LLM endpoint.
* **Auditable** — all claims map back to addresses and artifacts.

---

## 🤝 Contributing

Contributions are welcome. High-impact areas:

* Editor / Ghidra / IDA / Binary Ninja integrations
* MCP / HTTP service wrapper
* New search helpers & heuristics
* Performance improvements on very large snapshots

Basic flow:

1. Fork & clone
2. Run tests
3. Open a PR with a focused change

---

## 📜 License

* kernagent is licensed under the Apache 2.0 License. See the [LICENSE](./LICENSE) file for details.
* The Docker image and snapshot tooling use **Ghidra** and **PyGhidra**.
  Ensure your usage complies with their respective licenses and terms.
