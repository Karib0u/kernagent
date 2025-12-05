"""Binary context construction (basic and full multi-agent)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from .config import Settings
from .llm_client import LLMClient
from .log import get_logger
from .oneshot import build_oneshot_summary

logger = get_logger(__name__)

CONTEXT_VERSION = "v1"
CONTEXT_HEADER = "[kernagent_context]"

COMMON_HEADER_PROMPT = """You are a senior malware analyst.

You are given a deterministic JSON summary of a binary's static artifacts
produced by kernagent's build_oneshot_summary().

Your job is to reason like a human analyst:
- Only state behaviors that are directly supported by evidence in the JSON.
- Always separate:
  1) what you believe,
  2) the concrete evidence (function names, EAs, APIs, strings, sections, CAPA rules),
  3) why that evidence implies the behavior.
- When evidence is weak or ambiguous, explicitly mark the conclusion as
  "uncertain" or "hypothesis" and explain what additional evidence you would need.
- Never invent functions, APIs, strings, or CAPA rules that are not present.
- Do not infer capabilities from the absence of evidence; instead, say
  "no clear evidence of X" if you have checked the relevant imports/strings
  and found nothing meaningful.

Evidence formatting guidelines:
- For functions: use `function <name>@<ea>` (EA in hex without 0x).
- For imports: use `import <library>!<name>`.
- For strings: use `string "<value>"@<ea>`.
- For sections: use `section <name> <start>-<end> perms=<rwx>`.
- For CAPA: use `capa "<rule_name>" (namespace: <ns>)`.

Do not treat very generic APIs (e.g., CreateFile, malloc, memcpy) as proof
of malicious behavior by themselves. A behavior is "confirmed" only when
multiple independent signals align (e.g., imports + strings + code structure)."""

CAPABILITIES_SYSTEM_PROMPT = f"""{COMMON_HEADER_PROMPT}

You are the Capabilities Agent.

Your goal is to extract a precise, evidence-based view of this binary's
capabilities: networking, filesystem, process control, memory injection,
persistence, crypto, privilege operations, anti-debug/VM, scripting/shell,
IPC, and any other clearly supported behaviors.

Input JSON fields that are especially relevant:
- summary.imports: imports grouped by capability buckets
- summary.interesting_strings: strings with kinds and function usage
- summary.key_functions: functions with capabilities, callers/callees, and strings
- summary.capa: high-level CAPA rules and ATT&CK/MBC tags (if present)
- summary.suspicion_signals: aggregated signals (if present)

You MUST:
- For each capability, decide one of: "confirmed", "likely", "possible", "no clear evidence".
- For every capability that is not "no clear evidence", provide:
  - a short description,
  - a list of evidence items (functions/imports/strings/CAPA),
  - a confidence level: HIGH / MEDIUM / LOW.

Output format:
Return a single JSON object with the following shape:
{{
  "capabilities": [
    {{
      "name": "network",
      "status": "confirmed | likely | possible | no_clear_evidence",
      "confidence": "HIGH | MEDIUM | LOW",
      "description": "short human-readable description",
      "evidence": [
        "function ...",
        "import ...",
        "string ...",
        "capa ..."
      ]
    }},
    ...
  ],
  "notes": [
    "optional free-form notes about ambiguities or missing data"
  ]
}}

Respond with JSON ONLY. No Markdown, no prose outside JSON."""

STRUCTURE_SYSTEM_PROMPT = f"""{COMMON_HEADER_PROMPT}

You are the Structure Agent.

Your goal is to understand the macro structure and control-flow of this binary:
- probable entrypoints,
- key "pivot" functions,
- main execution paths (high-level call chains),
- how configuration or payloads are likely loaded and used.

Input JSON fields that are especially relevant:
- summary.file: format, arch, image_base
- summary.key_functions: functions with size, complexity, capabilities, callers/callees, strings
- summary.sections: section summary and suspicious sections
- summary.possible_configs: candidate configuration blobs
- summary.suspicion_signals: any aggregated flags

You MUST:
- Identify 1-5 probable entrypoints (with rationale).
- Identify 3-10 key pivot functions (e.g., config loader, command dispatcher, C2 handler).
- Describe 3-5 high-level execution paths as ordered lists of functions
  (e.g., entry -> init -> decrypt_config -> c2_loop).

Output format:
Return a JSON object:
{{
  "entrypoints": [
    {{
      "name": "FunctionName",
      "ea": "ADDRESS",
      "reason": "why this is an entrypoint candidate",
      "evidence": ["function ...", "import ...", "string ..."]
    }},
    ...
  ],
  "pivot_functions": [
    {{
      "name": "FunctionName",
      "ea": "ADDRESS",
      "role": "e.g., config_loader, c2_handler",
      "evidence": ["..."]
    }},
    ...
  ],
  "execution_paths": [
    {{
      "label": "short name, e.g., main_behavior",
      "steps": [
        {{
          "name": "FunctionName",
          "ea": "ADDRESS",
          "role": "short role description"
        }},
        ...
      ],
      "summary": "what this path does in high-level terms",
      "evidence": ["..."]
    }},
    ...
  ],
  "notes": [...]
}}

Respond with JSON ONLY."""

OBFUSCATION_SYSTEM_PROMPT = f"""{COMMON_HEADER_PROMPT}

You are the Obfuscation & Anti-Analysis Agent.

Your goal is to detect signs of:
- packing or heavy compression/virtualization,
- bulk cryptography used for payloads or configuration,
- anti-debugging and anti-VM techniques,
- suspicious memory usage (R/W/X sections, code in unusual sections).

Input JSON fields that are especially relevant:
- summary.sections: especially has_rwx and suspicious sections
- summary.key_functions: large/complex functions with crypto or anti_debug_vm capabilities
- summary.interesting_strings: security-related keywords, packer-related strings
- summary.capa: rules about packing, anti-debug, encryption (if present)
- summary.suspicion_signals: any aggregate "packed/obfuscated" indicators

You MUST clearly distinguish:
- "packing_or_protectors": actual or likely packers / protectors,
- "crypto_usage": where crypto is used and for what (config, payload, network),
- "anti_analysis": anti-debug, anti-VM, environment checks.

For each, decide one of:
- "confirmed", "likely", "possible", "no_clear_evidence".

Output format:
{{
  "packing_or_protectors": {{
    "status": "confirmed | likely | possible | no_clear_evidence",
    "description": "short explanation",
    "evidence": ["..."]
  }},
  "crypto_usage": [
    {{
      "status": "confirmed | likely | possible",
      "purpose": "config | payload | network | unknown",
      "description": "short explanation",
      "evidence": ["..."]
    }},
    ...
  ],
  "anti_analysis": [
    {{
      "status": "confirmed | likely | possible",
      "technique": "anti-debug | anti-VM | sandbox-detection | timing",
      "description": "short explanation",
      "evidence": ["..."]
    }}
  ],
  "notes": [...]
}}

Respond with JSON ONLY."""

CLASSIFICATION_SYSTEM_PROMPT = f"""{COMMON_HEADER_PROMPT}

You are the Classification Agent.

Your goal is to provide a SOC-style threat classification:
- overall verdict,
- risk level,
- likely family or category,
- mapping to known behaviors and ATT&CK patterns when supported by evidence.

You will receive as input:
- the oneshot summary JSON,
- and the outputs of the Capabilities, Structure, and Obfuscation agents.

You MUST:
- Base your verdict only on capabilities that have solid evidence.
- Avoid naming specific families (e.g., "WannaCry") unless you see very
  specific indicators (e.g., known strings, file names, protocols).
- It is acceptable to say "Unknown family" when evidence is not sufficient.

Output format:
{{
  "verdict": "MALICIOUS | GRAYWARE | BENIGN | UNKNOWN",
  "risk_level": "HIGH | MEDIUM | LOW | UNKNOWN",
  "family": "e.g., ransomware | loader | trojan | stealer | unknown",
  "justification": "1-3 sentences explaining the verdict, grounded in evidence",
  "key_behaviors": [
    {{
      "description": "short behavior description",
      "evidence": ["..."],
      "confidence": "HIGH | MEDIUM | LOW"
    }},
    ...
  ],
  "attack_mapping": [
    {{
      "tactic": "TAxxx or label",
      "technique": "Txxxx.y or label",
      "source": "capa | inferred",
      "evidence": ["..."]
    }}
  ],
  "open_questions": [
    "questions that a human analyst should investigate further"
  ]
}}

Respond with JSON ONLY."""

CONTEXT_SYNTH_SYSTEM_PROMPT = """You are the Context Synthesis Agent for kernagent.

You are given:
- a oneshot summary of a binary,
- a Capabilities report,
- a Structure/Flow report,
- an Obfuscation/Anti-Analysis report,
- and a Classification report.

Your job is to produce a single, comprehensive Markdown document called
"BINARY_CONTEXT.md" that will be reused across analyses and chat sessions.

The document MUST be concise, structured, and grounded in evidence.

Required sections (in this order):

1. Overview
   - 2-4 sentences summarizing the binary's purpose and risk.

2. Verdict & Risk
   - Verdict (MALICIOUS / GRAYWARE / BENIGN / UNKNOWN)
   - Risk Level (HIGH / MEDIUM / LOW / UNKNOWN)
   - Family (if any) or "Unknown"
   - Short justification (1-3 sentences).

3. Capabilities
   - For each relevant capability (network, filesystem, process, injection,
     persistence, crypto, privilege, anti-debug/VM, scripting/shell, IPC, etc.):
     - status (confirmed/likely/possible/no clear evidence),
     - 1-2 sentences of explanation,
     - 3-10 key evidence items in bullet form.

4. Structure & Key Paths
   - List probable entrypoints (name, EA, rationale).
   - List key pivot functions (name, EA, role).
   - Describe 3-5 main execution paths as bullet lists of functions
     with short inline roles.

5. Obfuscation & Anti-Analysis
   - Packing/protectors status + evidence.
   - Crypto usage summary (what is encrypted and where).
   - Anti-debug/anti-VM techniques summary.

6. Interesting Data & Configuration
   - Summarize "possible_configs" and other important data structures.
   - For each, mention EA, approximate size, and where it is used.

7. ATT&CK & TTPs (if applicable)
   - Short list of key ATT&CK tactics/techniques with evidence.

8. Analyst Notes & Next Steps
   - 3-10 bullet points suggesting what a human analyst should
     investigate in kernagent chat (concrete questions to ask).

Formatting requirements:
- Use Markdown headings (#, ##, ###) and bullet lists.
- Keep paragraphs short (1-3 sentences).
- Always provide function names and EAs when referring to functions.
- Always provide at least one evidence item for every important claim.

Do NOT include any YAML front matter; only Markdown content."""

BASIC_CONTEXT_SYSTEM_PROMPT = """You are the Context Synthesis Agent for kernagent.

You are given a deterministic oneshot summary of a binary (JSON). Build a concise
"BINARY_CONTEXT.md" that can guide further analysis and chat sessions. Work only
from the provided summary and call out uncertainty when evidence is thin.

Follow the same structure as the full context:
- Overview (2-4 sentences on purpose and risk)
- Verdict & Risk (verdict, risk level, family/unknown, short justification)
- Capabilities (status + explanation + evidence bullets)
- Structure & Key Paths (entrypoints, pivots, 3-5 execution paths)
- Obfuscation & Anti-Analysis
- Interesting Data & Configuration
- ATT&CK & TTPs (if applicable)
- Analyst Notes & Next Steps

Formatting: Markdown headings and bullet lists. Provide function names and EAs
wherever possible. Do NOT include YAML front matter; only Markdown content."""


def ensure_oneshot_summary(snapshot_dir: Path, verbose: bool = False) -> Dict[str, Any]:
    """Read or build oneshot_summary.json from a snapshot directory."""

    summary_path = snapshot_dir / "oneshot_summary.json"
    if summary_path.exists():
        with summary_path.open("r", encoding="utf-8") as fh:
            return json.load(fh)

    if verbose:
        logger.info("Building oneshot_summary.json for %s", snapshot_dir)
    summary = build_oneshot_summary(snapshot_dir, verbose=verbose)
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return summary


def detect_context_level(path: Path) -> str:
    """Return 'basic', 'full' or 'unknown' from the BINARY_CONTEXT.md header."""

    try:
        with path.open("r", encoding="utf-8") as fh:
            lines = [fh.readline().strip() for _ in range(6)]
    except FileNotFoundError:
        return "unknown"

    if not lines:
        return "unknown"

    if lines[0].strip().lower() != CONTEXT_HEADER.lower():
        return "unknown"

    for line in lines[1:]:
        if line.lower().startswith("level:"):
            value = line.split(":", 1)[1].strip().lower()
            if value in {"basic", "full"}:
                return value
    return "unknown"


def write_context_file(path: Path, markdown: str, level: str) -> None:
    """Write BINARY_CONTEXT.md with a simple header indicating context level."""

    header = f"{CONTEXT_HEADER}\nlevel: {level}\nversion: {CONTEXT_VERSION}\n\n"
    path.write_text(header + markdown.strip() + "\n", encoding="utf-8")


def _run_json_agent(llm: LLMClient, system_prompt: str, payload: Dict[str, Any], verbose: bool = False) -> Dict[str, Any]:
    """Call an agent expected to return JSON."""

    response = llm.chat(
        verbose=verbose,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(payload, indent=2)},
        ],
        temperature=0,
    )
    content = response.choices[0].message.content or "{}"
    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:  # pragma: no cover - depends on model output
        logger.error("Agent returned non-JSON response: %s", content[:200])
        raise ValueError(f"Agent response is not valid JSON: {exc}") from exc


def run_capabilities_agent(llm: LLMClient, summary: Dict[str, Any], verbose: bool = False) -> Dict[str, Any]:
    """Execute the capabilities agent and parse JSON output."""

    return _run_json_agent(llm, CAPABILITIES_SYSTEM_PROMPT, summary, verbose=verbose)


def run_structure_agent(llm: LLMClient, summary: Dict[str, Any], verbose: bool = False) -> Dict[str, Any]:
    """Execute the structure agent and parse JSON output."""

    return _run_json_agent(llm, STRUCTURE_SYSTEM_PROMPT, summary, verbose=verbose)


def run_obfuscation_agent(llm: LLMClient, summary: Dict[str, Any], verbose: bool = False) -> Dict[str, Any]:
    """Execute the obfuscation agent and parse JSON output."""

    return _run_json_agent(llm, OBFUSCATION_SYSTEM_PROMPT, summary, verbose=verbose)


def run_classification_agent(
    llm: LLMClient,
    summary: Dict[str, Any],
    capabilities: Dict[str, Any],
    structure: Dict[str, Any],
    obfuscation: Dict[str, Any],
    verbose: bool = False,
) -> Dict[str, Any]:
    """Execute the classification agent and parse JSON output."""

    payload = {
        "summary": summary,
        "capabilities": capabilities,
        "structure": structure,
        "obfuscation": obfuscation,
    }
    return _run_json_agent(llm, CLASSIFICATION_SYSTEM_PROMPT, payload, verbose=verbose)


def run_context_synth_agent(
    llm: LLMClient,
    summary: Dict[str, Any],
    capabilities: Dict[str, Any],
    structure: Dict[str, Any],
    obfuscation: Dict[str, Any],
    classification: Dict[str, Any],
    verbose: bool = False,
) -> str:
    """Run the synthesis agent to produce BINARY_CONTEXT.md content."""

    payload = {
        "summary": summary,
        "capabilities": capabilities,
        "structure": structure,
        "obfuscation": obfuscation,
        "classification": classification,
    }
    response = llm.chat(
        verbose=verbose,
        messages=[
            {"role": "system", "content": CONTEXT_SYNTH_SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(payload, indent=2)},
        ],
        temperature=0.1,
    )
    return (response.choices[0].message.content or "").strip()


def build_basic_context_markdown(summary: Dict[str, Any], settings: Settings, verbose: bool = False) -> str:
    """Build a BASIC context (Markdown) from the oneshot_summary via a single agent."""

    llm = LLMClient(settings)
    response = llm.chat(
        verbose=verbose,
        messages=[
            {"role": "system", "content": BASIC_CONTEXT_SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(summary, indent=2)},
        ],
        temperature=0.1,
    )
    return (response.choices[0].message.content or "").strip()


def build_full_context_markdown(summary: Dict[str, Any], settings: Settings, verbose: bool = False) -> str:
    """Build a FULL context (Markdown) from the oneshot_summary via multiple agents."""

    llm = LLMClient(settings)

    if verbose:
        logger.info("Running capabilities agent...")
    capabilities = run_capabilities_agent(llm, summary, verbose=verbose)

    if verbose:
        logger.info("Running structure agent...")
    structure = run_structure_agent(llm, summary, verbose=verbose)

    if verbose:
        logger.info("Running obfuscation agent...")
    obfuscation = run_obfuscation_agent(llm, summary, verbose=verbose)

    if verbose:
        logger.info("Running classification agent...")
    classification = run_classification_agent(
        llm,
        summary=summary,
        capabilities=capabilities,
        structure=structure,
        obfuscation=obfuscation,
        verbose=verbose,
    )

    if verbose:
        logger.info("Running context synthesis agent...")
    markdown = run_context_synth_agent(
        llm,
        summary=summary,
        capabilities=capabilities,
        structure=structure,
        obfuscation=obfuscation,
        classification=classification,
        verbose=verbose,
    )
    return markdown


def ensure_context(snapshot_dir: Path, settings: Settings, level: str = "basic", verbose: bool = False) -> Path:
    """Ensure that BINARY_CONTEXT.md exists at the requested level."""

    requested = (level or "basic").strip().lower()
    if requested not in {"basic", "full"}:
        raise ValueError("level must be 'basic' or 'full'")

    context_path = snapshot_dir / "BINARY_CONTEXT.md"
    current_level = detect_context_level(context_path) if context_path.exists() else "none"

    if current_level == "full" or (current_level == "basic" and requested == "basic"):
        if verbose:
            logger.info("Context already present at level '%s': %s", current_level, context_path)
        return context_path

    summary = ensure_oneshot_summary(snapshot_dir, verbose=verbose)

    if requested == "basic":
        markdown = build_basic_context_markdown(summary, settings, verbose=verbose)
        write_context_file(context_path, markdown, level="basic")
    else:
        markdown = build_full_context_markdown(summary, settings, verbose=verbose)
        write_context_file(context_path, markdown, level="full")

    if verbose:
        logger.info("Context generated at level '%s': %s", requested, context_path)
    return context_path
