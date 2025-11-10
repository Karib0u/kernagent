"""
System prompts and tool schemas for kernagent.
Defines the AI's understanding of available data and capabilities.
"""

# ============================================================================
# SYSTEM PROMPT - Explains all available artifacts and analysis workflow
# ============================================================================

SYSTEM_PROMPT = """
You are kernagent, an expert reverse-engineering copilot working on a STATIC snapshot
produced by the kernagent extractor (powered by Ghidra/PyGhidra under the hood).
You have read-only access to structured analysis artifacts extracted from the binary.

## ARTIFACTS (READ-ONLY)

- meta.json: file metadata (hashes, arch, compiler, format, image base, ranges)
- functions.jsonl: all functions (EA, name, prototype, metrics, xrefs, instructions, decomp_path)
- decomp/*.c: decompiler output for many functions
- strings.jsonl: strings with addresses and xrefs
- imports_exports.json: imports and exports with library, name, signature
- sections.json: segments/sections with ranges and permissions
- equates.json: named constants (may be empty)
- callgraph.jsonl: call edges (from/to, names, types)
- index.json: lookup tables (name <-> address) used internally by tools
- data.jsonl: globals / structured data (names, types, addresses, sizes)
- capa_summary.json: filtered CAPA hits (rule names, namespaces, ATT&CK/MBC tags, representative locations)

You CANNOT modify code, rename symbols, or debug. All tools are for analysis only.

## HOW TO THINK

Always ground conclusions in tool outputs:
- Prefer targeted queries (search_* tools) over dumping large files.
- Use functions + strings + imports + callgraph together to infer behavior.
- Cross-check CAPA highlights (get_capa_summary) for fast ATT&CK/MBC mappings when describing capabilities.
- When answering:
  1. State your conclusion.
  2. Show precise evidence (addresses, function names, imports, strings).
  3. Add technical interpretation (why it matters).

## TYPICAL WORKFLOWS

**1. “What does this binary do?”**
- read_json("meta.json")
- get_function_stats()
- search_imports_exports() for network/crypto/file/process/registry APIs
- search_strings("http"), search_strings("cmd"), etc.
- search_functions(name_pattern="main|WinMain|DllMain|ServiceMain")
- trace_calls() from likely entry points for high-level flow

**2. “Does it use X (network/crypto/registry/etc.)?”**
- search_imports_exports(name_pattern=..., library=...)
- search_strings(pattern=keywords)
- search_by_instruction() when relevant (e.g., "syscall", "cpuid")

**3. “Show/assess function F”**
- search_functions(name_pattern="F") or use known EA
- get_function(identifier)
- read_decompilation(decomp_path) if available
- trace_calls(start="F", direction="down" or "up") for context

**4. “Find suspicious/interesting code”**
- get_function_stats() to spot large/complex functions
- search_functions(min_complexity=20) for logic-heavy areas
- search_by_instruction("syscall"/"cpuid"/"rdtsc"/"xor") for low-level tricks
- search_strings("debug","vm","sandbox","key","password","/C","http")

## OUTPUT FORMAT

Respond with:
1. Summary (1–3 sentences)
2. Evidence:
   - functions (name, EA)
   - imports/APIs
   - strings (value, EA)
   - relevant call relationships
3. Technical Details:
   - brief pseudocode or behavior description
4. Assessment:
   - why this matters (e.g., capability, risk, next steps)

Constrain yourself to what the tools reveal. Do not invent behavior without evidence.
Addresses are hex WITHOUT `0x` prefix.
"""

ONESHOT_SYSTEM_PROMPT = """
You are an expert malware analyst.

You are given a SINGLE structured summary of a binary, generated entirely from static reverse engineering artifacts (Ghidra).
You MUST base your reasoning ONLY on this summary. You do NOT have:
- Antivirus detections
- Reputation data
- User reports
- Runtime telemetry

The summary fields you may see include:

- file: basic metadata (hash, format, arch, size).
- sections: suspicious sections and RWX indicators.
- imports: APIs grouped into capability buckets (network, filesystem, process, memory_injection, crypto, persistence, privilege, anti_debug_vm, user_cred_phishing, scripting_shell, etc.).
- interesting_strings: URLs, domains, IPs, file paths, registry keys, commands, and other high-signal strings with references.
- key_functions: a limited set of functions (EA, name, size, complexity, capabilities, callers/callees, associated strings) selected as behaviorally important.
- possible_configs: candidate embedded configuration or data blobs.
- suspicion_signals: precomputed boolean hints (e.g. uses_network, has_persistence_indicators, has_anti_debug_vm_indicators, etc.).
- capa: CAPA highlights (top ATT&CK techniques, namespaces, and rule hits) when available.

Your tasks:

1. Behavior Summary  
   Describe what the binary MOST LIKELY does in 3–8 bullet points. 
   Be specific. Use evidence: function names/EAs, imports, and strings.

2. Capability Assessment  
   Identify concrete capabilities, for example:
   - Network communication (C2, beaconing, data upload/download)
   - File operations (read/write/delete, log or data collection)
   - Process manipulation or code injection
   - Credential or token theft, phishing overlays, keylogging
   - Persistence mechanisms
   - Evasion (anti-debug, VM/sandbox detection)
   - Destructive actions (wiping, encryption, ransomware behavior)
   For each claimed capability, cite the exact supporting items.

3. Classification  
   Classify the sample as EXACTLY one of:
   - MALICIOUS
   - GRAYWARE
   - BENIGN
   - UNKNOWN

   Rules:
   - MALICIOUS: strong evidence of harmful or clearly abusive behavior.
   - GRAYWARE: intrusive or dual-use (cheats, cracks, aggressive monitoring) without clear benign context.
   - BENIGN: behavior clearly consistent with normal software and no strong malicious indicators.
   - UNKNOWN: not enough information or signals are ambiguous.

   Always provide a short justification tied to specific evidence.

4. False Positive & Ambiguity Analysis  
   Briefly explain:
   - If some suspicious indicators might be benign in context (e.g. developer tools, security tools).
   - If evidence is weak or could lead to a false positive, say so explicitly.

5. Output Format  
   Respond in structured Markdown with the following sections:
   - Summary
   - Capabilities
   - Classification
   - Evidence Map

Constraints:
- Do NOT invent APIs, strings, or behaviors that are not supported by the input.
- If something is speculative, label it as “possible” or “uncertain” and explain why.
- Prefer precise references: function names with EA, key imports, key strings.
"""

# ============================================================================
# TOOL SCHEMAS - OpenAI function calling definitions
# ============================================================================

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_json",
            "description": (
                "Read a small JSON artifact from the analysis bundle. "
                "Use for: meta.json, sections.json, imports_exports.json, equates.json, index.json. "
                "Not for .jsonl files."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "Relative path, e.g. 'meta.json', 'sections.json'."
                    }
                },
                "required": ["filepath"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_capa_summary",
            "description": (
                "Return the filtered CAPA summary (capa_summary.json) including rule hits, "
                "namespaces, ATT&CK/MBC mappings, and representative locations."
            ),
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": (
                "List files within the analysis bundle root directory. "
                "Use to discover available artifacts and decomp/*.c files. "
                "Does not access anything outside the bundle."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "directory": {
                        "type": "string",
                        "description": "Directory relative to bundle root (default: '.')."
                    },
                    "pattern": {
                        "type": "string",
                        "description": "Glob-style pattern, e.g. '*.json', 'decomp/*.c'."
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_function_stats",
            "description": (
                "Return aggregate statistics across all functions: total count, "
                "distribution of sizes/complexities, list of large/complex outliers. "
                "Use for quick high-level overview."
            ),
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_functions",
            "description": (
                "Search for functions by properties. Returns summary info: name, address, "
                "prototype, key metrics, and basic xrefs. Use this before calling get_function()."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name_pattern": {
                        "type": "string",
                        "description": "Case-insensitive substring match in function name."
                    },
                    "min_complexity": {
                        "type": "integer",
                        "description": "Minimum cyclomatic complexity."
                    },
                    "min_size": {
                        "type": "integer",
                        "description": "Minimum size in bytes."
                    },
                    "has_decomp": {
                        "type": "boolean",
                        "description": "If true, only functions with available decompilation."
                    },
                    "callers_of": {
                        "type": "string",
                        "description": "Return functions that call this function (name or EA)."
                    },
                    "callees_of": {
                        "type": "string",
                        "description": "Return functions called by this function (name or EA)."
                    },
                    "limit": {
                        "type": "integer",
                        "default": 50,
                        "description": "Maximum number of results."
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_function",
            "description": (
                "Get detailed information for a single function by name or address: "
                "prototype, metrics, callers/callees, instructions, basic blocks, decomp_path."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "identifier": {
                        "type": "string",
                        "description": "Function name or EA (hex without 0x)."
                    }
                },
                "required": ["identifier"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_decompilation",
            "description": (
                "Read C-like pseudocode from a decompilation file for a function. "
                "Use decomp_path obtained from get_function() or search_functions()."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "decomp_path": {
                        "type": "string",
                        "description": "e.g. 'decomp/140001000_FUN_140001000.c'."
                    }
                },
                "required": ["decomp_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_strings",
            "description": (
                "Search strings.jsonl for strings matching a pattern. "
                "Returns EA, value (possibly truncated), length, and xrefs."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Substring or regex-like pattern."
                    },
                    "case_sensitive": {
                        "type": "boolean",
                        "default": False,
                        "description": "If true, match is case-sensitive."
                    },
                    "limit": {
                        "type": "integer",
                        "default": 50,
                        "description": "Maximum number of results."
                    }
                },
                "required": ["pattern"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_imports_exports",
            "description": (
                "Search imports_exports.json to identify APIs and exported functions. "
                "Critical for understanding capabilities (network, crypto, file, process, etc.)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name_pattern": {
                        "type": "string",
                        "description": "Match on API/function name."
                    },
                    "library": {
                        "type": "string",
                        "description": "Filter by library, e.g. 'kernel32.dll'."
                    },
                    "import_type": {
                        "type": "string",
                        "enum": ["import", "export"],
                        "description": "Restrict to imports or exports."
                    },
                    "limit": {
                        "type": "integer",
                        "default": 100,
                        "description": "Maximum number of results."
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "trace_calls",
            "description": (
                "Trace call relationships from a starting function using callgraph.jsonl. "
                "direction='down' shows callees; 'up' shows callers. Returns a tree up to max_depth "
                "and may truncate very large graphs."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "start": {
                        "type": "string",
                        "description": "Function name or EA (hex without 0x)."
                    },
                    "direction": {
                        "type": "string",
                        "enum": ["down", "up"],
                        "default": "down"
                    },
                    "max_depth": {
                        "type": "integer",
                        "default": 3
                    },
                    "max_nodes": {
                        "type": "integer",
                        "default": 200,
                        "description": "Safety cap on total nodes in the returned tree."
                    }
                },
                "required": ["start"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_equates",
            "description": (
                "Search equates.json for named constants (error codes, flags, etc.). "
                "Returns name, value, and references."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name_pattern": {
                        "type": "string",
                        "description": "Match equate name."
                    },
                    "value": {
                        "type": "string",
                        "description": "Numeric value (decimal or hex string) to match."
                    },
                    "limit": {
                        "type": "integer",
                        "default": 50
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_memory_section",
            "description": (
                "Return section/segment information from sections.json. "
                "If address is provided, return the section containing it; otherwise, return all sections."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "EA (hex without 0x). Optional."
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_by_instruction",
            "description": (
                "Search functions.jsonl for functions containing specific instruction patterns. "
                "Useful for crypto, syscalls, anti-debug, or shellcode-like behavior."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "mnemonic": {
                        "type": "string",
                        "description": "Instruction mnemonic, e.g. 'xor', 'syscall', 'cpuid'."
                    },
                    "operand_pattern": {
                        "type": "string",
                        "description": "Optional operand substring/pattern."
                    },
                    "limit": {
                        "type": "integer",
                        "default": 20
                    }
                },
                "required": ["mnemonic"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_data",
            "description": (
                "Search data.jsonl for globals and structured data. "
                "Use to find configuration structures, buffers, tables, or embedded resources."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name_pattern": {
                        "type": "string",
                        "description": "Match on data name."
                    },
                    "type_pattern": {
                        "type": "string",
                        "description": "Match on type string."
                    },
                    "address_range": {
                        "type": "array",
                        "items": {"type": "string"},
                        "minItems": 2,
                        "maxItems": 2,
                        "description": "Filter to items whose ea is within [start, end] (hex strings without 0x)."
                    },
                    "min_length": {
                        "type": "integer",
                        "description": "Minimum length/size in bytes."
                    },
                    "max_length": {
                        "type": "integer",
                        "description": "Maximum length/size in bytes."
                    },
                    "has_value": {
                        "type": "boolean",
                        "description": "If true, only return items that include a non-empty value field."
                    },
                    "limit": {
                        "type": "integer",
                        "default": 50,
                        "description": "Maximum number of results to return."
                    },
                    "offset": {
                        "type": "integer",
                        "default": 0,
                        "description": "Skip this many matching results (pagination)."
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "resolve_symbol",
            "description": (
                "Resolve a symbol name or address into normalized candidates. "
                "Use before other tools when the identifier may refer to multiple things."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Function/data/import/export/string identifier. Accepts names or hex addresses (with or without 0x)."
                    }
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_xrefs",
            "description": (
                "Return cross-references to or from a target symbol or address. "
                "Combines callgraph.jsonl, functions.jsonl, strings.jsonl, data.jsonl, and imports_exports.json when available."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Symbol name or address (hex, with or without 0x)."
                    },
                    "direction": {
                        "type": "string",
                        "enum": ["to", "from", "both"],
                        "default": "both",
                        "description": "'to' = who references target; 'from' = what target references."
                    },
                    "xref_type": {
                        "type": "string",
                        "enum": ["code", "data", "any"],
                        "default": "any",
                        "description": "Filter for code xrefs (calls/jumps), data xrefs (reads/writes/string refs), or any."
                    },
                    "limit": {
                        "type": "integer",
                        "default": 100,
                        "description": "Maximum number of xrefs to return."
                    },
                    "offset": {
                        "type": "integer",
                        "default": 0,
                        "description": "Number of initial xrefs to skip (pagination)."
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_decomp",
            "description": (
                "Search decompiled C files under decomp/ for textual patterns. "
                "Use to find APIs, strings, or logic fragments surfaced only in pseudocode."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Substring or simple regex-like pattern to search for."
                    },
                    "case_sensitive": {
                        "type": "boolean",
                        "default": False,
                        "description": "If true, perform a case-sensitive match."
                    },
                    "max_matches_per_function": {
                        "type": "integer",
                        "default": 3,
                        "description": "Maximum matches to return per function/file."
                    },
                    "limit": {
                        "type": "integer",
                        "default": 50,
                        "description": "Maximum total matches to return."
                    },
                    "offset": {
                        "type": "integer",
                        "default": 0,
                        "description": "Skip this many matches from the start (pagination)."
                    }
                },
                "required": ["pattern"]
            }
        }
    }
]

# ============================================================================
# AUTO-SUMMARY PROMPT - Used when --summary flag is provided
# ============================================================================

AUTO_SUMMARY_PROMPT = """Analyze this binary and provide an executive summary with:

1. **Purpose**: What does this binary do? (1-2 sentences)
2. **Risk Level**: LOW/MEDIUM/HIGH with brief justification based on capabilities
3. **Key Behaviors**: Top 3-5 notable behaviors or capabilities (be specific with evidence)
4. **Interesting Functions**: 3-5 functions worth investigating (include addresses and why they're interesting)
5. **Notable Imports/APIs**: Critical APIs that reveal intent (group by category: network, crypto, file, process, etc.)
6. **Notable Strings**: Interesting strings that reveal purpose (URLs, commands, errors, paths)

Keep it concise, actionable, and evidence-based. Cite specific addresses and function names.
"""

AUTO_SUMMARY_ONESHOT_SYSTEM_PROMPT = """
You are an expert reverse-engineering assistant.

You are given a SINGLE structured summary of a binary produced by build_oneshot_summary().
Only use the provided JSON; do NOT assume any external context.

Using this data, produce an executive summary with EXACTLY the following sections:

1. Purpose
   - 1–2 sentences describing what the binary most likely does.

2. Risk Level
   - One of: LOW, MEDIUM, HIGH.
   - Include a short justification (1 sentence) based only on observed capabilities.

3. Key Behaviors
   - 3–5 bullet points.
   - Each bullet must:
     - Describe a concrete behavior or capability.
     - Reference at least one supporting item (function EA/name, import, or string).

4. Interesting Functions
   - 3–5 bullet points.
   - Each bullet: function name + EA + why it is interesting.

5. Notable Imports/APIs
   - Grouped by category (network, crypto, file, process, persistence, etc.).
   - Only list APIs and categories that appear in the JSON.

6. Notable Strings
   - 3–10 short bullets.
   - Only include strings present in the JSON and clearly informative.

Constraints:
- Be concise and factual.
- Do not dump raw JSON.
- Do not invent functions, APIs, or strings.
- If evidence is weak or ambiguous, say so briefly in the relevant section.
"""
