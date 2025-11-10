"""Lightweight wrapper around flare-capa to emit filtered JSON summaries."""

from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .log import get_logger

logger = get_logger(__name__)

CAPA_SUMMARY_VERSION = "capa_summary_v1"
CAPA_MAX_LOCATIONS_PER_RULE = 5
CAPA_MAX_RULES_IN_SUMMARY = 200
EXCLUDED_RULE_NAMES = {"contain loop"}

try:  # pragma: no cover - optional dependency resolved at runtime
    import capa.main
    import capa.rules
    import capa.loader
    import capa.capabilities.common
    import capa.render.result_document as rd
    from capa.features.common import FORMAT_AUTO, OS_AUTO
    from capa.version import __version__ as CAPA_VERSION

    _CAPA_IMPORT_ERROR: Exception | None = None
except Exception as exc:  # pragma: no cover - handled gracefully at runtime
    capa = None  # type: ignore[assignment]
    FORMAT_AUTO = OS_AUTO = None  # type: ignore[assignment]
    CAPA_VERSION = None  # type: ignore[assignment]
    rd = None  # type: ignore[assignment]
    _CAPA_IMPORT_ERROR = exc


@dataclass
class CapaRuleSummary:
    """Filtered view of a single capa rule hit."""

    name: str
    namespace: str | None
    scope: str | None
    description: str | None
    attack: List[Dict[str, Any]]
    mbc: List[Dict[str, Any]]
    locations: List[Dict[str, Any]]
    tags: List[str]
    match_count: int


def _env_flag(name: str) -> bool:
    value = os.getenv(name, "")
    return value.lower() in {"1", "true", "yes", "on"}


def _resolve_rules_path(explicit: Optional[Path]) -> Optional[Path]:
    """Resolve capa rules directory (env override > explicit argument)."""

    if explicit:
        return explicit

    env_value = os.getenv("CAPA_RULES_PATH")
    if not env_value:
        return None

    path = Path(env_value).expanduser()
    if path.exists():
        return path

    logger.warning("CAPA_RULES_PATH=%s does not exist; falling back to built-in rules", env_value)
    return None


def _format_location(location) -> Dict[str, Any]:
    """Convert capa location info into JSON-safe dict."""

    loc_type = getattr(location, "type", None)
    type_label = getattr(loc_type, "value", None) if loc_type is not None else None
    if not type_label and loc_type is not None:
        type_label = str(loc_type)

    value = getattr(location, "value", None)
    entry: Dict[str, Any] = {"type": type_label or "unknown"}

    if isinstance(value, int):
        entry["address"] = f"0x{value:0x}"
    elif value is not None:
        entry["value"] = str(value)

    return entry


def _normalize_namespace(rule_meta) -> str | None:
    namespace = getattr(rule_meta, "namespace", None)
    if not namespace:
        return None
    return str(namespace)


def _normalize_scope(rule_meta) -> str | None:
    scope = getattr(rule_meta, "scope", None)
    if not scope:
        return None
    return str(scope)


def _normalize_tags(rule_meta) -> List[str]:
    tags = getattr(rule_meta, "tags", None)
    if not tags:
        return []
    return sorted({str(tag) for tag in tags})


def _ensure_string_list(value) -> List[str]:
    """Normalize a tactic/objective field to a list of strings."""

    if not value:
        return []
    if isinstance(value, str):
        return [value]
    try:
        return [str(item) for item in value if item]
    except TypeError:
        return [str(value)]


def _summarize_rule(rule_name: str, rule_data) -> Optional[CapaRuleSummary]:
    """Filter and normalize a capa rule entry."""

    if rule_name in EXCLUDED_RULE_NAMES:
        return None

    meta = getattr(rule_data, "meta", None)
    if meta is None:
        return None

    attack_entries: List[Dict[str, Any]] = []
    for attack in getattr(meta, "attack", []) or []:
        attack_entries.append(
            {
                "id": getattr(attack, "id", None),
                "technique": getattr(attack, "technique", None),
                "subtechnique": getattr(attack, "subtechnique", None),
                "tactic": _ensure_string_list(getattr(attack, "tactic", None)),
            }
        )

    mbc_entries: List[Dict[str, Any]] = []
    for mbc in getattr(meta, "mbc", []) or []:
        mbc_entries.append(
            {
                "id": getattr(mbc, "id", None),
                "behavior": getattr(mbc, "behavior", None),
                "objective": _ensure_string_list(getattr(mbc, "objective", None)),
                "method": getattr(mbc, "method", None),
            }
        )

    locations: List[Dict[str, Any]] = []
    for location, _detail in getattr(rule_data, "matches", []):
        locations.append(_format_location(location))
        if len(locations) >= CAPA_MAX_LOCATIONS_PER_RULE:
            break

    return CapaRuleSummary(
        name=rule_name,
        namespace=_normalize_namespace(meta),
        scope=_normalize_scope(meta),
        description=getattr(meta, "description", None),
        attack=attack_entries,
        mbc=mbc_entries,
        locations=locations,
        tags=_normalize_tags(meta),
        match_count=len(getattr(rule_data, "matches", [])),
    )


def _rule_score(summary: CapaRuleSummary) -> int:
    """Deterministic ranking heuristic for capa results."""

    score = 0
    if summary.attack:
        score += 100
    if summary.mbc:
        score += 40
    if summary.namespace and any(keyword in summary.namespace.lower() for keyword in ("network", "process", "crypto", "persistence")):
        score += 10
    score += min(summary.match_count, 25)
    if summary.tags:
        score += 5
    return score


def _aggregate_highlights(rules: Iterable[CapaRuleSummary]) -> Dict[str, Any]:
    attack_counter: Counter[str] = Counter()
    tactic_counter: Counter[str] = Counter()
    namespace_counter: Counter[str] = Counter()
    attack_lookup: Dict[str, Dict[str, Any]] = {}

    for summary in rules:
        namespace_counter[summary.namespace or "global"] += 1
        for attack in summary.attack:
            attack_id = attack.get("id") or attack.get("technique")
            if not attack_id:
                continue
            attack_counter[attack_id] += 1
            attack_lookup.setdefault(attack_id, attack)
            for tactic in attack.get("tactic") or []:
                tactic_counter[tactic] += 1

    top_attack = [
        {
            "id": attack_id,
            "count": count,
            "technique": attack_lookup[attack_id].get("technique"),
            "tactic": attack_lookup[attack_id].get("tactic"),
        }
        for attack_id, count in attack_counter.most_common(8)
    ]

    top_tactics = [{"tactic": name, "count": count} for name, count in tactic_counter.most_common(8)]
    top_namespaces = [{"namespace": name, "count": count} for name, count in namespace_counter.most_common(8)]

    return {
        "top_attack_ids": top_attack,
        "top_tactics": top_tactics,
        "top_namespaces": top_namespaces,
    }


def _analyze_with_capa(binary_path: Path, rules_path: Optional[Path]):
    """Run capa analysis and return the result document."""

    if _CAPA_IMPORT_ERROR is not None:
        raise RuntimeError(
            "flare-capa is unavailable. Install flare-capa to enable CAPA summaries."
        ) from _CAPA_IMPORT_ERROR

    rule_dirs = [rules_path] if rules_path else []
    rules = capa.rules.get_rules(rule_dirs)

    extractor = capa.loader.get_extractor(
        binary_path,
        FORMAT_AUTO,
        OS_AUTO,
        capa.main.BACKEND_VIV,
        [],
        False,
        disable_progress=True,
    )

    capabilities = capa.capabilities.common.find_capabilities(rules, extractor, disable_progress=True)

    meta = capa.loader.collect_metadata(
        ["kernagent", "capa"],
        binary_path,
        FORMAT_AUTO,
        OS_AUTO,
        rule_dirs,
        extractor,
        capabilities,
    )

    meta.analysis.layout = capa.loader.compute_layout(rules, extractor, capabilities.matches)

    doc = rd.ResultDocument.from_capa(meta, rules, capabilities.matches)
    return doc, rules


def build_capa_summary(binary_path: Path, output_dir: Path, rules_path: Path | None = None) -> Optional[Path]:
    """
    Execute flare-capa on `binary_path` and write a filtered JSON summary.

    Returns:
        Path to capa_summary.json if generated, else None.
    """

    if _env_flag("CAPA_DISABLE"):
        logger.info("CAPA_DISABLE is set; skipping capa analysis.")
        return None

    binary_path = Path(binary_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    resolved_rules = _resolve_rules_path(rules_path)
    output_path = output_dir / "capa_summary.json"

    try:
        doc, rules = _analyze_with_capa(binary_path, resolved_rules)
    except Exception as exc:  # pragma: no cover - depends on runtime environment
        logger.warning("capa analysis failed for %s: %s", binary_path, exc)
        return None

    summaries: List[CapaRuleSummary] = []
    for rule_name, rule_data in doc.rules.items():
        summary = _summarize_rule(rule_name, rule_data)
        if summary:
            summaries.append(summary)

    if not summaries:
        logger.info("capa produced no high-signal matches for %s", binary_path)
        return None

    summaries = sorted(
        summaries,
        key=lambda entry: (-_rule_score(entry), entry.namespace or "", entry.name),
    )[:CAPA_MAX_RULES_IN_SUMMARY]

    counts = {
        "rules": len(summaries),
        "matches": sum(entry.match_count for entry in summaries),
        "attack_mappings": sum(len(entry.attack) for entry in summaries),
        "mbc_mappings": sum(len(entry.mbc) for entry in summaries),
    }

    highlights = _aggregate_highlights(summaries)

    rules_payload = [
        {
            "name": entry.name,
            "namespace": entry.namespace,
            "scope": entry.scope,
            "description": entry.description,
            "attack": entry.attack,
            "mbc": entry.mbc,
            "locations": entry.locations,
            "tags": entry.tags,
            "match_count": entry.match_count,
        }
        for entry in summaries
    ]

    sample_meta = {
        "sha256": getattr(doc.meta.sample, "sha256", None),
        "md5": getattr(doc.meta.sample, "md5", None),
        "path": str(binary_path),
    }

    payload = {
        "schema_version": CAPA_SUMMARY_VERSION,
        "capa_version": CAPA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "rules_source": str(resolved_rules) if resolved_rules else "builtin",
        "rules_loaded": len(rules),
        "sample": sample_meta,
        "counts": counts,
        "highlights": highlights,
        "rules": rules_payload,
    }

    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    logger.info(
        "capa summary written for %s (%d rules, %d attack mappings)",
        binary_path.name,
        counts["rules"],
        counts["attack_mappings"],
    )
    return output_path


__all__ = ["build_capa_summary", "CAPA_SUMMARY_VERSION"]
