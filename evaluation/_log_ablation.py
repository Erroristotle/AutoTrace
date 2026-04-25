#!/usr/bin/env python3
"""Shared log/results parsing helpers for RQ3-style evaluation."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    from _common import (
        AgentSliceEvaluator,
        PredictionComparison,
        PROJECT_ROOT,
        best_per_cve,
        compute_metrics,
    )
except ModuleNotFoundError:  # pragma: no cover - package import path
    from evaluation._common import (
        AgentSliceEvaluator,
        PredictionComparison,
        PROJECT_ROOT,
        best_per_cve,
        compute_metrics,
    )


DEFAULT_LOGS_DIR = PROJECT_ROOT / "logs"
DEFAULT_ABLATION_ROOT = PROJECT_ROOT / "experiments" / "results" / "exp_ablation"


_TIMESTAMP_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
_HARD_REJECT_RE = re.compile(
    r"Layer 1 FAILED:\s+No dataflow\s+(?P<variable>.+?)\s+→\s+(?P<statement>.+?)\s*$"
)
_SOFT_REJECT_RE = re.compile(
    r"Layer 1 UNVERIFIED .*?:\s+no path found for\s+(?P<variable>.+?)\s+→\s+"
    r"(?P<statement>.+?)(?:\s+—\s+forwarding to agent)?\s*$"
)
_VERIFIER_REJECT_RE = re.compile(r"Verification Agent REJECTED:\s+(?P<reason>.+?)\s*$")
_RETRY_RE = re.compile(r"reflection retry", re.IGNORECASE)
_MID_REFLECTION_RE = re.compile(r"\[Reflection iter=(?P<iteration>\d+)\]")
_BATCH_REACHABILITY_RE = re.compile(
    r"Batch reachability:\s+.*?from\s+'(?P<variable>[^']+)'\s+in\s+(?P<function>.+?)\s*$"
)
_JOERN_EXPAND_RE = re.compile(
    r"Joern auto-expand:\s+(?P<target>[A-Za-z_][A-Za-z0-9_]*)\('(?P<variable>[^']+)'\)\s+"
    r"depth=(?P<depth>-?\d+)\s+\(confirmed CV flow from\s+(?P<source>.+?)\)"
)
_TEXT_EXPAND_RE = re.compile(
    r"Text callee-expand:\s+(?P<target>[A-Za-z_][A-Za-z0-9_]*)\('(?P<variable>[^']+)'\)\s+"
    r"depth=(?P<depth>-?\d+)\s+\(text analysis of\s+(?P<source>.+?)\)"
)
_PROVEN_TRIGGER_RE = re.compile(
    r"\[(?P<label>[^\]]+)\]\s+Proven trigger at\s+(?P<file>.+?):(?P<line>\d+)\s*$"
)
_AGENT_STOP_RE = re.compile(r"Agent says stop:\s+(?P<reason>.+?)\s*$")

_MEMORY_WRITE_RE = re.compile(
    r"memcpy|memmove|memset|strcpy|strncpy|strcat|strncat|sprintf|snprintf|copy_to_user"
)
_MEMORY_READ_RE = re.compile(
    r"strcmp|strncmp|memcmp|strlen|strchr|strrchr|copy_from_user|extract_|get_user|\*[^=]+"
)
_ALLOC_RE = re.compile(r"malloc|calloc|realloc|kmalloc|kzalloc|kcalloc|alloc")
_FREE_RE = re.compile(r"\bfree\b|kfree|vfree|relinquish")
_ARITH_RE = re.compile(r"\+|-|\*|/|%|<<|>>")


@dataclass
class LLMCallRecord:
    ts: Optional[float]
    agent: str
    mode: str
    function: str
    variable: str
    sink_line: int
    meta: Dict[str, Any]
    prompt_path: str
    response_path: str


@dataclass
class LogEvent:
    kind: str
    ts: Optional[float]
    line_no: int
    variable: str = ""
    function: str = ""
    statement: str = ""
    reason: str = ""
    source_function: str = ""
    target_function: str = ""
    depth: int = 0
    sink_line: int = 0
    raw: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _load_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    rows: List[Dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(payload, dict):
                    rows.append(payload)
    except Exception:
        return []
    return rows


def result_dirs(results_dir: Path) -> List[Path]:
    return sorted(
        path for path in results_dir.iterdir()
        if path.is_dir() and path.name.startswith("CVE-")
    )


def normalize_function_name(func: Any) -> str:
    if not func:
        return ""
    text = str(func).strip()
    if "(" in text:
        text = text.split("(", 1)[0].strip()
    return text


def normalize_statement(stmt: Any) -> str:
    if not stmt:
        return ""
    text = re.sub(r"\s+", " ", str(stmt).strip())
    return text.rstrip(";")


def _compact_statement(stmt: Any) -> str:
    return re.sub(r"\s+", "", normalize_statement(stmt))


def parse_gt_lines(gt_entry: Dict[str, Any]) -> List[int]:
    line_data = gt_entry.get("Vulnerability-triggered line numbers", "")
    if isinstance(line_data, list):
        out: List[int] = []
        for item in line_data:
            try:
                out.append(int(str(item).strip()))
            except (TypeError, ValueError):
                continue
        return out
    if isinstance(line_data, (int, float)):
        return [int(line_data)]
    out = []
    for chunk in str(line_data).split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            out.append(int(chunk))
        except (TypeError, ValueError):
            continue
    return out


def parse_gt_statements(gt_entry: Dict[str, Any]) -> List[str]:
    raw = gt_entry.get("Vulnerability-triggered statements", [])
    if isinstance(raw, list):
        return [str(item) for item in raw if str(item).strip()]
    text = str(raw).strip()
    return [text] if text else []


def parse_patch_functions(gt_entry: Dict[str, Any]) -> List[str]:
    raw = gt_entry.get("Patch statement function", "") or ""
    parts = [normalize_function_name(piece) for piece in re.split(r"[\n,]", str(raw))]
    seen = set()
    out = []
    for item in parts:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def anchor_functions(gt_entry: Dict[str, Any]) -> List[str]:
    seen = set()
    out = []
    for item in [gt_entry.get("Vulnerability-triggered function", "")] + parse_patch_functions(gt_entry):
        norm = normalize_function_name(item)
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out


def infer_sink_family(statement: Any) -> str:
    text = normalize_statement(statement).lower()
    if not text:
        return "unknown"
    if _FREE_RE.search(text):
        return "deallocation"
    if _ALLOC_RE.search(text):
        return "allocation"
    if _MEMORY_WRITE_RE.search(text):
        return "memory_write"
    if _MEMORY_READ_RE.search(text):
        return "memory_read"
    if text.startswith("if (") or text.startswith("while (") or text.startswith("switch ("):
        return "memory_read" if "->" in text or "*" in text else "control"
    if "=" in text and ("[" in text or "->" in text or "*" in text):
        return "memory_write"
    if _ARITH_RE.search(text):
        return "arithmetic"
    return "unknown"


def _parse_timestamp(line: str) -> Optional[float]:
    match = _TIMESTAMP_RE.match(line)
    if not match:
        return None
    try:
        return datetime.strptime(match.group("ts"), "%Y-%m-%d %H:%M:%S").timestamp()
    except ValueError:
        return None


def load_llm_calls(cve_dir: Path) -> List[LLMCallRecord]:
    rows = _load_jsonl(cve_dir / "llm_calls.jsonl")
    calls: List[LLMCallRecord] = []
    for row in rows:
        meta = row.get("meta") if isinstance(row.get("meta"), dict) else {}
        try:
            sink_line = int(meta.get("sink_line", 0) or 0)
        except Exception:
            sink_line = 0
        calls.append(
            LLMCallRecord(
                ts=float(row.get("ts")) if row.get("ts") is not None else None,
                agent=str(row.get("agent") or ""),
                mode=str(meta.get("mode") or ""),
                function=normalize_function_name(meta.get("function") or ""),
                variable=str(meta.get("variable") or ""),
                sink_line=sink_line,
                meta=meta,
                prompt_path=str(row.get("prompt_path") or ""),
                response_path=str(row.get("response_path") or ""),
            )
        )
    calls.sort(key=lambda item: (item.ts is None, item.ts or 0.0))
    return calls


def _nearest_llm_call(
    calls: Iterable[LLMCallRecord],
    *,
    ts: Optional[float],
    variable: str = "",
    agent: Optional[str] = None,
    before_only: bool = True,
    max_delta_seconds: float = 900.0,
) -> Optional[LLMCallRecord]:
    best: Optional[LLMCallRecord] = None
    best_delta = float("inf")
    for call in calls:
        if agent and call.agent != agent:
            continue
        if variable and call.variable and call.variable != variable:
            continue
        if ts is not None and call.ts is not None:
            delta = call.ts - ts
            if before_only and delta > 0:
                continue
            abs_delta = abs(delta)
            if abs_delta > max_delta_seconds:
                continue
        else:
            abs_delta = 0.0
        if abs_delta < best_delta:
            best = call
            best_delta = abs_delta
    return best


def _next_llm_call(
    calls: Iterable[LLMCallRecord],
    *,
    ts: Optional[float],
    variable: str = "",
    agent: Optional[str] = None,
    max_delta_seconds: float = 120.0,
) -> Optional[LLMCallRecord]:
    best: Optional[LLMCallRecord] = None
    best_delta = float("inf")
    for call in calls:
        if agent and call.agent != agent:
            continue
        if variable and call.variable and call.variable != variable:
            continue
        if ts is not None and call.ts is not None:
            delta = call.ts - ts
            if delta < 0 or delta > max_delta_seconds:
                continue
        else:
            delta = 0.0
        if delta < best_delta:
            best = call
            best_delta = delta
    return best


def parse_log_events(log_path: Path, llm_calls: Optional[List[LLMCallRecord]] = None) -> List[LogEvent]:
    if not log_path.exists():
        return []

    current_function = ""
    current_variable = ""
    events: List[LogEvent] = []
    llm_calls = llm_calls or []

    try:
        lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []

    for line_no, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        ts = _parse_timestamp(line)

        match = _BATCH_REACHABILITY_RE.search(line)
        if match:
            current_function = normalize_function_name(match.group("function"))
            current_variable = str(match.group("variable") or "")
            events.append(
                LogEvent(
                    kind="batch_reachability",
                    ts=ts,
                    line_no=line_no,
                    function=current_function,
                    variable=current_variable,
                    raw=line,
                )
            )
            continue

        match = _HARD_REJECT_RE.search(line)
        if match:
            events.append(
                LogEvent(
                    kind="hard_reject",
                    ts=ts,
                    line_no=line_no,
                    function=current_function,
                    variable=str(match.group("variable") or current_variable),
                    statement=str(match.group("statement") or ""),
                    raw=line,
                )
            )
            continue

        match = _SOFT_REJECT_RE.search(line)
        if match:
            events.append(
                LogEvent(
                    kind="soft_reject",
                    ts=ts,
                    line_no=line_no,
                    function=current_function,
                    variable=str(match.group("variable") or current_variable),
                    statement=str(match.group("statement") or ""),
                    raw=line,
                )
            )
            continue

        match = _VERIFIER_REJECT_RE.search(line)
        if match:
            events.append(
                LogEvent(
                    kind="verifier_reject",
                    ts=ts,
                    line_no=line_no,
                    function=current_function,
                    variable=current_variable,
                    reason=str(match.group("reason") or ""),
                    raw=line,
                )
            )
            continue

        if _RETRY_RE.search(line):
            events.append(
                LogEvent(
                    kind="retry",
                    ts=ts,
                    line_no=line_no,
                    function=current_function,
                    variable=current_variable,
                    raw=line,
                )
            )
            continue

        match = _MID_REFLECTION_RE.search(line)
        if match:
            events.append(
                LogEvent(
                    kind="mid_reflection",
                    ts=ts,
                    line_no=line_no,
                    function=current_function,
                    variable=current_variable,
                    reason=f"iter={match.group('iteration')}",
                    raw=line,
                )
            )
            continue

        match = _JOERN_EXPAND_RE.search(line)
        if match:
            current_variable = str(match.group("variable") or current_variable)
            events.append(
                LogEvent(
                    kind="joern_expand",
                    ts=ts,
                    line_no=line_no,
                    variable=current_variable,
                    source_function=normalize_function_name(match.group("source")),
                    target_function=normalize_function_name(match.group("target")),
                    depth=int(match.group("depth") or 0),
                    raw=line,
                )
            )
            continue

        match = _TEXT_EXPAND_RE.search(line)
        if match:
            current_function = normalize_function_name(match.group("source"))
            current_variable = str(match.group("variable") or current_variable)
            events.append(
                LogEvent(
                    kind="text_expand",
                    ts=ts,
                    line_no=line_no,
                    function=current_function,
                    variable=current_variable,
                    source_function=current_function,
                    target_function=normalize_function_name(match.group("target")),
                    depth=int(match.group("depth") or 0),
                    raw=line,
                )
            )
            continue

        match = _PROVEN_TRIGGER_RE.search(line)
        if match:
            events.append(
                LogEvent(
                    kind="proven_trigger",
                    ts=ts,
                    line_no=line_no,
                    function=current_function,
                    variable=current_variable,
                    reason=str(match.group("label") or ""),
                    sink_line=int(match.group("line") or 0),
                    raw=line,
                )
            )
            continue

        match = _AGENT_STOP_RE.search(line)
        if match:
            events.append(
                LogEvent(
                    kind="agent_stop",
                    ts=ts,
                    line_no=line_no,
                    function=current_function,
                    variable=current_variable,
                    reason=str(match.group("reason") or ""),
                    raw=line,
                )
            )

    for event in events:
        if not event.variable:
            prev_call = _nearest_llm_call(
                llm_calls,
                ts=event.ts,
                agent="exploration_agent",
                before_only=True,
                max_delta_seconds=1200.0,
            )
            if prev_call and prev_call.variable:
                event.variable = prev_call.variable
        if not event.function:
            prev_call = _nearest_llm_call(
                llm_calls,
                ts=event.ts,
                variable=event.variable,
                before_only=True,
                max_delta_seconds=1200.0,
            )
            if prev_call and prev_call.function:
                event.function = prev_call.function
        if event.kind in {"hard_reject", "soft_reject", "verifier_reject"} and event.sink_line <= 0:
            next_verifier = _next_llm_call(
                llm_calls,
                ts=event.ts,
                variable=event.variable,
                agent="verification_agent",
                max_delta_seconds=90.0,
            )
            if next_verifier:
                if next_verifier.function and not event.function:
                    event.function = next_verifier.function
                if next_verifier.sink_line > 0:
                    event.sink_line = next_verifier.sink_line

    return _dedupe_events(events)


def _event_identity(event: LogEvent) -> Tuple[Any, ...]:
    return (
        event.kind,
        event.variable,
        event.function,
        event.statement,
        event.reason,
        event.source_function,
        event.target_function,
        event.depth,
        event.sink_line,
    )


def _dedupe_events(events: List[LogEvent]) -> List[LogEvent]:
    grouped: Dict[Tuple[Any, ...], List[LogEvent]] = defaultdict(list)
    for event in events:
        grouped[_event_identity(event)].append(event)

    retained_ids = set()
    for group in grouped.values():
        timed = [event for event in group if event.ts is not None]
        untimed = [event for event in group if event.ts is None]
        if timed and untimed:
            retained = timed
        else:
            retained = group
        for event in retained:
            retained_ids.add(id(event))

    return [event for event in events if id(event) in retained_ids]


def build_comparison_maps(
    gt_path: Path,
    results_dir: Path,
) -> Tuple[
    List[PredictionComparison],
    Dict[str, PredictionComparison],
    Dict[Tuple[str, str], PredictionComparison],
]:
    evaluator = AgentSliceEvaluator(str(gt_path), str(results_dir))
    comparisons = evaluator.compare_predictions()
    best = best_per_cve(comparisons)
    by_key = {(comp.cve_id, comp.variable): comp for comp in comparisons}
    return comparisons, best, by_key


def _critical_variable_names(critical_variables: Dict[str, Any]) -> List[str]:
    out = []
    for key in ("llm_extracted", "llm_refined"):
        for item in critical_variables.get(key, []) or []:
            if isinstance(item, dict):
                name = str(item.get("name") or "").strip()
                if name:
                    out.append(name)
    return out


def _component_flags_for_variable(record: Dict[str, Any]) -> Dict[str, Any]:
    llm_calls: List[LLMCallRecord] = record.get("llm_calls", [])
    events: List[LogEvent] = record.get("events", [])
    trigger = record.get("trigger") or {}
    search_stats = trigger.get("search_stats") if isinstance(trigger, dict) else {}
    agent_stats = trigger.get("agent_stats") if isinstance(trigger, dict) else {}
    verifier_stats = trigger.get("verification_agent_stats") if isinstance(trigger, dict) else {}

    retry_used = any(event.kind == "retry" for event in events)
    reflection_call_present = any(
        call.agent == "exploration_agent" and str(call.mode or "").lower() == "native_reflection"
        for call in llm_calls
    )
    mid_reflection_used = any(event.kind == "mid_reflection" for event in events) or (
        reflection_call_present and not retry_used
    )
    verification_used = bool(
        int((verifier_stats or {}).get("calls", 0) or 0) > 0
        or any(call.agent == "verification_agent" for call in llm_calls)
    )
    cv_refinement_used = bool(
        record.get("cv_refined")
        or any(call.agent == "cv_refine" for call in llm_calls)
    )
    long_term_hints_used = bool(int((search_stats or {}).get("policy_hint_samples", 0) or 0) > 0)
    hard_reject = any(event.kind == "hard_reject" for event in events)
    soft_reject = any(event.kind == "soft_reject" for event in events)
    verifier_reject = any(event.kind == "verifier_reject" for event in events) or bool(
        int((verifier_stats or {}).get("rejections", 0) or 0) > 0
    )

    return {
        "retry_used": retry_used,
        "mid_reflection_used": mid_reflection_used,
        "reflection_used": retry_used or mid_reflection_used or int((agent_stats or {}).get("reflection_calls", 0) or 0) > 0,
        "verification_used": verification_used,
        "cv_refinement_used": cv_refinement_used,
        "long_term_hints_used": long_term_hints_used,
        "hard_reject": hard_reject,
        "soft_reject": soft_reject,
        "verifier_reject": verifier_reject,
    }


def collect_cve_bundle(
    cve_dir: Path,
    gt_entry: Optional[Dict[str, Any]],
    comparison_by_key: Dict[Tuple[str, str], PredictionComparison],
    logs_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    cve_id = cve_dir.name
    gt_entry = gt_entry or {}
    result = _load_json(cve_dir / "result.json")
    triggers = _load_json(cve_dir / "triggers.json")
    agent_metrics = _load_json(cve_dir / "agent_metrics.json")
    agent_events = _load_jsonl(cve_dir / "agent_events.jsonl")
    critical_variables = _load_json(cve_dir / "critical_variables.json")
    llm_calls = load_llm_calls(cve_dir)
    log_path = (logs_dir or DEFAULT_LOGS_DIR) / f"{cve_id}.log"
    log_events = parse_log_events(log_path, llm_calls=llm_calls)

    patch_funcs = parse_patch_functions(gt_entry)
    anchors = anchor_functions(gt_entry)
    variable_names = set(triggers.keys())
    variable_names.update(_critical_variable_names(critical_variables))
    variable_names.update(call.variable for call in llm_calls if call.variable)
    variable_names.update(event.variable for event in log_events if event.variable)

    llm_refined = {
        str(item.get("name") or "").strip()
        for item in critical_variables.get("llm_refined", []) or []
        if isinstance(item, dict)
    }

    variables: Dict[str, Dict[str, Any]] = {}
    for variable in sorted(name for name in variable_names if name):
        trigger = triggers.get(variable, {})
        record = {
            "cve_id": cve_id,
            "variable": variable,
            "trigger": trigger if isinstance(trigger, dict) else {},
            "comparison": comparison_by_key.get((cve_id, variable)),
            "llm_calls": [call for call in llm_calls if call.variable == variable],
            "events": [event for event in log_events if event.variable == variable],
            "cv_refined": variable in llm_refined,
        }
        record["flags"] = _component_flags_for_variable(record)
        variables[variable] = record

    cve_flags = {
        "retry_used": any(record["flags"]["retry_used"] for record in variables.values()),
        "mid_reflection_used": any(record["flags"]["mid_reflection_used"] for record in variables.values()),
        "reflection_used": any(record["flags"]["reflection_used"] for record in variables.values()),
        "verification_used": any(record["flags"]["verification_used"] for record in variables.values()),
        "cv_refinement_used": any(record["flags"]["cv_refinement_used"] for record in variables.values()),
        "long_term_hints_used": any(record["flags"]["long_term_hints_used"] for record in variables.values()),
        "hard_reject_present": any(record["flags"]["hard_reject"] for record in variables.values()),
        "soft_reject_present": any(record["flags"]["soft_reject"] for record in variables.values()),
        "verifier_reject_present": any(record["flags"]["verifier_reject"] for record in variables.values()),
        "llm_calls": int((result.get("llm_call_summary") or {}).get("total_calls", 0) or len(llm_calls)),
        "tool_calls": sum(
            int((record.get("trigger") or {}).get("agent_stats", {}).get("tool_calls", 0) or 0)
            for record in variables.values()
        ),
        "verifier_calls": sum(
            int((record.get("trigger") or {}).get("verification_agent_stats", {}).get("calls", 0) or 0)
            for record in variables.values()
        ),
    }

    return {
        "cve_id": cve_id,
        "result_dir": cve_dir,
        "result": result,
        "triggers": triggers,
        "agent_metrics": agent_metrics,
        "agent_events": agent_events,
        "critical_variables": critical_variables,
        "llm_calls": llm_calls,
        "log_events": log_events,
        "tool_stats": result.get("tool_stats", {}) if isinstance(result.get("tool_stats"), dict) else {},
        "gt": gt_entry,
        "patch_functions": patch_funcs,
        "anchor_functions": anchors,
        "variables": variables,
        "flags": cve_flags,
    }


def collect_corpus_bundles(
    results_dir: Path,
    gt_path: Path,
    logs_dir: Optional[Path] = None,
) -> Tuple[
    Dict[str, Dict[str, Any]],
    List[PredictionComparison],
    Dict[str, PredictionComparison],
    Dict[Tuple[str, str], PredictionComparison],
]:
    gt_evaluator = AgentSliceEvaluator(str(gt_path), str(results_dir))
    gt_index = gt_evaluator.gt_index
    comparisons, best, by_key = build_comparison_maps(gt_path, results_dir)

    bundles: Dict[str, Dict[str, Any]] = {}
    for cve_dir in result_dirs(results_dir):
        bundles[cve_dir.name] = collect_cve_bundle(
            cve_dir=cve_dir,
            gt_entry=gt_index.get(cve_dir.name, {}),
            comparison_by_key=by_key,
            logs_dir=logs_dir,
        )
    return bundles, comparisons, best, by_key


def summarize_tool_attribution(
    bundles: Dict[str, Dict[str, Any]],
    best_by_cve: Dict[str, PredictionComparison],
) -> Dict[str, Dict[str, Any]]:
    by_tool: Dict[str, Dict[str, Any]] = {}
    for cve_id, comparison in best_by_cve.items():
        bundle = bundles.get(cve_id, {})
        tool_stats = bundle.get("tool_stats") or {}
        for tool_name, stats in tool_stats.items():
            if not isinstance(stats, dict):
                continue
            calls = int(stats.get("calls", 0) or 0)
            if calls <= 0:
                continue
            bucket = by_tool.setdefault(
                tool_name,
                {
                    "cves_using": 0,
                    "total_calls": 0,
                    "total_time_ms": 0.0,
                    "avg_time_ms_per_call": 0.0,
                    "_comparisons": [],
                },
            )
            bucket["cves_using"] += 1
            bucket["total_calls"] += calls
            bucket["total_time_ms"] += float(stats.get("total_time_ms", 0.0) or 0.0)
            bucket["_comparisons"].append(comparison)

    for tool_name, bucket in by_tool.items():
        comps = bucket.pop("_comparisons", [])
        metrics = compute_metrics(comps) if comps else {"count": 0}
        total_calls = int(bucket.get("total_calls", 0) or 0)
        total_time_ms = float(bucket.get("total_time_ms", 0.0) or 0.0)
        bucket["avg_calls_per_using_cve"] = total_calls / bucket["cves_using"] if bucket["cves_using"] else 0.0
        bucket["avg_time_ms_per_call"] = total_time_ms / total_calls if total_calls else 0.0
        bucket["exact_line_pct_when_used"] = metrics.get("exact_line_pct", 0.0)
        bucket["func_hit_pct_when_used"] = metrics.get("func_hit_pct", 0.0)
    return dict(
        sorted(
            by_tool.items(),
            key=lambda item: (-int(item[1].get("total_calls", 0) or 0), item[0]),
        )
    )


def summarize_component_usage(
    bundles: Dict[str, Dict[str, Any]],
    best_by_cve: Dict[str, PredictionComparison],
) -> Dict[str, Dict[str, Any]]:
    definitions = {
        "direct": lambda flags: not flags["retry_used"] and not flags["mid_reflection_used"],
        "retry_assisted": lambda flags: flags["retry_used"],
        "mid_reflection_assisted": lambda flags: flags["mid_reflection_used"],
        "verification_assisted": lambda flags: flags["verification_used"],
        "cv_refinement_assisted": lambda flags: flags["cv_refinement_used"],
        "long_term_hints_assisted": lambda flags: flags["long_term_hints_used"],
    }

    rows: Dict[str, Dict[str, Any]] = {}
    localized_total = len(best_by_cve)
    for label, selector in definitions.items():
        items: List[PredictionComparison] = []
        llm_calls: List[float] = []
        verifier_calls: List[float] = []
        tool_calls: List[float] = []
        count = 0
        for cve_id, bundle in bundles.items():
            flags = bundle.get("flags", {})
            if not selector(flags):
                continue
            count += 1
            if cve_id in best_by_cve:
                items.append(best_by_cve[cve_id])
                llm_calls.append(float(flags.get("llm_calls", 0) or 0))
                verifier_calls.append(float(flags.get("verifier_calls", 0) or 0))
                tool_calls.append(float(flags.get("tool_calls", 0) or 0))
        metrics = compute_metrics(items) if items else {"count": 0}
        rows[label] = {
            **metrics,
            "cve_count": count,
            "localized_rate": (len(items) / localized_total * 100.0) if localized_total else 0.0,
            "avg_llm_calls": (sum(llm_calls) / len(llm_calls)) if llm_calls else 0.0,
            "avg_verifier_calls": (sum(verifier_calls) / len(verifier_calls)) if verifier_calls else 0.0,
            "avg_tool_calls": (sum(tool_calls) / len(tool_calls)) if tool_calls else 0.0,
        }
    return rows


def summarize_component_presence(
    bundles: Dict[str, Dict[str, Any]],
    *,
    denominator: Optional[int] = None,
) -> Dict[str, Dict[str, Any]]:
    denom = denominator or len(bundles)
    keys = [
        "retry_used",
        "mid_reflection_used",
        "reflection_used",
        "verification_used",
        "cv_refinement_used",
        "long_term_hints_used",
        "hard_reject_present",
        "soft_reject_present",
        "verifier_reject_present",
    ]
    summary: Dict[str, Dict[str, Any]] = {}
    for key in keys:
        count = sum(1 for bundle in bundles.values() if bundle.get("flags", {}).get(key))
        summary[key] = {
            "count": count,
            "rate": (count / denom * 100.0) if denom else 0.0,
        }
    return summary


def _comparison_metrics_for_results_dir(gt_path: Path, results_dir: Path) -> Dict[str, PredictionComparison]:
    _, best, _ = build_comparison_maps(gt_path, results_dir)
    return best


def build_controlled_overlay(
    gt_path: Path,
    baseline_results_dir: Path,
    overlay_root: Path = DEFAULT_ABLATION_ROOT,
) -> Dict[str, Any]:
    if not overlay_root.exists():
        return {}

    baseline_best = _comparison_metrics_for_results_dir(gt_path, baseline_results_dir)
    overlay: Dict[str, Any] = {}

    for variant_dir in sorted(path for path in overlay_root.iterdir() if path.is_dir()):
        run_dir = variant_dir / "run_0"
        if not run_dir.exists():
            continue

        variant_best = _comparison_metrics_for_results_dir(gt_path, run_dir)
        variant_cves = sorted(
            {
                path.name
                for path in result_dirs(run_dir)
            }
        )
        if not variant_cves:
            continue

        baseline_items = [baseline_best[cve] for cve in variant_cves if cve in baseline_best]
        variant_items = [variant_best[cve] for cve in variant_cves if cve in variant_best]
        baseline_metrics = compute_metrics(baseline_items) if baseline_items else {"count": 0}
        variant_metrics = compute_metrics(variant_items) if variant_items else {"count": 0}

        overlay[variant_dir.name] = {
            "variant": variant_dir.name,
            "sample_size": len(variant_cves),
            "baseline_subset": baseline_metrics,
            "variant_subset": variant_metrics,
            "delta_exact_line_pct": variant_metrics.get("exact_line_pct", 0.0) - baseline_metrics.get("exact_line_pct", 0.0),
            "delta_func_hit_pct": variant_metrics.get("func_hit_pct", 0.0) - baseline_metrics.get("func_hit_pct", 0.0),
            "cves": variant_cves,
            "directional_only": True,
        }
    return overlay


def _match_statement_tier(event: LogEvent, gt_entry: Dict[str, Any], anchors: Iterable[str]) -> Tuple[bool, str]:
    gt_statements = parse_gt_statements(gt_entry)
    gt_lines = parse_gt_lines(gt_entry)
    event_stmt = _compact_statement(event.statement)
    anchor_set = {normalize_function_name(item) for item in anchors if normalize_function_name(item)}
    event_function = normalize_function_name(event.function)

    if not event_function or event_function not in anchor_set:
        return False, ""

    if event.sink_line and gt_lines and event.sink_line in gt_lines:
        return True, "A"
    if event_stmt and any(_compact_statement(stmt) == event_stmt for stmt in gt_statements):
        return True, "A"
    if event.sink_line and gt_lines and min(abs(line - event.sink_line) for line in gt_lines) <= 5:
        return True, "B"
    if event_stmt:
        for stmt in gt_statements:
            gt_stmt = _compact_statement(stmt)
            if gt_stmt and (gt_stmt in event_stmt or event_stmt in gt_stmt):
                return True, "B"
    if infer_sink_family(event.statement) != "unknown":
        return True, "C"
    return True, ""


def evaluate_vff_rejection(
    record: Dict[str, Any],
    gt_entry: Dict[str, Any],
    anchors: Iterable[str],
) -> Dict[str, Any]:
    rejection_events = [
        event for event in record.get("events", [])
        if event.kind in {"hard_reject", "soft_reject", "verifier_reject"}
    ]
    local_events = []
    best_tier = ""
    best_event: Optional[LogEvent] = None
    for event in rejection_events:
        is_local, tier = _match_statement_tier(event, gt_entry, anchors)
        if not is_local:
            continue
        local_events.append(event)
        if tier and (not best_tier or {"A": 0, "B": 1, "C": 2}.get(tier, 9) < {"A": 0, "B": 1, "C": 2}.get(best_tier, 9)):
            best_tier = tier
            best_event = event
        elif best_event is None:
            best_event = event

    trigger = record.get("trigger") if isinstance(record.get("trigger"), dict) else {}
    final_function = normalize_function_name(trigger.get("trigger_function", ""))
    anchor_set = {normalize_function_name(item) for item in anchors if normalize_function_name(item)}
    first_local_ts = min((event.ts for event in local_events if event.ts is not None), default=None)

    escaped_outside = False
    if local_events:
        for call in record.get("llm_calls", []):
            if call.agent != "exploration_agent" or not call.function:
                continue
            if first_local_ts is not None and call.ts is not None and call.ts <= first_local_ts:
                continue
            if normalize_function_name(call.function) not in anchor_set:
                escaped_outside = True
                break
        if final_function and final_function not in anchor_set:
            escaped_outside = True

    if not trigger:
        recovery_source = "failure"
    elif final_function and final_function in anchor_set:
        recovery_source = "same_function_retry"
    else:
        recovery_source = "outward_expansion"

    comparison: Optional[PredictionComparison] = record.get("comparison")
    return {
        "has_local_rejection": bool(local_events),
        "local_rejection_count": len(local_events),
        "tier": best_tier,
        "best_event": best_event,
        "escaped_outside_vff": escaped_outside if local_events else False,
        "recovery_source": recovery_source,
        "trigger_found": bool(trigger),
        "func_hit": bool(comparison.any_function_match) if comparison else False,
        "exact_line": bool(comparison.exact_match) if comparison else False,
        "explicit_retry_used": bool(record.get("flags", {}).get("retry_used")),
    }


def bundle_to_case_row(
    bundle: Dict[str, Any],
    record: Dict[str, Any],
    cohort_label: str,
    vff_eval: Dict[str, Any],
) -> Dict[str, Any]:
    comparison: Optional[PredictionComparison] = record.get("comparison")
    trigger = record.get("trigger") if isinstance(record.get("trigger"), dict) else {}
    event: Optional[LogEvent] = vff_eval.get("best_event")
    gt_entry = bundle.get("gt") or {}
    return {
        "cve_id": bundle.get("cve_id"),
        "variable": record.get("variable"),
        "cohort": cohort_label,
        "tier": vff_eval.get("tier", ""),
        "has_local_rejection": vff_eval.get("has_local_rejection", False),
        "escaped_outside_vff": vff_eval.get("escaped_outside_vff", False),
        "recovery_source": vff_eval.get("recovery_source", ""),
        "trigger_found": vff_eval.get("trigger_found", False),
        "func_hit": vff_eval.get("func_hit", False),
        "exact_line": vff_eval.get("exact_line", False),
        "explicit_retry_used": vff_eval.get("explicit_retry_used", False),
        "rejection_kind": event.kind if event else "",
        "rejection_function": event.function if event else "",
        "rejection_statement": event.statement if event else "",
        "rejection_sink_line": event.sink_line if event else 0,
        "rejection_reason": event.reason if event else "",
        "rejection_sink_family": infer_sink_family(event.statement) if event else "unknown",
        "gt_function": normalize_function_name(gt_entry.get("Vulnerability-triggered function", "")),
        "patch_functions": "; ".join(bundle.get("patch_functions", [])),
        "final_trigger_function": normalize_function_name(trigger.get("trigger_function", "")),
        "final_trigger_line": int(trigger.get("trigger_line", 0) or 0) if trigger else 0,
        "gt_line": comparison.gt_line if comparison else 0,
        "pred_line": comparison.pred_line if comparison else 0,
        "pred_statement": comparison.pred_statement if comparison else "",
    }
