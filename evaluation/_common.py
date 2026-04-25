#!/usr/bin/env python3
"""Shared utilities for all RQ evaluation scripts."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RESULTS_DIR = PROJECT_ROOT / "results"
OUTPUT_DIR = Path(__file__).resolve().parent / "output"

# Allow importing from experiments/
sys.path.insert(0, str(PROJECT_ROOT / "experiments"))
from evaluate import AgentSliceEvaluator, PredictionComparison  # noqa: E402

GT_FUNC_HIT_LABEL = "GTFuncHit"
FUNC_HIT_LABEL = "FuncHit"  # GT trigger function OR patch-function hit, depending on the cohort/task.


# ---------------------------------------------------------------------------
# Ground truth path resolution
# ---------------------------------------------------------------------------
_GT_CANDIDATES = [
    PROJECT_ROOT / "data" / "interpvd" / "InterPVD_Sheet1_processed.json",
    PROJECT_ROOT / "data" / "InterPVD_Sheet1_processed.json",
    Path("/home/azibaeir/Research/Datasets/InterPVD/2026_slice_agent/data/InterPVD_Sheet1_processed.json"),
]


def resolve_gt_path() -> Path:
    for p in _GT_CANDIDATES:
        if p.exists():
            return p
    raise FileNotFoundError(f"Ground truth not found in any of: {_GT_CANDIDATES}")


# ---------------------------------------------------------------------------
# Best-per-CVE selection (ported from rq4a_layer_breakdown.py)
# ---------------------------------------------------------------------------
def best_per_cve(comparisons: List[PredictionComparison]) -> Dict[str, PredictionComparison]:
    """Pick the single best prediction per CVE."""
    grouped: Dict[str, List[PredictionComparison]] = defaultdict(list)
    for c in comparisons:
        grouped[c.cve_id].append(c)

    def _score(c: PredictionComparison) -> Tuple:
        line_diff = abs((c.gt_line or 0) - (c.pred_line or 0))
        return (
            1 if c.any_function_match else 0,
            1 if c.function_match else 0,
            1 if getattr(c, "line_match", False) else 0,
            1 if c.statement_match else 0,
            1 if c.exact_match else 0,
            1 if c.within_5_lines else 0,
            -line_diff,
        )

    return {cve: max(items, key=_score) for cve, items in grouped.items() if items}


# ---------------------------------------------------------------------------
# Eligible sample selection
# ---------------------------------------------------------------------------
def eligible_autotrace_cves(
    evaluator: AgentSliceEvaluator,
    *,
    require_gt: bool = True,
) -> Dict[str, str]:
    """
    Return CVEs eligible for RQ1/RQ1_1 evaluation.

    Rule:
    - `result.json` must exist
    - `result.status` must be `success`
    - `triggers.json` must contain at least one predicted trigger object
    - GT must exist when `require_gt=True`

    The returned dict maps `cve_id -> exclusion-free status label`.
    """
    eligible: Dict[str, str] = {}
    outputs = evaluator.load_agent_outputs()

    for cve_id, payload in outputs.items():
        if require_gt and cve_id not in evaluator.gt_index:
            continue
        if require_gt and not evaluator.has_valid_gt_trigger(evaluator.gt_index[cve_id]):
            continue

        result_path = evaluator.results_dir / cve_id / "result.json"
        if not result_path.exists():
            continue

        result = payload.get("result", {}) or {}
        status = result.get("status")
        # Allow CVEs whose result.json failed to decode (status absent) if triggers exist
        if status is not None and status != "success":
            continue

        triggers = payload.get("triggers", {}) or {}
        has_trigger = any(isinstance(v, dict) for v in triggers.values())
        if not has_trigger:
            continue

        eligible[cve_id] = "success_with_triggers"

    return eligible


# ---------------------------------------------------------------------------
# VulTrigger-style exact-hit aggregation
# ---------------------------------------------------------------------------
def _iter_identified_triggers(pred: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    """
    Yield all model-identified trigger candidates for one variable.

    Prefer `all_triggers` because the pipeline keeps it inclusive of the primary
    trigger. Fall back to the legacy primary + secondary lists when needed.
    """
    all_triggers = pred.get("all_triggers")
    if isinstance(all_triggers, list) and all_triggers:
        for item in all_triggers:
            if isinstance(item, dict):
                yield item
        return

    if isinstance(pred, dict):
        yield pred

    for key in ("additional_triggers", "variant_triggers"):
        extra = pred.get(key)
        if not isinstance(extra, list):
            continue
        for item in extra:
            if isinstance(item, dict):
                yield item


def collect_vultrigger_exact_hits(
    evaluator: AgentSliceEvaluator,
) -> Dict[str, Dict[str, bool]]:
    """
    Compute CVE-level trigger hits over all identified trigger candidates.

    `exact_match` is the paper-facing relaxed hit:
    a CVE is correct if any identified trigger matches a GT trigger line OR the
    exact GT trigger statement text.
    """
    hits: Dict[str, Dict[str, bool]] = {}
    outputs = evaluator.load_agent_outputs()

    for cve_id, payload in outputs.items():
        if cve_id not in evaluator.gt_index:
            continue

        gt = evaluator.gt_index[cve_id]
        if not evaluator.has_valid_gt_trigger(gt):
            continue
        gt_lines = set(evaluator._parse_lines(gt.get("Vulnerability-triggered line numbers", "")))
        gt_statements = gt.get("Vulnerability-triggered statements", [])
        line_hit = False
        stmt_hit = False
        triggers = payload.get("triggers", {}) or {}
        for pred in triggers.values():
            if not isinstance(pred, dict):
                continue
            for candidate in _iter_identified_triggers(pred):
                if not line_hit:
                    try:
                        pred_line = int(candidate.get("trigger_line"))
                    except (TypeError, ValueError):
                        pred_line = None
                    line_hit = pred_line in gt_lines if pred_line is not None else False

                if not stmt_hit:
                    pred_stmt = str(
                        candidate.get("trigger_statement")
                        or candidate.get("trigger_code")
                        or ""
                    )
                    stmt_hit = evaluator._statement_match(gt_statements, pred_stmt)

                if line_hit or stmt_hit:
                    break
            if line_hit or stmt_hit:
                break

        hits[cve_id] = {
            "exact_line": line_hit,
            "exact_stmt": stmt_hit,
            "exact_match": line_hit or stmt_hit,
        }

    return hits


def _rq11_patch_function_set(evaluator: "AgentSliceEvaluator", gt: Dict[str, Any]) -> set:
    raw = str(gt.get("Patch statement function", "") or "")
    return {
        evaluator._normalize_func(item)
        for item in raw.split("\n")
        if evaluator._normalize_func(item)
    }


def _rq11_is_patch_fallback(candidate: Dict[str, Any]) -> bool:
    category = str(candidate.get("sink_category") or candidate.get("category") or "").strip().lower()
    if category == "patch_site_fallback":
        return True
    reason = str(candidate.get("trigger_reason") or candidate.get("reasoning") or "").strip().lower()
    code = str(candidate.get("trigger_code") or candidate.get("trigger_statement") or "").strip().lower()
    return "patch site used as proxy trigger" in reason or "patch-site fallback" in code


def compute_rq11_vuln_hits(
    evaluator: "AgentSliceEvaluator",
    *,
    eligible_cves: set,
) -> Dict[str, Dict[str, Any]]:
    """
    Broad VulnHit (matches RQ1.1): line OR statement OR function match.
    Withholds function-only credit for cross-function patch-fallback candidates.
    Returns a dict with `exact_match` key compatible with compute_metrics_with_vulnerability_hits.
    """
    outputs = evaluator.load_agent_outputs()
    hits: Dict[str, Dict[str, Any]] = {}

    for cve_id in sorted(eligible_cves):
        payload = outputs.get(cve_id, {}) or {}
        gt = evaluator.gt_index.get(cve_id)
        if not gt or not evaluator.has_valid_gt_trigger(gt):
            continue

        gt_function = evaluator._normalize_func(gt.get("Vulnerability-triggered function", ""))
        gt_lines = set(evaluator._parse_lines(gt.get("Vulnerability-triggered line numbers", "")))
        gt_statements = gt.get("Vulnerability-triggered statements", [])
        gt_layers = evaluator._parse_layers(gt.get("The number of cross-function layers", "1"))
        patch_funcs = _rq11_patch_function_set(evaluator, gt)

        line_hit = False
        within_5_hit = False
        stmt_hit = False
        function_hit = False
        excluded_patch_fallback = False

        triggers = payload.get("triggers", {}) or {}
        for pred in triggers.values():
            if not isinstance(pred, dict):
                continue
            for candidate in _iter_identified_triggers(pred):
                pred_function = evaluator._normalize_func(candidate.get("trigger_function", ""))
                pred_statement = str(
                    candidate.get("trigger_statement") or candidate.get("trigger_code") or ""
                )
                try:
                    pred_line = int(candidate.get("trigger_line"))
                except (TypeError, ValueError):
                    pred_line = None

                cand_line_hit = pred_line in gt_lines if pred_line is not None else False
                cand_within5 = (
                    pred_line is not None
                    and bool(gt_lines)
                    and min(abs(pred_line - g) for g in gt_lines) <= 5
                )
                cand_stmt_hit = evaluator._statement_match(gt_statements, pred_statement)
                cand_func_hit = bool(gt_function and pred_function and pred_function == gt_function)

                if cand_line_hit:
                    line_hit = True
                if cand_within5:
                    within_5_hit = True
                if cand_stmt_hit:
                    stmt_hit = True
                if cand_func_hit:
                    if (
                        not cand_line_hit
                        and not cand_stmt_hit
                        and _rq11_is_patch_fallback(candidate)
                        and gt_layers >= 2
                        and gt_function in patch_funcs
                    ):
                        excluded_patch_fallback = True
                    else:
                        function_hit = True

                if line_hit or stmt_hit or function_hit:
                    break
            if line_hit or stmt_hit or function_hit:
                break

        hits[cve_id] = {
            "exact_line": line_hit,
            "within_5_match": within_5_hit or stmt_hit or function_hit,
            "exact_stmt": stmt_hit,
            "function_match_credit": function_hit,
            "excluded_patch_fallback": excluded_patch_fallback,
            "exact_match": line_hit or stmt_hit or function_hit,
            "hit_reason": (
                "line" if line_hit else
                "statement" if stmt_hit else
                "function" if function_hit else
                "excluded_patch_fallback" if excluded_patch_fallback else
                "miss"
            ),
        }

    return hits


def compute_metrics_with_exact_hits(
    items: List[PredictionComparison],
    exact_hits: Dict[str, Dict[str, bool]],
) -> Dict[str, Any]:
    """Compute standard metrics, overriding exact-line with relaxed CVE-level hits."""
    metrics = compute_metrics(items)
    n = metrics.get("count", 0)
    if n == 0:
        return metrics

    exact_line = sum(
        1
        for c in items
        if exact_hits.get(c.cve_id, {}).get("exact_match", getattr(c, "line_match", False))
    )

    metrics["exact_line"] = exact_line
    metrics["exact_line_pct"] = exact_line / n * 100
    return metrics


def compute_metrics_with_vulnerability_hits(
    items: List[PredictionComparison],
    exact_hits: Dict[str, Dict[str, bool]],
) -> Dict[str, Any]:
    """
    Compute strict best-per-CVE metrics plus VulTrigger-style CVE-level hit rate.

    `vuln_hit` follows the paper-style criterion: a CVE is correct if any
    identified trigger candidate matches any ground-truth trigger.
    """
    metrics = compute_metrics(items)
    n = metrics.get("count", 0)
    if n == 0:
        metrics["vuln_hit"] = 0
        metrics["vuln_hit_pct"] = 0.0
        return metrics

    vuln_hit = 0
    for comp in items:
        hit = exact_hits.get(comp.cve_id)
        if hit is None:
            matched = bool(
                getattr(comp, "line_match", False)
                or getattr(comp, "statement_match", False)
            )
        else:
            matched = bool(hit.get("exact_match", False))
        vuln_hit += 1 if matched else 0

    metrics["vuln_hit"] = vuln_hit
    metrics["vuln_hit_pct"] = vuln_hit / n * 100
    return metrics


# ---------------------------------------------------------------------------
# Layer buckets
# ---------------------------------------------------------------------------
def layer_bucket(layers: int) -> str:
    return str(layers) if layers <= 3 else "4+"


# ---------------------------------------------------------------------------
# Metric computation
# ---------------------------------------------------------------------------
def compute_metrics(items: List[PredictionComparison]) -> Dict[str, Any]:
    """Compute standard accuracy metrics from a list of best-per-CVE comparisons."""
    n = len(items)
    if n == 0:
        return {"count": 0}

    def _cnt(attr: str) -> int:
        return sum(1 for c in items if getattr(c, attr, False))

    return {
        "count": n,
        "exact_line": _cnt("line_match"),
        "exact_line_pct": _cnt("line_match") / n * 100,
        "exact_stmt": _cnt("statement_match"),
        "exact_stmt_pct": _cnt("statement_match") / n * 100,
        "gt_func_hit": _cnt("function_match"),
        "gt_func_hit_pct": _cnt("function_match") / n * 100,
        "func_hit": _cnt("any_function_match"),
        "func_hit_pct": _cnt("any_function_match") / n * 100,
        "within_5": _cnt("within_5_lines"),
        "within_5_pct": _cnt("within_5_lines") / n * 100,
        "patch_func": _cnt("patch_function_match"),
        "patch_func_pct": _cnt("patch_function_match") / n * 100,
    }


# ---------------------------------------------------------------------------
# CWE family mapping
# ---------------------------------------------------------------------------
CWE_FAMILIES = {
    "Memory Safety": {"CWE-119", "CWE-120", "CWE-125", "CWE-787", "CWE-788"},
    "Integer": {"CWE-189", "CWE-190", "CWE-191"},
    "NULL Pointer": {"CWE-476"},
    "Use-After-Free": {"CWE-416"},
    "Resource Leak": {"CWE-401", "CWE-772"},
    "Infinite Loop": {"CWE-835"},
    "Division by Zero": {"CWE-369"},
    "Assertion Failure": {"CWE-617"},
    "Path Traversal": {"CWE-22"},
    "Input Validation": {"CWE-20", "CWE-129"},
    "Double Free": {"CWE-415"},
}

# Reverse map: CWE-XXX -> family name
_CWE_TO_FAMILY: Dict[str, str] = {}
for fam, members in CWE_FAMILIES.items():
    for m in members:
        _CWE_TO_FAMILY[m] = fam


def cwe_family(cwe: str) -> str:
    """Map a CWE-XXX string to its family name."""
    m = re.search(r"CWE-\d+", str(cwe).upper())
    if m:
        return _CWE_TO_FAMILY.get(m.group(0), "Other")
    return "Other"


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------
def standard_argparser(description: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR,
                    help="Directory with CVE result folders")
    p.add_argument("--ground-truth", type=Path, default=None,
                    help="InterPVD ground truth JSON (auto-detected if omitted)")
    p.add_argument("--benchmark", type=Path, default=None,
                    help="Benchmark JSON")
    p.add_argument("--output", type=Path, default=None,
                    help="JSON report output path")
    p.add_argument("--latex", action="store_true",
                    help="Emit LaTeX table to stdout")
    return p


def get_gt_path(args) -> Path:
    if args.ground_truth and args.ground_truth.exists():
        return args.ground_truth
    return resolve_gt_path()


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
def save_json_report(data: dict, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"\nReport saved to {output_path}")


def print_summary_table(title: str, headers: List[str], rows: List[List[str]]) -> None:
    """Print an aligned console table."""
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}")
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    hdr = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    print(hdr)
    print("-" * len(hdr))
    for row in rows:
        print("  ".join(c.ljust(w) for c, w in zip(row, widths)))
    print()


def fmt_pct(value: float, bold: bool = False) -> str:
    s = f"{value:.1f}\\%"
    return f"\\textbf{{{s}}}" if bold else s


def latex_table(caption: str, label: str, headers: List[str],
                rows: List[List[str]], note: str = "") -> str:
    """Generate a complete LaTeX table string."""
    ncols = len(headers)
    col_spec = "l" + "c" * (ncols - 1)
    lines = [
        "\\begin{table}[t]",
        "\\centering",
        "\\footnotesize",
        f"\\caption{{{caption}}}",
        f"\\label{{{label}}}",
        f"\\begin{{tabular}}{{{col_spec}}}",
        "\\toprule",
        " & ".join(f"\\textbf{{{h}}}" for h in headers) + " \\\\",
        "\\midrule",
    ]
    for row in rows:
        lines.append(" & ".join(row) + " \\\\")
    lines.append("\\bottomrule")
    lines.append("\\end{tabular}")
    if note:
        lines.append(f"\\vspace{{1mm}}\\scriptsize {note}")
    lines.append("\\end{table}")
    return "\n".join(lines)
