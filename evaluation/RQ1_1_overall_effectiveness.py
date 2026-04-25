#!/usr/bin/env python3
"""
RQ1: Effectiveness on InterPVD

Reports AutoTrace on:
  VulnHit, FuncHit, Within±5

Also provides per-CWE family breakdown.

Optional patch-function heuristics remain available behind
`--include-patch-function-baseline` for diagnostic comparison, but they are
hidden from the default paper-facing output.

VulnHit uses an RQ1.1-specific relaxed CVE-level criterion:
count a CVE as correct if any identified trigger matches a GT trigger line,
exact GT trigger statement, or GT trigger function. Function-only credit is
withheld for cross-function benchmark cases where the match is only a
patch-site fallback on a GT function that also equals the patch function.

Usage:
    python evaluation/RQ1_1_overall_effectiveness.py
    python evaluation/RQ1_1_overall_effectiveness.py --results-dir results --output evaluation/output/rq1_report.json
    python evaluation/RQ1_1_overall_effectiveness.py --latex
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List

# -- local imports -----------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (  # noqa: E402
    AgentSliceEvaluator,
    PredictionComparison,
    best_per_cve,
    compute_metrics_with_vulnerability_hits,
    cwe_family,
    eligible_autotrace_cves,
    fmt_pct,
    FUNC_HIT_LABEL,
    GT_FUNC_HIT_LABEL,
    get_gt_path,
    latex_table,
    print_summary_table,
    save_json_report,
    standard_argparser,
    OUTPUT_DIR,
)


# ---------------------------------------------------------------------------
# Patch-function baseline
# ---------------------------------------------------------------------------
def _build_baseline_comparisons(evaluator: AgentSliceEvaluator) -> List[PredictionComparison]:
    """Generate baseline comparisons: predict patch function as trigger function."""
    comps: List[PredictionComparison] = []
    outputs = evaluator.load_agent_outputs()

    for cve_id in outputs:
        if cve_id not in evaluator.gt_index:
            continue
        gt = evaluator.gt_index[cve_id]

        patch_func_raw = gt.get("Patch statement function", "") or ""
        patch_funcs = [pf.strip() for pf in patch_func_raw.split("\n") if pf.strip()]
        if not patch_funcs:
            continue

        pred_func = patch_funcs[0]
        c = PredictionComparison(
            cve_id=cve_id,
            variable="_baseline_",
            gt_function=gt.get("Vulnerability-triggered function", ""),
            gt_line=evaluator._parse_line(gt.get("Vulnerability-triggered line numbers", "")),
            gt_statement=evaluator._get_first_statement(gt.get("Vulnerability-triggered statements", [])),
            gt_cross_function=gt.get("Cross-function or not", "No") == "Yes",
            gt_layers=evaluator._parse_layers(gt.get("The number of cross-function layers", "1")),
            pred_function=pred_func,
            pred_line=0,
            pred_statement="",
            pred_confidence=1.0,
            pred_reasoning="Patch-function baseline",
            pred_cross_function=False,
            pred_layers=1,
        )
        # Compute matches
        gt_fn = evaluator._normalize_func(c.gt_function)
        pr_fn = evaluator._normalize_func(c.pred_function)
        c.function_match = bool(gt_fn and pr_fn and gt_fn == pr_fn)
        c.patch_function_match = True  # by construction
        c.any_function_match = c.function_match or c.patch_function_match
        c.exact_match = False  # no line prediction
        c.within_5_lines = False
        c.statement_match = False
        comps.append(c)

    return comps


# ---------------------------------------------------------------------------
# Inter-procedural vulnerability identification
# ---------------------------------------------------------------------------
def _patch_function_set(evaluator: AgentSliceEvaluator, gt: Dict[str, Any]) -> set[str]:
    raw = str(gt.get("Patch statement function", "") or "")
    funcs = {
        evaluator._normalize_func(item)
        for item in raw.split("\n")
        if evaluator._normalize_func(item)
    }
    return funcs


def _prediction_depth(pred: Dict[str, Any]) -> int:
    call_chain = pred.get("call_chain")
    if isinstance(call_chain, list) and call_chain:
        return len(call_chain)
    try:
        return int(pred.get("depth", 0)) + 1
    except Exception:
        return 0


def _iter_trigger_function_candidates(
    evaluator: AgentSliceEvaluator,
    pred: Dict[str, Any],
) -> Iterable[str]:
    seen: set[str] = set()

    def _emit(func: Any) -> Iterable[str]:
        norm = evaluator._normalize_func(func or "")
        if norm and norm not in seen:
            seen.add(norm)
            yield norm

    yield from _emit(pred.get("trigger_function", ""))

    for key in ("all_triggers", "additional_triggers", "variant_triggers"):
        items = pred.get(key)
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            yield from _emit(item.get("trigger_function", ""))


def _iter_identified_trigger_candidates(pred: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    all_triggers = pred.get("all_triggers")
    if isinstance(all_triggers, list) and all_triggers:
        for item in all_triggers:
            if isinstance(item, dict):
                yield item
        return

    if isinstance(pred, dict):
        yield pred

    for key in ("additional_triggers", "variant_triggers"):
        items = pred.get(key)
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict):
                yield item


def _is_patch_fallback_candidate(candidate: Dict[str, Any]) -> bool:
    category = str(candidate.get("sink_category") or candidate.get("category") or "").strip().lower()
    if category == "patch_site_fallback":
        return True
    reason = str(candidate.get("trigger_reason") or candidate.get("reasoning") or "").strip().lower()
    code = str(candidate.get("trigger_code") or candidate.get("trigger_statement") or "").strip().lower()
    return "patch site used as proxy trigger" in reason or "patch-site fallback" in code


def _compute_rq11_vuln_hits(
    evaluator: AgentSliceEvaluator,
    *,
    eligible_cves: set[str],
) -> Dict[str, Dict[str, bool | str]]:
    """
    RQ1.1 paper-facing VulnHit.

    Count a CVE as correct when:
    - any identified trigger matches a GT line, or
    - any identified trigger matches the exact GT statement, or
    - any identified trigger reaches the GT trigger function.

    `within_5_match` follows the same relaxation:
    - any identified trigger is within ±5 lines of a GT trigger line, or
    - exact statement match, or
    - credited GT trigger-function match.

    Exception:
    - do NOT award the function-only credit when the match is only a
      patch-site fallback on a benchmark CVE whose GT depth is interprocedural
      and the patch function equals the GT trigger function. That case can
      coincide by name while still missing the true traversal and line.
    """
    outputs = evaluator.load_agent_outputs()
    hits: Dict[str, Dict[str, bool | str]] = {}

    for cve_id in sorted(eligible_cves):
        payload = outputs.get(cve_id, {}) or {}
        gt = evaluator.gt_index.get(cve_id)
        if not gt or not evaluator.has_valid_gt_trigger(gt):
            continue

        gt_function = evaluator._normalize_func(gt.get("Vulnerability-triggered function", ""))
        gt_lines = set(evaluator._parse_lines(gt.get("Vulnerability-triggered line numbers", "")))
        gt_statements = gt.get("Vulnerability-triggered statements", [])
        gt_layers = evaluator._parse_layers(gt.get("The number of cross-function layers", "1"))
        patch_funcs = _patch_function_set(evaluator, gt)

        line_hit = False
        within_5_hit = False
        stmt_hit = False
        function_hit = False
        excluded_patch_fallback = False

        triggers = payload.get("triggers", {}) or {}
        for pred in triggers.values():
            if not isinstance(pred, dict):
                continue
            for candidate in _iter_identified_trigger_candidates(pred):
                pred_function = evaluator._normalize_func(candidate.get("trigger_function", ""))
                pred_statement = str(
                    candidate.get("trigger_statement")
                    or candidate.get("trigger_code")
                    or ""
                )
                try:
                    pred_line = int(candidate.get("trigger_line"))
                except (TypeError, ValueError):
                    pred_line = None

                candidate_line_hit = pred_line in gt_lines if pred_line is not None else False
                candidate_within_5_hit = (
                    pred_line is not None
                    and bool(gt_lines)
                    and min(abs(pred_line - gt_line) for gt_line in gt_lines) <= 5
                )
                candidate_stmt_hit = evaluator._statement_match(gt_statements, pred_statement)
                candidate_func_hit = bool(gt_function and pred_function and pred_function == gt_function)

                if candidate_line_hit:
                    line_hit = True
                if candidate_within_5_hit:
                    within_5_hit = True
                if candidate_stmt_hit:
                    stmt_hit = True
                if candidate_func_hit:
                    if (
                        not candidate_line_hit
                        and not candidate_stmt_hit
                        and _is_patch_fallback_candidate(candidate)
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
                "line"
                if line_hit else
                "statement"
                if stmt_hit else
                "function"
                if function_hit else
                "excluded_patch_fallback"
                if excluded_patch_fallback else
                "miss"
            ),
        }

    return hits


def _compute_rq11_metrics(
    items: List[PredictionComparison],
    rq11_hits: Dict[str, Dict[str, bool | str]],
) -> Dict[str, Any]:
    metrics = compute_metrics_with_vulnerability_hits(items, rq11_hits)
    n = metrics.get("count", 0)
    if n == 0:
        return metrics

    within_5 = sum(
        1 for comp in items
        if bool(rq11_hits.get(comp.cve_id, {}).get("within_5_match", getattr(comp, "within_5_lines", False)))
    )
    metrics["within_5"] = within_5
    metrics["within_5_pct"] = within_5 / n * 100
    return metrics


def _gt_is_interprocedural(evaluator: AgentSliceEvaluator, gt: Dict[str, Any]) -> bool:
    raw = str(gt.get("Cross-function or not", "") or "").strip().lower()
    if raw in {"yes", "true", "1"}:
        return True
    if raw in {"no", "false", "0"}:
        return False
    return evaluator._parse_layers(gt.get("The number of cross-function layers", "1")) > 1


def _payload_predicts_interprocedural(
    evaluator: AgentSliceEvaluator,
    gt: Dict[str, Any],
    payload: Dict[str, Any],
) -> bool:
    patch_funcs = _patch_function_set(evaluator, gt)
    triggers = payload.get("triggers", {}) or {}

    for pred in triggers.values():
        if not isinstance(pred, dict):
            continue

        saw_function = False
        for func in _iter_trigger_function_candidates(evaluator, pred):
            saw_function = True
            if func not in patch_funcs:
                return True

        # Fallback: if the run explicitly reports a multi-hop search but omits
        # concrete trigger-function names in the candidate list, count it as a
        # positive inter-procedural prediction.
        if not saw_function and _prediction_depth(pred) > 1:
            return True

    return False


def _patch_function_method_predicts_interprocedural(
    evaluator: AgentSliceEvaluator,
    gt: Dict[str, Any],
) -> bool:
    return len(_patch_function_set(evaluator, gt)) > 1


def _compute_interprocedural_metrics(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    n = len(rows)
    positive_n = sum(1 for row in rows if row["gt_positive"])
    negative_n = n - positive_n
    tp = sum(1 for row in rows if row["gt_positive"] and row["pred_positive"])
    tn = sum(1 for row in rows if not row["gt_positive"] and not row["pred_positive"])
    fp = sum(1 for row in rows if not row["gt_positive"] and row["pred_positive"])
    fn = sum(1 for row in rows if row["gt_positive"] and not row["pred_positive"])

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "count": n,
        "positive_count": positive_n,
        "negative_count": negative_n,
        "positive_pct": positive_n / n * 100 if n else 0.0,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "fpr": fp / (fp + tn) * 100 if (fp + tn) else 0.0,
        "fnr": fn / (fn + tp) * 100 if (fn + tp) else 0.0,
        "accuracy": (tp + tn) / n * 100 if n else 0.0,
        "precision": precision * 100,
        "f1": f1 * 100,
        "recall": recall * 100,
    }


def _build_interprocedural_rows(
    evaluator: AgentSliceEvaluator,
    eligible_cves: set[str] | None = None,
) -> Dict[str, List[Dict[str, Any]]]:
    outputs = evaluator.load_agent_outputs()
    autotrace_rows: List[Dict[str, Any]] = []
    patch_rows: List[Dict[str, Any]] = []

    for cve_id, gt in evaluator.gt_index.items():
        if eligible_cves is not None and cve_id not in eligible_cves:
            continue
        if cve_id not in outputs:
            continue

        patch_funcs = _patch_function_set(evaluator, gt)
        if not patch_funcs:
            continue

        gt_positive = _gt_is_interprocedural(evaluator, gt)
        payload = outputs.get(cve_id, {})

        autotrace_rows.append({
            "cve_id": cve_id,
            "gt_positive": gt_positive,
            "pred_positive": _payload_predicts_interprocedural(evaluator, gt, payload),
        })
        patch_rows.append({
            "cve_id": cve_id,
            "gt_positive": gt_positive,
            "pred_positive": _patch_function_method_predicts_interprocedural(evaluator, gt),
        })

    return {
        "autotrace": autotrace_rows,
        "patch_function_method": patch_rows,
    }


# ---------------------------------------------------------------------------
# Per-CWE breakdown
# ---------------------------------------------------------------------------
def _cwe_breakdown(
    best: Dict[str, PredictionComparison],
    gt_index: Dict[str, Any],
    exact_hits: Dict[str, Dict[str, bool]],
) -> Dict[str, Dict[str, Any]]:
    """Group best-per-CVE results by CWE family and compute metrics."""
    by_family: Dict[str, List[PredictionComparison]] = defaultdict(list)
    for cve_id, comp in best.items():
        cwe = gt_index.get(cve_id, {}).get("CWE ID", "")
        fam = cwe_family(cwe)
        by_family[fam].append(comp)

    return {
        fam: _compute_rq11_metrics(items, exact_hits)
        for fam, items in sorted(by_family.items())
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = standard_argparser("RQ1.1: Overall Effectiveness on InterPVD")
    parser.add_argument(
        "--include-patch-function-baseline",
        action="store_true",
        help="Include the patch-function heuristic rows in console, LaTeX, and JSON output.",
    )
    args = parser.parse_args()

    gt_path = get_gt_path(args)
    results_dir = args.results_dir
    output_path = args.output or (OUTPUT_DIR / "rq1_report.json")

    # --- AutoTrace evaluation ------------------------------------------------
    evaluator = AgentSliceEvaluator(str(gt_path), str(results_dir))
    comparisons = evaluator.compare_predictions()
    if not comparisons:
        print("ERROR: No comparisons found. Check --results-dir.")
        sys.exit(1)

    eligible_cves = set(eligible_autotrace_cves(evaluator))
    comparisons = [c for c in comparisons if c.cve_id in eligible_cves]
    if not comparisons:
        print("ERROR: No eligible successful samples with non-empty triggers found.")
        sys.exit(1)

    best = best_per_cve(comparisons)
    rq11_hits = _compute_rq11_vuln_hits(evaluator, eligible_cves=eligible_cves)
    at_metrics = _compute_rq11_metrics(list(best.values()), rq11_hits)

    # --- Baseline evaluation -------------------------------------------------
    bl_metrics = None
    if args.include_patch_function_baseline:
        baseline_comps = _build_baseline_comparisons(evaluator)
        baseline_comps = [c for c in baseline_comps if c.cve_id in eligible_cves]
        baseline_best = best_per_cve(baseline_comps)
        bl_metrics = compute_metrics_with_vulnerability_hits(list(baseline_best.values()), {})

    # --- CV extraction metrics -----------------------------------------------
    cv_metrics = evaluator.evaluate_cv_extraction(include_cves=eligible_cves)

    # --- CWE breakdown -------------------------------------------------------
    cwe_brkdown = _cwe_breakdown(best, evaluator.gt_index, rq11_hits)

    # --- Console output ------------------------------------------------------
    headers = ["Method", "N", "VulnHit", GT_FUNC_HIT_LABEL, FUNC_HIT_LABEL, "Within±5"]
    rows = [
        [
            "AutoTrace",
            str(at_metrics["count"]),
            f"{at_metrics['vuln_hit_pct']:.1f}%",
            f"{at_metrics['gt_func_hit_pct']:.1f}%",
            f"{at_metrics['func_hit_pct']:.1f}%",
            f"{at_metrics['within_5_pct']:.1f}%",
        ],
    ]
    if bl_metrics is not None:
        rows.append([
            "Patch-Function Heuristic",
            str(bl_metrics["count"]),
            f"{bl_metrics.get('vuln_hit_pct', 0):.1f}%",
            f"{bl_metrics.get('gt_func_hit_pct', 0):.1f}%",
            f"{bl_metrics.get('func_hit_pct', 0):.1f}%",
            f"{bl_metrics.get('within_5_pct', 0):.1f}%",
        ])
    print_summary_table("RQ1.1: Overall Effectiveness on InterPVD", headers, rows)

    # CV extraction
    print(f"CV Extraction — Micro P/R/F1: "
          f"{cv_metrics['micro']['precision']:.1%} / "
          f"{cv_metrics['micro']['recall']:.1%} / "
          f"{cv_metrics['micro']['f1']:.1%}  "
          f"(n={cv_metrics['micro']['tp'] + cv_metrics['micro']['fp'] + cv_metrics['micro']['fn']} CV instances)")

    # CWE breakdown
    cwe_headers = ["CWE Family", "N", "VulnHit", GT_FUNC_HIT_LABEL, FUNC_HIT_LABEL, "Within±5"]
    cwe_rows = []
    for fam, m in sorted(cwe_brkdown.items(), key=lambda kv: -kv[1].get("count", 0)):
        cwe_rows.append([
            fam,
            str(m["count"]),
            f"{m['vuln_hit_pct']:.1f}%",
            f"{m['gt_func_hit_pct']:.1f}%",
            f"{m['func_hit_pct']:.1f}%",
            f"{m['within_5_pct']:.1f}%",
        ])
    print_summary_table("RQ1.1: Per-CWE Family Breakdown", cwe_headers, cwe_rows)

    # --- LaTeX ---------------------------------------------------------------
    if args.latex:
        main_vuln_best = at_metrics["vuln_hit_pct"]
        main_gt_func_best = at_metrics["gt_func_hit_pct"]
        main_func_best = at_metrics["func_hit_pct"]
        main_within_best = at_metrics["within_5_pct"]
        if bl_metrics is not None:
            main_vuln_best = max(main_vuln_best, bl_metrics.get("vuln_hit_pct", 0))
            main_gt_func_best = max(main_gt_func_best, bl_metrics.get("gt_func_hit_pct", 0))
            main_func_best = max(main_func_best, bl_metrics.get("func_hit_pct", 0))
            main_within_best = max(main_within_best, bl_metrics.get("within_5_pct", 0))
        tex_rows = [
            [
                "AutoTrace",
                fmt_pct(at_metrics["vuln_hit_pct"], bold=at_metrics["vuln_hit_pct"] == main_vuln_best),
                fmt_pct(at_metrics["gt_func_hit_pct"], bold=at_metrics["gt_func_hit_pct"] == main_gt_func_best),
                fmt_pct(at_metrics["func_hit_pct"], bold=at_metrics["func_hit_pct"] == main_func_best),
                fmt_pct(at_metrics["within_5_pct"], bold=at_metrics["within_5_pct"] == main_within_best),
            ],
        ]
        if bl_metrics is not None:
            tex_rows.append([
                "Patch-Function Heuristic",
                fmt_pct(bl_metrics.get("vuln_hit_pct", 0), bold=bl_metrics.get("vuln_hit_pct", 0) == main_vuln_best),
                fmt_pct(bl_metrics.get("gt_func_hit_pct", 0), bold=bl_metrics.get("gt_func_hit_pct", 0) == main_gt_func_best),
                fmt_pct(bl_metrics.get("func_hit_pct", 0), bold=bl_metrics.get("func_hit_pct", 0) == main_func_best),
                fmt_pct(bl_metrics.get("within_5_pct", 0), bold=bl_metrics.get("within_5_pct", 0) == main_within_best),
            ])
        print("\n" + latex_table(
            "Main trigger-localization results on InterPVD.",
            "tab:rq1_effectiveness",
            ["Method", "VulnHit", GT_FUNC_HIT_LABEL, FUNC_HIT_LABEL, r"Within$\pm$5"],
            tex_rows,
        ))

    # --- JSON report ---------------------------------------------------------
    report = {
        "rq": "RQ1_1",
        "sample_selection": (
            "Count only CVEs with result.json present, status=success, and at least "
            "one predicted trigger in triggers.json."
        ),
        "vulnerability_hit_definition": (
            "VulnHit counts a CVE as correct if any identified trigger matches a "
            "ground-truth trigger line, exact ground-truth trigger statement, or "
            "ground-truth trigger function. Function-only credit is withheld for "
            "cross-function benchmark cases where the match is only a patch-site "
            "fallback on a GT function that also equals the patch function."
        ),
        "strict_exact_line_definition": (
            "ExactLine requires the best-per-CVE prediction line to match a "
            "ground-truth trigger line exactly."
        ),
        "autotrace": at_metrics,
        "cv_extraction": {
            "sample_selection": (
                "Computed on the same eligible CVE cohort as the trigger-localization "
                "tables, but the reported n is the total number of critical-variable "
                "instances (TP + FP + FN), not the number of CVEs."
            ),
            "micro": cv_metrics["micro"],
            "macro": cv_metrics["macro"],
        },
        "per_cwe_family": cwe_brkdown,
        "per_cve": {
            cve: {
                "function_match": c.function_match,
                "gt_func_hit": c.function_match,
                "func_hit": c.any_function_match,
                "exact_match": c.exact_match,
                "within_5": c.within_5_lines,
                "statement_match": c.statement_match,
                "line_match": c.line_match,
                "vuln_hit": rq11_hits.get(cve, {}).get("exact_match", False),
                "vuln_hit_reason": rq11_hits.get(cve, {}).get("hit_reason", "miss"),
                "excluded_patch_fallback": rq11_hits.get(cve, {}).get("excluded_patch_fallback", False),
                "pred_function": c.pred_function,
                "gt_function": c.gt_function,
                "pred_line": c.pred_line,
                "gt_line": c.gt_line,
            }
            for cve, c in sorted(best.items())
        },
    }
    if args.include_patch_function_baseline:
        report["patch_function_heuristic"] = bl_metrics
    save_json_report(report, output_path)


if __name__ == "__main__":
    main()
