#!/usr/bin/env python3
"""
RQ1.2: Accuracy by Interprocedural Depth

Groups RQ1 metrics by call-chain layer (1, 2, 3, 4+) to show
how accuracy changes with cross-function complexity. Also reports the
largest CWE-family and project breakdowns used in the paper.

VulnHit uses a relaxed CVE-level hit criterion:
count a CVE as correct if any identified trigger matches any GT trigger line
or exact GT trigger statement.
ExactLine / ExactStmt remain strict best-per-CVE metrics.

Usage:
    python evaluation/RQ1_2_depth_breakdown.py
    python evaluation/RQ1_2_depth_breakdown.py --latex
"""

from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (  # noqa: E402
    AgentSliceEvaluator,
    PredictionComparison,
    best_per_cve,
    compute_metrics_with_vulnerability_hits,
    compute_rq11_vuln_hits,
    cwe_family,
    eligible_autotrace_cves,
    fmt_pct,
    FUNC_HIT_LABEL,
    GT_FUNC_HIT_LABEL,
    get_gt_path,
    latex_table,
    layer_bucket,
    print_summary_table,
    save_json_report,
    standard_argparser,
    OUTPUT_DIR,
)


def _software_name(gt_entry: Dict[str, Any]) -> str:
    name = str(gt_entry.get("Software", "") or "").strip()
    return name or "Unknown"


def _sort_groups(metrics: Dict[str, Dict[str, Any]], limit: int | None = None) -> List[tuple[str, Dict[str, Any]]]:
    items = sorted(
        metrics.items(),
        key=lambda kv: (-kv[1].get("count", 0), kv[0]),
    )
    return items[:limit] if limit is not None else items


def _override_within5(
    metrics: Dict[str, Any],
    items: List[PredictionComparison],
    rq11_hits: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Make Within±5 consistent with the RQ1.1 paper-facing definition:
    within ±5 lines OR exact statement OR GT trigger-function credit.
    """
    n = metrics.get("count", 0)
    if n == 0:
        return metrics

    within_5 = sum(
        1
        for comp in items
        if bool(rq11_hits.get(comp.cve_id, {}).get("within_5_match", getattr(comp, "within_5_lines", False)))
    )
    metrics["within_5"] = within_5
    metrics["within_5_pct"] = within_5 / n * 100
    return metrics


def main() -> None:
    parser = standard_argparser("RQ1.2: Accuracy by Interprocedural Depth")
    args = parser.parse_args()

    gt_path = get_gt_path(args)
    evaluator = AgentSliceEvaluator(str(gt_path), str(args.results_dir))
    comparisons = evaluator.compare_predictions()
    if not comparisons:
        print("ERROR: No comparisons found.")
        sys.exit(1)

    eligible_cves = set(eligible_autotrace_cves(evaluator))
    comparisons = [c for c in comparisons if c.cve_id in eligible_cves]
    if not comparisons:
        print("ERROR: No eligible successful samples with non-empty triggers found.")
        sys.exit(1)

    best = best_per_cve(comparisons)
    rq11_hits = compute_rq11_vuln_hits(evaluator, eligible_cves=eligible_cves)

    # Group by layer bucket
    buckets: Dict[str, List[PredictionComparison]] = defaultdict(list)
    for cve_id, comp in best.items():
        bkt = layer_bucket(comp.gt_layers)
        buckets[bkt].append(comp)

    # Compute per-bucket and aggregates
    per_layer: Dict[str, Dict[str, Any]] = {}
    for bkt in ["1", "2", "3", "4+"]:
        items = buckets.get(bkt, [])
        per_layer[bkt] = _override_within5(
            compute_metrics_with_vulnerability_hits(items, rq11_hits),
            items,
            rq11_hits,
        )

    intra = buckets.get("1", [])
    cross = [c for bkt, items in buckets.items() if bkt != "1" for c in items]
    total = list(best.values())

    agg = {
        "intra": _override_within5(compute_metrics_with_vulnerability_hits(intra, rq11_hits), intra, rq11_hits),
        "cross": _override_within5(compute_metrics_with_vulnerability_hits(cross, rq11_hits), cross, rq11_hits),
        "total": _override_within5(compute_metrics_with_vulnerability_hits(total, rq11_hits), total, rq11_hits),
    }

    # Additional paper-facing breakdowns
    by_cwe: Dict[str, List[PredictionComparison]] = defaultdict(list)
    by_project: Dict[str, List[PredictionComparison]] = defaultdict(list)
    for cve_id, comp in best.items():
        gt_entry = evaluator.gt_index.get(cve_id, {})
        by_cwe[cwe_family(gt_entry.get("CWE ID", ""))].append(comp)
        by_project[_software_name(gt_entry)].append(comp)

    cwe_metrics = {
        group: _override_within5(compute_metrics_with_vulnerability_hits(items, rq11_hits), items, rq11_hits)
        for group, items in by_cwe.items()
    }
    project_metrics = {
        group: _override_within5(compute_metrics_with_vulnerability_hits(items, rq11_hits), items, rq11_hits)
        for group, items in by_project.items()
    }

    # Console output
    headers = ["Layer", "N", "VulnHit", GT_FUNC_HIT_LABEL, FUNC_HIT_LABEL, "Within±5"]
    rows = []
    for bkt in ["1", "2", "3", "4+"]:
        m = per_layer[bkt]
        if m.get("count", 0) == 0:
            continue
        rows.append([
            bkt, str(m["count"]),
            f"{m['vuln_hit_pct']:.1f}%",
            f"{m['gt_func_hit_pct']:.1f}%",
            f"{m['func_hit_pct']:.1f}%",
            f"{m['within_5_pct']:.1f}%",
        ])

    # Separator + aggregates
    for label, key in [("Intra (L1)", "intra"), ("Cross (L2+)", "cross"), ("Total", "total")]:
        m = agg[key]
        if m.get("count", 0) == 0:
            continue
        rows.append([
            label, str(m["count"]),
            f"{m['vuln_hit_pct']:.1f}%",
            f"{m['gt_func_hit_pct']:.1f}%",
            f"{m['func_hit_pct']:.1f}%",
            f"{m['within_5_pct']:.1f}%",
        ])

    print_summary_table("RQ1.2: Accuracy by Layer Depth", headers, rows)

    char_headers = ["Group", "N", "VulnHit", GT_FUNC_HIT_LABEL, FUNC_HIT_LABEL, "Within±5"]
    cwe_rows = []
    for group, metrics in _sort_groups(cwe_metrics, limit=8):
        cwe_rows.append([
            group,
            str(metrics["count"]),
            f"{metrics['vuln_hit_pct']:.1f}%",
            f"{metrics['gt_func_hit_pct']:.1f}%",
            f"{metrics['func_hit_pct']:.1f}%",
            f"{metrics['within_5_pct']:.1f}%",
        ])
    print_summary_table("RQ1.2: Top CWE Family Breakdown", char_headers, cwe_rows)

    project_rows = []
    for group, metrics in _sort_groups(project_metrics, limit=8):
        project_rows.append([
            group,
            str(metrics["count"]),
            f"{metrics['vuln_hit_pct']:.1f}%",
            f"{metrics['gt_func_hit_pct']:.1f}%",
            f"{metrics['func_hit_pct']:.1f}%",
            f"{metrics['within_5_pct']:.1f}%",
        ])
    print_summary_table("RQ1.2: Top Project Breakdown", char_headers, project_rows)

    # LaTeX
    if args.latex:
        tex_rows = []
        for bkt in ["1", "2", "3", "4+"]:
            m = per_layer[bkt]
            if m.get("count", 0) == 0:
                continue
            tex_rows.append([
                bkt, str(m["count"]),
                fmt_pct(m["vuln_hit_pct"]),
                fmt_pct(m["gt_func_hit_pct"]),
                fmt_pct(m["func_hit_pct"]),
            ])
        m = agg["total"]
        tex_rows.append([
            "Total", str(m["count"]),
            fmt_pct(m["vuln_hit_pct"], bold=True),
            fmt_pct(m["gt_func_hit_pct"], bold=True),
            fmt_pct(m["func_hit_pct"], bold=True),
        ])
        print("\n" + latex_table(
            "Trigger-localization and vulnerability-level hit accuracy by interprocedural depth.",
            "tab:rq1_layer_breakdown",
            ["Layer", "N", "VulnHit", GT_FUNC_HIT_LABEL, FUNC_HIT_LABEL],
            tex_rows,
        ))

        cwe_tex_rows = []
        for group, metrics in _sort_groups(cwe_metrics, limit=8):
            cwe_tex_rows.append([
                group,
                str(metrics["count"]),
                fmt_pct(metrics["vuln_hit_pct"]),
                fmt_pct(metrics["gt_func_hit_pct"]),
                fmt_pct(metrics["func_hit_pct"]),
                fmt_pct(metrics["within_5_pct"]),
            ])
        print("\n" + latex_table(
            "AutoTrace effectiveness across the largest CWE families.",
            "tab:rq1_cwe_breakdown",
            ["CWE Family", "N", "VulnHit", GT_FUNC_HIT_LABEL, FUNC_HIT_LABEL, r"Within$\pm$5"],
            cwe_tex_rows,
        ))

        project_tex_rows = []
        for group, metrics in _sort_groups(project_metrics, limit=8):
            project_tex_rows.append([
                group,
                str(metrics["count"]),
                fmt_pct(metrics["vuln_hit_pct"]),
                fmt_pct(metrics["gt_func_hit_pct"]),
                fmt_pct(metrics["func_hit_pct"]),
                fmt_pct(metrics["within_5_pct"]),
            ])
        print("\n" + latex_table(
            "AutoTrace effectiveness across the largest projects.",
            "tab:rq1_project_breakdown",
            ["Project", "N", "VulnHit", GT_FUNC_HIT_LABEL, FUNC_HIT_LABEL, r"Within$\pm$5"],
            project_tex_rows,
        ))

    # JSON report
    output_path = args.output or (OUTPUT_DIR / "rq1_1_report.json")
    save_json_report({
        "rq": "RQ1_2_depth",
        "sample_selection": (
            "Count only CVEs with result.json present, status=success, and at least "
            "one predicted trigger in triggers.json."
        ),
        "vulnerability_hit_definition": (
            "VulnHit (broad RQ1.1 criterion): a CVE is correct if any identified trigger "
            "matches a GT trigger line, exact GT trigger statement, or GT trigger function. "
            "Function-only credit is withheld for cross-function patch-fallback candidates."
        ),
        "per_layer": per_layer,
        "aggregate": agg,
        "top_cwe_family": dict(_sort_groups(cwe_metrics, limit=8)),
        "top_project": dict(_sort_groups(project_metrics, limit=8)),
        "total_cves": len(best),
    }, output_path)


if __name__ == "__main__":
    main()
