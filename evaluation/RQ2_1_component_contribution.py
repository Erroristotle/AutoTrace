#!/usr/bin/env python3
"""
RQ2.1: Log-Based Component Contribution Analysis.

Observational study over existing `results/` runs:
  - direct evidence for retry / reflection / verifier / hints / CV refinement
  - tool attribution from per-CVE `result.json.tool_stats`
  - partial controlled overlay from `experiments/results/exp_ablation/*/run_0`
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (  # noqa: E402
    FUNC_HIT_LABEL,
    OUTPUT_DIR,
    AgentSliceEvaluator,
    eligible_autotrace_cves,
    fmt_pct,
    get_gt_path,
    latex_table,
    print_summary_table,
    save_json_report,
    standard_argparser,
)
from _log_ablation import (  # noqa: E402
    DEFAULT_ABLATION_ROOT,
    DEFAULT_LOGS_DIR,
    build_controlled_overlay,
    collect_corpus_bundles,
    summarize_component_presence,
    summarize_component_usage,
    summarize_tool_attribution,
)


def _stage_stats(bundles: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    total_runs = len(bundles)
    extract_ok = 0
    slice_progress = 0
    detect_ok = 0
    detect_failed = 0
    trigger_found = 0

    for bundle in bundles.values():
        result = bundle.get("result") or {}
        stage_map = {
            stage.get("stage"): stage
            for stage in result.get("stage_outcomes", [])
            if isinstance(stage, dict)
        }

        extract_stage = stage_map.get("extract_cvs", {})
        if extract_stage.get("status") == "ok" and int((extract_stage.get("data") or {}).get("count", 0) or 0) > 0:
            extract_ok += 1

        slice_stage = stage_map.get("slice_vars", {})
        if slice_stage.get("status") in {"ok", "degraded"}:
            slice_progress += 1

        detect_stage = stage_map.get("detect_triggers", {})
        status = detect_stage.get("status")
        if status in {"ok", "degraded"}:
            detect_ok += 1
        elif status == "failed":
            detect_failed += 1

        detect_count = int((detect_stage.get("data") or {}).get("trigger_count", 0) or 0)
        result_count = int(result.get("trigger_count", 0) or 0)
        if max(detect_count, result_count) > 0:
            trigger_found += 1

    def _pct(value: int) -> float:
        return value / total_runs * 100.0 if total_runs else 0.0

    return {
        "total_runs": total_runs,
        "extract_ok": {"count": extract_ok, "pct": _pct(extract_ok)},
        "slice_progress": {"count": slice_progress, "pct": _pct(slice_progress)},
        "detect_ok": {"count": detect_ok, "pct": _pct(detect_ok)},
        "detect_failed": {"count": detect_failed, "pct": _pct(detect_failed)},
        "trigger_found": {"count": trigger_found, "pct": _pct(trigger_found)},
    }


def build_rq3_report(
    *,
    gt_path: Path,
    results_dir: Path,
    logs_dir: Path = DEFAULT_LOGS_DIR,
    overlay_root: Path = DEFAULT_ABLATION_ROOT,
) -> Dict[str, Any]:
    bundles, _, best_by_cve, _ = collect_corpus_bundles(
        results_dir=results_dir,
        gt_path=gt_path,
        logs_dir=logs_dir,
    )
    stage_stats = _stage_stats(bundles)

    evaluator = AgentSliceEvaluator(str(gt_path), str(results_dir))
    eligible_cves = set(eligible_autotrace_cves(evaluator))
    eligible_bundles = {cve: b for cve, b in bundles.items() if cve in eligible_cves}
    eligible_best_by_cve = {cve: cmp for cve, cmp in best_by_cve.items() if cve in eligible_cves}

    component_groups = summarize_component_usage(eligible_bundles, eligible_best_by_cve)
    component_presence = summarize_component_presence(eligible_bundles)
    tool_attribution = summarize_tool_attribution(eligible_bundles, eligible_best_by_cve)
    controlled_overlay = build_controlled_overlay(
        gt_path=gt_path,
        baseline_results_dir=results_dir,
        overlay_root=overlay_root,
    )

    return {
        "rq": "RQ2_1",
        "study_type": "observational_log_based",
        "total_runs": len(bundles),
        "eligible_runs": len(eligible_bundles),
        "localized_cves": len(eligible_best_by_cve),
        "stage_coverage": stage_stats,
        "component_groups": component_groups,
        "component_usage": component_presence,
        "tool_attribution": tool_attribution,
        "controlled_overlay": controlled_overlay,
    }


def _component_rows(component_groups: Dict[str, Dict[str, Any]]) -> List[List[str]]:
    labels = {
        "direct": "First-pass (no retry)",
        "retry_assisted": "Retry-assisted",
        "mid_reflection_assisted": "Mid-reflection",
        "verification_assisted": "Verification-assisted",
        "cv_refinement_assisted": "CV refinement",
        "long_term_hints_assisted": "Long-term Memory",
    }
    rows: List[List[str]] = []
    for key in (
        "direct",
        "retry_assisted",
        "mid_reflection_assisted",
        "verification_assisted",
        "cv_refinement_assisted",
        "long_term_hints_assisted",
    ):
        metrics = component_groups.get(key)
        if not metrics or metrics.get("cve_count", 0) <= 0:
            continue
        rows.append(
            [
                labels.get(key, key),
                str(metrics.get("cve_count", 0)),
                f"{metrics.get('exact_line_pct', 0.0):.1f}%",
                f"{metrics.get('func_hit_pct', 0.0):.1f}%",
                f"{metrics.get('avg_llm_calls', 0.0):.1f}",
                f"{metrics.get('avg_verifier_calls', 0.0):.1f}",
                f"{metrics.get('avg_tool_calls', 0.0):.1f}",
            ]
        )
    return rows


def _presence_rows(component_usage: Dict[str, Dict[str, Any]]) -> List[List[str]]:
    labels = {
        "retry_used": "Reflection retry",
        "mid_reflection_used": "Mid-search reflection",
        "reflection_used": "Any reflection",
        "verification_used": "Verification agent",
        "cv_refinement_used": "CV refinement",
        "long_term_hints_used": "Long-term Memory",
        "hard_reject_present": "Layer 1 hard reject",
        "soft_reject_present": "Layer 1 soft reject",
        "verifier_reject_present": "Verifier reject",
    }
    rows: List[List[str]] = []
    for key in (
        "retry_used",
        "mid_reflection_used",
        "reflection_used",
        "verification_used",
        "cv_refinement_used",
        "long_term_hints_used",
        "hard_reject_present",
        "soft_reject_present",
        "verifier_reject_present",
    ):
        payload = component_usage.get(key, {})
        rows.append(
            [
                labels.get(key, key),
                str(payload.get("count", 0)),
                f"{payload.get('rate', 0.0):.1f}%",
            ]
        )
    return rows


def _tool_rows(tool_attribution: Dict[str, Dict[str, Any]], limit: int = 8) -> List[List[str]]:
    rows: List[List[str]] = []
    for idx, (tool_name, payload) in enumerate(tool_attribution.items()):
        if idx >= limit:
            break
        rows.append(
            [
                tool_name,
                str(payload.get("cves_using", 0)),
                str(int(payload.get("total_calls", 0) or 0)),
                f"{payload.get('avg_time_ms_per_call', 0.0):.1f}",
                f"{payload.get('exact_line_pct_when_used', 0.0):.1f}%",
                f"{payload.get('func_hit_pct_when_used', 0.0):.1f}%",
            ]
        )
    return rows


def _overlay_rows(controlled_overlay: Dict[str, Dict[str, Any]]) -> List[List[str]]:
    rows: List[List[str]] = []
    for variant, payload in sorted(controlled_overlay.items()):
        rows.append(
            [
                variant,
                str(payload.get("sample_size", 0)),
                f"{payload.get('delta_exact_line_pct', 0.0):+.1f}",
                f"{payload.get('delta_func_hit_pct', 0.0):+.1f}",
            ]
        )
    return rows


def main() -> None:
    parser = standard_argparser("RQ2.1: Log-Based Component Contribution Analysis")
    parser.add_argument(
        "--logs-dir",
        type=Path,
        default=DEFAULT_LOGS_DIR,
        help="Directory containing per-CVE plaintext logs.",
    )
    parser.add_argument(
        "--overlay-root",
        type=Path,
        default=DEFAULT_ABLATION_ROOT,
        help="Root containing partial controlled ablation reruns.",
    )
    parser.add_argument(
        "--top-tools",
        type=int,
        default=8,
        help="How many tools to show in the console/LaTeX summary.",
    )
    args = parser.parse_args()

    gt_path = get_gt_path(args)
    report = build_rq3_report(
        gt_path=gt_path,
        results_dir=args.results_dir,
        logs_dir=args.logs_dir,
        overlay_root=args.overlay_root,
    )

    print_summary_table(
        "RQ2.1: Component-Assisted Localization",
        ["Group", "N", "VulnHit", FUNC_HIT_LABEL, "LLM/CVE", "Ver/CVE", "Tool/CVE"],
        _component_rows(report.get("component_groups", {})),
    )
    print_summary_table(
        "RQ2.1: Component Presence Across Runs",
        ["Component", "Count", "Rate"],
        _presence_rows(report.get("component_usage", {})),
    )
    print_summary_table(
        "RQ2.1: Tool Attribution",
        ["Tool", "CVEs", "Calls", "AvgMs/Call", "VulnHit", FUNC_HIT_LABEL],
        _tool_rows(report.get("tool_attribution", {}), limit=args.top_tools),
    )

    overlay_rows = _overlay_rows(report.get("controlled_overlay", {}))
    if overlay_rows:
        print_summary_table(
            "RQ2.1: Controlled Overlay (Directional Only)",
            ["Variant", "N", "ΔExact", f"Δ{FUNC_HIT_LABEL}"],
            overlay_rows,
        )

    stage = report.get("stage_coverage", {})
    print_summary_table(
        "RQ2.1: Pipeline Stage Coverage",
        ["Stage", "Count", "Rate"],
        [
            ["CV extraction succeeded", str(stage.get("extract_ok", {}).get("count", 0)), f"{stage.get('extract_ok', {}).get('pct', 0.0):.1f}%"],
            ["Variable slicing progressed", str(stage.get("slice_progress", {}).get("count", 0)), f"{stage.get('slice_progress', {}).get('pct', 0.0):.1f}%"],
            ["Trigger detection reached", str(stage.get("detect_ok", {}).get("count", 0)), f"{stage.get('detect_ok', {}).get('pct', 0.0):.1f}%"],
            ["Runs with at least one trigger", str(stage.get("trigger_found", {}).get("count", 0)), f"{stage.get('trigger_found', {}).get('pct', 0.0):.1f}%"],
        ],
    )

    if args.latex:
        component_tex = latex_table(
            "Observed component contribution groups on the existing AutoTrace corpus. Groups are telemetry-derived and not mutually exclusive.",
            "tab:rq3_log_components",
            ["Group", "N", "VulnHit", FUNC_HIT_LABEL, "LLM/CVE", "Tool/CVE"],
            [
                [
                    row[0],
                    row[1],
                    fmt_pct(float(row[2].rstrip("%"))),
                    fmt_pct(float(row[3].rstrip("%"))),
                    row[4],
                    row[6],
                ]
                for row in _component_rows(report.get("component_groups", {}))
            ],
        )
        print("\n" + component_tex)

        tool_rows = _tool_rows(report.get("tool_attribution", {}), limit=min(args.top_tools, 6))
        if tool_rows:
            tool_tex = latex_table(
                "Observed tool usage on localized CVEs. This is aggregate attribution, not causal per-tool ablation.",
                "tab:rq3_tools",
                ["Tool", "CVEs", "Calls", "AvgMs/Call", "VulnHit", FUNC_HIT_LABEL],
                [
                    [
                        row[0].replace("_", "\\_"),
                        row[1],
                        row[2],
                        row[3],
                        fmt_pct(float(row[4].rstrip("%"))),
                        fmt_pct(float(row[5].rstrip("%"))),
                    ]
                    for row in tool_rows
                ],
            )
            print("\n" + tool_tex)

        if overlay_rows:
            overlay_tex = latex_table(
                "Partial controlled ablation overlay on the subset already rerun under `experiments/results/exp_ablation`. Deltas are relative to the same CVEs in the full baseline and should be treated as directional only.",
                "tab:rq3_controlled_overlay",
                ["Variant", "N", "$\\Delta$Exact", f"$\\Delta${FUNC_HIT_LABEL}"],
                overlay_rows,
            )
            print("\n" + overlay_tex)

    output_path = args.output or (OUTPUT_DIR / "rq3_report.json")
    save_json_report(report, output_path)


if __name__ == "__main__":
    main()
