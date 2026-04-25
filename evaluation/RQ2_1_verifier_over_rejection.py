#!/usr/bin/env python3
"""
RQ2.1: Verifier Over-Rejection Study.

Separates historical hard rejects from newer soft-unverified runs and
measures how often locally rejected candidates were later recovered.
"""

from __future__ import annotations

import csv
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

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
    DEFAULT_LOGS_DIR,
    bundle_to_case_row,
    collect_corpus_bundles,
    evaluate_vff_rejection,
)


COHORTS: Tuple[Tuple[str, str], ...] = (
    ("hard_reject", "Layer 1 hard reject"),
    ("soft_reject", "Layer 1 soft reject"),
    ("verifier_reject", "Verification reject"),
)

TIER_ORDER = {"A": 0, "B": 1, "C": 2, "": 3}
RECOVERY_KEYS = ("same_function_retry", "outward_expansion", "failure")


def _pct(count: int, denom: int) -> float:
    return count / denom * 100.0 if denom else 0.0


def _mean(values: List[int]) -> float:
    return sum(values) / len(values) if values else 0.0


def _truncate(text: str, limit: int = 96) -> str:
    clean = " ".join(str(text or "").split())
    if len(clean) <= limit:
        return clean
    return clean[: limit - 3] + "..."


def _case_sort_key(row: Dict[str, Any]) -> Tuple[Any, ...]:
    return (
        0 if row.get("has_local_rejection") else 1,
        TIER_ORDER.get(str(row.get("tier") or ""), 9),
        0 if row.get("exact_line") else 1,
        0 if row.get("func_hit") else 1,
        -(int(row.get("rejection_count", 0) or 0)),
        str(row.get("cve_id") or ""),
        str(row.get("variable") or ""),
    )


def _collect_case_rows(
    bundles: Dict[str, Dict[str, Any]],
    *,
    logs_dir: Path,
) -> Dict[str, List[Dict[str, Any]]]:
    rows_by_cohort: Dict[str, List[Dict[str, Any]]] = {key: [] for key, _ in COHORTS}

    for cohort_key, cohort_label in COHORTS:
        for bundle in bundles.values():
            for record in bundle.get("variables", {}).values():
                if not record.get("flags", {}).get(cohort_key):
                    continue
                matching_events = [event for event in record.get("events", []) if event.kind == cohort_key]
                vff_eval = evaluate_vff_rejection(record, bundle.get("gt") or {}, bundle.get("anchor_functions", []))
                row = bundle_to_case_row(bundle, record, cohort_label, vff_eval)
                row["rejection_count"] = len(matching_events)
                row["first_rejection_line_no"] = min((event.line_no for event in matching_events), default=0)
                row["rejection_kinds_present"] = "; ".join(sorted({event.kind for event in matching_events}))
                row["result_dir"] = str(bundle.get("result_dir") or "")
                row["log_path"] = str(logs_dir / f"{bundle.get('cve_id')}.log")
                rows_by_cohort[cohort_key].append(row)

        rows_by_cohort[cohort_key].sort(key=_case_sort_key)

    return rows_by_cohort


def _summarize_rows(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    local_rows = [row for row in rows if row.get("has_local_rejection")]
    tier_counts = Counter((str(row.get("tier") or "") or "unranked") for row in local_rows)
    recovery_counts = Counter(str(row.get("recovery_source") or "failure") for row in local_rows)

    summary = {
        "sample_size": len(rows),
        "trigger_found_count": sum(1 for row in rows if row.get("trigger_found")),
        "trigger_found_pct": _pct(sum(1 for row in rows if row.get("trigger_found")), len(rows)),
        "func_hit_count": sum(1 for row in rows if row.get("func_hit")),
        "func_hit_pct": _pct(sum(1 for row in rows if row.get("func_hit")), len(rows)),
        "exact_line_count": sum(1 for row in rows if row.get("exact_line")),
        "exact_line_pct": _pct(sum(1 for row in rows if row.get("exact_line")), len(rows)),
        "local_rejection_count": len(local_rows),
        "local_rejection_pct": _pct(len(local_rows), len(rows)),
        "escaped_outside_vff_count": sum(1 for row in local_rows if row.get("escaped_outside_vff")),
        "escaped_outside_vff_pct": _pct(
            sum(1 for row in local_rows if row.get("escaped_outside_vff")),
            len(local_rows),
        ),
        "explicit_retry_count": sum(1 for row in rows if row.get("explicit_retry_used")),
        "explicit_retry_pct": _pct(sum(1 for row in rows if row.get("explicit_retry_used")), len(rows)),
        "avg_rejections_per_record": _mean([int(row.get("rejection_count", 0) or 0) for row in rows]),
        "tier_breakdown": {},
        "recovery_source": {},
    }

    for tier in ("A", "B", "C", "unranked"):
        count = int(tier_counts.get(tier, 0) or 0)
        summary["tier_breakdown"][tier] = {"count": count, "pct": _pct(count, len(local_rows))}

    for key in RECOVERY_KEYS:
        count = int(recovery_counts.get(key, 0) or 0)
        summary["recovery_source"][key] = {"count": count, "pct": _pct(count, len(local_rows))}

    return summary


def build_rq3_1_report(
    *,
    gt_path: Path,
    results_dir: Path,
    logs_dir: Path = DEFAULT_LOGS_DIR,
) -> Dict[str, Any]:
    bundles, _, _, _ = collect_corpus_bundles(
        results_dir=results_dir,
        gt_path=gt_path,
        logs_dir=logs_dir,
    )
    evaluator = AgentSliceEvaluator(str(gt_path), str(results_dir))
    eligible_cves = set(eligible_autotrace_cves(evaluator))
    bundles = {cve: b for cve, b in bundles.items() if cve in eligible_cves}
    case_rows = _collect_case_rows(bundles, logs_dir=logs_dir)
    cohort_summaries = {
        cohort_key: _summarize_rows(rows)
        for cohort_key, rows in case_rows.items()
    }

    ranked_cases = [
        row
        for cohort_key, _ in COHORTS
        for row in case_rows.get(cohort_key, [])
    ]
    ranked_cases.sort(key=_case_sort_key)

    return {
        "rq": "RQ2_1_verifier",
        "study_type": "verifier_over_rejection",
        "total_runs": len(bundles),
        "cohorts": cohort_summaries,
        "ranked_cases_preview": ranked_cases[:25],
        "case_count": len(ranked_cases),
    }


def _summary_rows(cohorts: Dict[str, Dict[str, Any]]) -> List[List[str]]:
    rows: List[List[str]] = []
    for cohort_key, cohort_label in COHORTS:
        payload = cohorts.get(cohort_key, {})
        rows.append(
            [
                cohort_label,
                str(payload.get("sample_size", 0)),
                f"{payload.get('trigger_found_pct', 0.0):.1f}%",
                f"{payload.get('func_hit_pct', 0.0):.1f}%",
                f"{payload.get('exact_line_pct', 0.0):.1f}%",
                f"{payload.get('local_rejection_pct', 0.0):.1f}%",
                f"{payload.get('escaped_outside_vff_pct', 0.0):.1f}%",
            ]
        )
    return rows


def _recovery_rows(cohorts: Dict[str, Dict[str, Any]]) -> List[List[str]]:
    rows: List[List[str]] = []
    for cohort_key, cohort_label in COHORTS:
        payload = cohorts.get(cohort_key, {})
        tiers = payload.get("tier_breakdown", {})
        recovery = payload.get("recovery_source", {})
        rows.append(
            [
                cohort_label,
                str(payload.get("local_rejection_count", 0)),
                f"{tiers.get('A', {}).get('pct', 0.0):.1f}%",
                f"{tiers.get('B', {}).get('pct', 0.0):.1f}%",
                f"{tiers.get('C', {}).get('pct', 0.0):.1f}%",
                f"{recovery.get('same_function_retry', {}).get('pct', 0.0):.1f}%",
                f"{recovery.get('outward_expansion', {}).get('pct', 0.0):.1f}%",
                f"{recovery.get('failure', {}).get('pct', 0.0):.1f}%",
            ]
        )
    return rows


def _write_case_csv(rows: List[Dict[str, Any]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "cve_id",
        "variable",
        "cohort",
        "tier",
        "has_local_rejection",
        "escaped_outside_vff",
        "recovery_source",
        "trigger_found",
        "func_hit",
        "exact_line",
        "explicit_retry_used",
        "rejection_count",
        "rejection_kind",
        "rejection_function",
        "rejection_sink_line",
        "rejection_sink_family",
        "rejection_statement",
        "gt_function",
        "patch_functions",
        "final_trigger_function",
        "final_trigger_line",
        "gt_line",
        "pred_line",
        "first_rejection_line_no",
        "result_dir",
        "log_path",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def _write_case_markdown(rows: List[Dict[str, Any]], output_path: Path, *, limit: int) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# RQ2.1 Ranked Verifier Cases",
        "",
        f"| Rank | CVE | Variable | Cohort | Tier | RejectFn | Recovery | Escape | Exact | {FUNC_HIT_LABEL} | Statement |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for idx, row in enumerate(rows[:limit], 1):
        lines.append(
            "| {rank} | {cve} | {var} | {cohort} | {tier} | {reject_fn} | {recovery} | {escape} | {exact} | {func_hit} | {stmt} |".format(
                rank=idx,
                cve=row.get("cve_id", ""),
                var=row.get("variable", ""),
                cohort=row.get("cohort", ""),
                tier=row.get("tier") or "-",
                reject_fn=row.get("rejection_function") or "-",
                recovery=row.get("recovery_source") or "-",
                escape="yes" if row.get("escaped_outside_vff") else "no",
                exact="yes" if row.get("exact_line") else "no",
                func_hit="yes" if row.get("func_hit") else "no",
                stmt=_truncate(str(row.get("rejection_statement") or "-")).replace("|", "\\|"),
            )
        )
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = standard_argparser("RQ2.1: Verifier Over-Rejection Study")
    parser.add_argument(
        "--logs-dir",
        type=Path,
        default=DEFAULT_LOGS_DIR,
        help="Directory containing per-CVE plaintext logs.",
    )
    parser.add_argument(
        "--cases-csv",
        type=Path,
        default=OUTPUT_DIR / "rq3_1_cases.csv",
        help="CSV output path for ranked cohort cases.",
    )
    parser.add_argument(
        "--cases-md",
        type=Path,
        default=OUTPUT_DIR / "rq3_1_cases.md",
        help="Markdown output path for ranked cohort cases.",
    )
    parser.add_argument(
        "--case-limit",
        type=int,
        default=30,
        help="How many ranked cases to include in the Markdown dump.",
    )
    args = parser.parse_args()

    gt_path = get_gt_path(args)
    bundles, _, _, _ = collect_corpus_bundles(
        results_dir=args.results_dir,
        gt_path=gt_path,
        logs_dir=args.logs_dir,
    )
    evaluator = AgentSliceEvaluator(str(gt_path), str(args.results_dir))
    eligible_cves = set(eligible_autotrace_cves(evaluator))
    bundles = {cve: b for cve, b in bundles.items() if cve in eligible_cves}
    case_rows = _collect_case_rows(bundles, logs_dir=args.logs_dir)
    cohorts = {
        cohort_key: _summarize_rows(rows)
        for cohort_key, rows in case_rows.items()
    }
    ranked_cases = [
        row
        for cohort_key, _ in COHORTS
        for row in case_rows.get(cohort_key, [])
    ]
    ranked_cases.sort(key=_case_sort_key)

    print_summary_table(
        "RQ2.1: Rejection Cohorts",
        ["Cohort", "N", "TriggerFound", FUNC_HIT_LABEL, "ExactLine", "VFF-Local", "EscapeAfterLocal"],
        _summary_rows(cohorts),
    )
    print_summary_table(
        "RQ2.1: Local-Rejection Recovery",
        ["Cohort", "Nlocal", "TierA", "TierB", "TierC", "SameFn", "Outward", "Failure"],
        _recovery_rows(cohorts),
    )

    if args.latex:
        summary_tex = latex_table(
            "Verifier-over-rejection cohorts separated by historical hard reject versus newer soft-unverified behavior.",
            "tab:rq3_1_rejection_cohorts",
            ["Cohort", "N", "TriggerFound", FUNC_HIT_LABEL, "ExactLine", "VFF-Local", "EscapeAfterLocal"],
            [
                [
                    row[0],
                    row[1],
                    fmt_pct(float(row[2].rstrip("%"))),
                    fmt_pct(float(row[3].rstrip("%"))),
                    fmt_pct(float(row[4].rstrip("%"))),
                    fmt_pct(float(row[5].rstrip("%"))),
                    fmt_pct(float(row[6].rstrip("%"))),
                ]
                for row in _summary_rows(cohorts)
            ],
        )
        print("\n" + summary_tex)

        recovery_tex = latex_table(
            "Evidence tiers and recovery sources after VFF-local rejection. Percentages are over the local-rejection subset within each cohort.",
            "tab:rq3_1_recovery",
            ["Cohort", "Nlocal", "TierA", "TierB", "TierC", "SameFn", "Outward", "Failure"],
            [
                [
                    row[0],
                    row[1],
                    fmt_pct(float(row[2].rstrip("%"))),
                    fmt_pct(float(row[3].rstrip("%"))),
                    fmt_pct(float(row[4].rstrip("%"))),
                    fmt_pct(float(row[5].rstrip("%"))),
                    fmt_pct(float(row[6].rstrip("%"))),
                    fmt_pct(float(row[7].rstrip("%"))),
                ]
                for row in _recovery_rows(cohorts)
            ],
        )
        print("\n" + recovery_tex)

    _write_case_csv(ranked_cases, args.cases_csv)
    _write_case_markdown(ranked_cases, args.cases_md, limit=max(args.case_limit, 0))

    report = {
        "rq": "RQ2_1_verifier",
        "study_type": "verifier_over_rejection",
        "total_runs": len(bundles),
        "cohorts": cohorts,
        "case_outputs": {
            "csv": str(args.cases_csv),
            "markdown": str(args.cases_md),
        },
        "ranked_cases_preview": ranked_cases[:25],
        "case_count": len(ranked_cases),
    }
    output_path = args.output or (OUTPUT_DIR / "rq3_1_report.json")
    save_json_report(report, output_path)


if __name__ == "__main__":
    main()
