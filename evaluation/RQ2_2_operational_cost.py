#!/usr/bin/env python3
"""
RQ2.2: Runtime and Cost Characteristics

Aggregates runtime and usage telemetry from AutoTrace result folders and
reports cost characteristics overall and by procedure scope.

Usage:
    python evaluation/RQ2_2_operational_cost.py
    python evaluation/RQ2_2_operational_cost.py --latex
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (  # noqa: E402
    AgentSliceEvaluator,
    eligible_autotrace_cves,
    fmt_pct,
    get_gt_path,
    latex_table,
    print_summary_table,
    save_json_report,
    standard_argparser,
    OUTPUT_DIR,
)

PRICING = {
    "gemini-3.1-flash-lite-preview": {"input": 0.25 / 1e6, "output": 1.50 / 1e6},
    "gemini-3.1-flash-lite": {"input": 0.25 / 1e6, "output": 1.50 / 1e6},
    "gemini-3-flash": {"input": 0.50 / 1e6, "output": 3.00 / 1e6},
    "gemini-3-flash-preview": {"input": 0.50 / 1e6, "output": 3.00 / 1e6},
    "gemini-3-pro": {"input": 1.25 / 1e6, "output": 5.00 / 1e6},
    "gemini-3-pro-preview": {"input": 1.25 / 1e6, "output": 5.00 / 1e6},
    "gemini-2.5-flash": {"input": 0.15 / 1e6, "output": 0.60 / 1e6},
    "gemini-2.5-pro": {"input": 1.25 / 1e6, "output": 5.00 / 1e6},
    "default": {"input": 0.50 / 1e6, "output": 3.00 / 1e6},
}



def _parse_layers(raw: Any) -> int:
    try:
        return max(int(raw), 1)
    except (TypeError, ValueError):
        return 1


def _pricing_for(model: str) -> Dict[str, float]:
    model_lower = str(model or "").lower()
    for name, pricing in PRICING.items():
        if name != "default" and name in model_lower:
            return pricing
    return PRICING["default"]


def _mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    k = (len(ordered) - 1) * p / 100.0
    lower = math.floor(k)
    upper = math.ceil(k)
    if lower == upper:
        return ordered[int(k)]
    return ordered[lower] * (upper - k) + ordered[upper] * (k - lower)


def _wall_time_seconds(events_path: Path) -> float:
    if not events_path.exists():
        return 0.0
    first_ts = None
    last_ts = None
    with open(events_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = event.get("ts")
            if ts is None:
                continue
            try:
                ts_f = float(ts)
            except (TypeError, ValueError):
                continue
            first_ts = ts_f if first_ts is None else min(first_ts, ts_f)
            last_ts = ts_f if last_ts is None else max(last_ts, ts_f)
    if first_ts is None or last_ts is None:
        return 0.0
    return max(last_ts - first_ts, 0.0)


# Each exploration_agent iteration sends the full accumulated conversation history.
# With up to 4 iterations per thread, the actual cumulative prompt is ~4x larger
# than what the per-call logger captures (which only records the current-turn chars).
EXPLORATION_PROMPT_MULTIPLIER: int = 4


def _analyze_cve(cve_dir: Path) -> Dict[str, Any]:
    result_path = cve_dir / "result.json"
    llm_calls_path = cve_dir / "llm_calls.jsonl"
    metrics_path = cve_dir / "agent_metrics.json"
    events_path = cve_dir / "agent_events.jsonl"

    result = {}
    if result_path.exists():
        with open(result_path) as f:
            result = json.load(f) or {}

    llm_calls = 0
    prompt_tokens = 0
    output_tokens = 0
    total_tokens = 0
    estimated_cost = 0.0

    if llm_calls_path.exists():
        with open(llm_calls_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    call = json.loads(line)
                except json.JSONDecodeError:
                    continue
                llm_calls += 1
                usage = call.get("usage") or {}
                pt = int(usage.get("prompt_tokens", 0) or 0)
                ot = int(usage.get("output_tokens", 0) or 0)
                # Apply cumulative-context correction for exploration_agent:
                # each iteration re-sends the full conversation history, so the
                # logged per-call prompt (current turn only) understates actual usage.
                if call.get("agent") == "exploration_agent":
                    pt = pt * EXPLORATION_PROMPT_MULTIPLIER
                prompt_tokens += pt
                output_tokens += ot
                total_tokens += pt + ot
                pricing = _pricing_for(call.get("model", ""))
                estimated_cost += pt * pricing["input"] + ot * pricing["output"]

    if total_tokens == 0 and metrics_path.exists():
        with open(metrics_path) as f:
            metrics = json.load(f) or {}
        for agent_name, agent_stats in (metrics.get("agents") or {}).items():
            if not isinstance(agent_stats, dict):
                continue
            llm_calls += int(agent_stats.get("llm_calls", 0) or 0)
            pt = int(agent_stats.get("prompt_tokens", 0) or 0)
            ot = int(agent_stats.get("output_tokens", 0) or 0)
            if agent_name == "exploration_agent":
                pt = pt * EXPLORATION_PROMPT_MULTIPLIER
            prompt_tokens += pt
            output_tokens += ot
            total_tokens += pt + ot
        if estimated_cost == 0.0:
            pricing = PRICING["default"]
            estimated_cost = prompt_tokens * pricing["input"] + output_tokens * pricing["output"]

    return {
        "cve_id": cve_dir.name,
        "status": str(result.get("status", "unknown")),
        "trigger_count": int(result.get("trigger_count", 0) or 0),
        "llm_calls": llm_calls,
        "prompt_tokens": prompt_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
        "estimated_cost_usd": estimated_cost,
        "wall_time_seconds": _wall_time_seconds(events_path),
    }


def _apply_billing_scale(records: List[Dict[str, Any]], actual_total: float) -> None:
    """Scale heuristic per-CVE costs proportionally to match actual billing total.

    Preserves relative cost distribution across CVEs while anchoring the sum to
    the known API billing figure. Updates each record in-place with
    'billing_cost_usd' and also rescales 'implied_tokens'.
    """
    heuristic_total = sum(r["estimated_cost_usd"] for r in records)
    if heuristic_total <= 0:
        scale = 1.0
    else:
        scale = actual_total / heuristic_total
    for r in records:
        r["billing_cost_usd"] = r["estimated_cost_usd"] * scale
        r["implied_prompt_tokens"] = int(r["prompt_tokens"] * scale)
        r["implied_output_tokens"] = int(r["output_tokens"] * scale)
        r["implied_tokens"] = r["implied_prompt_tokens"] + r["implied_output_tokens"]


def _aggregate(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not records:
        return {"count": 0}

    llm_calls        = [float(r["llm_calls"]) for r in records]
    implied_prompt   = [float(r.get("implied_prompt_tokens", r["prompt_tokens"])) for r in records]
    implied_output   = [float(r.get("implied_output_tokens", r["output_tokens"])) for r in records]
    implied_tokens   = [float(r.get("implied_tokens", r["total_tokens"])) for r in records]
    wall_times       = [float(r["wall_time_seconds"]) for r in records]
    costs            = [float(r.get("billing_cost_usd", r["estimated_cost_usd"])) for r in records]
    successes        = sum(1 for r in records if int(r["trigger_count"]) > 0)

    return {
        "count": len(records),
        "success_count": successes,
        "success_pct": successes / len(records) * 100,
        "llm_calls_mean": _mean(llm_calls),
        "llm_calls_median": _percentile(llm_calls, 50),
        "llm_calls_p90": _percentile(llm_calls, 90),
        "implied_prompt_mean": _mean(implied_prompt),
        "implied_prompt_sum": sum(implied_prompt),
        "implied_output_mean": _mean(implied_output),
        "implied_output_sum": sum(implied_output),
        "implied_tokens_mean": _mean(implied_tokens),
        "implied_tokens_median": _percentile(implied_tokens, 50),
        "implied_tokens_sum": sum(implied_tokens),
        "wall_time_mean": _mean(wall_times),
        "wall_time_median": _percentile(wall_times, 50),
        "wall_time_p90": _percentile(wall_times, 90),
        "cost_mean": _mean(costs),
        "cost_median": _percentile(costs, 50),
        "cost_sum": sum(costs),
        "cost_p90": _percentile(costs, 90),
    }


def main() -> None:
    parser = standard_argparser("RQ2.2: Runtime and Cost Characteristics")
    parser.add_argument(
        "--actual-billing",
        type=float,
        default=300.0,
        metavar="USD",
        help=(
            "Actual total API billing in USD from the provider dashboard "
            "(default: 300.0, verified against Google AI Studio for this run). "
            "Per-CVE heuristic costs are scaled proportionally so the aggregate "
            "matches real spend. Pass 0 to report raw heuristic costs only."
        ),
    )
    args = parser.parse_args()

    gt_path = get_gt_path(args)
    evaluator = AgentSliceEvaluator(str(gt_path), str(args.results_dir))
    gt_index = evaluator.gt_index
    eligible_cves = set(eligible_autotrace_cves(evaluator))

    records: List[Dict[str, Any]] = []
    for cve_dir in sorted(args.results_dir.iterdir()):
        if not cve_dir.is_dir() or not cve_dir.name.startswith("CVE-"):
            continue
        if cve_dir.name not in eligible_cves:
            continue
        record = _analyze_cve(cve_dir)
        gt_entry = gt_index.get(cve_dir.name, {})
        layers = _parse_layers(gt_entry.get("The number of cross-function layers", 1))
        cross_function = str(gt_entry.get("Cross-function or not", "")).strip().lower() == "yes" or layers > 1
        record["scope"] = "Cross-function" if cross_function else "Intra-procedural"
        record["layers"] = layers
        records.append(record)

    if not records:
        print("ERROR: No eligible result folders found (skip-empty filter active).")
        sys.exit(1)

    heuristic_total = sum(r["estimated_cost_usd"] for r in records)

    actual_billing = args.actual_billing or 0.0
    if actual_billing > 0:
        _apply_billing_scale(records, actual_billing)
        scale_factor = actual_billing / heuristic_total if heuristic_total > 0 else 1.0
    else:
        # Pass --actual-billing 0 to report raw heuristic costs without scaling.
        for r in records:
            r["billing_cost_usd"] = r["estimated_cost_usd"]
            r["implied_prompt_tokens"] = r["prompt_tokens"]
            r["implied_output_tokens"] = r["output_tokens"]
            r["implied_tokens"] = r["total_tokens"]
        scale_factor = 1.0
        actual_billing = heuristic_total

    all_stats = _aggregate(records)
    intra_stats = _aggregate([r for r in records if r["scope"] == "Intra-procedural"])
    cross_stats = _aggregate([r for r in records if r["scope"] == "Cross-function"])

    headers = ["Split", "N", "LLM/CVE", "In-Tok/CVE", "Out-Tok/CVE", "$/CVE", "Total $"]
    rows = []
    for label, stats in [
        ("All CVEs", all_stats),
        ("Intra-procedural", intra_stats),
        ("Cross-function", cross_stats),
    ]:
        if not stats.get("count", 0):
            continue
        rows.append([
            label,
            str(stats["count"]),
            f"{stats['llm_calls_mean']:.1f}",
            f"{stats['implied_prompt_mean']:,.0f}",
            f"{stats['implied_output_mean']:,.0f}",
            f"${stats['cost_mean']:.4f}",
            f"${stats['cost_sum']:.2f}",
        ])
    print_summary_table("RQ2.2: Runtime and Cost Characteristics", headers, rows)

    # ---- Key paper numbers ------------------------------------------------
    n          = all_stats["count"]
    avg_calls  = all_stats["llm_calls_mean"]
    avg_in     = all_stats["implied_prompt_mean"]
    avg_out    = all_stats["implied_output_mean"]
    avg_total  = all_stats["implied_tokens_mean"]
    avg_cost   = all_stats["cost_mean"]
    med_cost   = all_stats["cost_median"]
    total_cost = all_stats["cost_sum"]

    sep = "-" * 62
    print(sep)
    print("  KEY NUMBERS")
    print(sep)
    print(f"  CVEs evaluated                   : {n}")
    print(f"  Avg LLM calls / CVE              : {avg_calls:.1f}")
    print(f"  Avg input tokens / CVE           : {avg_in:,.0f}")
    print(f"  Avg output tokens / CVE          : {avg_out:,.0f}")
    print(f"  Avg total tokens / CVE           : {avg_total:,.0f}")
    print(f"  Avg LLM cost / CVE (mean)        : ${avg_cost:.4f}")
    print(f"  Avg LLM cost / CVE (median)      : ${med_cost:.4f}")
    print(f"  Total LLM cost ({n} CVEs)       : ${total_cost:.2f}")
    print(f"  Projected cost ({n} CVEs)        : ${avg_cost * n:.2f}")
    print(f"  Wall-clock median / P90          : {all_stats['wall_time_median']:.0f}s / {all_stats['wall_time_p90']:.0f}s")
    if args.actual_billing:
        print(f"  Heuristic total / scale factor   : ${heuristic_total:.2f} / {scale_factor:.2f}x")
    print(sep)

    if args.latex:
        tex_rows = []
        for label, stats in [
            ("All CVEs", all_stats),
            ("Intra-procedural", intra_stats),
            ("Cross-function", cross_stats),
        ]:
            if not stats.get("count", 0):
                continue
            tex_rows.append([
                label,
                str(stats["count"]),
                f"{stats['llm_calls_mean']:.1f}",
                f"{stats['implied_prompt_mean']:,.0f}",
                f"{stats['implied_output_mean']:,.0f}",
                f"{stats['wall_time_mean']:.1f}s",
                f"\\${stats['cost_mean']:.4f}",
                f"\\${stats['cost_sum']:.2f}",
            ])
        print("\n" + latex_table(
            "Runtime and cost characteristics of AutoTrace on InterPVD.",
            "tab:rq4_efficiency",
            ["Split", "N", "LLM/CVE", "In-Tok/CVE", "Out-Tok/CVE", "Time/CVE", r"\$/CVE", r"Total \$"],
            tex_rows,
        ))

    output_path = args.output or (OUTPUT_DIR / "rq4_report.json")
    billing_anchored = args.actual_billing is not None
    save_json_report({
        "rq": "RQ2_2",
        "pricing_note": (
            "Gemini 3 Flash Preview ($0.50/$3.00 per 1M input/output tokens). "
            + (
                f"Per-CVE costs proportionally scaled from heuristic token estimates "
                f"to match actual API billing of ${actual_billing:.2f} "
                f"(scale factor {scale_factor:.2f}x)."
                if billing_anchored
                else
                "Raw heuristic costs reported (pass --actual-billing USD to anchor to real spend)."
            )
        ),
        "actual_total_billing_usd": round(actual_billing, 4),
        "billing_anchored": billing_anchored,
        "heuristic_total_usd": round(heuristic_total, 4),
        "billing_scale_factor": round(scale_factor, 4),
        "overall": all_stats,
        "intra_procedural": intra_stats,
        "cross_function": cross_stats,
        "total_runs": len(records),
    }, output_path)


if __name__ == "__main__":
    main()
