#!/usr/bin/env python3
"""
RQ3.1 (Auxiliary): LLM Benchmark by Interprocedural Depth

Same evaluation as the main SinkTrace-Bench benchmark, but broken down by
call-chain depth (1, 2, 3, 4+).

Usage:
    python evaluation/RQ3_1_benchmark_by_depth.py --evaluate --responses-dir evaluation/responses
    python evaluation/RQ3_1_benchmark_by_depth.py --evaluate --responses-dir evaluation/responses --latex
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (  # noqa: E402
    FUNC_HIT_LABEL,
    fmt_pct,
    latex_table,
    layer_bucket,
    print_summary_table,
    save_json_report,
    standard_argparser,
    OUTPUT_DIR,
    PROJECT_ROOT,
)
from RQ3_1_sinktrace_benchmark import _load_dataset, _build_gt_from_dataset, _func_match, _normalize  # noqa: E402

RESPONSES_DEFAULT = Path(__file__).resolve().parent / "responses"


def main() -> None:
    parser = standard_argparser("RQ3.1: LLM Benchmark by Layer Depth")
    parser.add_argument("--evaluate", action="store_true", required=True)
    parser.add_argument(
        "--responses-dir",
        "--response-dir",
        type=Path,
        default=RESPONSES_DEFAULT,
        help="Directory with model response subdirectories (alias: --response-dir)",
    )
    args = parser.parse_args()

    samples = _load_dataset()
    vuln_samples = [s for s in samples if s.get("vulnerability_present", True)]
    gt = _build_gt_from_dataset(vuln_samples)

    responses_dir = args.responses_dir
    if not responses_dir.exists():
        print(f"WARNING: responses directory not found: {responses_dir}")
        output_path = args.output or (OUTPUT_DIR / "rq5_1_report.json")
        save_json_report({"rq": "RQ3_1_depth", "per_model": {}}, output_path)
        return
    model_dirs = sorted([d for d in responses_dir.iterdir() if d.is_dir()])
    if not model_dirs:
        print(f"ERROR: No model directories in {responses_dir}")
        sys.exit(1)

    report: Dict[str, Any] = {}

    for model_dir in model_dirs:
        model_name = model_dir.name
        pred_file = model_dir / "predictions.jsonl"
        if not pred_file.exists():
            continue

        preds = []
        with open(pred_file) as f:
            for line in f:
                line = line.strip()
                if line:
                    preds.append(json.loads(line))

        # Score per layer bucket
        buckets: Dict[str, Dict[str, int]] = defaultdict(lambda: {
            "total": 0, "func_correct": 0, "line_correct": 0, "stmt_correct": 0,
        })

        for p in preds:
            sid = p.get("id", "")
            if sid not in gt:
                continue
            g = gt[sid]
            bkt = layer_bucket(g["layers"])
            buckets[bkt]["total"] += 1

            pred_func = p.get("pred_function") or p.get("trigger_function", "")
            pred_line = p.get("pred_line") or p.get("trigger_line", 0)
            pred_stmt = p.get("pred_statement") or p.get("trigger_statement", "")

            if _func_match(g["gt_function"], pred_func):
                buckets[bkt]["func_correct"] += 1
            if g["gt_line"] and pred_line and int(g["gt_line"]) == int(pred_line):
                buckets[bkt]["line_correct"] += 1
            if (_normalize(g["gt_statement"]) and _normalize(pred_stmt) and
                    (_normalize(g["gt_statement"]) in _normalize(pred_stmt) or
                     _normalize(pred_stmt) in _normalize(g["gt_statement"]))):
                buckets[bkt]["stmt_correct"] += 1

        # Format results
        model_result: Dict[str, Any] = {}
        rows = []
        for bkt in ["1", "2", "3", "4+"]:
            b = buckets.get(bkt, {"total": 0, "func_correct": 0, "line_correct": 0, "stmt_correct": 0})
            n = b["total"]
            if n == 0:
                continue
            model_result[bkt] = {
                "count": n,
                "func_hit_pct": b["func_correct"] / n * 100,
                "exact_line_pct": b["line_correct"] / n * 100,
                "exact_stmt_pct": b["stmt_correct"] / n * 100,
            }
            rows.append([
                bkt, str(n),
                f"{b['func_correct'] / n * 100:.1f}%",
                f"{b['line_correct'] / n * 100:.1f}%",
                f"{b['stmt_correct'] / n * 100:.1f}%",
            ])

        print_summary_table(
            f"RQ3.1: {model_name} — Accuracy by Layer Depth",
            ["Layer", "N", FUNC_HIT_LABEL, "ExactLine", "ExactStmt"],
            rows,
        )
        report[model_name] = model_result

    # LaTeX — one table per model (or combined)
    if args.latex and report:
        tex_rows = []
        for model_name, by_layer in sorted(report.items()):
            for bkt in ["1", "2", "3", "4+"]:
                m = by_layer.get(bkt)
                if not m:
                    continue
                tex_rows.append([
                    model_name.replace("_", " ") if bkt == "1" else "",
                    bkt,
                    str(m["count"]),
                    fmt_pct(m["func_hit_pct"]),
                    fmt_pct(m["exact_line_pct"]),
                    fmt_pct(m["exact_stmt_pct"]),
                ])
        print("\n" + latex_table(
            "LLM trigger localization by interprocedural depth.",
            "tab:rq5_layer_breakdown",
            ["Model", "Layer", "N", FUNC_HIT_LABEL, "ExactLine", "ExactStmt"],
            tex_rows,
        ))

    output_path = args.output or (OUTPUT_DIR / "rq5_1_report.json")
    save_json_report({"rq": "RQ3_1_depth", "per_model": report}, output_path)


if __name__ == "__main__":
    main()
