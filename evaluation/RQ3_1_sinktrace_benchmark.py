#!/usr/bin/env python3
"""
RQ3.1: AutoTrace vs State-of-the-Art LLMs on SinkTrace-Bench

Modes:
  --generate   Build prompts from dataset/train.jsonl -> evaluation/prompts/
  --evaluate   Score AutoTrace and model responses on SinkTrace-Bench

Usage:
    python evaluation/RQ3_1_sinktrace_benchmark.py --generate
    python evaluation/RQ3_1_sinktrace_benchmark.py --evaluate --responses-dir evaluation/responses
    python evaluation/RQ3_1_sinktrace_benchmark.py --evaluate --responses-dir evaluation/responses --latex
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (  # noqa: E402
    FUNC_HIT_LABEL,
    fmt_pct,
    latex_table,
    print_summary_table,
    save_json_report,
    standard_argparser,
    OUTPUT_DIR,
    PROJECT_ROOT,
)

DATASET_PATH = PROJECT_ROOT / "dataset" / "train.jsonl"
PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"

SYSTEM_PROMPT = """\
You are a vulnerability analysis expert. Given a code context from a \
vulnerability-fixing commit, identify the exact trigger statement — the \
statement where vulnerable state becomes an unsafe operation (e.g., \
out-of-bounds write, use-after-free, null dereference).

Respond with ONLY a JSON object:
{
  "trigger_function": "<function name containing the trigger>",
  "trigger_line": <line number>,
  "trigger_statement": "<the exact code statement>"
}
"""


def _normalize_trigger_map(raw: Any) -> Dict[str, Dict[str, Any]]:
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, list):
        return {}

    normalized: Dict[str, Dict[str, Any]] = {}
    for idx, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            continue
        key = str(item.get("variable") or item.get("cv_logical_name") or f"trigger_{idx}").strip()
        if not key:
            key = f"trigger_{idx}"
        if key in normalized:
            key = f"{key}#{idx}"
        normalized[key] = item
    return normalized


def _load_dataset() -> List[Dict[str, Any]]:
    samples = []
    with open(DATASET_PATH) as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def generate_prompts() -> None:
    samples = _load_dataset()
    PROMPTS_DIR.mkdir(parents=True, exist_ok=True)

    vuln_samples = [sample for sample in samples if sample.get("vulnerability_present", True)]
    print(f"Generating prompts for {len(vuln_samples)} vulnerable samples...")

    manifest = []
    for sample in vuln_samples:
        sample_id = sample["id"]
        code_ctx = sample.get("code", {}).get("source_to_sink") or sample.get("code", {}).get("full", "")
        diff = sample.get("code", {}).get("diff", "")

        user_prompt = (
            f"## Vulnerability Context\n"
            f"CVE: {sample['cve_id']}\n"
            f"CWE: {sample.get('cwe', '')}\n"
            f"Critical Variable: {sample.get('variable', '')}\n\n"
            f"## Source-to-Sink Code\n```c\n{code_ctx}\n```\n\n"
        )
        if diff:
            user_prompt += f"## Vulnerability-Fixing Diff\n```diff\n{diff}\n```\n\n"
        user_prompt += (
            "Identify the trigger statement — the exact statement where the "
            "critical variable causes an unsafe operation. Return JSON only."
        )

        prompt_file = PROMPTS_DIR / f"{sample_id}.json"
        with open(prompt_file, "w") as f:
            json.dump({
                "id": sample_id,
                "cve_id": sample["cve_id"],
                "variable": sample.get("variable", ""),
                "system": SYSTEM_PROMPT,
                "user": user_prompt,
            }, f, indent=2)

        manifest.append({
            "id": sample_id,
            "cve_id": sample["cve_id"],
            "variable": sample.get("variable", ""),
            "file": prompt_file.name,
        })

    with open(PROMPTS_DIR / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"Wrote {len(manifest)} prompts to {PROMPTS_DIR}/")


def _build_gt_from_dataset(samples: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    gt = {}
    for sample in samples:
        sample_id = sample["id"]
        trigger = sample.get("vulnerability", {}).get("trigger") or sample.get("trigger") or {}
        sink = sample.get("dataflow", {}).get("sink") or {}
        call_chain = sample.get("context", {}).get("call_chain") or []
        gt[sample_id] = {
            "sample_id": sample_id,
            "cve_id": sample["cve_id"],
            "variable": sample.get("variable", ""),
            "gt_function": trigger.get("function") or sink.get("function", ""),
            "gt_line": trigger.get("line") or sink.get("line", 0),
            "gt_statement": trigger.get("statement") or sink.get("statement", ""),
            "layers": max(len(call_chain), 1),
            "interprocedural": sample.get("context", {}).get("interprocedural", False),
        }
    return gt


def _normalize(text: str) -> str:
    return re.sub(r"\s+", "", str(text).strip()).rstrip(";").lower()


def _func_match(gt_function: str, pred_function: str) -> bool:
    gt_name = gt_function.strip().split("(")[0].strip() if gt_function else ""
    pred_name = pred_function.strip().split("(")[0].strip() if pred_function else ""
    return bool(gt_name and pred_name and gt_name == pred_name)


def _line_match(gt_line: Any, pred_line: Any) -> bool:
    try:
        return bool(gt_line and pred_line and int(gt_line) == int(pred_line))
    except (TypeError, ValueError):
        return False


def _stmt_match(gt_statement: str, pred_statement: str) -> bool:
    gt_norm = _normalize(gt_statement)
    pred_norm = _normalize(pred_statement)
    return bool(gt_norm and pred_norm and (gt_norm in pred_norm or pred_norm in gt_norm))


def _evaluate_predictions(
    name: str,
    predictions: Iterable[Dict[str, Any]],
    gt: Dict[str, Dict[str, Any]],
    allowed_ids: Optional[Set[str]] = None,
    skip_empty: bool = True,
) -> Dict[str, Any]:
    func_correct = 0
    line_correct = 0
    stmt_correct = 0
    cross_correct = 0
    cross_total = 0
    total = 0
    skipped_empty = 0

    for prediction in predictions:
        sample_id = prediction.get("id", "")
        if sample_id not in gt:
            continue
        if allowed_ids is not None and sample_id not in allowed_ids:
            continue

        pred_function = prediction.get("pred_function") or prediction.get("trigger_function", "")
        pred_line = prediction.get("pred_line") or prediction.get("trigger_line", 0)
        pred_statement = prediction.get("pred_statement") or prediction.get("trigger_statement", "")

        is_empty = (
            bool(prediction.get("parse_error"))
            or (not str(pred_function).strip() and not str(pred_statement).strip() and not pred_line)
        )
        if skip_empty and is_empty:
            skipped_empty += 1
            continue

        item_gt = gt[sample_id]
        total += 1

        func_ok = _func_match(item_gt["gt_function"], pred_function)
        line_ok = _line_match(item_gt["gt_line"], pred_line)
        stmt_ok = _stmt_match(item_gt["gt_statement"], pred_statement)

        func_correct += int(func_ok)
        line_correct += int(line_ok)
        stmt_correct += int(stmt_ok)

        if item_gt["layers"] >= 2:
            cross_total += 1
            cross_correct += int(func_ok)

    return {
        "model": name,
        "total": total,
        "skipped_empty": skipped_empty,
        "func_hit": func_correct,
        "func_hit_pct": func_correct / total * 100 if total else 0.0,
        "exact_line": line_correct,
        "exact_line_pct": line_correct / total * 100 if total else 0.0,
        "exact_stmt": stmt_correct,
        "exact_stmt_pct": stmt_correct / total * 100 if total else 0.0,
        "cross_func_total": cross_total,
        "cross_func_correct": cross_correct,
        "cross_func_pct": cross_correct / cross_total * 100 if cross_total else 0.0,
    }


def collect_autotrace_predictions(results_dir: Path, samples: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_cve: Dict[str, Dict[str, Any]] = {}
    for sample in samples:
        by_cve.setdefault(sample["cve_id"], {})

    for cve_id in by_cve:
        trigger_path = results_dir / cve_id / "triggers.json"
        if not trigger_path.exists():
            by_cve[cve_id] = {}
            continue
        with open(trigger_path) as f:
            by_cve[cve_id] = _normalize_trigger_map(json.load(f) or {})

    predictions: List[Dict[str, Any]] = []
    for sample in samples:
        trigger_map = by_cve.get(sample["cve_id"], {})
        variable = sample.get("variable", "")
        trigger = trigger_map.get(variable)

        if not isinstance(trigger, dict):
            for candidate in trigger_map.values():
                if not isinstance(candidate, dict):
                    continue
                if candidate.get("cv_logical_name") == variable or candidate.get("variable") == variable:
                    trigger = candidate
                    break

        if not isinstance(trigger, dict):
            continue

        predictions.append({
            "id": sample["id"],
            "pred_function": trigger.get("trigger_function", ""),
            "pred_line": trigger.get("trigger_line", 0),
            "pred_statement": trigger.get("trigger_code", ""),
        })

    return predictions


def evaluate_responses(
    responses_dir: Path,
    results_dir: Path,
    latex: bool = False,
) -> Dict[str, Any]:
    samples = _load_dataset()
    vuln_samples = [sample for sample in samples if sample.get("vulnerability_present", True)]
    gt = _build_gt_from_dataset(vuln_samples)

    autotrace_predictions = collect_autotrace_predictions(results_dir, vuln_samples)
    autotrace_ids = {prediction["id"] for prediction in autotrace_predictions}
    allowed_ids: Optional[Set[str]] = autotrace_ids or None

    all_results: Dict[str, Dict[str, Any]] = {}
    if autotrace_predictions:
        all_results["AutoTrace"] = _evaluate_predictions("AutoTrace", autotrace_predictions, gt, allowed_ids=allowed_ids)

    model_dirs: List[Path] = []
    if responses_dir.exists():
        model_dirs = sorted([path for path in responses_dir.iterdir() if path.is_dir()])
    else:
        print(f"WARNING: responses directory not found: {responses_dir}")

    for model_dir in model_dirs:
        prediction_file = model_dir / "predictions.jsonl"
        if not prediction_file.exists():
            print(f"  SKIP {model_dir.name}: no predictions.jsonl")
            continue

        predictions = []
        with open(prediction_file) as f:
            for line in f:
                line = line.strip()
                if line:
                    predictions.append(json.loads(line))

        all_results[model_dir.name] = _evaluate_predictions(
            model_dir.name,
            predictions,
            gt,
            allowed_ids=allowed_ids,
        )

    ordered_names = ["AutoTrace"] + sorted(name for name in all_results if name != "AutoTrace")
    headers = ["Model", "N", FUNC_HIT_LABEL, "ExactLine", "ExactStmt", "Layer≥2"]
    rows = []
    for name in ordered_names:
        result = all_results.get(name)
        if not result:
            continue
        rows.append([
            name,
            str(result["total"]),
            f"{result['func_hit_pct']:.1f}%",
            f"{result['exact_line_pct']:.1f}%",
            f"{result['exact_stmt_pct']:.1f}%",
            f"{result['cross_func_pct']:.1f}%",
        ])
    print_summary_table("RQ3.1: AutoTrace vs LLMs on SinkTrace-Bench", headers, rows)

    if allowed_ids is not None:
        print(f"Compared on the shared subset with AutoTrace coverage: {len(allowed_ids)} samples.")
    if not model_dirs:
        print("No LLM response directories were found; reported comparison currently includes AutoTrace only.")

    if latex:
        tex_rows = []
        for name in ordered_names:
            result = all_results.get(name)
            if not result:
                continue
            tex_rows.append([
                name.replace("_", " "),
                fmt_pct(result["func_hit_pct"], bold=name == "AutoTrace"),
                fmt_pct(result["exact_line_pct"], bold=name == "AutoTrace"),
                fmt_pct(result["exact_stmt_pct"], bold=name == "AutoTrace"),
                fmt_pct(result["cross_func_pct"], bold=name == "AutoTrace"),
            ])
        print("\n" + latex_table(
            "AutoTrace and state-of-the-art LLMs on SinkTrace-Bench. LLM baselines receive only textual context and no analysis tools.",
            "tab:rq5_llm_comparison",
            ["Model", FUNC_HIT_LABEL, "ExactLine", "ExactStmt", r"Layer$\geq$2"],
            tex_rows,
        ))

    return {
        "results": all_results,
        "shared_subset_size": len(allowed_ids) if allowed_ids is not None else len(gt),
    }


def main() -> None:
    parser = standard_argparser("RQ3.1: AutoTrace vs State-of-the-Art LLMs on SinkTrace-Bench")
    parser.add_argument("--generate", action="store_true", help="Generate prompts from dataset/train.jsonl")
    parser.add_argument("--evaluate", action="store_true", help="Evaluate AutoTrace and model responses")
    parser.add_argument(
        "--responses-dir",
        "--response-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "responses",
        help="Directory with model response subdirectories (alias: --response-dir)",
    )
    args = parser.parse_args()

    if args.generate:
        generate_prompts()
        return

    if args.evaluate:
        results = evaluate_responses(args.responses_dir, args.results_dir, latex=args.latex)
        output_path = args.output or (OUTPUT_DIR / "rq3_1_sinktrace_report.json")
        save_json_report({
            "rq": "RQ3_1",
            "shared_subset_size": results["shared_subset_size"],
            "models": results["results"],
        }, output_path)
        return

    print("Usage: python evaluation/RQ3_1_sinktrace_benchmark.py --generate")
    print("   or: python evaluation/RQ3_1_sinktrace_benchmark.py --evaluate --responses-dir <dir>")


if __name__ == "__main__":
    main()
