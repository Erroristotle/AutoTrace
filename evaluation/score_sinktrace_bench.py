#!/usr/bin/env python3
"""
Score all SinkTrace-Bench model results against the full 2,481-sample dataset.
Merges all result files per model, deduplicates by ID (latest timestamp wins),
then computes macro-averaged Accuracy, Precision, Recall, F1.
"""
from __future__ import annotations

import glob
import json
from pathlib import Path
from collections import defaultdict

REPO = Path(__file__).resolve().parent.parent
DATASET = REPO / "dataset" / "train.jsonl"
HF_DIR  = REPO / "logs" / "hf_benchmark"
GEM_DIR = REPO / "logs" / "gemini_benchmark"

MODEL_GLOBS = {
    "Gemini-3-Flash":    [str(GEM_DIR / "results_*.jsonl")],
    "GLM-4.7-Flash":     [str(HF_DIR / "results_zai_org_GLM_4.7_Flash_*.jsonl")],
    "Qwen3-Coder-Next":  [str(HF_DIR / "results_Qwen_Qwen3_Coder_Next_*.jsonl")],
    "Qwen3.5-9B":        [str(HF_DIR / "results_Qwen_Qwen3.5_9B_*.jsonl")],
    "DeepSeek-R1-8B":    [str(HF_DIR / "results_deepseek_ai_DeepSeek_R1_Distill_Llama_8B_*.jsonl")],
}

def load_dataset_ids() -> set[str]:
    ids = set()
    with open(DATASET) as f:
        for line in f:
            line = line.strip()
            if line:
                ids.add(json.loads(line)["id"])
    return ids

def load_model_results(globs: list[str]) -> dict[str, dict]:
    """Merge all result files, keeping latest timestamp per ID."""
    by_id: dict[str, dict] = {}
    for pattern in globs:
        for path in sorted(glob.glob(pattern)):
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    rid = rec.get("id")
                    if not rid:
                        continue
                    existing = by_id.get(rid)
                    if existing is None or rec.get("timestamp", "") >= existing.get("timestamp", ""):
                        by_id[rid] = rec
    return by_id

def is_valid_pred(pred: str) -> bool:
    return pred in ("Vulnerable", "Safe")

def compute_metrics(results: dict[str, dict], valid_ids: set[str]) -> dict:
    tp = fp = tn = fn = 0
    covered = 0
    errors = 0
    for rid in valid_ids:
        rec = results.get(rid)
        if rec is None:
            continue
        pred  = rec.get("pred", "")
        truth = rec.get("truth", "")
        if not is_valid_pred(pred):
            errors += 1
            continue
        covered += 1
        pos_pred  = pred  == "Vulnerable"
        pos_truth = truth == "Vulnerable"
        if pos_pred and pos_truth:     tp += 1
        elif pos_pred and not pos_truth: fp += 1
        elif not pos_pred and pos_truth: fn += 1
        else:                            tn += 1

    total = tp + fp + tn + fn
    acc   = (tp + tn) / total * 100 if total else 0.0

    prec_v  = tp / (tp + fp) * 100 if (tp + fp) else 0.0
    rec_v   = tp / (tp + fn) * 100 if (tp + fn) else 0.0
    f1_v    = 2 * prec_v * rec_v / (prec_v + rec_v) if (prec_v + rec_v) else 0.0

    prec_s  = tn / (tn + fn) * 100 if (tn + fn) else 0.0
    rec_s   = tn / (tn + fp) * 100 if (tn + fp) else 0.0
    f1_s    = 2 * prec_s * rec_s / (prec_s + rec_s) if (prec_s + rec_s) else 0.0

    macro_prec = (prec_v + prec_s) / 2
    macro_rec  = (rec_v  + rec_s)  / 2
    macro_f1   = (f1_v   + f1_s)   / 2

    return {
        "n": total, "covered": covered, "errors": errors,
        "acc": round(acc, 1),
        "prec": round(macro_prec, 1),
        "rec":  round(macro_rec,  1),
        "f1":   round(macro_f1,   1),
    }

def main():
    valid_ids = load_dataset_ids()
    print(f"Dataset: {len(valid_ids)} samples\n")

    results = {}
    for model, globs in MODEL_GLOBS.items():
        recs = load_model_results(globs)
        m = compute_metrics(recs, valid_ids)
        results[model] = m
        print(f"{model:25s}  N={m['n']:5d}  Acc={m['acc']:5.1f}  "
              f"Prec={m['prec']:5.1f}  Rec={m['rec']:5.1f}  F1={m['f1']:5.1f}  "
              f"(errors={m['errors']})")

    # Save for chart
    out = Path(__file__).parent / "output" / "sinktrace_bench_scores.json"
    out.parent.mkdir(exist_ok=True)
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved: {out}")

if __name__ == "__main__":
    main()
