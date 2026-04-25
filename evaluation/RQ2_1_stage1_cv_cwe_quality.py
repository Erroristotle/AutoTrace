#!/usr/bin/env python3
"""
RQ2.1: Stage-1 CV Extraction and CWE Quality
============================================

Ground truth: data/interpvd/InterPVD_Sheet1_processed.json  (InterPVD dataset)

Metrics
-------
  1. CV Recall (exact)   — any extracted CV name matches a GT critical variable
  2. CV Recall (fuzzy)   — substring match (handles partial variable names)
  3. CWE Accuracy        — consensus predicted CWE == GT CWE ID
  4. CWE → Trigger corr  — does CWE accuracy predict trigger match quality?

Per-CWE-family breakdown + LaTeX table.

Usage:
    python evaluation/RQ2_1_stage1_cv_cwe_quality.py
    python evaluation/RQ2_1_stage1_cv_cwe_quality.py --output evaluation/output/agent1_report.json
    python evaluation/RQ2_1_stage1_cv_cwe_quality.py --latex
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (  # noqa: E402
    OUTPUT_DIR,
    AgentSliceEvaluator,
    FUNC_HIT_LABEL,
    GT_FUNC_HIT_LABEL,
    best_per_cve,
    collect_vultrigger_exact_hits,
    cwe_family,
    eligible_autotrace_cves,
    fmt_pct,
    latex_table,
    print_summary_table,
    save_json_report,
    standard_argparser,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_ROOT / "results"
GT_PATH = PROJECT_ROOT / "data" / "interpvd" / "InterPVD_Sheet1_processed.json"


# ---------------------------------------------------------------------------
# GT loading  (InterPVD format)
# ---------------------------------------------------------------------------

def load_gt(gt_path: Path) -> Dict[str, Dict]:
    """Load InterPVD GT, one entry per CVE (last wins on duplicate CVE IDs)."""
    with open(gt_path) as f:
        data = json.load(f)
    gt: Dict[str, Dict] = {}
    for entry in data:
        cve = entry.get("CVE ID", "").strip()
        if cve:
            gt[cve] = entry
    return gt


# ---------------------------------------------------------------------------
# Result loading
# ---------------------------------------------------------------------------

def load_result(cve_dir: Path) -> Optional[Dict]:
    p = cve_dir / "result.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def load_triggers(cve_dir: Path) -> Dict:
    p = cve_dir / "triggers.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# CWE consensus from per-CV predictions
# ---------------------------------------------------------------------------

def consensus_cwe(llm_cvs: List[Dict]) -> Optional[str]:
    """Majority-voted predicted CWE across all extracted CVs."""
    if not llm_cvs:
        return None
    cwe_votes = Counter(
        c.get("predicted_cwe", "").strip()
        for c in llm_cvs
        if c.get("predicted_cwe", "").strip()
    )
    if not cwe_votes:
        return None
    top, _ = cwe_votes.most_common(1)[0]
    return top


def normalize_cwe(raw: str) -> str:
    m = re.search(r"CWE-\d+", str(raw).upper())
    return m.group(0) if m else ""


# ---------------------------------------------------------------------------
# CV recall helpers
# ---------------------------------------------------------------------------

def normalize_varname(v: str) -> str:
    return v.strip().lower().lstrip("*").lstrip("&")


def cv_recall_exact(gt_variables: List[str], llm_cvs: List[Dict]) -> bool:
    """True if ANY extracted CV name exactly matches ANY GT critical variable."""
    if not gt_variables or not llm_cvs:
        return False
    gt_norms = {normalize_varname(v) for v in gt_variables if v}
    for cv in llm_cvs:
        if normalize_varname(cv.get("name", "")) in gt_norms:
            return True
    return False


def cv_recall_fuzzy(gt_variables: List[str], llm_cvs: List[Dict]) -> bool:
    """True if any extracted CV name is a substring of (or contains) a GT variable."""
    if not gt_variables or not llm_cvs:
        return False
    gt_norms = [normalize_varname(v) for v in gt_variables if v]
    for cv in llm_cvs:
        name = normalize_varname(cv.get("name", ""))
        if not name:
            continue
        for gt_v in gt_norms:
            if gt_v in name or name in gt_v:
                return True
    return False


def matched_gt_vars(gt_variables: List[str], llm_cvs: List[Dict]) -> List[str]:
    """Return which GT variables were successfully extracted."""
    gt_norms = {normalize_varname(v): v for v in gt_variables if v}
    matched = []
    for cv in llm_cvs:
        norm = normalize_varname(cv.get("name", ""))
        if norm in gt_norms:
            matched.append(gt_norms[norm])
    return matched


# ---------------------------------------------------------------------------
# Trigger match helper (for CWE-correlation analysis)
# ---------------------------------------------------------------------------

def _normalize(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower())


def _parse_gt_lines(raw) -> List[int]:
    """Parse GT line numbers — can be int, list, or str."""
    if raw is None:
        return []
    if isinstance(raw, int):
        return [raw]
    if isinstance(raw, float):
        return [int(raw)]
    if isinstance(raw, list):
        out = []
        for v in raw:
            try:
                out.append(int(v))
            except (TypeError, ValueError):
                pass
        return out
    try:
        return [int(str(raw).strip())]
    except (TypeError, ValueError):
        return []


def _gt_trigger_matched(gt_entry: Dict, triggers_data: Dict) -> bool:
    """
    Check if the GT trigger is found anywhere in all_triggers.

    Match logic (in priority order):
    1. Exact line: trigger_line in GT line numbers
    2. Statement: any GT statement is a substring of trigger_code
       (handles incorrect GT line numbers)
    3. Function + operation: trigger_function == GT function AND operation in code
    """
    gt_lines = set(_parse_gt_lines(gt_entry.get("Vulnerability-triggered line numbers")))
    gt_stmts = [
        _normalize(s)
        for s in (gt_entry.get("Vulnerability-triggered statements") or [])
        if s
    ]
    gt_func = _normalize(gt_entry.get("Vulnerability-triggered function") or "")

    if isinstance(triggers_data, dict):
        _iter = triggers_data.values()
    elif isinstance(triggers_data, list):
        _iter = triggers_data
    else:
        _iter = []
    for trig_obj in _iter:
        if not isinstance(trig_obj, dict):
            continue
        for at in trig_obj.get("all_triggers", []):
            pred_line = at.get("trigger_line")
            pred_code = _normalize(at.get("trigger_code") or "")
            pred_func = _normalize(at.get("trigger_function") or "")

            # 1. Exact line
            if gt_lines and pred_line is not None:
                try:
                    if int(pred_line) in gt_lines:
                        return True
                except (TypeError, ValueError):
                    pass
            # 2. GT statement in trigger_code
            for gs in gt_stmts:
                if gs and gs in pred_code:
                    return True
            # 3. Function + operation
            if gt_func and pred_func == gt_func and pred_code:
                op = _normalize(at.get("operation") or "")
                if op and op in pred_code:
                    return True
    return False


def build_downstream_hit_map(
    evaluator: AgentSliceEvaluator,
    eligible_cves: set[str],
) -> Dict[str, Dict[str, bool]]:
    """
    Build paper-aligned downstream trigger-localization outcomes per CVE.

    - VulnHit: exact GT line OR exact GT statement match across identified triggers
    - GTFuncHit: best-per-CVE predicted function exactly matches the GT trigger function
    - FuncHit: best-per-CVE predicted function matches the GT function under the
      shared RQ1 definition (`any_function_match`)
    """
    exact_hits = collect_vultrigger_exact_hits(evaluator)
    comparisons = [
        comp for comp in evaluator.compare_predictions()
        if comp.cve_id in eligible_cves
    ]
    best_map = best_per_cve(comparisons)

    downstream: Dict[str, Dict[str, bool]] = {}
    for cve_id in eligible_cves:
        best = best_map.get(cve_id)
        hit = exact_hits.get(cve_id, {})
        downstream[cve_id] = {
            "vuln_hit": bool(hit.get("exact_match", False)),
            "gt_func_hit": bool(getattr(best, "function_match", False)) if best is not None else False,
            "func_hit": bool(getattr(best, "any_function_match", False)) if best is not None else False,
        }
    return downstream


# ---------------------------------------------------------------------------
# Per-CVE record
# ---------------------------------------------------------------------------

def evaluate_cve(
    cve_id: str,
    gt_entry: Dict,
    result: Dict,
    triggers_data: Dict,
    downstream_hits: Optional[Dict[str, bool]] = None,
) -> Dict[str, Any]:
    llm_cvs = result.get("llm_cvs") or []
    gt_variables: List[str] = [
        v for v in (gt_entry.get("Critical variables") or []) if v
    ]
    gt_cwe = normalize_cwe(gt_entry.get("CWE ID") or "")
    pred_cwe = normalize_cwe(consensus_cwe(llm_cvs) or "")
    cwe_label_in_result = normalize_cwe(result.get("cwe_label") or "")

    n_cvs = len(llm_cvs)
    recall_exact = cv_recall_exact(gt_variables, llm_cvs)
    recall_fuzzy = cv_recall_fuzzy(gt_variables, llm_cvs)
    matched_vars = matched_gt_vars(gt_variables, llm_cvs)
    cwe_correct = bool(gt_cwe and pred_cwe and gt_cwe == pred_cwe)
    trigger_found = _gt_trigger_matched(gt_entry, triggers_data)
    vuln_hit = bool((downstream_hits or {}).get("vuln_hit", False))
    gt_func_hit = bool((downstream_hits or {}).get("gt_func_hit", False))
    func_hit = bool((downstream_hits or {}).get("func_hit", False))

    return {
        "cve_id": cve_id,
        "gt_variables": gt_variables,
        "gt_cwe": gt_cwe,
        "cwe_family": cwe_family(gt_cwe),
        "pred_cwe": pred_cwe,
        "cwe_label_in_result": cwe_label_in_result,
        "cwe_correct": cwe_correct,
        "n_cvs_extracted": n_cvs,
        "cv_exact_recall": recall_exact,
        "cv_fuzzy_recall": recall_fuzzy,
        "matched_gt_vars": matched_vars,
        "n_gt_vars": len(gt_variables),
        "trigger_found": trigger_found,
        "vuln_hit": vuln_hit,
        "gt_func_hit": gt_func_hit,
        "func_hit": func_hit,
        "extracted_cv_names": [c.get("name") for c in llm_cvs],
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(results_dir: Path, output_path: Optional[Path], emit_latex: bool) -> None:
    if not GT_PATH.exists():
        print(f"ERROR: GT not found at {GT_PATH}", file=sys.stderr)
        sys.exit(1)

    gt_map = load_gt(GT_PATH)

    evaluator = AgentSliceEvaluator(str(GT_PATH), str(results_dir))
    eligible_cves = set(eligible_autotrace_cves(evaluator))
    downstream_hit_map = build_downstream_hit_map(evaluator, eligible_cves)

    records: List[Dict] = []
    skipped = 0

    for cve_dir in sorted(results_dir.iterdir()):
        if not cve_dir.is_dir():
            continue
        cve_id = cve_dir.name
        if cve_id not in gt_map:
            skipped += 1
            continue
        if cve_id not in eligible_cves:
            skipped += 1
            continue
        result = load_result(cve_dir)
        if not result:
            skipped += 1
            continue
        triggers_data = load_triggers(cve_dir)
        rec = evaluate_cve(
            cve_id,
            gt_map[cve_id],
            result,
            triggers_data,
            downstream_hit_map.get(cve_id),
        )
        records.append(rec)

    if not records:
        print("No evaluable CVEs found.", file=sys.stderr)
        return

    n = len(records)

    # ---- Overall metrics ----
    cv_exact_n = sum(1 for r in records if r["cv_exact_recall"])
    cv_fuzzy_n = sum(1 for r in records if r["cv_fuzzy_recall"])
    cwe_correct_n = sum(1 for r in records if r["cwe_correct"])
    trig_found_n = sum(1 for r in records if r["trigger_found"])
    vuln_hit_n = sum(1 for r in records if r["vuln_hit"])
    gt_func_hit_n = sum(1 for r in records if r["gt_func_hit"])
    func_hit_n = sum(1 for r in records if r["func_hit"])
    avg_cvs = sum(r["n_cvs_extracted"] for r in records) / n
    avg_matched = sum(len(r["matched_gt_vars"]) for r in records) / n

    print(f"\n{'='*70}")
    print(f"  AGENT 1: CV Extraction + CWE Detection  ({n} CVEs, {skipped} skipped)")
    print(f"{'='*70}")
    print(f"  CV Recall (exact name match): {cv_exact_n}/{n} = {cv_exact_n/n*100:.1f}%")
    print(f"  CV Recall (fuzzy/substring):  {cv_fuzzy_n}/{n} = {cv_fuzzy_n/n*100:.1f}%")
    print(f"  Avg CVs extracted per CVE:    {avg_cvs:.2f}")
    print(f"  Avg GT vars matched per CVE:  {avg_matched:.2f}")
    print(f"  CWE Accuracy (consensus):     {cwe_correct_n}/{n} = {cwe_correct_n/n*100:.1f}%")
    print(f"  Trigger found (any match):    {trig_found_n}/{n} = {trig_found_n/n*100:.1f}%")
    print(f"  Downstream VulnHit:           {vuln_hit_n}/{n} = {vuln_hit_n/n*100:.1f}%")
    print(f"  Downstream {GT_FUNC_HIT_LABEL}:         {gt_func_hit_n}/{n} = {gt_func_hit_n/n*100:.1f}%")
    print(f"  Downstream {FUNC_HIT_LABEL}:            {func_hit_n}/{n} = {func_hit_n/n*100:.1f}%")
    print(f"  Skipped (no GT or result):    {skipped}")

    # ---- CWE Correlation ----
    cwe_ok = [r for r in records if r["cwe_correct"]]
    cwe_wrong = [r for r in records if not r["cwe_correct"]]
    trig_when_cwe_ok = sum(1 for r in cwe_ok if r["trigger_found"])
    trig_when_cwe_wrong = sum(1 for r in cwe_wrong if r["trigger_found"])
    vuln_when_cwe_ok = sum(1 for r in cwe_ok if r["vuln_hit"])
    vuln_when_cwe_wrong = sum(1 for r in cwe_wrong if r["vuln_hit"])
    gt_func_when_cwe_ok = sum(1 for r in cwe_ok if r["gt_func_hit"])
    gt_func_when_cwe_wrong = sum(1 for r in cwe_wrong if r["gt_func_hit"])
    func_when_cwe_ok = sum(1 for r in cwe_ok if r["func_hit"])
    func_when_cwe_wrong = sum(1 for r in cwe_wrong if r["func_hit"])
    cv_when_cwe_ok = sum(1 for r in cwe_ok if r["cv_exact_recall"])
    cv_when_cwe_wrong = sum(1 for r in cwe_wrong if r["cv_exact_recall"])

    print(f"\n  CWE Prediction → Downstream Impact:")
    print(f"    CWE correct ({len(cwe_ok):3d} CVEs):")
    print(f"      CV recall:      {cv_when_cwe_ok}/{len(cwe_ok) or 1} = "
          f"{cv_when_cwe_ok/(len(cwe_ok) or 1)*100:.1f}%")
    print(f"      Trigger found:  {trig_when_cwe_ok}/{len(cwe_ok) or 1} = "
          f"{trig_when_cwe_ok/(len(cwe_ok) or 1)*100:.1f}%")
    print(f"      VulnHit:        {vuln_when_cwe_ok}/{len(cwe_ok) or 1} = "
          f"{vuln_when_cwe_ok/(len(cwe_ok) or 1)*100:.1f}%")
    print(f"      {GT_FUNC_HIT_LABEL}:       {gt_func_when_cwe_ok}/{len(cwe_ok) or 1} = "
          f"{gt_func_when_cwe_ok/(len(cwe_ok) or 1)*100:.1f}%")
    print(f"      {FUNC_HIT_LABEL}:         {func_when_cwe_ok}/{len(cwe_ok) or 1} = "
          f"{func_when_cwe_ok/(len(cwe_ok) or 1)*100:.1f}%")
    print(f"    CWE wrong   ({len(cwe_wrong):3d} CVEs):")
    print(f"      CV recall:      {cv_when_cwe_wrong}/{len(cwe_wrong) or 1} = "
          f"{cv_when_cwe_wrong/(len(cwe_wrong) or 1)*100:.1f}%")
    print(f"      Trigger found:  {trig_when_cwe_wrong}/{len(cwe_wrong) or 1} = "
          f"{trig_when_cwe_wrong/(len(cwe_wrong) or 1)*100:.1f}%")
    print(f"      VulnHit:        {vuln_when_cwe_wrong}/{len(cwe_wrong) or 1} = "
          f"{vuln_when_cwe_wrong/(len(cwe_wrong) or 1)*100:.1f}%")
    print(f"      {GT_FUNC_HIT_LABEL}:       {gt_func_when_cwe_wrong}/{len(cwe_wrong) or 1} = "
          f"{gt_func_when_cwe_wrong/(len(cwe_wrong) or 1)*100:.1f}%")
    print(f"      {FUNC_HIT_LABEL}:         {func_when_cwe_wrong}/{len(cwe_wrong) or 1} = "
          f"{func_when_cwe_wrong/(len(cwe_wrong) or 1)*100:.1f}%")

    # ---- Per-CWE family breakdown ----
    family_data: Dict[str, Dict] = defaultdict(
        lambda: {
            "n": 0,
            "cwe_ok": 0,
            "cv_exact": 0,
            "cv_fuzzy": 0,
            "trig_found": 0,
            "vuln_hit": 0,
            "gt_func_hit": 0,
            "func_hit": 0,
        }
    )
    for r in records:
        fam = r["cwe_family"]
        family_data[fam]["n"] += 1
        if r["cwe_correct"]:
            family_data[fam]["cwe_ok"] += 1
        if r["cv_exact_recall"]:
            family_data[fam]["cv_exact"] += 1
        if r["cv_fuzzy_recall"]:
            family_data[fam]["cv_fuzzy"] += 1
        if r["trigger_found"]:
            family_data[fam]["trig_found"] += 1
        if r["vuln_hit"]:
            family_data[fam]["vuln_hit"] += 1
        if r["gt_func_hit"]:
            family_data[fam]["gt_func_hit"] += 1
        if r["func_hit"]:
            family_data[fam]["func_hit"] += 1

    rows = []
    for fam in sorted(family_data.keys()):
        fd = family_data[fam]
        fn = fd["n"]
        rows.append([
            fam,
            str(fn),
            f"{fd['cv_exact']}/{fn} ({fd['cv_exact']/fn*100:.0f}%)",
            f"{fd['cwe_ok']}/{fn} ({fd['cwe_ok']/fn*100:.0f}%)",
            f"{fd['trig_found']}/{fn} ({fd['trig_found']/fn*100:.0f}%)",
            f"{fd['vuln_hit']}/{fn} ({fd['vuln_hit']/fn*100:.0f}%)",
            f"{fd['gt_func_hit']}/{fn} ({fd['gt_func_hit']/fn*100:.0f}%)",
            f"{fd['func_hit']}/{fn} ({fd['func_hit']/fn*100:.0f}%)",
        ])

    print_summary_table(
        "Per-CWE Family Breakdown",
        ["Family", "CVEs", "CV Recall", "CWE Acc.", "Trig Found", "VulnHit", GT_FUNC_HIT_LABEL, FUNC_HIT_LABEL],
        rows,
    )

    # ---- CWE confusion: what wrong CWE does the model predict? ----
    wrong_preds = Counter(
        (r["gt_cwe"], r["pred_cwe"])
        for r in records
        if not r["cwe_correct"] and r["pred_cwe"]
    )
    if wrong_preds:
        print("  Most common CWE mispredictions (gt → pred):")
        for (gt_c, pred_c), cnt in wrong_preds.most_common(8):
            print(f"    {gt_c} → {pred_c}: {cnt}")

    # ---- LaTeX ----
    if emit_latex:
        latex_rows = [
            [
                fam,
                str(family_data[fam]["n"]),
                fmt_pct(family_data[fam]["cv_exact"] / (family_data[fam]["n"] or 1) * 100),
                fmt_pct(family_data[fam]["cwe_ok"] / (family_data[fam]["n"] or 1) * 100),
                fmt_pct(family_data[fam]["trig_found"] / (family_data[fam]["n"] or 1) * 100),
                fmt_pct(family_data[fam]["vuln_hit"] / (family_data[fam]["n"] or 1) * 100),
                fmt_pct(family_data[fam]["gt_func_hit"] / (family_data[fam]["n"] or 1) * 100),
                fmt_pct(family_data[fam]["func_hit"] / (family_data[fam]["n"] or 1) * 100),
            ]
            for fam in sorted(family_data.keys())
        ]
        print(latex_table(
            caption="Agent 1: CV Extraction and CWE Detection Accuracy per CWE Family",
            label="tab:agent1_cwe_family",
            headers=["CWE Family", "CVEs", "CV Recall", "CWE Acc.", "Trig Found", "VulnHit", GT_FUNC_HIT_LABEL, FUNC_HIT_LABEL],
            rows=latex_rows,
        ))

    # ---- Save report ----
    report = {
        "summary": {
            "n_cves": n,
            "skipped": skipped,
            "cv_exact_recall": cv_exact_n,
            "cv_exact_recall_pct": cv_exact_n / n * 100,
            "cv_fuzzy_recall": cv_fuzzy_n,
            "cv_fuzzy_recall_pct": cv_fuzzy_n / n * 100,
            "avg_cvs_extracted": avg_cvs,
            "cwe_correct": cwe_correct_n,
            "cwe_accuracy_pct": cwe_correct_n / n * 100,
            "trigger_found": trig_found_n,
            "trigger_found_pct": trig_found_n / n * 100,
            "vuln_hit": vuln_hit_n,
            "vuln_hit_pct": vuln_hit_n / n * 100,
            "gt_func_hit": gt_func_hit_n,
            "gt_func_hit_pct": gt_func_hit_n / n * 100,
            "func_hit": func_hit_n,
            "func_hit_pct": func_hit_n / n * 100,
        },
        "cwe_correlation": {
            "cwe_correct_cves": len(cwe_ok),
            "cv_when_cwe_correct_pct": cv_when_cwe_ok / (len(cwe_ok) or 1) * 100,
            "trig_when_cwe_correct_pct": trig_when_cwe_ok / (len(cwe_ok) or 1) * 100,
            "vuln_when_cwe_correct_pct": vuln_when_cwe_ok / (len(cwe_ok) or 1) * 100,
            "gt_func_when_cwe_correct_pct": gt_func_when_cwe_ok / (len(cwe_ok) or 1) * 100,
            "func_when_cwe_correct_pct": func_when_cwe_ok / (len(cwe_ok) or 1) * 100,
            "cwe_wrong_cves": len(cwe_wrong),
            "cv_when_cwe_wrong_pct": cv_when_cwe_wrong / (len(cwe_wrong) or 1) * 100,
            "trig_when_cwe_wrong_pct": trig_when_cwe_wrong / (len(cwe_wrong) or 1) * 100,
            "vuln_when_cwe_wrong_pct": vuln_when_cwe_wrong / (len(cwe_wrong) or 1) * 100,
            "gt_func_when_cwe_wrong_pct": gt_func_when_cwe_wrong / (len(cwe_wrong) or 1) * 100,
            "func_when_cwe_wrong_pct": func_when_cwe_wrong / (len(cwe_wrong) or 1) * 100,
        },
        "per_family": {
            fam: {
                "n": fd["n"],
                "cv_exact_pct": fd["cv_exact"] / fd["n"] * 100,
                "cwe_acc_pct": fd["cwe_ok"] / fd["n"] * 100,
                "trig_found_pct": fd["trig_found"] / fd["n"] * 100,
                "vuln_hit_pct": fd["vuln_hit"] / fd["n"] * 100,
                "gt_func_hit_pct": fd["gt_func_hit"] / fd["n"] * 100,
                "func_hit_pct": fd["func_hit"] / fd["n"] * 100,
            }
            for fam, fd in family_data.items()
        },
        "per_cve": records,
    }

    out = output_path or OUTPUT_DIR / "agent1_report.json"
    save_json_report(report, out)


def main() -> None:
    p = standard_argparser("RQ2.1: CV Extraction and CWE Detection Quality")
    args = p.parse_args()
    run(args.results_dir, args.output, args.latex)


if __name__ == "__main__":
    main()
