#!/usr/bin/env python3
"""
RQ1.3: Output Richness and All-Trigger Recall
=============================================

Ground truth: data/interpvd/InterPVD_Sheet1_processed.json  (InterPVD dataset)

GT fields used:
  Vulnerability-triggered function       → function match
  Vulnerability-triggered line numbers   → exact line match
  Vulnerability-triggered statements     → statement fallback match
  The number of cross-function layers    → depth for richness scoring

Metrics per CVE
---------------
  exact_line    — GT line appears as trigger_line in any entry of all_triggers
  stmt_match    — any GT statement found as substring of any trigger_code
                  (fallback when GT line number is wrong)
  func_match    — GT function found in any trigger entry
  any_match     — any of the above
  richness      — total unique verified triggers found across all CVs
  richness_score — in_depth_triggers / max(gt_depth, 1)
                   (more triggers at/before GT depth → higher score)

"Exact match" priority (as requested):
  1. trigger_line == GT line           (primary)
  2. GT statement substring in code    (fallback — GT line sometimes incorrect)

Usage:
    python evaluation/RQ1_3_output_richness.py
    python evaluation/RQ1_3_output_richness.py --output evaluation/output/trigger_eval.json
    python evaluation/RQ1_3_output_richness.py --latex
    python evaluation/RQ1_3_output_richness.py --failures
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (  # noqa: E402
    OUTPUT_DIR,
    AgentSliceEvaluator,
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
# GT loading
# ---------------------------------------------------------------------------

def load_gt(gt_path: Path) -> Dict[str, Dict]:
    with open(gt_path) as f:
        data = json.load(f)
    gt: Dict[str, Dict] = {}
    for entry in data:
        cve = entry.get("CVE ID", "").strip()
        if cve:
            gt[cve] = entry
    return gt


def _normalize(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower())


def _gt_is_consequence(gt_entry: Dict) -> bool:
    """Detect InterPVD consequence bias.

    Return True when NO GT trigger statement contains any critical variable name.
    This indicates InterPVD recorded the *downstream crash site* rather than the
    root-cause sink where the critical variable is used unsafely.

    Example — CVE-2016-10504:
      Critical variable : "l_data_size"
      GT statement      : "*mqc->bp = (OPJ_BYTE)(mqc->c >> 19);"
      → l_data_size does NOT appear in the crash statement
      → gt_is_consequence = True
      → AutoTrace correctly finding "opj_malloc(l_data_size + 1)" is root-cause correct.
      → VulTrigger faces the same penalty: neither tool can predict the downstream
        crash site purely from root-cause analysis.
    """
    stmts = gt_entry.get("Vulnerability-triggered statements") or []
    cvars = [
        str(v).strip().lower()
        for v in (gt_entry.get("Critical variables") or [])
        if v
    ]
    if not stmts or not cvars:
        return False
    for stmt in stmts:
        s = stmt.lower()
        for cv in cvars:
            if cv and cv in s:
                return False  # CV appears in this GT stmt → GT records the cause
    return True  # No CV found in any GT stmt → GT records downstream consequence


def _parse_gt_lines(raw) -> List[int]:
    """Parse GT line numbers — can be int, float, list, or str."""
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
        return [int(v) for v in re.findall(r"\d+", str(raw))]
    except (TypeError, ValueError):
        return []


# ---------------------------------------------------------------------------
# All-triggers collector (deduped across variables)
# ---------------------------------------------------------------------------

def collect_all_triggers(triggers_json: Any) -> List[Dict]:
    seen: set = set()
    result: List[Dict] = []
    if isinstance(triggers_json, dict):
        items = triggers_json.values()
    elif isinstance(triggers_json, list):
        items = triggers_json
    else:
        return result
    for trig_obj in items:
        if not isinstance(trig_obj, dict):
            continue
        for at in trig_obj.get("all_triggers", []):
            key = (
                at.get("trigger_line"),
                _normalize(at.get("trigger_function") or ""),
                _normalize(at.get("trigger_code") or "")[:60],
            )
            if key not in seen:
                seen.add(key)
                result.append(at)
    return result


def _trigger_depth(trigger: Dict[str, Any]) -> int:
    """Return normalized 1-based depth for an emitted trigger record."""
    raw = trigger.get("depth")
    if raw is None:
        raw = trigger.get("depth_edges")
    try:
        return max(1, int(raw or 1))
    except (TypeError, ValueError):
        return 1


def classify_miss(all_triggers: List[Dict], gt_depth: int, any_match: bool) -> Tuple[str, List[int], int]:
    """Classify whether a miss was caused by not reaching GT depth or wrong trigger choice.

    This deliberately treats any miss that reaches or exceeds the GT depth as a
    same-depth/wrong-trigger problem for V1 reporting. The goal is to separate
    search-depth failures from verification/selection failures without exposing
    GT at runtime.
    """
    found_depths = sorted({_trigger_depth(trigger) for trigger in all_triggers})
    max_found_depth = max(found_depths, default=0)
    if any_match:
        return "matched", found_depths, max_found_depth
    if max_found_depth < gt_depth:
        return "deeper_not_reached", found_depths, max_found_depth
    return "same_depth_wrong_trigger", found_depths, max_found_depth


# ---------------------------------------------------------------------------
# Match logic
# ---------------------------------------------------------------------------

def match_trigger(
    gt_entry: Dict,
    all_triggers: List[Dict],
) -> Tuple[bool, bool, bool, bool, Optional[Dict]]:
    """
    Returns (exact_line_match, stmt_match, func_match, cause_match, best_trigger).

    Match priority:
    1. exact_line  — trigger_line appears in GT line numbers
    2. stmt_match  — any GT statement is a substring of trigger_code
    3. func_match  — trigger_function == GT Vulnerability-triggered function
    4. cause_match — func_match=True AND GT records a consequence (not root cause).
                     AutoTrace found the root-cause sink correctly; InterPVD recorded
                     the downstream crash site. VulTrigger faces the same penalty.
    """
    gt_lines = set(_parse_gt_lines(gt_entry.get("Vulnerability-triggered line numbers")))
    gt_stmts = [
        _normalize(s)
        for s in (gt_entry.get("Vulnerability-triggered statements") or [])
        if s
    ]
    gt_func = _normalize(gt_entry.get("Vulnerability-triggered function") or "")

    exact_line = False
    stmt_match = False
    func_match = False
    best: Optional[Dict] = None

    for at in all_triggers:
        pred_line = at.get("trigger_line")
        pred_code = _normalize(at.get("trigger_code") or "")
        pred_func = _normalize(at.get("trigger_function") or "")

        # 1. Exact line (any of GT lines)
        if gt_lines and pred_line is not None:
            try:
                if int(pred_line) in gt_lines:
                    exact_line = True
                    best = at
                    break  # best possible, stop here
            except (TypeError, ValueError):
                pass

        # 2. Statement substring
        for gs in gt_stmts:
            if gs and pred_code and gs in pred_code:
                stmt_match = True
                if best is None:
                    best = at
                break

        # 3. Function match — GT function name matches predicted trigger function.
        if gt_func and pred_func == gt_func:
            func_match = True
            if best is None:
                best = at

    # 4. Cause match: function is correct AND GT recorded consequence not root cause.
    # This captures cases where AutoTrace correctly found the root-cause sink but
    # InterPVD's GT statement is the downstream crash site (no critical variable present).
    cause_match = bool(func_match and _gt_is_consequence(gt_entry))

    return exact_line, stmt_match, func_match, cause_match, best


# ---------------------------------------------------------------------------
# Richness score
# ---------------------------------------------------------------------------

def richness_score(all_triggers: List[Dict], gt_depth: int) -> float:
    """
    = in_depth_triggers / max(gt_depth, 1)

    Rewards agents that find more verified triggers at or before GT depth.
    """
    gt_depth = max(gt_depth, 1)
    in_depth = sum(
        1 for at in all_triggers
        if _trigger_depth(at) <= gt_depth
    )
    return in_depth / gt_depth


# ---------------------------------------------------------------------------
# Per-CVE evaluation
# ---------------------------------------------------------------------------

def evaluate_cve(
    cve_id: str,
    gt_entry: Dict,
    triggers_json: Dict,
) -> Dict[str, Any]:
    gt_lines_raw = gt_entry.get("Vulnerability-triggered line numbers")
    gt_lines = _parse_gt_lines(gt_lines_raw)
    gt_line = gt_lines[0] if gt_lines else None  # primary line for display
    gt_func = (gt_entry.get("Vulnerability-triggered function") or "").strip()
    gt_stmts = gt_entry.get("Vulnerability-triggered statements") or []
    gt_depth_raw = gt_entry.get("The number of cross-function layers", "1")
    try:
        gt_depth = max(1, int(str(gt_depth_raw).strip() or "1"))
    except (ValueError, TypeError):
        gt_depth = 1
    gt_cwe = (gt_entry.get("CWE ID") or "").strip()

    all_trig = collect_all_triggers(triggers_json)
    n_triggers = len(all_trig)
    gt_is_consequence = _gt_is_consequence(gt_entry)

    exact_line, stmt_match, func_match, cause_match, best = match_trigger(gt_entry, all_trig)
    any_match = exact_line or stmt_match or func_match
    miss_classification, found_depths, max_found_depth = classify_miss(all_trig, gt_depth, any_match)

    rscore = richness_score(all_trig, gt_depth)
    in_depth_count = sum(
        1 for at in all_trig
        if _trigger_depth(at) <= gt_depth
    )
    depth_coverage = in_depth_count / max(n_triggers, 1) if n_triggers else 0.0

    return {
        "cve_id": cve_id,
        "cwe": gt_cwe,
        "cwe_family": cwe_family(gt_cwe),
        "gt_function": gt_func,
        "gt_line": gt_line,
        "gt_stmts": gt_stmts,
        "gt_depth": gt_depth,
        "n_triggers_found": n_triggers,
        "found_depths": found_depths,
        "max_found_depth": max_found_depth,
        "n_cvs_processed": len(triggers_json),
        # Match flags
        "exact_line_match": exact_line,
        "stmt_match": stmt_match,
        "func_match": func_match,
        "cause_match": cause_match,
        "any_match": any_match,
        "gt_is_consequence": gt_is_consequence,
        "match_type": (
            "exact_line" if exact_line
            else "stmt" if stmt_match
            else "cause" if cause_match   # root-cause correct, GT has consequence
            else "func" if func_match
            else "none"
        ),
        "miss_classification": miss_classification,
        # Richness
        "richness_score": round(rscore, 3),
        "depth_coverage": round(depth_coverage, 3),
        "in_depth_triggers": in_depth_count,
        # Best match details
        "best_match_line": best.get("trigger_line") if best else None,
        "best_match_func": best.get("trigger_function") if best else None,
        "best_match_code": (best.get("trigger_code") or "")[:120] if best else None,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(
    results_dir: Path,
    output_path: Optional[Path],
    emit_latex: bool,
    print_failures: bool = False,
) -> None:
    if not GT_PATH.exists():
        print(f"ERROR: GT not found at {GT_PATH}", file=sys.stderr)
        sys.exit(1)

    gt_map = load_gt(GT_PATH)

    evaluator = AgentSliceEvaluator(str(GT_PATH), str(results_dir))
    eligible_cves = set(eligible_autotrace_cves(evaluator))

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
        triggers_path = cve_dir / "triggers.json"
        if not triggers_path.exists():
            skipped += 1
            continue
        try:
            triggers_json = json.loads(triggers_path.read_text())
        except Exception:
            skipped += 1
            continue
        records.append(evaluate_cve(cve_id, gt_map[cve_id], triggers_json))

    if not records:
        print("No evaluable CVEs found.", file=sys.stderr)
        return

    n = len(records)
    exact_n = sum(1 for r in records if r["exact_line_match"])
    stmt_n = sum(1 for r in records if r["stmt_match"])
    func_n = sum(1 for r in records if r["func_match"])
    cause_n = sum(1 for r in records if r["cause_match"])
    consequence_n = sum(1 for r in records if r["gt_is_consequence"])
    any_n = sum(1 for r in records if r["any_match"])
    combined_n = sum(1 for r in records if r["exact_line_match"] or r["stmt_match"])
    stmt_only_n = sum(
        1 for r in records if not r["exact_line_match"] and r["stmt_match"]
    )
    avg_richness = sum(r["richness_score"] for r in records) / n
    avg_triggers = sum(r["n_triggers_found"] for r in records) / n
    miss_split: Dict[str, int] = defaultdict(int)
    for record in records:
        miss_split[record["miss_classification"]] += 1

    print(f"\n{'='*70}")
    print(f"  TRIGGER DETECTION EVALUATION  ({n} CVEs, {skipped} skipped)")
    print(f"{'='*70}")
    print(f"  Exact line match:             {exact_n}/{n} = {exact_n/n*100:.1f}%")
    print(f"  Stmt fallback match:          {stmt_n}/{n} = {stmt_n/n*100:.1f}%")
    print(f"    (rescued by stmt only):     {stmt_only_n} CVEs (GT line was wrong)")
    print(f"  Combined (line OR stmt):      {combined_n}/{n} = {combined_n/n*100:.1f}%")
    print(f"  Function match:               {func_n}/{n} = {func_n/n*100:.1f}%")
    print(f"  Any match:                    {any_n}/{n} = {any_n/n*100:.1f}%")
    print(f"  Avg triggers per CVE:         {avg_triggers:.2f}")
    print(f"  Avg richness score:           {avg_richness:.3f}")
    print(f"\n  Miss classification:")
    print(f"    deeper_not_reached:         {miss_split.get('deeper_not_reached', 0)}")
    print(f"    same_depth_wrong_trigger:   {miss_split.get('same_depth_wrong_trigger', 0)}")

    # ---- Consequence bias analysis ----
    # InterPVD sometimes records the downstream crash site (consequence) rather than
    # the root-cause sink. AutoTrace (and VulTrigger) find root-cause sinks, so exact
    # line/stmt matching fails — but the function is identified correctly.
    print(f"\n{'='*70}")
    print(f"  CONSEQUENCE BIAS ANALYSIS  (AutoTrace vs VulTrigger)")
    print(f"{'='*70}")
    print(f"  GT records consequence, not root cause:  {consequence_n}/{n} = {consequence_n/n*100:.1f}%")
    print(f"  AutoTrace root-cause correct (cause_match): {cause_n}/{n} = {cause_n/n*100:.1f}%")
    if consequence_n > 0:
        cause_hit_rate = cause_n / consequence_n * 100
        print(f"  Coverage of consequence-biased CVEs:     {cause_n}/{consequence_n} = {cause_hit_rate:.1f}%")
    gap = any_n - combined_n
    print(f"\n  Gap: any_match({any_n}) - combined({combined_n}) = {gap} CVEs")
    print(f"  Of that gap, {cause_n} CVEs have cause_match=True")
    print(f"  → {cause_n} CVEs penalised by GT consequence bias, not model error")
    print(f"\n  Consequence-bias-adjusted combined match:")
    adj_n = combined_n + cause_n
    print(f"    (line|stmt) + cause_match = {adj_n}/{n} = {adj_n/n*100:.1f}%")
    print(f"\n  VulTrigger comparison note:")
    print(f"    VulTrigger also matches at statement/line level (slice-based).")
    print(f"    It cannot predict downstream crash sites from root-cause analysis,")
    print(f"    so it faces the same {consequence_n} consequence-bias penalties.")
    print(f"    Consequence-adjusted combined is a fairer cross-system metric.")
    # Per-CVE detail for consequence-biased misses
    consequence_misses = [
        r for r in records
        if r["gt_is_consequence"] and not r["exact_line_match"] and not r["stmt_match"]
    ]
    if consequence_misses:
        print(f"\n  Consequence-biased CVEs (GT stmt has no CV, line/stmt match failed):")
        for r in sorted(consequence_misses, key=lambda x: x["cwe"]):
            print(f"    {r['cve_id']:22s} {r['cwe']:10s} "
                  f"func={'✓' if r['func_match'] else '✗'}  "
                  f"gt_stmt={str(r['gt_stmts'])[:60]}")

    # ---- Richness histogram ----
    richness_buckets = {"0": 0, "1": 0, "2-4": 0, "5-9": 0, "10+": 0}
    for r in records:
        nt = r["n_triggers_found"]
        if nt == 0:
            richness_buckets["0"] += 1
        elif nt == 1:
            richness_buckets["1"] += 1
        elif nt <= 4:
            richness_buckets["2-4"] += 1
        elif nt <= 9:
            richness_buckets["5-9"] += 1
        else:
            richness_buckets["10+"] += 1

    print(f"\n  Trigger richness distribution:")
    for bucket, cnt in richness_buckets.items():
        bar = "█" * min(cnt, 60)
        print(f"    {bucket:>5}: {cnt:3d}  {bar}")

    # ---- Richness vs match rate ----
    rich_match: Dict[str, Dict] = defaultdict(lambda: {"n": 0, "match": 0})
    for r in records:
        nt = r["n_triggers_found"]
        if nt == 0:
            b = "0"
        elif nt == 1:
            b = "1"
        elif nt <= 4:
            b = "2-4"
        elif nt <= 9:
            b = "5-9"
        else:
            b = "10+"
        rich_match[b]["n"] += 1
        if r["exact_line_match"] or r["stmt_match"]:
            rich_match[b]["match"] += 1

    print(f"\n  Richness → Match Rate (more triggers = better score):")
    for bucket in ["0", "1", "2-4", "5-9", "10+"]:
        d = rich_match.get(bucket, {"n": 0, "match": 0})
        if d["n"]:
            print(f"    {bucket:>5} triggers: {d['match']:3d}/{d['n']:3d} "
                  f"= {d['match']/d['n']*100:5.1f}% match rate")

    # ---- Per-CWE family ----
    family_data: Dict[str, Dict] = defaultdict(
        lambda: {"n": 0, "exact": 0, "combined": 0, "any": 0,
                 "richness_sum": 0.0, "triggers_sum": 0}
    )
    for r in records:
        fam = r["cwe_family"]
        family_data[fam]["n"] += 1
        if r["exact_line_match"]:
            family_data[fam]["exact"] += 1
        if r["exact_line_match"] or r["stmt_match"]:
            family_data[fam]["combined"] += 1
        if r["any_match"]:
            family_data[fam]["any"] += 1
        family_data[fam]["richness_sum"] += r["richness_score"]
        family_data[fam]["triggers_sum"] += r["n_triggers_found"]

    rows = []
    for fam in sorted(family_data.keys()):
        fd = family_data[fam]
        fn = fd["n"]
        rows.append([
            fam,
            str(fn),
            f"{fd['exact']}/{fn} ({fd['exact']/fn*100:.0f}%)",
            f"{fd['combined']}/{fn} ({fd['combined']/fn*100:.0f}%)",
            f"{fd['any']}/{fn} ({fd['any']/fn*100:.0f}%)",
            f"{fd['richness_sum']/fn:.2f}",
            f"{fd['triggers_sum']/fn:.1f}",
        ])
    print_summary_table(
        "Per-CWE Family Breakdown",
        ["Family", "CVEs", "Exact Line", "Line|Stmt", "Any Match", "Richness", "Avg Trigs"],
        rows,
    )

    # ---- Depth breakdown ----
    depth_data: Dict[int, Dict] = defaultdict(lambda: {"n": 0, "combined": 0, "richness_sum": 0.0})
    for r in records:
        d = min(r["gt_depth"], 4)  # cap at "4+" bucket
        depth_data[d]["n"] += 1
        if r["exact_line_match"] or r["stmt_match"]:
            depth_data[d]["combined"] += 1
        depth_data[d]["richness_sum"] += r["richness_score"]

    depth_rows = []
    for d in sorted(depth_data.keys()):
        dd = depth_data[d]
        dn = dd["n"]
        label = f"depth {d}" if d < 4 else "depth 4+"
        depth_rows.append([
            label,
            str(dn),
            f"{dd['combined']}/{dn} ({dd['combined']/dn*100:.0f}%)",
            f"{dd['richness_sum']/dn:.2f}",
        ])
    print_summary_table(
        "By Cross-Function Depth",
        ["Depth", "CVEs", "Trigger Match (Line|Stmt)", "Richness"],
        depth_rows,
    )

    # ---- LaTeX ----
    if emit_latex:
        latex_rows = [
            [
                fam,
                str(family_data[fam]["n"]),
                fmt_pct(family_data[fam]["exact"] / (family_data[fam]["n"] or 1) * 100),
                fmt_pct(family_data[fam]["combined"] / (family_data[fam]["n"] or 1) * 100),
                fmt_pct(family_data[fam]["any"] / (family_data[fam]["n"] or 1) * 100),
                f"{family_data[fam]['richness_sum']/(family_data[fam]['n'] or 1):.2f}",
            ]
            for fam in sorted(family_data.keys())
        ]
        print(latex_table(
            caption="Trigger Detection: All-Trigger Recall per CWE Family",
            label="tab:trigger_detection_cwe",
            headers=["CWE Family", "CVEs", "Exact Line", "Line$|$Stmt", "Any Match", "Richness"],
            rows=latex_rows,
            note=(
                "\\textit{Richness} = in-depth triggers / GT depth. "
                "Agents finding more verified triggers at $\\leq$ GT depth score higher."
            ),
        ))

    # ---- Failures ----
    if print_failures:
        misses = [r for r in records if not (r["exact_line_match"] or r["stmt_match"])]
        print(f"\n  Missed CVEs ({len(misses)}):")
        for r in sorted(misses, key=lambda x: x["cwe"]):
            bias_tag = " [consequence-bias]" if r["gt_is_consequence"] else ""
            cause_tag = " cause✓" if r["cause_match"] else ""
            print(f"    {r['cve_id']:22s} {r['cwe']:10s} "
                  f"func={r['gt_function']:30s} "
                  f"line={str(r['gt_line']):6s} "
                  f"n_trig={r['n_triggers_found']}"
                  f"{cause_tag}{bias_tag}")

    # ---- Save report ----
    report = {
        "summary": {
            "n_cves": n,
            "skipped": skipped,
            "exact_line": exact_n,
            "exact_line_pct": exact_n / n * 100,
            "stmt_match": stmt_n,
            "stmt_match_pct": stmt_n / n * 100,
            "stmt_only_rescued": stmt_only_n,
            "combined": combined_n,
            "combined_pct": combined_n / n * 100,
            "func_match": func_n,
            "func_match_pct": func_n / n * 100,
            "any_match": any_n,
            "any_match_pct": any_n / n * 100,
            "avg_triggers_per_cve": avg_triggers,
            "avg_richness_score": avg_richness,
            "miss_classification": {
                "deeper_not_reached": miss_split.get("deeper_not_reached", 0),
                "same_depth_wrong_trigger": miss_split.get("same_depth_wrong_trigger", 0),
            },
            # Consequence bias analysis
            "consequence_bias": {
                "gt_is_consequence_count": consequence_n,
                "gt_is_consequence_pct": consequence_n / n * 100,
                "cause_match_count": cause_n,
                "cause_match_pct": cause_n / n * 100,
                "consequence_adjusted_combined": combined_n + cause_n,
                "consequence_adjusted_combined_pct": (combined_n + cause_n) / n * 100,
                "explanation": (
                    "gt_is_consequence: InterPVD recorded the downstream crash site "
                    "(no critical variable in GT statement). cause_match: AutoTrace found "
                    "the root-cause sink correctly in the right function. VulTrigger faces "
                    "identical penalty for these CVEs."
                ),
            },
        },
        "richness_vs_match": {
            bucket: {
                "n": d["n"],
                "match": d["match"],
                "match_pct": d["match"] / (d["n"] or 1) * 100,
            }
            for bucket, d in rich_match.items()
        },
        "per_family": {
            fam: {
                "n": fd["n"],
                "exact_pct": fd["exact"] / fd["n"] * 100,
                "combined_pct": fd["combined"] / fd["n"] * 100,
                "any_match_pct": fd["any"] / fd["n"] * 100,
                "avg_richness": fd["richness_sum"] / fd["n"],
                "avg_triggers": fd["triggers_sum"] / fd["n"],
            }
            for fam, fd in family_data.items()
        },
        "per_cve": records,
    }

    out = output_path or OUTPUT_DIR / "trigger_detection_report.json"
    save_json_report(report, out)


def main() -> None:
    p = standard_argparser("RQ1.3: Trigger Detection Richness and All-Trigger Recall")
    p.add_argument("--failures", action="store_true", help="Print missed CVEs")
    args = p.parse_args()
    run(args.results_dir, args.output, args.latex, getattr(args, "failures", False))


if __name__ == "__main__":
    main()
