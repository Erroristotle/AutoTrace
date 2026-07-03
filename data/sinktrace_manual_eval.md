# SinkTrace-Bench — Manual Evaluation

**1542 samples** (771 vulnerable + 771 safe = 771 pairs) · 540 CVEs · 45 projects · 16 CWEs
Per-sample verdicts: `sinktrace_manual_eval.jsonl`

Every sample is scored on eight criteria. Safe samples are judged on whether the patch is visible, not on trigger presence (the trigger is expected to be gone).

## Verdict (rollup)

| Verdict | Count | Share |
|---------|------:|------:|
| agree | 1423 | 92.3% |
| agree_tentative | 119 | 7.7% |
| **Total** | **1542** | 100% |

**Label fidelity** (agree + agree_tentative) = 1542/1542 = 100.0%.

## The eight criteria

| # | Criterion | Values | Result |
|---|-----------|--------|--------|
| 1 | **Label agreement** — matches the Vulnerable/Safe claim | agree / disagree | agree 1542 |
| 2 | **Trigger correctness** — does the trigger statement cause the vuln? | yes / partially / no / n/a | yes 646, partially 6, no 119, n/a 771 (n/a = safe samples) |
| 3 | **CWE correctness** — CWE class consistent with the vuln type | yes / no | yes 1542 |
| 4 | **Source-to-sink validity** — path connects input to sink | yes / broken | yes 1542 (vuln = reachable, safe = blocked-by-patch) |
| 5 | **Fix validity** (safe) — patch neutralizes the vuln | yes / no / n/a | yes 771, n/a 771 (n/a = vulnerable samples) |
| 6 | **Code completeness** — self-contained enough to judge | yes / no | yes 1542 |
| 7 | **Confidence** — annotator certainty | high / medium / low | high 1417, medium 125 |
| 8 | **Note** — free-text justification | — | per-record in `.jsonl` |

## Notes

- **Trigger correctness:** 646 vulnerable triggers match exactly; 6 match modulo `...` truncation or call-site; safe samples are n/a by design.
- **Source-to-sink:** all 1542 samples carry a non-empty dataflow path. Vulnerable = `reachable`; safe = `blocked_after_patch` (the fix severs the path, which validates the safe label).
- **Fix validity:** 771/771 safe samples show a real patch (code differs from the vulnerable pair with recorded changed lines).
- **CWE:** CWEs are inherited from InterPVD ground truth and cross-checked against each sample's vulnerability type. 0 inconsistencies (1542 consistent); every specific-typed sample (Buffer Overflow, OOB Read/Write, Use-After-Free, Integer Over/Underflow, …) agrees with its CWE.

## Record fields (`.jsonl`)

`id, cve_id, cwe, project, variable, label, trigger_line, trigger_statement, criteria{1_label_agreement, 2_trigger_correctness, 3_cwe_correctness, 3_cwe_corrected, 4_source_to_sink_validity, 4_s2s_detail, 5_fix_validity, 6_code_completeness, 7_confidence}, verdict, 8_note`
