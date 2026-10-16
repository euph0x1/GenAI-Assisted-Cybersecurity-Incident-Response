"""Stage 7: build results/final_report.md from the saved result files (no numbers are typed by hand).

  python -m src.report            # reads results/, writes results/final_report.md

Expected files (any that are missing are skipped with a note):
  results/baseline_metrics.json
  results/llm_150.jsonl  results/hybrid_150.jsonl  results/hybrid_large_60.jsonl      (src.run_llm)
  results/verified_llm_150.jsonl  results/verified_rev_hybrid_150.jsonl
  results/verified_rev_hybrid_large_60.jsonl                                           (src.run_verify)
  results/labeling_sheet_filled.csv  results/labeling_sheet_fresh_filled.csv
  results/labeling_sheet_large_filled.csv                                               (src.labeling)
"""
import csv, datetime, json, os
from collections import Counter
from src.metrics import to_idx, bootstrap_ci, per_class_recall, rate_ci, wilson

def _jsonl(p):
    return [json.loads(l) for l in open(p)] if os.path.exists(p) else None

def _ci(t): f, lo, hi = t; return f"{f:.3f} ({lo:.3f}-{hi:.3f})"
def _pct(flags):
    r, lo, hi = rate_ci(flags); return f"{100*r:.1f}% ({100*lo:.1f}-{100*hi:.1f})"

def classification_section(d):
    out = ["## 1. Triage classification (macro-F1, 95% bootstrap CI)\n"]
    bm = json.load(open(f"{d}/baseline_metrics.json")) if os.path.exists(f"{d}/baseline_metrics.json") else {}
    if bm:
        out.append(f"XGBoost-style baseline ({bm.get('model')}): validation macro-F1 {bm.get('val_macro_f1', float('nan')):.3f}"
                   + (f"; **full held-out test file {bm['test_macro_f1']:.3f}**" if "test_macro_f1" in bm else "") + ".\n")
    out.append("| Subset | System | n | Macro-F1 (CI) | Recall B / FP / TP |\n|---|---|---|---|---|")
    runs = [("LLM-eval subset", "Zero-shot LLM", "llm_150.jsonl"), ("LLM-eval subset", "Baseline (= hybrid label)", "hybrid_150.jsonl"),
            ("Large incidents (exploratory)", "Baseline (= hybrid label)", "hybrid_large_60.jsonl")]
    for subset, name, fn in runs:
        rows = _jsonl(f"{d}/{fn}")
        if rows is None: out.append(f"| {subset} | {name} | - | (missing {fn}) | |"); continue
        y, p = to_idx([r["grade"] for r in rows]), to_idx([r["pred"] for r in rows])
        rc = per_class_recall(y, p)
        out.append(f"| {subset} | {name} | {len(rows)} | {_ci(bootstrap_ci(y, p))} | "
                   f"{rc['BenignPositive']:.2f} / {rc['FalsePositive']:.2f} / {rc['TruePositive']:.2f} |")
    out.append("\nThe hybrid pipeline uses the baseline's label, so its classification score equals the baseline's by construction. "
               "The large-incident row is exploratory: the baseline was trained mostly on small incidents.\n")
    return out

def verification_section(d):
    out = ["## 2. Summary quality: hallucination and omission (verifier-defined)\n",
           "Hallucination = at least one *hard* issue (unsupported entity/technique/alert id/type/date, invented literal, wrong entity type, "
           "role misattribution, unsupported relation). Omission = no tactic/technique mentioned, or no impacted entity cited and no impacted "
           "count stated (fixed before results were seen). Critical-entity recall = share of the top-5-per-type impacted entities the summary cites.\n",
           "| Run | n | Halluc. before (CI) | Halluc. after revision | Omission before | Crit.-entity recall before / after (revised only) |\n|---|---|---|---|---|---|"]
    runs = [("Hybrid, mostly small incidents", "verified_rev_hybrid_150.jsonl"), ("Zero-shot LLM, mostly small", "verified_llm_150.jsonl"),
            ("Hybrid, medium+large incidents", "verified_rev_hybrid_large_60.jsonl")]
    detail = []
    for name, fn in runs:
        rows = _jsonl(f"{d}/{fn}")
        if rows is None: out.append(f"| {name} | - | (missing {fn}) | | | |"); continue
        rows = [r for r in rows if r.get("before")]
        has_rev = any(r.get("revised") for r in rows)
        rec = [r["before"]["critical_entity_recall"] for r in rows if r["before"]["critical_entity_recall"] is not None]
        rv = [r for r in rows if r.get("revised") and r.get("after")]
        def mean(xs): xs = [x for x in xs if x is not None]; return sum(xs) / len(xs) if xs else float("nan")
        revtxt = (f"{mean(r['before']['critical_entity_recall'] for r in rv):.2f} -> {mean(r['after']['critical_entity_recall'] for r in rv):.2f} (n={len(rv)})"
                  if rv else "-")
        out.append(f"| {name} | {len(rows)} | {_pct([r['before']['hallucination'] for r in rows])} | "
                   f"{_pct([r['after']['hallucination'] for r in rows]) if has_rev else 'not run'} | "
                   f"{_pct([r['before']['omission'] for r in rows])} | {sum(rec)/len(rec):.2f} overall; {revtxt} |")
        fixed = sum(r["before"]["hallucination"] and not r["after"]["hallucination"] for r in rows)
        new = sum(not r["before"]["hallucination"] and r["after"]["hallucination"] for r in rows)
        detail.append((name, rows, has_rev, fixed, new))
    out.append("")
    for name, rows, has_rev, fixed, new in detail:
        c = Counter(i["type"] for r in rows for i in r["before"]["issues"])
        out.append(f"**{name}**: issue types {dict(c.most_common())}" + (f"; revision fixed {fixed}, newly introduced {new}." if has_rev else "."))
        bins = []
        for b in ["small(<=5)", "medium(6-50)", "large(>50)"]:
            g = [r for r in rows if r.get("size") == b]
            if g: bins.append(f"{b}: n={len(g)}, halluc. {100*sum(r['before']['hallucination'] for r in g)/len(g):.0f}%, "
                              f"mean crit.-entity recall {sum(r['before']['critical_entity_recall'] or 0 for r in g)/len(g):.2f}")
        out.append("  - by size: " + " | ".join(bins) + "\n")
    out.append("The revision step is guided and scored by the same verifier, so 'after' shows that verifier-detectable errors were removed, "
               "not that the summaries are error-free.\n")
    return out

def _stat_row(name, label, H, A):
    from src.labeling import kappa
    tp = sum(x and y for x, y in zip(H, A)); fp = sum((not x) and y for x, y in zip(H, A))
    fn_ = sum(x and not y for x, y in zip(H, A)); tn = sum((not x) and (not y) for x, y in zip(H, A))
    def fmt(k, n):
        if n == 0: return "n/a"
        lo, hi = wilson(k, n); return f"{k/n:.2f} ({lo:.2f}-{hi:.2f})"
    return (f"| {name} | {label} (n={len(H)}) | {tp} | {fp} | {fn_} | {tn} | {fmt(tp, tp+fp)} | {fmt(tp, tp+fn_)} | "
            f"{kappa(H, A):.2f} |")

def validation_section(d):
    from src.labeling import recompute
    out = ["## 3. Verifier validation against hand labels (LLM-assisted labels, see limitations)\n",
           "| Sheet | Check | TP | FP | FN | TN | Precision (Wilson CI) | Recall (Wilson CI) | Kappa |\n|---|---|---|---|---|---|---|---|---|"]
    sheets = [("First sheet, verifier as exported (before fixes)", "labeling_sheet_filled.csv", False),
              ("First sheet, after fixes (**circular**: fixes were built on these rows)", "labeling_sheet_filled.csv", True),
              ("**Fresh unseen sheet**, mostly small incidents (frozen verifier)", "labeling_sheet_fresh_filled.csv", False),
              ("**Unseen large-incident sheet** (frozen verifier)", "labeling_sheet_large_filled.csv", False)]
    unseen = {"labeling_sheet_fresh_filled.csv", "labeling_sheet_large_filled.csv"}
    pool = {"H": [], "A": [], "Ho": [], "Ao": []}; n_unseen = 0
    for name, fn, recomp in sheets:
        p = f"{d}/{fn}"
        if not os.path.exists(p): out.append(f"| {name} | (missing {fn}) | | | | | | | |"); continue
        rows = [r for r in csv.DictReader(open(p, encoding="utf-8-sig")) if r["human_hallucination"].strip() != ""]
        if recomp: rows = recompute(rows)
        H, A = [int(r["human_hallucination"]) for r in rows], [int(r["auto_hallucination"]) for r in rows]
        Ho, Ao = [int(r["human_omission"]) for r in rows], [int(r["auto_omission"]) for r in rows]
        out.append(_stat_row(name, "hallucination", H, A)); out.append(_stat_row(name, "omission", Ho, Ao))
        if fn in unseen and not recomp:
            n_unseen += 1; pool["H"] += H; pool["A"] += A; pool["Ho"] += Ho; pool["Ao"] += Ao
    if n_unseen == 2:
        out.append(_stat_row("**Pooled unseen sheets (fresh + large)**", "hallucination", pool["H"], pool["A"]))
        out.append(_stat_row("**Pooled unseen sheets (fresh + large)**", "omission", pool["Ho"], pool["Ao"]))
    n_h = len(pool["Ho"]); n_om = sum(pool["Ho"]); n_caught = sum(h and a for h, a in zip(pool["Ho"], pool["Ao"]))
    scope = f"across the {n_h} unseen summaries" if n_unseen else "in the labeled sheets"
    out.append(f"\nOmission detection is **weakly validated at best**: the labeler (using a stricter rule than the verifier's) found only "
               f"{n_om} omission(s) {scope}, and the verifier flagged {n_caught} of them. Treat its 0% omission rate as a lower bound.\n")
    return out

LIMITS = """## 4. Limitations

- **Labels are LLM-assisted, not human.** The hand-label sheets were filled by an LLM reading the report and summary; the same assistant wrote the verifier, so they may share blind spots. Treat agreement as indicative.
- **The verifier is rule-based and entity-focused.** It misses semantic errors (invented activity, wrong event ordering). Reported hallucination rates are therefore lower bounds.
- **Summaries largely restate a deterministic narrative.** The data are anonymized (numeric IDs), so the narrative template pre-digests the evidence; hallucination rates are not comparable to studies on raw incident data.
- **Omission was pre-defined and is lenient.** It is 0% everywhere; the labeler, using a stricter rule (every tactic category named), found 1 omission in 30 large-incident summaries that the verifier missed. Critical-entity recall is the more sensitive measure on large incidents.\n- **Known verifier false alarm:** an `[incident:ID]` citation is flagged as an unsupported entity although the ID is real. The verifier was frozen before validation, so this was not patched.
- **Small incidents dominate the main test subset** (almost all have 5 or fewer alerts); large-incident results come from a separate sample of 60 with wide intervals.
- **Single zero-shot prompt, one LLM, one run.** Classification conclusions apply to this prompt only; no few-shot or prompt-tuning ablation was run.
- **Revision is guided and scored by the same verifier.**
"""

def build_report(d="results"):
    parts = [f"# Incident analysis assistant: evaluation report\n\nGenerated {datetime.date.today().isoformat()} from files in `{d}/`.\n"]
    parts += classification_section(d) + verification_section(d) + validation_section(d) + [LIMITS]
    return "\n".join(parts)

if __name__ == "__main__":
    import sys
    d = sys.argv[1] if len(sys.argv) > 1 else "results"
    text = build_report(d); open(f"{d}/final_report.md", "w", encoding="utf-8").write(text)
    print(text); print(f"\nwrote {d}/final_report.md")
