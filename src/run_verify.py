"""Verify LLM summaries against the evidence, optionally with one revision pass.

  python -m src.run_verify --input results/hybrid_150.jsonl            # verify only (no API calls)
  python -m src.run_verify --input results/hybrid_150.jsonl --revise   # + verifier-feedback revision

Writes results/verified_<name>.jsonl (resumable) and prints before/after rates with 95% CIs.
"""
import argparse, json, os
from collections import Counter
from src.classify import load
from src.analyst import revise
from src.verify import verify
from src.metrics import rate_ci

def size_bin(n): return "small(<=5)" if n <= 5 else "medium(6-50)" if n <= 50 else "large(>50)"

def fmt(flags):
    r, lo, hi = rate_ci(flags); return f"{100*r:5.1f}%  (95% CI {100*lo:.1f}-{100*hi:.1f})"

def report(rows, revised):
    rows = [r for r in rows if r["before"]]
    print(f"\nsummaries verified: {len(rows)}")
    cols = [("hallucination (hard issues)", "hallucination"), ("hallucination incl. soft counts", "hallucination_any"), ("omission", "omission")]
    for label, k in cols:
        print(f"{label:34s} before: {fmt([r['before'][k] for r in rows])}")
        if revised: print(f"{'':34s} after : {fmt([r['after'][k] for r in rows])}")
    rec = [r["before"]["critical_entity_recall"] for r in rows if r["before"]["critical_entity_recall"] is not None]
    if rec: print(f"mean critical-entity recall (before): {sum(rec)/len(rec):.3f}" +
                  (f" | after: {sum(r['after']['critical_entity_recall'] for r in rows if r['after']['critical_entity_recall'] is not None)/len(rec):.3f}" if revised else ""))
    if revised:   # the all-rows mean hides losses in the few revised summaries, so check those alone
        rv = [r for r in rows if r["revised"] and r["after"]]
        def mr(k, w):
            xs = [r[w][k] for r in rv if r[w][k] is not None]; return sum(xs) / len(xs) if xs else float("nan")
        print(f"among the {len(rv)} revised summaries only: critical-entity recall {mr('critical_entity_recall','before'):.3f} -> "
              f"{mr('critical_entity_recall','after'):.3f}")
    c = Counter(i["type"] for r in rows for i in r["before"]["issues"])
    print("issue types before:", dict(c.most_common()))
    if revised:
        fixed = sum(r["before"]["hallucination"] and not r["after"]["hallucination"] for r in rows)
        new = sum(not r["before"]["hallucination"] and r["after"]["hallucination"] for r in rows)
        print(f"hallucination: fixed {fixed}, newly introduced {new} | revisions attempted {sum(r['revised'] for r in rows)}, "
              f"unusable {sum(r.get('revision_failed', False) for r in rows)}")
    print("\nby incident size (n | halluc before->after | omission before->after):")
    for b in ["small(<=5)", "medium(6-50)", "large(>50)"]:
        g = [r for r in rows if r["size"] == b]
        if not g: continue
        h = lambda k, w: 100 * sum(r[w][k] for r in g) / len(g)
        print(f"  {b:13s} {len(g):3d} | {h('hallucination','before'):4.0f}% -> {h('hallucination','after'):4.0f}% | "
              f"{h('omission','before'):4.0f}% -> {h('omission','after'):4.0f}%")

def main(a):
    inc_by_id = {r["incident_id"]: r for r in load(a.test)}
    name = os.path.basename(a.input)
    out = a.out or f"results/verified_{'rev_' if a.revise else ''}{name}"
    src = [json.loads(l) for l in open(a.input)]
    todo = src   # always recomputed: verifying is free, and LLM revisions are cached, so reruns cost no quota
    print(f"{len(src)} summaries -> {out} (recomputed every run with the current verifier)")
    with open(out, "w") as f:
        for r in todo:
            inc = inc_by_id[r["incident_id"]]; an = r["analysis"]
            row = {"incident_id": r["incident_id"], "grade": r["grade"], "size": size_bin(inc["n_alerts"]),
                   "n_alerts": inc["n_alerts"], "before": None, "after": None, "revised": False}
            if an:
                row["before"] = verify(inc, an)
                row["after"] = row["before"]
                if a.revise and (row["before"]["issues"] or row["before"]["omission"]):
                    try:
                        new = revise(inc, an, row["before"], r["mode"], r.get("baseline_pred") if r["mode"] == "hybrid" else None, None)
                    except Exception as e:
                        print(f"\nstopped at incident {r['incident_id']}: {type(e).__name__}: {str(e)[:200]}")
                        print("Finished work is saved. Re-run the same command to resume."); break
                    row["revised"] = True
                    if new: row["analysis_revised"] = new; row["after"] = verify(inc, new)
                    else: row["revision_failed"] = True
            f.write(json.dumps(row) + "\n"); f.flush()
    rows = [json.loads(l) for l in open(out)]
    report(rows, a.revise or any(r["revised"] for r in rows))

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True); p.add_argument("--test", default="data/incidents_test.jsonl")
    p.add_argument("--revise", action="store_true"); p.add_argument("--out")
    main(p.parse_args())
