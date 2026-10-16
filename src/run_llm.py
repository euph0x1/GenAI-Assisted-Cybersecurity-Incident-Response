"""Run the LLM analyst on a stratified test subset, then evaluate.

  python -m src.run_llm --mode llm --n 150
  python -m src.run_llm --mode hybrid --n 150
  python -m src.run_llm --mode llm --n 150 --eval-only        # no API calls

Resumable: finished incidents are skipped, and every response is cached. If the free
quota runs out the run stops cleanly; re-run the same command later to continue.
"""
import argparse, json, os, random
from collections import Counter, defaultdict
import numpy as np
from src.classify import load, baseline_predict
from src.analyst import analyze
from src.metrics import to_idx, bootstrap_ci, per_class_recall

def pick_subset(rows, n, seed=42):
    """Stratified by grade, deterministic. Same seed -> same subset in every mode."""
    rng = random.Random(seed)
    by = defaultdict(list)
    for r in sorted(rows, key=lambda r: r["incident_id"]): by[r["grade"]].append(r)
    out = []
    for g, items in sorted(by.items()):
        k = max(1, round(n * len(items) / len(rows)))
        out += rng.sample(items, min(k, len(items)))
    return sorted(out, key=lambda r: r["incident_id"])[:n]

def pick_large_extra(rows, base, n_extra, min_alerts, seed=42):
    """Base subset + n_extra incidents with >= min_alerts alerts (stratified by grade, seeded).
    The base incidents are untouched, so earlier results stay comparable."""
    taken = {r["incident_id"] for r in base}
    pool = [r for r in rows if r["n_alerts"] >= min_alerts and r["incident_id"] not in taken]
    if not pool: raise SystemExit(f"no incidents with >= {min_alerts} alerts")
    extra = pick_subset(pool, min(n_extra, len(pool)), seed)
    return sorted(base + extra, key=lambda r: r["incident_id"])

def read_done(path):
    if not os.path.exists(path): return {}
    return {json.loads(l)["incident_id"]: json.loads(l) for l in open(path)}

def evaluate(path, sub, base_pred=None):
    done = read_done(path)
    rows = [r for r in sub if r["incident_id"] in done]
    if not rows: print("nothing to evaluate yet"); return
    y = to_idx([r["grade"] for r in rows])
    llm = to_idx([done[r["incident_id"]]["pred"] for r in rows])
    fails = sum(done[r["incident_id"]]["analysis"] is None for r in rows)
    print(f"\nevaluated {len(rows)} incidents | unparseable LLM outputs: {fails}")
    f, lo, hi = bootstrap_ci(y, llm)
    print(f"LLM/pipeline macro-F1 = {f:.3f}  (95% CI {lo:.3f}-{hi:.3f})")
    print("  per-class recall:", per_class_recall(y, llm))
    if base_pred is not None:
        bp = to_idx([base_pred[r["incident_id"]] for r in rows])
        f, lo, hi = bootstrap_ci(y, bp)
        print(f"Baseline    macro-F1 = {f:.3f}  (95% CI {lo:.3f}-{hi:.3f})  [same incidents]")
        print("  per-class recall:", per_class_recall(y, bp))

def main(a):
    test = load(a.test)
    sub = pick_subset(test, a.n)
    tag = ""
    if a.extra_large:
        sub = pick_large_extra(test, sub, a.extra_large, a.min_alerts)
        tag = f"_plus{a.extra_large}large"
        print(f"added up to {a.extra_large} incidents with >= {a.min_alerts} alerts")
    print(f"subset: {len(sub)} incidents", dict(Counter(r['grade'] for r in sub)))
    base_pred, base_proba = None, {}
    if not a.no_baseline:
        names, proba = baseline_predict(a.train, sub, a.baseline_model)
        base_pred = {r["incident_id"]: n for r, n in zip(sub, names)}
        base_proba = {r["incident_id"]: float(p.max()) for r, p in zip(sub, proba)}
    elif a.mode == "hybrid": raise SystemExit("hybrid mode needs the baseline")

    os.makedirs("results", exist_ok=True)
    out = a.out or f"results/{a.mode}_{a.n}{tag}.jsonl"
    if not a.eval_only:
        done = read_done(out)
        todo = [r for r in sub if r["incident_id"] not in done]
        print(f"{len(done)} already done, {len(todo)} to run -> {out}")
        with open(out, "a") as f:
            for i, inc in enumerate(todo, 1):
                iid = inc["incident_id"]
                try:
                    res = analyze(inc, a.mode, base_pred and base_pred[iid], base_proba.get(iid))
                except Exception as e:  # API/quota failure: stop cleanly, keep finished work
                    print(f"\nstopped at incident {iid}: {type(e).__name__}: {str(e)[:200]}")
                    print("Finished work is saved. Re-run the same command to resume."); break
                an = res["analysis"]
                pred = (base_pred[iid] if a.mode == "hybrid" else an and an["classification"])
                f.write(json.dumps({"incident_id": iid, "grade": inc["grade"], "mode": a.mode,
                                    "pred": pred, "baseline_pred": base_pred and base_pred[iid],
                                    "confidence": an and an["confidence"], "analysis": an,
                                    "error": res["error"], "raw": res["raw"]}) + "\n"); f.flush()
                if i % 10 == 0: print(f"  {i}/{len(todo)}")
    evaluate(out, sub, base_pred)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["llm", "hybrid"], default="llm")
    p.add_argument("--n", type=int, default=150)
    p.add_argument("--train", default="data/incidents_train.jsonl")
    p.add_argument("--test", default="data/incidents_test.jsonl")
    p.add_argument("--baseline-model", choices=["xgb", "hgb"], default="xgb")
    p.add_argument("--no-baseline", action="store_true")
    p.add_argument("--eval-only", action="store_true")
    p.add_argument("--extra-large", type=int, default=0, help="add N incidents with >= --min-alerts alerts to the subset")
    p.add_argument("--min-alerts", type=int, default=20)
    p.add_argument("--out")
    main(p.parse_args())
