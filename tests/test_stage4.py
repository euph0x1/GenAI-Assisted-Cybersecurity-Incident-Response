"""Offline tests for Stage 4 (fake LLM, no network): python -m tests.test_stage4"""
import json, os, tempfile, argparse
import src.analyst as an
from src.analyst import parse_analysis, build_prompt, analyze
from src.run_llm import pick_subset, main as run_main
from src.metrics import to_idx, bootstrap_ci
from tests.test_core import INC

GOOD = {"classification": "TruePositive", "confidence": 85, "rationale": "r",
        "summary": "Account [account:453297] was impacted.", "claims": [{"text": "t", "cites": ["[account:453297]"]}]}

def test_parse():
    a = parse_analysis("```json\n" + json.dumps(GOOD) + "\n```")
    assert a["confidence"] == 0.85 and a["classification"] == "TruePositive"
    for bad in ["not json", '{"classification": "Maybe"}', "{}"]:
        try: parse_analysis(bad); raise AssertionError("should fail: " + bad)
        except ValueError: pass
    print("parse ok")

def test_prompt_no_leak():
    p = build_prompt(INC, "llm"); assert "TruePositive\n" not in p.split("INCIDENT REPORT")[1].split("Return a JSON")[0]
    h = build_prompt(INC, "hybrid", "FalsePositive", 0.7); assert "assessed this incident as FalsePositive (confidence 0.70)" in h
    print("prompt ok")

def test_repair_and_failure():
    calls = []
    def fake(prompt, **kw):
        calls.append(prompt)
        return "garbage" if len(calls) == 1 else json.dumps(GOOD)
    an.generate = fake
    r = analyze(INC); assert r["analysis"] and len(calls) == 2 and calls[1].endswith("JSON object.")
    an.generate = lambda prompt, **kw: "garbage"
    r = analyze(INC); assert r["analysis"] is None and r["error"].startswith("parse_error")
    print("repair ok")

def test_subset_and_metrics():
    rows = [{"incident_id": i, "grade": ["TruePositive", "BenignPositive", "FalsePositive"][i % 3 if i % 5 else 1]} for i in range(500)]
    s1, s2 = pick_subset(rows, 100), pick_subset(rows, 100)
    assert s1 == s2 and abs(len(s1) - 100) <= 2
    y = to_idx(["TruePositive"] * 50 + ["FalsePositive"] * 50)
    f, lo, hi = bootstrap_ci(y, y); assert f == lo == hi == 2 / 3 or f > 0.6  # 2 of 3 classes present
    assert to_idx(["junk", None]).tolist() == [-1, -1]
    print("subset/metrics ok")

def test_extra_large():
    from src.run_llm import pick_large_extra
    rows = [{"incident_id": i, "n_alerts": 3 if i % 4 else 60, "grade": ["TruePositive", "BenignPositive", "FalsePositive"][i % 3]} for i in range(400)]
    base = pick_subset(rows, 50)
    both = pick_large_extra(rows, base, 20, 20)
    ids = [r["incident_id"] for r in both]
    assert len(ids) == len(set(ids)) and {r["incident_id"] for r in base} <= set(ids), "base subset must be preserved"
    assert sum(r["n_alerts"] >= 20 for r in both) >= 20 and len(both) == 70
    assert pick_large_extra(rows, base, 20, 20) == both, "deterministic"
    print("extra-large ok")

def test_end_to_end_resume():
    from src.make_demo_data import main as demo; from src.prep import main as prep
    d = tempfile.mkdtemp(); cwd = os.getcwd(); os.chdir(d); os.makedirs("results")
    try:
        demo("tr.csv", 150, seed=1); prep("tr.csv", "tr.jsonl", 1, 0)
        demo("te.csv", 60, seed=2); prep("te.csv", "te.jsonl", 1, 0)
        n = {"c": 0}
        def fake(prompt, **kw):
            n["c"] += 1
            if n["c"] == 8: raise RuntimeError("429 quota")        # simulate quota exhaustion
            return json.dumps(GOOD)
        an.generate = fake
        args = argparse.Namespace(mode="hybrid", n=20, train="tr.jsonl", test="te.jsonl", baseline_model="hgb",
                                  no_baseline=False, eval_only=False, out=None, extra_large=0, min_alerts=20)
        run_main(args)
        lines = open("results/hybrid_20.jsonl").read().splitlines(); assert len(lines) == 7, len(lines)
        run_main(args)                                              # resume finishes the rest
        lines = open("results/hybrid_20.jsonl").read().splitlines(); assert len(lines) == 20
        assert len({json.loads(l)["incident_id"] for l in lines}) == 20, "no duplicates on resume"
    finally: os.chdir(cwd)
    print("end-to-end + resume ok")

if __name__ == "__main__":
    test_parse(); test_prompt_no_leak(); test_repair_and_failure(); test_subset_and_metrics(); test_extra_large(); test_end_to_end_resume()
    print("all stage 4 tests passed")
