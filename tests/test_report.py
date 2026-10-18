"""Offline test for the report builder: python -m tests.test_report"""
import csv, json, os, tempfile
from src.report import build_report

def w(p, rows): open(p, "w").write("\n".join(json.dumps(r) for r in rows) + "\n")

def ver(h, o, rec, issues, rev=False, ah=None, size="small(<=5)"):
    b = {"hallucination": h, "hallucination_any": h, "omission": o, "critical_entity_recall": rec,
         "issues": [{"type": t, "item": "x", "severity": "hard"} for t in issues]}
    a = dict(b, hallucination=h if ah is None else ah, issues=[] if ah is False else b["issues"])
    return {"incident_id": 0, "size": size, "before": b, "after": a, "revised": rev}

def test_report():
    d = tempfile.mkdtemp()
    G = ["TruePositive", "BenignPositive", "FalsePositive"]
    w(f"{d}/llm_150.jsonl", [{"incident_id": i, "grade": G[i % 3], "pred": "TruePositive"} for i in range(30)])
    w(f"{d}/hybrid_150.jsonl", [{"incident_id": i, "grade": G[i % 3], "pred": G[i % 3]} for i in range(30)])
    rows = [ver(i < 3, False, 0.9, ["role_misattribution"] if i < 3 else [], rev=i < 3, ah=False) for i in range(20)]
    w(f"{d}/verified_rev_hybrid_150.jsonl", rows)
    json.dump({"model": "xgb", "val_macro_f1": 0.64, "test_macro_f1": 0.625}, open(f"{d}/baseline_metrics.json", "w"))
    cols = ["incident_id", "report", "summary", "human_hallucination", "human_omission", "notes", "auto_hallucination", "auto_omission", "auto_issues"]
    with open(f"{d}/labeling_sheet_fresh_filled.csv", "w", newline="", encoding="utf-8-sig") as f:
        cw = csv.DictWriter(f, fieldnames=cols); cw.writeheader()
        for i in range(10):   # human: 2 positives; auto catches 1, misses 1, plus 1 false alarm
            cw.writerow({"incident_id": i, "report": "R", "summary": "S", "human_hallucination": int(i < 2), "human_omission": 0,
                         "notes": "", "auto_hallucination": int(i in (0, 5)), "auto_omission": 0, "auto_issues": ""})
    with open(f"{d}/labeling_sheet_large_filled.csv", "w", newline="", encoding="utf-8-sig") as f:
        cw = csv.DictWriter(f, fieldnames=cols); cw.writeheader()
        for i in range(10):   # human: 1 positive, auto catches it, no false alarms; 1 human omission missed
            cw.writerow({"incident_id": 100 + i, "report": "R", "summary": "S", "human_hallucination": int(i == 0), "human_omission": int(i == 1),
                         "notes": "", "auto_hallucination": int(i == 0), "auto_omission": 0, "auto_issues": ""})
    t = build_report(d)
    assert "Pooled unseen sheets" in t
    assert "| 2 | 1 | 1 | 16 |" in t, "pooled hallucination counts (fresh 1/1/1/7 + large 1/0/0/9)"
    assert "| 0 | 0 | 1 | 19 |" in t, "pooled omission counts: one missed omission"
    assert "| LLM-eval subset | Baseline (= hybrid label) | 30 | 1.000" in t, "baseline perfect on fixture"
    assert "(missing hybrid_large_60.jsonl)" in t and "(missing labeling_sheet_filled.csv)" in t, "missing files noted, not crashed"
    assert "15.0% (" in t and "0.0% (" in t, "hallucination before/after rates"
    assert "| 1 | 1 | 1 | 7 |" in t, "TP/FP/FN/TN counts from the fresh sheet"
    assert "revision fixed 3, newly introduced 0" in t
    assert "weakly validated" in t and "## 4. Limitations" in t
    print("report ok")

if __name__ == "__main__":
    test_report()
