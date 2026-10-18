"""Offline tests (no network): python -m tests.test_core"""
import os, tempfile, time
from src.narrative import build_narrative
import src.llm as llm

INC = {"incident_id": 7, "org_id": 1, "grade": "TruePositive", "n_alerts": 2, "n_evidence_rows": 9,
       "time_range": ["2024-06-11T08:12:42+00:00", "2024-06-13T02:37:04+00:00"], "time_span_hours": 42.4,
       "categories": ["InitialAccess"], "mitre": ["T1078.004", "T9999"],
       "alerts": [{"alert_id": 2, "title": 6, "category": "InitialAccess", "mitre": [], "first_seen": "2024-06-13T02:37:04+00:00"},
                  {"alert_id": 1, "title": 39, "category": "InitialAccess", "mitre": ["T1078.004"], "first_seen": "2024-06-11T08:12:42+00:00"}],
       "entities": {"account": ["453297", "322", "5"]}, "entity_counts": {"account": 3},
       "critical_evidence": {"account": ["453297"]}, "critical_counts": {"account": 1}}

def test_narrative():
    t = build_narrative(INC)
    assert "TruePositive" not in t and "grade" not in t.lower(), "label leaked into narrative"
    assert "[account:453297]" in t and "T1078.004 (Valid Accounts: Cloud Accounts)" in t
    assert "T9999" in t and "T9999 (" not in t, "unknown technique must not get an invented name"
    assert t.index("alert type 39") < t.index("alert type 6"), "patterns must be in order of first appearance"
    assert build_narrative(INC) == t, "must be deterministic"
    print("narrative ok")

def test_many_alerts_and_labels():
    from src.mitre import label
    big = dict(INC, n_alerts=3000, alerts=[
        {"alert_id": i, "title": 6, "category": "InitialAccess", "mitre": [], "first_seen": f"2024-06-05T{i%24:02d}:00:00+00:00"}
        for i in range(3000)])
    t = build_narrative(big)
    assert "3,000 alerts between" in t and len(t) < 2500, "alerts must be grouped, prompt bounded"
    assert label("T1110.002") == "T1110.002 (sub-technique of Brute Force)"
    assert label("T1110.001") == "T1110.001 (Brute Force: Password Guessing)"
    assert label("T9999") == "T9999"
    print("grouping/labels ok")

def test_prep_min_alerts():
    import json, pandas as pd
    from src.make_demo_data import main as demo; from src.prep import main as prep
    d = tempfile.mkdtemp(); csv = os.path.join(d, "x.csv"); out = os.path.join(d, "x.jsonl")
    demo(csv, 120, seed=5)
    df = pd.read_csv(csv); want = set(df.groupby("IncidentId")["AlertId"].nunique().loc[lambda s: s >= 4].index)
    prep(csv, out, 7, 0, min_alerts=4)                       # sample_mod=7 must be ignored in size mode
    got = [json.loads(l) for l in open(out)]
    assert {r["incident_id"] for r in got} == want and all(r["n_alerts"] >= 4 for r in got), "all large incidents, none small"
    prep(csv, out, 7, 5, min_alerts=4)
    a = [r["incident_id"] for r in map(json.loads, open(out))]; assert len(a) == 5
    prep(csv, out, 7, 5, min_alerts=4); assert a == [r["incident_id"] for r in map(json.loads, open(out))], "seeded sample is deterministic"
    print("prep --min-alerts ok")

def test_llm_cache_retry():
    llm.CACHE_PATH = os.path.join(tempfile.mkdtemp(), "c.sqlite")
    os.environ["LLM_RPM"] = "6000"; time.sleep = lambda s: None
    calls = {"n": 0}
    def fake(provider, model, system, prompt, json_mode, temperature):
        calls["n"] += 1
        if calls["n"] == 1: raise RuntimeError("429 RESOURCE_EXHAUSTED")
        return "hello"
    llm._call_provider = fake
    assert llm.generate("p") == "hello" and calls["n"] == 2, "should retry once"
    assert llm.generate("p") == "hello" and calls["n"] == 2, "second call must hit cache"
    assert llm.generate("p2") == "hello" and calls["n"] == 3
    print("llm cache/retry ok")

if __name__ == "__main__":
    test_narrative(); test_many_alerts_and_labels(); test_prep_min_alerts(); test_llm_cache_retry(); print("all tests passed")
