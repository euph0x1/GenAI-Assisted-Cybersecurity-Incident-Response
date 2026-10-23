"""Offline tests for the app logic: python -m tests.test_viewer"""
import argparse, html, json, os, re, tempfile
import src.analyst as an
from src import viewer
from src.verify import verify
from tests.test_core import INC
from tests.test_stage5 import A

def strip(h): return re.sub(r"</?mark[^>]*>", "", h)

def test_highlight():
    s = "Impacted entities include [account:453297] and [account:322] <script>x</script> in InitialAccess."
    v = verify(INC, A(s))
    h = viewer.highlight_html(s, v["issues"])
    assert '<mark class="hard"' in h and "[account:322]</mark>" in h
    assert "<script>" not in h and "&lt;script&gt;" in h, "must escape HTML"
    assert strip(h) == html.escape(s), "highlighting must not change the visible text"
    s2 = "Alert type 39 was triggered at [account:453297] in InitialAccess."
    h2 = viewer.highlight_html(s2, verify(INC, A(s2))["issues"])
    assert "<mark" in h2 and strip(h2) == html.escape(s2), "relation issue (no closing bracket) is highlighted"
    s3 = "About 5,000 alerts hit [account:453297] in InitialAccess."
    assert '<mark class="soft"' in viewer.highlight_html(s3, verify(INC, A(s3))["issues"])
    s4 = "Type [alert type:77] hit [account:453297] in InitialAccess."          # 'alert type' spelled with a space
    assert "<mark" in viewer.highlight_html(s4, verify(INC, A(s4))["issues"])
    assert viewer.highlight_html("clean text", []) == "clean text"
    print("highlight ok")

def test_omitted():
    om = viewer.omitted_evidence(INC, A("Something happened."))
    assert om["missing_entities"] == {"account": ["453297"]} and om["categories_missing"] == ["InitialAccess"]
    assert set(om["techniques_missing"]) == {"T1078.004", "T9999"} and om["entities_cited"] == 0 and om["entities_total"] == 1
    om = viewer.omitted_evidence(INC, A("InitialAccess via Valid Accounts: Cloud Accounts, T9999, hit [account:453297]."))
    assert not om["missing_entities"] and not om["categories_missing"] and not om["techniques_missing"] and om["entities_cited"] == 1
    print("omitted ok")

def test_discover():
    d = tempfile.mkdtemp()
    row = {"incident_id": 1, "grade": "TruePositive", "analysis": None}
    for n in ["llm_5.jsonl", "hybrid_5.jsonl", "verified_rev_hybrid_5.jsonl"]: open(f"{d}/{n}", "w").write(json.dumps(row) + "\n")
    open(f"{d}/other.jsonl", "w").write('{"x": 1}\n'); open(f"{d}/results.csv", "w").write("a,b\n"); open(f"{d}/empty.jsonl", "w").write("")
    assert set(viewer.discover_runs(d)) == {"llm_5", "hybrid_5"}
    print("discover ok")

def _fake_generate(replies):
    calls = []
    def g(prompt, **kw):
        calls.append(prompt); return replies[min(len(calls) - 1, len(replies) - 1)]
    g.calls = calls; return g

def _analysis(summary):
    return json.dumps({"classification": "TruePositive", "confidence": 0.7, "rationale": "r", "summary": summary, "claims": []})

def test_baseline_and_live():
    from src.make_demo_data import main as demo; from src.prep import main as prep; from src.classify import main as cls
    d = tempfile.mkdtemp(); cwd = os.getcwd(); os.chdir(d)
    try:
        demo("tr.csv", 150, seed=1); prep("tr.csv", "tr.jsonl", 1, 0); demo("te.csv", 20, seed=2); prep("te.csv", "te.jsonl", 1, 0)
        cls(argparse.Namespace(train="tr.jsonl", test="te.jsonl", eval_test=False, model="hgb"))
        bl = viewer.load_baseline("models"); assert bl is not None
        incs = viewer.load_incidents(["te.jsonl", "missing.jsonl"]); inc = next(iter(incs.values()))
        label, conf = viewer.predict_label(bl, inc); assert label in ("BenignPositive", "FalsePositive", "TruePositive") and 0 < conf <= 1
        assert viewer.load_baseline("nonexistent") is None
        # hybrid: first reply has an invented entity -> verifier flags it -> one revision -> clean
        g = _fake_generate([_analysis("Activity occurred. [ip:99999999] is suspicious."),
                            _analysis(f"Activity in {inc['categories'][0]} occurred.")]); an.generate = g
        out = viewer.live_analyze(inc, "hybrid", bl)
        assert out["baseline_pred"] == label and out["verify"]["hallucination"] and out["verify_revised"]["hallucination"] is False
        assert len(g.calls) == 2 and "assessed this incident as" in g.calls[0], "hybrid prompt must carry the classifier label"
        # no revision when disabled; llm mode needs no baseline; hybrid without baseline raises
        an.generate = _fake_generate([_analysis("Activity occurred. [ip:99999999] is suspicious.")])
        out = viewer.live_analyze(inc, "llm", None, do_revise=False); assert "revised" not in out and out["baseline_pred"] is None
        try: viewer.live_analyze(inc, "hybrid", None); raise AssertionError("should raise")
        except RuntimeError: pass
    finally: os.chdir(cwd)
    print("baseline + live ok")

if __name__ == "__main__":
    test_highlight(); test_omitted(); test_discover(); test_baseline_and_live(); print("all viewer tests passed")
