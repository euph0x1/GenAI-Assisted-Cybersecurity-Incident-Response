"""Smoke test: execute app.py end to end against a STUB of Streamlit (offline).
Catches broken calls/NameErrors in the app wiring; it cannot prove the page renders correctly.
  python -m tests.test_app_smoke"""
import argparse, json, os, runpy, shutil, sys, tempfile
import src.analyst as an
from src import viewer          # import everything needed before chdir
from tests.test_stage5 import A

APP = os.path.abspath("app.py")
ROOT = os.path.dirname(APP)

class Ctx:
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def __getattr__(self, n): return lambda *a, **k: Ctx()

class FakeSt:
    def __init__(self, pick=0, pressed=(), checks=None, picks=None):
        self.out, self.session_state, self.pick, self.pressed, self.checks = [], {}, pick, set(pressed), checks or {}
        self.picks = picks or {}
        self.sidebar = self
    def cache_data(self, *a, **k): return a[0] if a and callable(a[0]) else (lambda f: f)
    cache_resource = cache_data
    def _rec(self, *a, **k): self.out.append(" ".join(str(x) for x in a)); return Ctx()
    def __getattr__(self, name): return self._rec
    def columns(self, spec, **k): return [Ctx() for _ in range(spec if isinstance(spec, int) else len(spec))]
    def tabs(self, labels, **k): return [Ctx() for _ in labels]
    def expander(self, label, **k): self.out.append("EXPANDER " + label); return Ctx()
    def spinner(self, *a, **k): return Ctx()
    def text_input(self, label, value="", **k): return value
    def multiselect(self, label, options, default=None, **k): return default or []
    def checkbox(self, label, value=False, **k):
        return next((v for key, v in self.checks.items() if key in label), value)
    def radio(self, label, options, **k): return list(options)[0]
    def text_area(self, label, value="", **k): return value
    def file_uploader(self, *a, **k): return None
    def button(self, label, **k): return label in self.pressed
    def selectbox(self, label, options, format_func=None, **k):
        options = list(options)
        if format_func: [format_func(o) for o in options]
        i = self.picks.get(label, self.pick)
        return options[min(i, len(options) - 1)] if options else None

def run_app(**kw):
    st = FakeSt(**kw); sys.modules["streamlit"] = st
    runpy.run_path(APP); return st

def build_fixture():
    from src.make_demo_data import main as demo; from src.prep import main as prep; from src.classify import main as cls
    from src.run_verify import main as run_verify
    os.makedirs("data"); os.makedirs("results")
    demo("tr.csv", 150, seed=1); prep("tr.csv", "data/incidents_train.jsonl", 1, 0)
    demo("te.csv", 40, seed=3); prep("te.csv", "data/incidents_test.jsonl", 1, 0)
    cls(argparse.Namespace(train="data/incidents_train.jsonl", test="data/incidents_test.jsonl", eval_test=False, model="hgb"))
    incs = [json.loads(l) for l in open("data/incidents_test.jsonl")]
    for mode in ("hybrid", "llm"):
        with open(f"results/{mode}_40.jsonl", "w") as f:
            for i, inc in enumerate(incs):
                s = "Activity occurred. " + ("[ip:99999999] is suspicious." if i % 2 == 0 else "")
                f.write(json.dumps({"incident_id": inc["incident_id"], "grade": inc["grade"], "mode": mode, "pred": "TruePositive",
                                    "baseline_pred": "FalsePositive", "confidence": 0.8, "analysis": A(s), "error": None}) + "\n")
    clean = A("Activity in " + incs[0]["categories"][0] + " occurred.")
    an.generate = lambda prompt, **kw: json.dumps(clean)
    run_verify(argparse.Namespace(input="results/hybrid_40.jsonl", test="data/incidents_test.jsonl", revise=True, out=None))
    open("results/final_report.md", "w").write("# FINAL REPORT MARKER\n")

def test_app():
    d = tempfile.mkdtemp(); cwd = os.getcwd(); os.chdir(d)
    try:
        # empty project: friendly messages, no crash
        st = run_app(); assert any("No saved runs found" in o for o in st.out), st.out[:5]
        build_fixture()
        outs = [run_app(pick=k) for k in range(4)]
        text = "\n".join("\n".join(s.out) for s in outs)
        assert "Original summary" in text and "After verifier-guided revision" in text, "revision panel shown"
        assert '<mark class="hard"' in text, "flagged claim highlighted"
        assert "Structured classifier" in text and "Ground truth" in text and "FINAL REPORT MARKER" in text
        assert "Evidence the model saw" in text and "Evidence coverage" in text
        # filters, truth hidden, other run
        st = run_app(checks={"Only summaries the verifier flagged": True}); assert any("incidents match" in o for o in st.out)
        st = run_app(checks={"Only summaries that were revised": True, "Show ground-truth label": False}); assert not any("Ground truth" in o for o in st.out)
        # live tab: button pressed -> full pipeline (fake LLM) -> rendered
        calls = []
        an.generate = lambda prompt, **kw: (calls.append(1), json.dumps(A("Activity occurred. [ip:99999999] is suspicious.")))[1]
        st = run_app(pressed=["Analyze incident"])
        assert calls and any("Triage (structured classifier)" in o for o in st.out), "live analysis rendered"
        # free-text tab: sample chosen -> analysis rendered with revision + reference key
        import src.freetext as ft
        shutil.copytree(os.path.join(ROOT, "samples"), "samples")
        good = lambda extra="": json.dumps({"summary": "Scanning from 192.0.2.150 matched change CHG-5521." + extra,
            "activity": {"likely_activity": "Authorized penetration test (hypothesis)", "confidence": 0.9, "evidence": ["Authorized penetration test by RedTeam-Demo Ltd."]},
            "techniques": [{"id": "T1046", "name": "Network Service Discovery", "evidence": "SCAN_DETECTED src=192.0.2.150"}],
            "indicators": [{"type": "ip", "value": "192.0.2.150", "context": "scan source"}],
            "alternative_explanations": ["A real attacker using the same source"], "unknowns": ["Whether the account testadmin was removed"],
            "recommended_actions": ["Confirm the window with the contact in the change record"]})
        replies = [good(" Also 198.51.100.7."), good()]; ft_calls = []
        ft.generate = lambda prompt, **kw: (ft_calls.append(1), replies[min(len(ft_calls) - 1, 1)])[1]
        st = run_app(pressed=["Analyze text"], picks={"Start from": 1})
        txt = "\n".join(st.out)
        assert len(ft_calls) == 2 and "Likely activity" in txt and "After verifier-guided revision" in txt, txt[-600:]
        assert "Reference key for this sample" in "\n".join(st.out) and "Indicators in your text that the analysis did not mention" in txt
        assert '<mark class="hard"' in txt and "hypotheses" in txt
        st = run_app(pressed=["Analyze text"]); assert any("too short" in o for o in st.out), "empty text -> friendly error"
        # live tab error path: no baseline model -> friendly error, not a crash
        for p in os.listdir("models"): os.remove(f"models/{p}")
        st = run_app(pressed=["Analyze incident"]); assert any("RuntimeError" in o for o in st.out)
    finally:
        os.chdir(cwd); sys.modules.pop("streamlit", None)
    print("app smoke ok")

if __name__ == "__main__":
    test_app()
