"""Logic behind the Streamlit app (pure functions, testable without Streamlit)."""
import glob, html, json, os, re
from src.analyst import analyze, revise
from src.classify import load, CLASSES, Featurizer
from src.mitre import name as mitre_name
from src.narrative import build_narrative
from src.run_verify import size_bin
from src.verify import verify, TAG_RE, _t, _norm

def discover_runs(results_dir="results"):
    """{run name: path} for saved LLM-run files (skips verified_* and anything without analyses)."""
    runs = {}
    for p in sorted(glob.glob(os.path.join(results_dir, "*.jsonl"))):
        n = os.path.basename(p)[:-6]
        if n.startswith("verified_"): continue
        try:
            first = json.loads(open(p).readline())
        except (ValueError, OSError):
            continue
        if "analysis" in first and "grade" in first: runs[n] = p
    return runs

def load_incidents(paths):
    """Merge incident files (missing files are skipped). Same incident id -> same data in every file."""
    d = {}
    for p in paths:
        if os.path.exists(p):
            for r in load(p): d[r["incident_id"]] = r
    return d

def read_run(path):
    return [json.loads(l) for l in open(path)]

def load_revisions(results_dir, run):
    p = os.path.join(results_dir, f"verified_rev_{run}.jsonl")
    return {r["incident_id"]: r for r in map(json.loads, open(p))} if os.path.exists(p) else {}

def _candidates(issue):
    item = issue["item"]
    m = re.match(r"\[[A-Za-z_ ]+:[^\]]+\]", item)   # a tag only when the item STARTS with [type:value]
    if m: return [m.group(0)]
    item = re.sub(r"\s*\(plain mention\)\s*$", "", item).strip()
    if item.endswith("..."): item = item[:-3]
    return [item] if item else []

def highlight_html(text, issues):
    """HTML-escaped text with <mark> around the parts the verifier flagged (hard = red, soft = orange)."""
    spans = []
    for iss in issues:
        for cand in _candidates(iss):
            pat = re.escape(cand).replace("_", "[_ ]")      # tags may be written 'alert type' or 'alert_type'
            for m in re.finditer(pat, text, re.I): spans.append((m.start(), m.end(), iss))
    spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    out, pos = [], 0
    for a, b, iss in spans:
        if a < pos: continue                                  # skip overlaps
        out.append(html.escape(text[pos:a]))
        tip = html.escape(f"{iss['type']}: {iss['item']}", quote=True)
        out.append(f'<mark class="{iss["severity"]}" title="{tip}">{html.escape(text[a:b])}</mark>')
        pos = b
    out.append(html.escape(text[pos:]))
    return "".join(out)

def omitted_evidence(inc, analysis):
    """What the report contains that the summary does not mention."""
    s = analysis["summary"]; ns = _norm(s)
    cited = {(_t(t), v) for t, v in TAG_RE.findall(s)}
    missing = {t: [v for v in vs if (t, v) not in cited] for t, vs in inc["critical_evidence"].items()}
    missing = {t: vs for t, vs in missing.items() if vs}
    total = sum(len(v) for v in inc["critical_evidence"].values())
    def named(t):
        n = mitre_name(t)
        return _norm(t) in ns or bool(n and _norm(n) in ns)
    return {"missing_entities": missing,
            "categories_missing": [c for c in inc["categories"] if _norm(c) not in ns],
            "techniques_missing": [t for t in inc["mitre"] if not named(t)],
            "entities_total": total,
            "entities_cited": total - sum(len(v) for v in missing.values())}

def load_baseline(models_dir="models"):
    """Reload the saved structured classifier (None if it has not been trained or cannot be loaded)."""
    fj = os.path.join(models_dir, "featurizer.json")
    if not os.path.exists(fj): return None
    meta = json.load(open(fj))
    fz = Featurizer(); fz.cats, fz.mitre, fz.titles = meta["cats"], meta["mitre"], meta["titles"]
    xp, hp = os.path.join(models_dir, "baseline_xgb.json"), os.path.join(models_dir, "baseline_hgb.joblib")
    try:
        if os.path.exists(xp):
            from xgboost import XGBClassifier
            m = XGBClassifier(); m.load_model(xp)
        elif os.path.exists(hp):
            import joblib; m = joblib.load(hp)
        else: return None
    except Exception:
        return None
    return fz, m, meta

def predict_label(baseline, inc):
    fz, m, meta = baseline
    X = fz.transform([inc]).reindex(columns=meta["columns"], fill_value=0)
    proba = m.predict_proba(X)[0]; i = int(proba.argmax())
    return CLASSES[i], float(proba[i])

def live_analyze(inc, mode="hybrid", baseline=None, do_revise=True):
    """Full pipeline on one incident: triage -> summary -> verify -> (optional) one revision."""
    pred = conf = None
    if mode == "hybrid":
        if baseline is None: raise RuntimeError("No saved baseline model found. Run `python -m src.classify` first.")
        pred, conf = predict_label(baseline, inc)
    res = analyze(inc, mode, pred, conf)
    out = {"baseline_pred": pred, "baseline_conf": conf, "analysis": res["analysis"], "error": res["error"]}
    if res["analysis"]:
        v = verify(inc, res["analysis"]); out["verify"] = v
        if do_revise and (v["issues"] or v["omission"]):
            new = revise(inc, res["analysis"], v, mode, pred, conf)
            if new: out["revised"] = new; out["verify_revised"] = verify(inc, new)
    return out
