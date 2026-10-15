"""Incident Analysis Assistant (Streamlit).   Run from the project root:  streamlit run app.py

Tab 1 browses saved runs (no API calls; the verifier runs live and is free).
Tab 2 analyzes any incident live (needs GEMINI_API_KEY in .env and a trained baseline in models/).
Tab 3 shows the evaluation report.
"""
import hashlib, os
import pandas as pd
import streamlit as st
from src import freetext, viewer

st.set_page_config(page_title="Incident Analysis Assistant", page_icon="🛡️", layout="wide")
st.markdown("""<style>
mark.hard{background:#ffd9d9;color:#111;border-bottom:2px solid #d62828;padding:0 3px;border-radius:3px}
mark.soft{background:#fff0cc;color:#111;border-bottom:2px solid #e09f00;padding:0 3px;border-radius:3px}
.summary-box{border:1px solid rgba(128,128,128,.4);border-radius:8px;padding:12px 14px;line-height:1.7}
.pill{display:inline-block;padding:2px 12px;border-radius:12px;font-weight:600;color:#111}
.TruePositive{background:#ffd9d9}.BenignPositive{background:#d9f2df}.FalsePositive{background:#e3e3e3}
</style>""", unsafe_allow_html=True)

DATA_PATHS = ("data/incidents_test.jsonl", "data/incidents_test_large.jsonl")
SIZES = ["small(<=5)", "medium(6-50)", "large(>50)"]

@st.cache_data(show_spinner=False)
def get_incidents(paths): return viewer.load_incidents(list(paths))

@st.cache_data(show_spinner=False)
def get_run(path): return viewer.read_run(path)

@st.cache_data(show_spinner=False)
def get_revisions(results_dir, run): return viewer.load_revisions(results_dir, run)

@st.cache_data(show_spinner=False)
def verify_run(path, paths):
    incs = get_incidents(paths)
    return {r["incident_id"]: viewer.verify(incs[r["incident_id"]], r["analysis"])
            for r in get_run(path) if r.get("analysis") and r["incident_id"] in incs}

@st.cache_resource(show_spinner=False)
def get_baseline(models_dir): return viewer.load_baseline(models_dir)

def pill(label): return f'<span class="pill {label}">{label}</span>'

def render_summary(inc, analysis, v, heading):
    st.markdown(f"**{heading}**")
    st.markdown(f'<div class="summary-box">{viewer.highlight_html(analysis["summary"], v["issues"])}</div>', unsafe_allow_html=True)
    if v["issues"]:
        st.markdown('<mark class="hard">red</mark> = unsupported by the report &nbsp; <mark class="soft">orange</mark> = soft (a count not in the report). Hover for details.',
                    unsafe_allow_html=True)
        st.dataframe(pd.DataFrame([{"severity": i["severity"], "type": i["type"], "detail": i["item"]} for i in v["issues"]]))
    else:
        st.success("Verifier: every checkable claim is supported by the report.")
    om = viewer.omitted_evidence(inc, analysis)
    if v["omission"]: st.warning("Verifier omission flag: no tactic/technique named, or no impacted entity cited/counted.")
    with st.expander(f"Evidence coverage: {om['entities_cited']} of {om['entities_total']} key impacted entities cited"):
        if om["categories_missing"]: st.write("Tactic categories not named: " + ", ".join(om["categories_missing"]))
        if om["techniques_missing"]: st.write("MITRE techniques not named: " + ", ".join(om["techniques_missing"]))
        for t, vals in om["missing_entities"].items(): st.write(f"Impacted {t} not cited: " + ", ".join(vals))
        if not (om["categories_missing"] or om["techniques_missing"] or om["missing_entities"]): st.write("Nothing key was left out.")
    with st.expander("Claims and citations"):
        for c in analysis["claims"]: st.write(f"- {c['text']}  \n  cites: {', '.join(c['cites']) or '(none)'}")

def render_evidence(inc):
    with st.expander("Evidence the model saw (the incident report)"):
        st.code(viewer.build_narrative(inc), language=None)
    with st.expander("Raw incident data"):
        st.json(inc)

def render_freetext(text, result, v, missed, heading):
    tn = freetext.norm_text(text)
    st.markdown(f"### {heading}")
    st.markdown(f'<div class="summary-box">{viewer.highlight_html(result["summary"], v["issues"])}</div>', unsafe_allow_html=True)
    if v["issues"]:
        st.markdown('<mark class="hard">red</mark> = not found in your text &nbsp; <mark class="soft">orange</mark> = soft (format or lookup). Hover for details.',
                    unsafe_allow_html=True)
        st.dataframe(pd.DataFrame([{"severity": i["severity"], "type": i["type"], "detail": i["item"]} for i in v["issues"]]))
    else:
        st.success("Verifier: every indicator, evidence snippet and address/hash/URL in the answer is found in your text.")
    act = result["activity"]
    st.markdown(f"**Likely activity (a hypothesis, not a verdict):** {act['likely_activity'] or 'not stated'}")
    st.caption(f"Model-stated confidence: {act['confidence']:.0%}. No True/Benign/False label is given in this mode.")
    st.progress(float(act["confidence"]))
    for e in act["evidence"]:
        st.write(("✅ " if freetext.snippet_present(e, tn) else "❌ NOT IN TEXT: ") + f"`{e}`")
    if v["technique_status"]:
        st.markdown("**Suggested ATT&CK techniques** (hypotheses: check each against the quoted evidence)")
        st.dataframe(pd.DataFrame([{"id": t["id"], "name (model)": t["name"], "ATT&CK name (local table)": t["attack_name"] or "not in local table",
                                    "quoted evidence": t["evidence"], "evidence in text": "yes" if t["evidence_found"] else "NO",
                                    "name matches table": {True: "yes", False: "NO", None: "n/a"}[t["name_ok"]]}
                                   for t in v["technique_status"]]))
    if v["indicator_status"]:
        st.markdown("**Indicators**")
        st.dataframe(pd.DataFrame([{"type": i["type"], "value": i["value"], "context": i["context"],
                                    "in text": "yes" if i["found_in_text"] else "NO"} for i in v["indicator_status"]]))
    with st.expander(f"Indicators in your text that the analysis did not mention ({len(missed)})"):
        if missed: st.write(", ".join(f"{m['type']}: {m['value']}" for m in missed))
        else: st.write("None: every IP, URL, hash, e-mail, CVE and domain found by regex is covered.")
    for title, key in [("Alternative explanations", "alternative_explanations"), ("What cannot be determined from this text", "unknowns"),
                       ("Suggested next steps", "recommended_actions")]:
        if result[key]:
            st.markdown(f"**{title}**")
            for x in result[key]: st.write(f"- {x}")

st.title("🛡️ Incident Analysis Assistant")
st.caption("GenAI triage and summarization for security incidents (GUIDE data), with an evidence-grounded verifier.")
tab1, tab2, tab3, tab4 = st.tabs(["Saved runs", "Live analysis", "Evaluation report", "Free-text analysis"])

with tab1:
    st.sidebar.caption("The sidebar settings apply to the 'Saved runs' tab only.")
    results_dir = st.sidebar.text_input("Results folder", "results")
    runs = viewer.discover_runs(results_dir)
    incs = get_incidents(DATA_PATHS)
    if not runs: st.info("No saved runs found. Run `python -m src.run_llm ...` first.")
    elif not incs: st.warning("No incident files found in data/. Run `python -m src.prep ...` first.")
    else:
        run = st.sidebar.selectbox("Run", list(runs))
        rows = [r for r in get_run(runs[run]) if r.get("analysis") and r["incident_id"] in incs]
        ver = verify_run(runs[run], DATA_PATHS); revs = get_revisions(results_dir, run)
        sizes = st.sidebar.multiselect("Incident size", SIZES, default=SIZES)
        only_flag = st.sidebar.checkbox("Only summaries the verifier flagged", False)
        only_rev = st.sidebar.checkbox("Only summaries that were revised", False)
        show_truth = st.sidebar.checkbox("Show ground-truth label", True)
        keep = [r for r in rows if viewer.size_bin(incs[r["incident_id"]]["n_alerts"]) in sizes
                and (not only_flag or ver[r["incident_id"]]["issues"])
                and (not only_rev or revs.get(r["incident_id"], {}).get("revised"))]
        st.sidebar.caption(f"{len(keep)} of {len(rows)} incidents match")
        if not keep: st.info("No incidents match the filters.")
        else:
            by_id = {r["incident_id"]: r for r in keep}
            def label(i):
                n = incs[i]["n_alerts"]; flag = " | flagged" if ver[i]["issues"] else ""
                return f"{i} | {n} alert{'s' if n != 1 else ''}{flag}"
            sel = st.selectbox("Incident", list(by_id), format_func=label)
            r, inc, an, v = by_id[sel], incs[sel], by_id[sel]["analysis"], ver[sel]
            a, b, c = st.columns(3)
            a.metric("Alerts", f"{inc['n_alerts']:,}"); b.metric("Evidence records", f"{inc['n_evidence_rows']:,}")
            c.metric("Time span (hours)", f"{inc['time_span_hours']:.1f}")
            left, right = st.columns(2)
            with left:
                st.subheader("Triage")
                who = "Structured classifier" if r["mode"] == "hybrid" else "LLM (zero-shot)"
                st.markdown(f"{who}: {pill(r['pred'])}", unsafe_allow_html=True)
                st.caption(f"Model-stated confidence: {an['confidence']:.0%}")
                st.progress(float(an["confidence"]))
                if r["mode"] == "llm" and r.get("baseline_pred"):
                    st.markdown(f"Structured baseline would say: {pill(r['baseline_pred'])}", unsafe_allow_html=True)
                if show_truth:
                    ok = "correct" if r["pred"] == r["grade"] else "wrong"
                    st.markdown(f"Ground truth: {pill(r['grade'])} ({ok})", unsafe_allow_html=True)
            with right:
                st.subheader("Rationale"); st.write(an["rationale"])
            st.subheader("Summary")
            rev = revs.get(sel)
            if rev and rev.get("analysis_revised"):
                c1, c2 = st.columns(2)
                with c1: render_summary(inc, an, v, "Original summary")
                with c2:
                    nv = viewer.verify(inc, rev["analysis_revised"])
                    render_summary(inc, rev["analysis_revised"], nv, "After verifier-guided revision")
            else:
                render_summary(inc, an, v, "LLM summary")
                if rev and rev.get("revision_failed"): st.info("A revision was attempted but the reply was unusable.")
            render_evidence(inc)

with tab2:
    st.write("Analyze one incident end to end: triage, summary, verification, and one verifier-guided revision.")
    incs2 = get_incidents(DATA_PATHS)
    if not incs2: st.warning("No incident files found in data/.")
    else:
        if os.environ.get("LLM_PROVIDER", "gemini") == "gemini" and not os.environ.get("GEMINI_API_KEY"):
            st.warning("GEMINI_API_KEY is not set (see .env.example). Live analysis will fail until it is.")
        mode = st.radio("Mode", ["hybrid", "llm"], help="hybrid: structured classifier decides, LLM explains. llm: LLM decides (zero-shot).")
        do_rev = st.checkbox("Run verifier-guided revision if problems are found", True)
        iid = st.selectbox("Incident", sorted(incs2), key="live_incident")
        if st.button("Analyze incident"):
            with st.spinner("Calling the LLM..."):
                try:
                    st.session_state["live"] = (iid, mode, viewer.live_analyze(incs2[iid], mode, get_baseline("models"), do_rev))
                except Exception as e:
                    st.session_state["live"] = None; st.error(f"{type(e).__name__}: {str(e)[:300]}")
        live = st.session_state.get("live")
        if live and live[0] == iid and live[1] == mode:
            inc, out = incs2[iid], live[2]
            if not out["analysis"]: st.error(out["error"])
            else:
                an = out["analysis"]
                pred = out["baseline_pred"] if mode == "hybrid" else an["classification"]
                st.markdown(f"Triage ({'structured classifier' if mode == 'hybrid' else 'LLM'}): {pill(pred)} | true label: {pill(inc['grade'])}",
                            unsafe_allow_html=True)
                st.write(an["rationale"])
                render_summary(inc, an, out["verify"], "Summary")
                if out.get("revised"): render_summary(inc, out["revised"], out["verify_revised"], "After verifier-guided revision")
                render_evidence(inc)

with tab3:
    rp = os.path.join(results_dir, "final_report.md")
    if os.path.exists(rp): st.markdown(open(rp, encoding="utf-8").read())
    else: st.info("No report yet. Run `python -m src.report`.")

with tab4:
    st.write("Paste logs, an alert export or an incident ticket (or upload a text file). The assistant summarizes it and suggests likely "
             "ATT&CK techniques and indicators. The verifier then checks that every indicator and evidence snippet is quoted from your text.")
    st.warning("Text you analyze is sent to the LLM provider. On Gemini's free tier, inputs may be used to improve Google's products, "
               "so do not paste confidential or personal data. Use the synthetic samples to try it out.")
    if os.environ.get("LLM_PROVIDER", "gemini") == "gemini" and not os.environ.get("GEMINI_API_KEY"):
        st.warning("GEMINI_API_KEY is not set (see .env.example). Analysis will fail until it is.")
    samples = freetext.load_samples()
    choice = st.selectbox("Start from", ["Paste or upload your own"] + [x["title"] for x in samples], key="ft_choice")
    sample = next((x for x in samples if x["title"] == choice), None)
    up = st.file_uploader("...or upload a text/log file", type=["txt", "log", "json", "csv", "md"], key="ft_upload")
    box = st.text_area("Incident text", value=sample["text"] if sample else "", height=300,
                       key="ft_text_" + (sample["file"] if sample else "own"))
    ft_text = box
    if up is not None:
        ft_text = freetext.decode_upload(up.getvalue())
        st.info(f"Using the uploaded file ({len(ft_text):,} characters) instead of the text box.")
    ft_rev = st.checkbox("Run verifier-guided revision if problems are found", True, key="ft_rev")
    cur = hashlib.sha1((ft_text + str(ft_rev)).encode("utf-8", "replace")).hexdigest()
    if st.button("Analyze text"):
        with st.spinner("Calling the LLM..."):
            try: st.session_state["ft_result"] = (cur, freetext.run_freetext(ft_text, ft_rev))
            except Exception as e:
                st.session_state["ft_result"] = None; st.error(f"{type(e).__name__}: {str(e)[:300]}")
    cached = st.session_state.get("ft_result")
    if cached and cached[0] == cur:
        out = cached[1]
        if out.get("error") and not out.get("result"): st.error(out["error"])
        else:
            if out["truncated"]: st.warning(f"The text was longer than {freetext.MAX_CHARS:,} characters; only the first part was analyzed and verified.")
            st.info("These are hypotheses to help an analyst, not verdicts. The verifier checks that quoted items exist in your text; "
                    "it cannot check that a technique mapping is correct or that the story hangs together.")
            render_freetext(out["text"], out["result"], out["verify"], out["missed"], "Analysis")
            if out.get("revised"):
                render_freetext(out["text"], out["revised"], out["verify_revised"], out["missed_revised"], "After verifier-guided revision")
            ref = freetext.match_sample(ft_text, samples)
            if ref:
                final = out.get("revised") or out["result"]
                found = {t["id"] for t in final["techniques"]}
                with st.expander("Reference key for this sample"):
                    st.write(ref["key"]["shows"])
                    st.write("Techniques an analyst would expect: " + ", ".join(
                        f"{t} {'✅' if t in found else '❌ not suggested'}" for t in ref["key"]["techniques"]))
                    if ref["key"]["plausible"]: st.write("Also plausible: " + ", ".join(ref["key"]["plausible"]))
                    st.write(ref["key"]["note"])
            with st.expander("Raw model output"): st.json(out["result"])
