"""Offline tests for the verifier (no network): python -m tests.test_stage5"""
import json, os, tempfile, argparse, csv
import src.analyst as an
from src.verify import verify
from tests.test_core import INC

def A(summary, cites=(), cls="TruePositive"):
    return {"classification": cls, "confidence": 0.8, "rationale": "r",
            "summary": summary, "claims": [{"text": summary, "cites": list(cites)}]}

CLEAN = A("Alert type 39 and 6 fired in InitialAccess over 2 alerts; technique T1078.004 (Valid Accounts) "
          "affected account [account:453297].", ["[account:453297]"])

def kinds(v): return {i["type"] for i in v["issues"]}

def test_clean():
    v = verify(INC, CLEAN)
    assert not v["issues"] and not v["hallucination"] and not v["omission"], v
    assert v["critical_entity_recall"] == 1.0
    print("clean ok")

def test_each_issue_type():
    cases = {
        "unsupported_entity": A("Account [account:999999] was impacted in InitialAccess."),
        "wrong_type": A("IP [ip:453297] was impacted in InitialAccess."),                    # value exists, as an account
        "unsupported_technique": A("T1110 brute force hit [account:453297] in InitialAccess."),
        "unsupported_alert_type": A("Alert type 77 hit [account:453297] in InitialAccess."),
        "invented_literal": A("Traffic from 10.20.30.40 hit [account:453297] in InitialAccess."),
        "unsupported_date": A("On 2024-01-01 [account:453297] was hit in InitialAccess."),
        "unsupported_count": A("About 5,000 alerts hit [account:453297] in InitialAccess."),
    }
    for want, an_ in cases.items():
        v = verify(INC, an_)
        assert want in kinds(v), (want, v["issues"])
    assert verify(INC, cases["unsupported_count"])["hallucination"] is False, "soft issue must not count as hard"
    assert verify(INC, cases["unsupported_count"])["hallucination_any"] is True
    assert "unsupported_entity" in kinds(verify(INC, A("Account 777 was hit in InitialAccess [account:453297].")))  # plain mention
    assert verify(INC, A("Alert type 39 hit [Account:453297] in InitialAccess; about 2 alerts.")).get("n_hard") == 0  # case + approx
    print("issue types ok")

def test_omission():
    v = verify(INC, A("Something suspicious happened to [account:453297]."))
    assert v["omit_tactics"] and not v["omit_impact"] and v["omission"]
    v = verify(INC, A("A valid accounts compromise occurred in the InitialAccess tactic."))
    assert v["omit_impact"] and not v["omit_tactics"] and v["omission"]
    v = verify(INC, A("Initial Access via Valid Accounts: [account:453297] was impacted."))
    assert not v["omission"], "spaced tactic name and technique name should count"
    print("omission ok")

def test_alert_tags_roles_relations():
    ok = A("Alert type [alert_type:39] (also [alert type:6]) fired via [alert:1] and [alert:2] in InitialAccess; "
           "account [account:453297] was impacted; T1078.004.", ["[account:453297]"])
    assert not verify(INC, ok)["issues"], verify(INC, ok)["issues"]
    assert "unsupported_alert_id" in kinds(verify(INC, A("Hit via [alert:777] in InitialAccess; [account:453297].")))
    assert "unsupported_alert_type" in kinds(verify(INC, A("Type [alert_type:77] in InitialAccess; [account:453297].")))
    # role: 322 is an 'other' entity, and ALL (1) impacted accounts are shown -> cannot be impacted
    v = verify(INC, A("Impacted entities include [account:453297] and [account:322] in InitialAccess."))
    assert "role_misattribution" in kinds(v) and v["hallucination"], v["issues"]
    assert not verify(INC, A("Account [account:453297] was impacted in InitialAccess. Additionally, other entities include [account:322]."))["issues"]
    assert not verify(INC, A("1 account was impacted, along with a total of 3 accounts including [account:322]; [account:453297] in InitialAccess."))["issues"]
    more = dict(INC, critical_counts={"account": 3})          # 3 impacted but only 1 shown -> 322 might be impacted
    assert "role_misattribution" not in kinds(verify(more, A("Impacted entities include [account:453297] and [account:322] in InitialAccess.")))
    assert "unsupported_relation" in kinds(verify(INC, A("Alert type 39 was triggered at [account:453297] in InitialAccess.")))
    print("alert tags / roles / relations ok")

def test_revise_flow_and_labeling():
    from src.make_demo_data import main as demo; from src.prep import main as prep
    from src.run_verify import main as run_verify
    import src.labeling as lab
    d = tempfile.mkdtemp(); cwd = os.getcwd(); os.chdir(d); os.makedirs("results")
    try:
        demo("te.csv", 40, seed=3); prep("te.csv", "te.jsonl", 1, 0)
        incs = [json.loads(l) for l in open("te.jsonl")]
        with open("results/hybrid_40.jsonl", "w") as f:
            for i, inc in enumerate(incs):
                bad = i % 2 == 0
                s = "Activity occurred. " + ("[ip:99999999] is suspicious." if bad else "")
                f.write(json.dumps({"incident_id": inc["incident_id"], "grade": inc["grade"], "mode": "llm",
                                    "pred": "TruePositive", "baseline_pred": None, "analysis": A(s), "error": None}) + "\n")
        fixed = A("InitialAccess activity occurred; see " + "{TAG}.")
        an.generate = lambda prompt, **kw: json.dumps(A("Activity in " + incs[0]["categories"][0] + "; nothing unsupported."))
        run_verify(argparse.Namespace(input="results/hybrid_40.jsonl", test="te.jsonl", revise=True, out=None))
        rows = [json.loads(l) for l in open("results/verified_rev_hybrid_40.jsonl")]
        assert len(rows) == 40 and all(r["revised"] for r in rows if r["before"]["issues"])
        assert all(not r["after"]["hallucination"] for r in rows), "revision should clear hard issues here"
        assert sum(r["before"]["hallucination"] for r in rows) == 20
        run_verify(argparse.Namespace(input="results/hybrid_40.jsonl", test="te.jsonl", revise=True, out=None))  # resume: no dupes
        assert len(open("results/verified_rev_hybrid_40.jsonl").read().splitlines()) == 40
        lab.export(argparse.Namespace(input="results/hybrid_40.jsonl", test="te.jsonl", n=10))
        rows = list(csv.DictReader(open(lab.SHEET, encoding="utf-8-sig"))); assert len(rows) == 10
        for r in rows: pass
        with open(lab.SHEET, newline="", encoding="utf-8-sig") as f: rr = list(csv.DictReader(f))
        for r in rr: r["human_hallucination"] = r["auto_hallucination"]; r["human_omission"] = r["auto_omission"]
        with open(lab.SHEET, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=rr[0].keys()); w.writeheader(); w.writerows(rr)
        lab.score(argparse.Namespace())
    finally: os.chdir(cwd)
    print("revise + resume + labeling ok")

if __name__ == "__main__":
    test_clean(); test_each_issue_type(); test_omission(); test_alert_tags_roles_relations(); test_revise_flow_and_labeling()
    print("all stage 5 tests passed")
