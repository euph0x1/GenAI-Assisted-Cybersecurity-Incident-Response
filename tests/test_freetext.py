"""Offline tests for free-text mode: python -m tests.test_freetext"""
import json, re
import src.freetext as ft
from src import viewer

SAMPLES = ft.load_samples("samples")
PHISH = next(s for s in SAMPLES if s["file"].startswith("phishing"))["text"]

GOOD = {"summary": "On 2026-10-06 the user received mail from docs-notify@sharepoint-docs-secure.example, opened "
                   "https://sharepoint-docs-secure.example/view?id=88f1c2 and posted to its login page. A sign-in from 203.0.113.58 "
                   "without MFA followed, then an inbox rule forwarding to archive.reports@mail-relay-demo.example.",
        "activity": {"likely_activity": "Phishing leading to account takeover (hypothesis)", "confidence": 0.8,
                     "evidence": ["SIGNIN_SUCCESS user=priya.nair@contoso-demo.example ip=203.0.113.58"]},
        "techniques": [{"id": "T1566.002", "name": "Phishing: Spearphishing Link",
                        "evidence": "URL_FOUND hxxps://sharepoint-docs-secure[.]example/view?id=88f1c2"},
                       {"id": "T1114.003", "name": "Email Collection: Email Forwarding Rule",
                        "evidence": "New-InboxRule user=priya.nair@contoso-demo.example"}],
        "indicators": [{"type": "ip", "value": "203.0.113.58", "context": "unknown sign-in"},
                       {"type": "url", "value": "https://sharepoint-docs-secure.example/view?id=88f1c2", "context": "phishing link"},
                       {"type": "email", "value": "archive.reports@mail-relay-demo.example", "context": "forward target"}],
        "alternative_explanations": ["The user signed in from a new network while travelling"],
        "unknowns": ["What was in the 214 accessed items"], "recommended_actions": ["Reset the password and revoke sessions"]}

def kinds(v): return {i["type"] for i in v["issues"]}

def test_normalisation_and_present():
    tn = ft.norm_text("hxxps://Evil[.]Example/Login   x")
    assert tn == "https://evil.example/login x"
    assert ft.present("https://evil.example/login", tn) and ft.present("EVIL.example", tn)
    assert not ft.present("10.20.4.3", ft.norm_text("src=10.20.4.37 ")), "IP must match on token boundaries"
    assert ft.present("10.20.4.37", ft.norm_text("src=10.20.4.37,")) and ft.present("203.0.113.9", ft.norm_text("dst=203.0.113.9:443"))
    assert ft.snippet_present("New-InboxRule user=...", ft.norm_text(PHISH)), "a trailing ellipsis is trimmed, the prefix is quoted"
    assert ft.snippet_present("New-InboxRule ...", ft.norm_text(PHISH))
    assert not ft.snippet_present("New-InboxRule ... ForwardTo", ft.norm_text(PHISH)), "an ellipsis in the middle is not verbatim"
    assert not ft.snippet_present("ab", ft.norm_text(PHISH)), "snippets under 3 characters are rejected"
    print("normalisation ok")

def test_verify_good_and_bad():
    v = ft.verify_text(PHISH, ft.validate_result(GOOD))
    assert not v["issues"] and not v["hallucination"], v["issues"]
    assert all(i["found_in_text"] for i in v["indicator_status"]) and all(t["evidence_found"] for t in v["technique_status"])
    bad = json.loads(json.dumps(GOOD))
    bad["summary"] += " Traffic also reached 198.51.100.7 and evil.example (CVE-2024-12345, hash " + "a" * 64 + ")."
    bad["summary"] += " This began on 2026-10-07 at 23:59:59."
    bad["indicators"].append({"type": "ip", "value": "203.0.113.99", "context": "x"})
    bad["indicators"].append({"type": "ip", "value": "10.20.4.3", "context": "prefix of 10.20.4.37"})
    bad["activity"]["evidence"].append("the attacker logged in via VPN")
    bad["techniques"] += [{"id": "T12", "name": "x", "evidence": "SIGNIN_SUCCESS"},
                          {"id": "T1059.001", "name": "PowerShell", "evidence": "powershell -enc AAAA"},
                          {"id": "T1110", "name": "Phishing", "evidence": "SIGNIN_SUCCESS"}]
    v = ft.verify_text(PHISH, ft.validate_result(bad))
    assert {"unsupported_indicator", "invented_literal", "unsupported_evidence", "invalid_technique_id",
            "unsupported_technique_evidence", "technique_name_mismatch", "unverified_datetime"} <= kinds(v), kinds(v)
    items = {i["item"] for i in v["issues"]}
    assert {"203.0.113.99", "10.20.4.3", "198.51.100.7", "evil.example", "CVE-2024-12345"} <= items, items
    assert v["hallucination"] and v["n_soft"] >= 2
    soft = {i["type"] for i in v["issues"] if i["severity"] == "soft"}
    assert soft == {"technique_name_mismatch", "unverified_datetime"}, "format/lookup issues must stay soft"
    print("verify ok")

def test_missed_and_extract():
    io = ft.extract_iocs(PHISH)
    assert "203.0.113.58" in io["ip"] and "192.0.2.14" in io["ip"] and "10.20.4.37" in io["ip"]
    assert "https://sharepoint-docs-secure.example/view?id=88f1c2" in io["url"] and "priya.nair@contoso-demo.example" in io["email"]
    r = ft.validate_result(GOOD)
    miss = {(m["type"], m["value"]) for m in ft.missed_indicators(PHISH, r)}
    assert ("ip", "192.0.2.14") in miss and ("ip", "10.20.4.37") in miss and ("ip", "203.0.113.58") not in miss
    assert ("email", "archive.reports@mail-relay-demo.example") not in miss
    print("missed/extract ok")

def test_parse():
    r = ft.parse_result("```json\n" + json.dumps(GOOD) + "\n```"); assert r["activity"]["confidence"] == 0.8
    assert ft.parse_result(json.dumps({"summary": "s", "activity": {"confidence": "85%"}}))["activity"]["confidence"] == 0.85
    for bad in ["nope", "{}", '{"summary": "s", "activity": {"confidence": 7000}}', '{"summary": "s", "techniques": ["x"]}']:
        try: ft.parse_result(bad); raise AssertionError("should fail: " + bad)
        except ValueError: pass
    print("parse ok")

def test_pipeline():
    bad = json.loads(json.dumps(GOOD)); bad["summary"] += " Also seen: 198.51.100.7."
    calls = []
    def gen(replies):
        def g(prompt, **kw): calls.append(prompt); return replies[min(len(calls) - 1, len(replies) - 1)]
        return g
    ft.generate = gen([json.dumps(bad), json.dumps(GOOD)])
    out = ft.run_freetext(PHISH)
    assert out["verify"]["hallucination"] and out["verify_revised"]["hallucination"] is False and len(calls) == 2
    assert "<incident_text>" in calls[0] and "UNTRUSTED" in ft.SYSTEM and "198.51.100.7" in calls[1], "wrapper + problems fed back"
    calls.clear(); ft.generate = gen([json.dumps(bad)]); out = ft.run_freetext(PHISH, do_revise=False)
    assert len(calls) == 1 and "revised" not in out
    calls.clear(); ft.generate = gen(["garbage", json.dumps(GOOD)]); out = ft.run_freetext(PHISH)
    assert out["result"] and len(calls) == 2 and not out["verify"]["issues"], "repair path"
    calls.clear(); ft.generate = gen(["garbage"]); out = ft.run_freetext(PHISH)
    assert out["result"] is None and out["error"].startswith("parse_error")
    assert "too short" in ft.run_freetext("hi")["error"]
    t, trunc = ft.truncate("x" * (ft.MAX_CHARS + 5)); assert len(t) == ft.MAX_CHARS and trunc
    print("pipeline ok")

def test_highlight_defanged():
    s = "Link hxxps://evil[.]example/x was opened."
    issues = [{"type": "invented_literal", "item": "hxxps://evil[.]example/x", "severity": "hard"}]
    h = viewer.highlight_html(s, issues)
    assert '<mark class="hard"' in h and "hxxps://evil[.]example/x</mark>" in h, h
    print("defanged highlight ok")

def test_samples_are_safe_and_wellformed():
    assert len(SAMPLES) == 9
    allowed = re.compile(r"^(192\.0\.2|198\.51\.100|203\.0\.113|10)\.")
    for s in SAMPLES:
        assert s["text"].startswith("SYNTHETIC SAMPLE"), s["file"]
        for ip in ft.IP_RE.findall(s["text"]):
            assert allowed.match(ip), f"{s['file']}: {ip} is not a documentation/private address"
        for typ, lit in ft.scan_literals(s["text"]):
            if typ in ("domain", "email"): assert lit.lower().endswith(".example"), f"{s['file']}: real-looking domain {lit}"
        k = s["key"]; assert k["title"] and k["note"] and k["shows"]
        assert all(ft.TECH_ID.match(t) for t in k["techniques"] + k["plausible"]), s["file"]
    assert len(ft.HASH_RE.findall(next(s for s in SAMPLES if s["file"].startswith("ransom"))["text"])) == 1
    assert ft.match_sample("  " + PHISH.upper() + " ", SAMPLES)["file"].startswith("phishing"), "match ignores case/whitespace"
    assert ft.match_sample("something else entirely", SAMPLES) is None
    print("samples ok")

if __name__ == "__main__":
    test_normalisation_and_present(); test_verify_good_and_bad(); test_missed_and_extract(); test_parse()
    test_pipeline(); test_highlight_defanged(); test_samples_are_safe_and_wellformed(); print("all free-text tests passed")
