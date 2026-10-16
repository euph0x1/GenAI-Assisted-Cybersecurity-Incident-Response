"""Stage 5: evidence-grounded verifier (rule-based, no LLM).

Every checkable item in an LLM summary is compared with what the model was actually
SHOWN (the narrative text), not with the full incident, so a hallucinated value that
happens to exist elsewhere in the data is still caught.

HALLUCINATION (a summary is flagged if it has >=1 HARD issue):
  hard: unsupported_entity, wrong_type, unsupported_technique, unsupported_alert_type,
        unsupported_alert_id, invented_literal (IPv4/long hex), unsupported_date
  soft: unsupported_count (number next to a count noun that is not in the report;
        derived sums can trigger it, so it is reported separately)
OMISSION (pre-registered definition; flagged if either holds):
  omit_tactics: report has tactic categories/techniques, summary mentions none
  omit_impact : report has impacted entities, summary neither cites one nor states an
                impacted count (>=2) from the report
  Also reported (continuous): critical_entity_recall.
Omission is judged on the summary text only.
"""
import re
from src.narrative import build_narrative
from src.mitre import name as mitre_name

TAG_RE = re.compile(r"\[([A-Za-z_][A-Za-z_ ]*):([^\]\s]+)\]")
CITE_RE = re.compile(r"\[?([A-Za-z_][A-Za-z_ ]*):([^\]\s,]+)\]?")
TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
ATYPE_RE = re.compile(r"alert type (\d+)", re.I)
AID_RE = re.compile(r"\balerts? (\d{4,})\b", re.I)
DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
NUM_RE = re.compile(r"\d[\d,]*(?:\.\d+)?")
COUNT_RE = re.compile(
    r"\b(?:(over|about|approximately|nearly|around|roughly|almost|more than|at least)\s+)?(\d[\d,]*)\s+"
    r"(?:(?:distinct|unique|impacted|separate|different|related|total)\s+)*"
    r"(alerts?|evidence records?|records?|accounts?|ips?|ip addresses|devices?|applications?|files?|urls?)\b", re.I)
PLAIN_RE = re.compile(r"\b(account|device|ip|url|application)\s+#?(\d{2,})\b", re.I)
HARD = {"unsupported_entity", "wrong_type", "unsupported_technique", "unsupported_alert_type",
        "unsupported_alert_id", "invented_literal", "unsupported_date",
        "role_misattribution", "unsupported_relation"}
# an alert is never reported "at <entity>" in the narrative (only "at <timestamp>"), so this is invented
REL_RE = re.compile(r"\balerts?\b[^.\n]{0,80}?\b(?:at|on|from|by)\s+\[(?!alert)([A-Za-z_ ]+):", re.I)
CUT_RE = re.compile(r"\b(along with|alongside|in addition|additionally|other|observed among|a total of)\b", re.I)
LEAD_RE = re.compile(r"^(additionally|also|moreover|furthermore),?\s*", re.I)

def _t(t): return t.lower().strip().replace(" ", "_")
TYPE_ALIASES = {"account": "account", "device": "device", "ip": "ip", "url": "url", "application": "application"}

def _norm(s): return re.sub(r"[^a-z0-9]", "", s.lower())
def _num(s): return float(s.replace(",", "").rstrip("."))

def shown_tags(narrative):
    return {(_t(t), v) for t, v in TAG_RE.findall(narrative)}

def check_roles(inc, summary):
    """Entity cited as 'impacted' that the report lists only under 'Other entities'.
    Only flagged when the report shows ALL impacted entities of that type (shown count >= true
    impacted count), so the entity provably is not impacted. Otherwise it could be an unshown impacted one."""
    out = []
    crit, counts = inc["critical_evidence"], inc["critical_counts"]
    for sent in re.split(r"(?<=[.!?])\s+(?=[A-Z])", summary):
        if not re.search(r"\bimpact", sent, re.I): continue
        sent = LEAD_RE.sub("", sent)
        m = CUT_RE.search(sent); scope = sent[:m.start()] if m else sent
        for t, v in TAG_RE.findall(scope):
            t = _t(t)
            if t in crit and v not in crit[t] and len(crit[t]) >= counts.get(t, len(crit[t])):
                out.append((t, f"[{t}:{v}] cited as impacted; report lists all {len(crit[t])} impacted {t} and it is not one"))
    return out

def check_hallucination(inc, analysis, narrative):
    shown = shown_tags(narrative)
    text = " ".join([analysis["summary"], analysis["rationale"]] + [c["text"] for c in analysis["claims"]])
    issues, seen = [], set()
    def add(t, item):
        if (t, item) not in seen: seen.add((t, item)); issues.append({"type": t, "item": item, "severity": "hard" if t in HARD else "soft"})

    cited = {(_t(t), v) for t, v in TAG_RE.findall(text)}
    cited |= {(_t(t), v) for s in (x for c in analysis["claims"] for x in c["cites"]) for t, v in CITE_RE.findall(s)}
    alert_ids = {x.strip() for m in re.findall(r"e\.g\. alert ([\d, ]+)", narrative) for x in m.split(",") if x.strip()}
    shown_atypes = set(ATYPE_RE.findall(narrative))
    for t, v in sorted(cited):
        if t == "alert":                      # [alert:ID] cites an alert shown as plain "alert ID"
            if v not in alert_ids: add("unsupported_alert_id", f"[alert:{v}]")
            continue
        if t == "alert_type":                 # [alert_type:N] cites "alert type N"
            if v not in shown_atypes: add("unsupported_alert_type", f"[alert_type:{v}]")
            continue
        if (t, v) in shown: continue
        other = [t2 for t2, v2 in shown if v2 == v]
        add("wrong_type" if other else "unsupported_entity", f"[{t}:{v}]" + (f" (shown as {other[0]})" if other else ""))
    for m in PLAIN_RE.finditer(text):
        t, v = TYPE_ALIASES[m.group(1).lower()], m.group(2)
        if (t, v) not in shown: add("unsupported_entity", f"{t} {v} (plain mention)")

    for t, v in check_roles(inc, analysis["summary"]): add("role_misattribution", v)
    for m in REL_RE.finditer(analysis["summary"]): add("unsupported_relation", m.group(0)[:80])

    techs = set(inc["mitre"])
    for t in set(TECH_RE.findall(text)):
        if t not in techs and not any(x.startswith(t + ".") for x in techs): add("unsupported_technique", t)

    nums = {str(int(_num(x))) for x in NUM_RE.findall(narrative) if _num(x) == int(_num(x))}
    for v in set(ATYPE_RE.findall(narrative)): nums.add(v)
    atypes = set(ATYPE_RE.findall(narrative))
    for v in set(ATYPE_RE.findall(text)):
        if v not in atypes: add("unsupported_alert_type", f"alert type {v}")
    for v in set(AID_RE.findall(text)):
        if v not in nums: add("unsupported_alert_id", f"alert {v}")
    for d in set(DATE_RE.findall(text)):
        if d not in narrative: add("unsupported_date", d)
    for m in IP_RE.findall(text):
        if m not in narrative: add("invented_literal", m)
    for m in HEX_RE.findall(text):
        if m not in narrative: add("invented_literal", m[:16] + "...")

    narr_nums = [_num(x) for x in NUM_RE.findall(narrative)]
    per_type = {}
    for t, _ in shown: per_type[t] = per_type.get(t, 0) + 1
    derived = set(per_type.values())
    for m in COUNT_RE.finditer(text):
        approx, x = m.group(1), _num(m.group(2))
        ok = x in narr_nums or x in derived
        if approx and not ok: ok = any(abs(n - x) <= 0.1 * max(n, 1) for n in narr_nums)
        if not ok: add("unsupported_count", m.group(0))
    return issues

def check_omission(inc, analysis):
    s = analysis["summary"]; ns = _norm(s)
    cited = {(_t(t), v) for t, v in TAG_RE.findall(s)}
    crit = inc["critical_evidence"]
    items = {(t, v) for t, vs in crit.items() for v in vs}
    recall = len(cited & items) / len(items) if items else None
    omit_tactics = False
    if inc["categories"] or inc["mitre"]:
        names = [_norm(c) for c in inc["categories"]]
        for t in inc["mitre"]:
            names.append(_norm(t))
            n = mitre_name(t)
            if n: names += [_norm(n)] + [_norm(p) for p in n.split(":")]
        omit_tactics = not any(x and x in ns for x in names)
    omit_impact = False
    if crit:
        counts = {str(int(c)) for c in inc["critical_counts"].values() if c >= 2}
        s_nums = {str(int(_num(x))) for x in NUM_RE.findall(s) if _num(x) == int(_num(x))}
        omit_impact = not (cited & items) and not (counts & s_nums)
    return {"critical_entity_recall": recall, "omit_tactics": omit_tactics,
            "omit_impact": omit_impact, "omission": omit_tactics or omit_impact}

def verify(inc, analysis, narrative=None):
    narrative = narrative or build_narrative(inc)
    issues = check_hallucination(inc, analysis, narrative)
    om = check_omission(inc, analysis)
    hard = [i for i in issues if i["severity"] == "hard"]
    return {"issues": issues, "n_hard": len(hard), "n_soft": len(issues) - len(hard),
            "hallucination": bool(hard), "hallucination_any": bool(issues),
            "n_claims": len(analysis["claims"]), **om}
