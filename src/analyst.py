"""Stage 4: LLM triage + summary for one incident (single JSON call per incident).

modes:
  llm     the LLM classifies the incident itself (zero-shot) and summarizes it
  hybrid  a structured classifier supplies the label; the LLM explains/summarizes it

The summary must cite entities as [type:id]; `claims` lists atomic statements with their
citations. The Stage 5 verifier checks both against the incident's evidence.
"""
import json, re
from src.llm import generate
from src.narrative import build_narrative

LABELS = ("TruePositive", "BenignPositive", "FalsePositive")

def _conf(v):
    if isinstance(v, str): v = float(v.strip().rstrip("%"))
    if isinstance(v, bool) or not isinstance(v, (int, float)): raise ValueError("confidence must be a number")
    v = v / 100 if 1 < v <= 100 else v     # tolerate 85 or "85%" meaning 0.85
    if not 0 <= v <= 1: raise ValueError("confidence out of range")
    return float(v)

def validate_analysis(d) -> dict:
    if not isinstance(d, dict): raise ValueError("top-level JSON must be an object")
    if d.get("classification") not in LABELS: raise ValueError(f"bad classification: {d.get('classification')!r}")
    for k in ("rationale", "summary"):
        if not isinstance(d.get(k), str) or not d[k].strip(): raise ValueError(f"missing/empty {k}")
    claims = d.get("claims", [])
    if not isinstance(claims, list): raise ValueError("claims must be a list")
    clean = []
    for c in claims:
        if not isinstance(c, dict) or not isinstance(c.get("text"), str): raise ValueError("bad claim")
        cites = c.get("cites", [])
        if not isinstance(cites, list) or not all(isinstance(x, str) for x in cites): raise ValueError("bad cites")
        clean.append({"text": c["text"], "cites": cites})
    return {"classification": d["classification"], "confidence": _conf(d.get("confidence")),
            "rationale": d["rationale"].strip(), "summary": d["summary"].strip(), "claims": clean}

SYSTEM = """You are a SOC analyst assistant. You receive an incident report generated from anonymized security telemetry. Triage and summarize it.

Class definitions:
- TruePositive: the alerts reflect real malicious activity.
- BenignPositive: the alerts fired correctly on activity that is real but legitimate or expected (for example authorized testing or normal administrative behaviour).
- FalsePositive: the alerts fired incorrectly; there was no real triggering activity.

Rules:
1. Use ONLY facts stated in the report. Alert types, accounts, IPs and other entities are anonymized numeric IDs: do not guess what they represent.
2. When you mention a specific entity, cite it exactly as written in the report, e.g. [account:94]. Never cite an entity that is not in the report. Never invent IDs, IPs, hostnames, hashes, dates or MITRE techniques.
3. Use counts exactly as given in the report. Do not imply you can see more entities than listed; refer to totals using the counts provided.
4. If the evidence is not sufficient to be confident, lower your confidence and say so.
5. Reply with ONLY a JSON object, no markdown fences."""

SCHEMA = """Return a JSON object with exactly these keys:
{"classification": "TruePositive" | "BenignPositive" | "FalsePositive",
 "confidence": <number between 0 and 1>,
 "rationale": "<1-3 sentences explaining the classification using evidence from the report>",
 "summary": "<3-6 sentences for a SOC analyst: what happened, scale, techniques, what was impacted. Cite entities inline as [type:id]>",
 "claims": [{"text": "<one factual statement from your summary>", "cites": ["[type:id]", ...]}]}"""

REPAIR = "\n\nYour previous reply was not valid JSON matching the schema. Reply with ONLY the JSON object."

def parse_analysis(text: str) -> dict:
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
    a, b = t.find("{"), t.rfind("}")
    if a < 0 or b < a: raise ValueError("no JSON object found")
    return validate_analysis(json.loads(t[a:b + 1]))

def build_prompt(inc, mode="llm", predicted=None, confidence=None):
    p = f"INCIDENT REPORT\n{build_narrative(inc)}\n\n"
    if mode == "hybrid":
        c = f" (confidence {confidence:.2f})" if confidence is not None else ""
        p += (f"A structured triage model assessed this incident as {predicted}{c}. Set your classification to "
              f"{predicted} and explain which evidence in the report is consistent with it. If the report "
              f"evidence clearly conflicts with that assessment, say so in the rationale.\n\n")
    return p + SCHEMA

def analyze(inc, mode="llm", predicted=None, confidence=None):
    """Returns {"analysis": dict|None, "error": str|None, "raw": str|None}.
    API/quota exceptions are NOT caught here: the caller decides whether to stop and resume."""
    prompt = build_prompt(inc, mode, predicted, confidence)
    raw = generate(prompt, system=SYSTEM, json_mode=True)
    try:
        return {"analysis": parse_analysis(raw), "error": None, "raw": None}
    except ValueError:
        raw2 = generate(prompt + REPAIR, system=SYSTEM, json_mode=True)  # different prompt -> own cache entry
        try:
            return {"analysis": parse_analysis(raw2), "error": None, "raw": None}
        except ValueError as e2:
            return {"analysis": None, "error": f"parse_error: {str(e2)[:200]}", "raw": raw2[:2000]}


def build_revision_prompt(inc, analysis, v, mode="llm", predicted=None, confidence=None):
    problems = "\n".join(f"- {i['type']}: {i['item']}" for i in v["issues"]) or "- (none)"
    todo = []
    if v["omit_impact"]:
        todo.append("- The summary must cite at least one impacted entity as [type:id], or state how many entities were impacted, using the counts in the report.")
    if v["omit_tactics"]:
        todo.append("- The summary must name the tactic categories and/or MITRE techniques observed in the report.")
    return (build_prompt(inc, mode, predicted, confidence)
            + "\n\nYour previous answer was:\n" + json.dumps(analysis)
            + "\n\nAn automatic check of that answer against the report found these problems:\n" + problems
            + ("\n" + "\n".join(todo) if todo else "")
            + "\n\nRewrite the JSON answer. Remove or correct every unsupported item, use only facts and entity tags "
              "that appear in the report, and keep the same classification and confidence. Return ONLY the JSON object.")

def revise(inc, analysis, v, mode="llm", predicted=None, confidence=None):
    """One verifier-feedback revision. Returns a new analysis dict, or None if the reply was unusable.
    Classification/confidence are pinned to the original so only the summary changes."""
    raw = generate(build_revision_prompt(inc, analysis, v, mode, predicted, confidence), system=SYSTEM, json_mode=True)
    try: new = parse_analysis(raw)
    except ValueError: return None
    new["classification"], new["confidence"] = analysis["classification"], analysis["confidence"]
    return new
