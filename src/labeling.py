"""Hand-label a sample to validate the automatic verifier.

  python -m src.labeling export --input results/hybrid_150.jsonl --n 50
      -> results/labeling_sheet.csv  (open in Excel; fill human_hallucination / human_omission with 0 or 1)
  python -m src.labeling score
      -> agreement between your labels and the verifier (confusion matrix, precision, recall, kappa)

The sample is half verifier-flagged, half unflagged, so you can estimate both false positives and misses.
Label from the REPORT column only: hallucination = the summary states something the report does not support;
omission = the summary leaves out something critical (tactics, or what was impacted).
"""
import argparse, csv, json, random
from src.classify import load
from src.narrative import build_narrative
from src.verify import verify, TAG_RE, TECH_RE
import re

SHEET = "results/labeling_sheet.csv"

def export(a):
    inc = {r["incident_id"]: r for r in load(a.test)}
    excl = set()
    if getattr(a, "exclude", None):   # skip incidents already labeled, so the new sample is unseen
        excl = {int(r["incident_id"]) for r in csv.DictReader(open(a.exclude, encoding="utf-8-sig"))}
    rows = []
    for l in open(a.input):
        r = json.loads(l)
        if not r["analysis"] or r["incident_id"] in excl: continue
        v = verify(inc[r["incident_id"]], r["analysis"])
        rows.append((r, v))
    rng = random.Random(getattr(a, 'seed', 7))
    flagged = [x for x in rows if x[1]["hallucination"] or x[1]["omission"]]
    clean = [x for x in rows if not (x[1]["hallucination"] or x[1]["omission"])]
    pick = rng.sample(flagged, min(a.n // 2, len(flagged))) + rng.sample(clean, min(a.n - a.n // 2, len(clean)))
    if len(pick) < min(a.n, len(rows)):   # one pool too small: top up from the rest
        taken = {id(x) for x in pick}
        rest = [x for x in rows if id(x) not in taken]
        pick += rng.sample(rest, min(a.n - len(pick), len(rest)))
    rng.shuffle(pick)
    with open(SHEET, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["incident_id", "report", "summary", "human_hallucination", "human_omission", "notes",
                    "auto_hallucination", "auto_omission", "auto_issues"])
        for r, v in pick:
            w.writerow([r["incident_id"], build_narrative(inc[r["incident_id"]]), r["analysis"]["summary"], "", "", "",
                        int(v["hallucination"]), int(v["omission"]), "; ".join(f"{i['type']}:{i['item']}" for i in v["issues"])])
    print(f"wrote {len(pick)} rows to {SHEET}. Fill the human_* columns with 0/1 (keep the auto_* columns hidden while labeling).")

def inc_from_narrative(report):
    """Rebuild the fields the verifier needs from the narrative text (deterministic format)."""
    inc = {"categories": [], "mitre": [], "critical_evidence": {}, "critical_counts": {}}
    sec = None
    for line in report.splitlines():
        if line.startswith("Tactic categories observed:"): inc["categories"] = [c.strip() for c in line.split(":", 1)[1].split(",")]
        elif line.startswith("MITRE techniques observed:"): inc["mitre"] = sorted(set(TECH_RE.findall(line)))
        elif line.startswith("Impacted entities"): sec = "imp"
        elif line.startswith("Other entities"): sec = "oth"
        elif sec == "imp":
            m = re.match(r"- (\w+): (.*) \(([\d,]+) distinct impacted\)", line)
            if m:
                inc["critical_evidence"][m.group(1)] = [v for _, v in TAG_RE.findall(m.group(2))]
                inc["critical_counts"][m.group(1)] = int(m.group(3).replace(",", ""))
    return inc

def recompute(rows):
    """Re-run the CURRENT verifier on the sheet's report+summary (no incident data needed)."""
    for r in rows:
        an = {"summary": r["summary"], "rationale": "", "claims": []}
        v = verify(inc_from_narrative(r["report"]), an, narrative=r["report"])
        r["auto_hallucination"], r["auto_omission"] = int(v["hallucination"]), int(v["omission"])
        r["auto_issues"] = "; ".join(f"{i['type']}:{i['item']}" for i in v["issues"])
    return rows

def kappa(a, b):
    n = len(a); po = sum(x == y for x, y in zip(a, b)) / n
    pe = sum((sum(x == k for x in a) / n) * (sum(y == k for y in b) / n) for k in (0, 1))
    return (po - pe) / (1 - pe) if pe < 1 else 1.0

def score(a):
    sheet = getattr(a, "sheet", None) or SHEET
    rows = [r for r in csv.DictReader(open(sheet, encoding="utf-8-sig")) if r["human_hallucination"].strip() != ""]
    if getattr(a, "recompute", False): rows = recompute(rows); print("(auto columns recomputed with the current verifier)")
    print(f"{len(rows)} labeled rows")
    for h, au in [("human_hallucination", "auto_hallucination"), ("human_omission", "auto_omission")]:
        pairs = [(int(r[h]), int(r[au])) for r in rows if r[h].strip() != ""]
        if not pairs: continue
        tp = sum(p == (1, 1) for p in pairs); fp = sum(p == (0, 1) for p in pairs)
        fn = sum(p == (1, 0) for p in pairs); tn = sum(p == (0, 0) for p in pairs)
        prec = tp / (tp + fp) if tp + fp else float("nan"); rec = tp / (tp + fn) if tp + fn else float("nan")
        print(f"\n{h[6:]}: TP={tp} FP={fp} FN={fn} TN={tn} | precision={prec:.2f} recall={rec:.2f} "
              f"kappa={kappa([p[0] for p in pairs], [p[1] for p in pairs]):.2f}")
    print("\nNote: the sample is stratified (half flagged), so precision/recall describe this sample, not the population.")

if __name__ == "__main__":
    p = argparse.ArgumentParser(); p.add_argument("cmd", choices=["export", "score"])
    p.add_argument("--input", default="results/hybrid_150.jsonl"); p.add_argument("--test", default="data/incidents_test.jsonl")
    p.add_argument("--n", type=int, default=50)
    p.add_argument("--sheet"); p.add_argument("--recompute", action="store_true")
    p.add_argument("--exclude"); p.add_argument("--seed", type=int, default=7)
    a = p.parse_args(); export(a) if a.cmd == "export" else score(a)
