"""Stage 3: deterministic incident narrative (no LLM, no randomness).

GUIDE is anonymized, so the only readable content is: time, alert category, MITRE
technique, counts, and entity types. Alert types and entities appear as numeric IDs,
rendered as typed tags like [account:453297] so the summarizer can cite them and the
verifier can check them exactly.

Alerts are GROUPED by (alert type, category, techniques) with counts and time windows,
so incidents with thousands of alerts are still fully represented in a bounded prompt.
The grade is NEVER included (it is the label).

Usage: python -m src.narrative data/incidents_test.jsonl 0
"""
import sys, json
from datetime import datetime
from src.mitre import label

MAX_GROUPS = 12          # alert groups shown (rest summarized as a count)
SHOW_OTHER = 5           # non-critical entities shown per type
EXAMPLES = 2             # example alert IDs per group

def _fmt(ts):
    if not ts: return "unknown time"
    try: return datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M")
    except ValueError: return str(ts)

def tag(etype, value): return f"[{etype}:{value}]"

def group_alerts(alerts):
    groups = {}
    for a in alerts:
        k = (a["title"], a["category"], tuple(a["mitre"]))
        groups.setdefault(k, []).append(a)
    out = []
    for (title, cat, mitre), items in groups.items():
        times = sorted(a["first_seen"] for a in items if a["first_seen"])
        out.append({"title": title, "category": cat, "mitre": list(mitre), "count": len(items),
                    "first": times[0] if times else None, "last": times[-1] if times else None,
                    "examples": [a["alert_id"] for a in items[:EXAMPLES]]})
    out.sort(key=lambda g: (g["first"] is None, g["first"] or "", -g["count"]))
    return out

def build_narrative(inc: dict, max_groups: int = MAX_GROUPS) -> str:
    L = [f"INCIDENT {inc['incident_id']}"]
    tr = inc.get("time_range")
    if tr: L.append(f"Time window: {_fmt(tr[0])} to {_fmt(tr[1])} UTC ({inc['time_span_hours']:.1f} hours)")
    L.append(f"Scale: {inc['n_alerts']:,} alerts, {inc['n_evidence_rows']:,} evidence records")
    if inc["categories"]: L.append("Tactic categories observed: " + ", ".join(inc["categories"]))
    if inc["mitre"]: L.append("MITRE techniques observed: " + "; ".join(label(t) for t in inc["mitre"]))

    groups = group_alerts(inc["alerts"])
    L += ["", f"Alert activity ({len(groups)} distinct alert patterns, in order of first appearance):"]
    for i, g in enumerate(groups[:max_groups], 1):
        parts = []
        if g["title"] is not None: parts.append(f"alert type {g['title']}")
        if g["category"]: parts.append(f"category {g['category']}")
        if g["mitre"]: parts.append("techniques: " + ", ".join(label(t) for t in g["mitre"]))
        if g["count"] == 1: parts.append(f"1 alert at {_fmt(g['first'])}")
        else: parts.append(f"{g['count']:,} alerts between {_fmt(g['first'])} and {_fmt(g['last'])}")
        parts.append("e.g. alert " + ", ".join(str(x) for x in g["examples"]))
        L.append(f"{i}. " + " | ".join(parts))
    if len(groups) > max_groups:
        rest = groups[max_groups:]
        L.append(f"... and {len(rest)} more alert patterns ({sum(g['count'] for g in rest):,} alerts) not shown")

    crit, ents = inc["critical_evidence"], inc["entities"]
    if crit:
        L += ["", "Impacted entities (most frequent shown):"]
        for et, vals in crit.items():
            total = inc["critical_counts"].get(et, len(vals))
            L.append(f"- {et}: " + ", ".join(tag(et, v) for v in vals) + f" ({total:,} distinct impacted)")
    other = {}
    for et, vals in ents.items():
        rest = [v for v in vals if v not in set(crit.get(et, []))][:SHOW_OTHER]
        if rest: other[et] = rest
    if other:
        L += ["", "Other entities observed (sample; some may also be impacted):"]
        for et, vals in other.items():
            L.append(f"- {et}: " + ", ".join(tag(et, v) for v in vals) +
                     f" ({inc['entity_counts'].get(et, len(vals)):,} distinct total)")
    return "\n".join(L)

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "data/incidents_test.jsonl"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    with open(path) as f:
        for i, line in enumerate(f):
            if i == n: print(build_narrative(json.loads(line))); break
