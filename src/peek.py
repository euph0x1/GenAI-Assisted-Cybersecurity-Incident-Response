"""Print a short summary of one incident from a prep output file.
Usage: python -m src.peek [path] [line_number]"""
import json, sys
path = sys.argv[1] if len(sys.argv) > 1 else "data/incidents_train.jsonl"
n = int(sys.argv[2]) if len(sys.argv) > 2 else 0
with open(path) as f:
    for i, line in enumerate(f):
        if i == n: inc = json.loads(line); break
print("keys:", list(inc.keys()))
print("grade:", inc["grade"], "| n_alerts:", inc["n_alerts"], "| rows:", inc["n_evidence_rows"], "| span_h:", inc["time_span_hours"])
print("categories:", inc["categories"][:5], "| mitre:", inc["mitre"][:5])
print("first 2 alerts:", inc["alerts"][:2])
print("entity_counts:", inc["entity_counts"])
print("critical_counts:", inc["critical_counts"])
print("critical_evidence:", {k: v[:3] for k, v in inc["critical_evidence"].items()})
