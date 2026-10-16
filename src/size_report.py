"""How many test incidents exist per size bin (run before --extra-large).
  python -m src.size_report data/incidents_test.jsonl"""
import json, sys
from collections import Counter
path = sys.argv[1] if len(sys.argv) > 1 else "data/incidents_test.jsonl"
rows = [json.loads(l) for l in open(path)]
bins = [(1, 5), (6, 20), (21, 50), (51, 200), (201, 10**9)]
for lo, hi in bins:
    g = [r for r in rows if lo <= r["n_alerts"] <= hi]
    print(f"alerts {lo:>4}-{hi if hi < 10**9 else '+':<5} {len(g):5d} incidents  {dict(Counter(r['grade'] for r in g))}")
