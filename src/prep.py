"""Stage 1: turn GUIDE's row-per-evidence CSV into one JSON object per incident.

Usage:
  python -m src.prep --csv data/GUIDE_Train.csv --out data/incidents_train.jsonl --sample-mod 200
  python -m src.prep --csv data/GUIDE_Test.csv  --out data/incidents_test.jsonl  --sample-mod 200

--sample-mod K keeps incidents whose IncidentId % K == 0 (consistent incident-level
sampling). The real files are large, so they are read in chunks.

GUIDE is anonymized: alert titles and entities are opaque numeric IDs. Category and
MITRE techniques are readable. Entity value "0" is treated as a placeholder and dropped.
"""
import argparse, json, random
from collections import Counter
import pandas as pd

KEEP_GRADES = {"TruePositive", "BenignPositive", "FalsePositive"}
ENTITY_COLS = {
    "IpAddress": "ip", "Url": "url", "Sha256": "file_hash", "FileName": "file_name",
    "AccountName": "account", "AccountUpn": "account_upn", "DeviceName": "device",
    "ApplicationName": "application", "ThreatFamily": "threat_family",
    "RegistryKey": "registry_key", "FolderPath": "folder_path",
}
ENTITY_NAMES = list(ENTITY_COLS.values())
MAX_PER_TYPE = 25     # entities stored per type (LLM-sized); true counts kept separately
CRIT_TOP_N = 5        # critical evidence the summary is expected to cover, per type
PLACEHOLDERS = {"0", "nan", "", "None"}

def norm(v) -> str:
    s = str(v).strip()
    return s[:-2] if s.endswith(".0") and s[:-2].isdigit() else s

def split_mitre(series):
    out = []
    for v in series.dropna().astype(str):
        out += [t.strip() for t in v.replace(";", ",").split(",") if t.strip()]
    return out

def first_valid(df, col):
    if col in df and df[col].notna().any():
        v = df[col].dropna().iloc[0]
        return v.item() if hasattr(v, "item") else v
    return None

def build_incident(inc_id, g: pd.DataFrame) -> dict:
    grade = g["IncidentGrade"].dropna().mode()
    ts = pd.to_datetime(g["Timestamp"], errors="coerce") if "Timestamp" in g else None
    has_ts = ts is not None and ts.notna().any()
    alerts = []
    for aid, ag in g.groupby("AlertId", sort=False):
        a_ts = pd.to_datetime(ag["Timestamp"], errors="coerce").min() if "Timestamp" in ag else None
        alerts.append({
            "alert_id": int(aid),
            "title": first_valid(ag, "AlertTitle"),
            "category": first_valid(ag, "Category"),
            "mitre": sorted(set(split_mitre(ag["MitreTechniques"]))) if "MitreTechniques" in ag else [],
            "first_seen": a_ts.isoformat() if a_ts is not None and pd.notna(a_ts) else None,
        })
    entities, entity_counts, critical, critical_counts = {}, {}, {}, {}
    has_role = "EvidenceRole" in g
    for col, name in ENTITY_COLS.items():
        if col not in g: continue
        sub = g[[col] + (["EvidenceRole"] if has_role else [])].dropna(subset=[col]).copy()
        sub[col] = sub[col].map(norm)
        sub = sub[~sub[col].isin(PLACEHOLDERS)]
        if sub.empty: continue
        counts = Counter(sub[col])
        entity_counts[name] = len(counts)
        entities[name] = [v for v, _ in counts.most_common(MAX_PER_TYPE)]
        if has_role:
            imp = Counter(sub[sub["EvidenceRole"] == "Impacted"][col])
            if imp:
                critical_counts[name] = len(imp)
                critical[name] = [v for v, _ in imp.most_common(CRIT_TOP_N)]
    span_h = float((ts.max() - ts.min()).total_seconds() / 3600) if has_ts else 0.0
    return {
        "incident_id": int(inc_id),
        "org_id": first_valid(g, "OrgId"),
        "grade": grade.iloc[0] if len(grade) else None,
        "n_alerts": len(alerts),
        "n_evidence_rows": int(len(g)),
        "time_range": [ts.min().isoformat(), ts.max().isoformat()] if has_ts else None,
        "time_span_hours": round(span_h, 3),
        "categories": sorted({a["category"] for a in alerts if a["category"]}),
        "mitre": sorted({t for a in alerts for t in a["mitre"]}),
        "alerts": alerts,
        "entities": entities,
        "entity_counts": entity_counts,
        "critical_evidence": critical,
        "critical_counts": critical_counts,
    }

def _default(o):
    return o.item() if hasattr(o, "item") else str(o)

def _select_rows(csv, chunksize, sample_mod, min_alerts, max_incidents):
    """Return the filtered rows. Two modes:
      sample mode (default): keep incidents with IncidentId % sample_mod == 0
      size mode (min_alerts>0): keep ALL incidents with >= min_alerts distinct alerts (two passes over the file),
                                optionally a seeded random sample of max_incidents of them"""
    if not min_alerts:
        parts = []
        for chunk in pd.read_csv(csv, chunksize=chunksize, low_memory=False):
            chunk = chunk[chunk["IncidentGrade"].isin(KEEP_GRADES)]
            chunk = chunk[chunk["IncidentId"] % sample_mod == 0]
            if len(chunk): parts.append(chunk)
        return pd.concat(parts, ignore_index=True), max_incidents
    pairs = []   # pass 1: distinct (incident, alert) pairs -> alerts per incident
    for chunk in pd.read_csv(csv, chunksize=chunksize, low_memory=False, usecols=["IncidentId", "AlertId", "IncidentGrade"]):
        chunk = chunk[chunk["IncidentGrade"].isin(KEEP_GRADES)]
        pairs.append(chunk[["IncidentId", "AlertId"]].drop_duplicates())
    cnt = pd.concat(pairs).drop_duplicates().groupby("IncidentId").size()
    ids = sorted(int(i) for i in cnt[cnt >= min_alerts].index)
    print(f"{len(ids):,} incidents with >= {min_alerts} alerts in the full file")
    if max_incidents and len(ids) > max_incidents:
        ids = sorted(random.Random(42).sample(ids, max_incidents))
    keep = set(ids)
    parts = []   # pass 2: only the rows of the chosen incidents
    for chunk in pd.read_csv(csv, chunksize=chunksize, low_memory=False):
        chunk = chunk[chunk["IncidentGrade"].isin(KEEP_GRADES) & chunk["IncidentId"].isin(keep)]
        if len(chunk): parts.append(chunk)
    return pd.concat(parts, ignore_index=True), 0

def main(csv, out, sample_mod, max_incidents, chunksize=500_000, min_alerts=0):
    df, max_incidents = _select_rows(csv, chunksize, sample_mod, min_alerts, max_incidents)
    print(f"{len(df):,} rows kept, {df['IncidentId'].nunique():,} incidents")
    n = 0
    with open(out, "w") as f:
        for inc_id, g in df.groupby("IncidentId", sort=True):
            f.write(json.dumps(build_incident(inc_id, g), default=_default) + "\n"); n += 1
            if max_incidents and n >= max_incidents: break
    print(f"wrote {n} incidents -> {out}")
    dist = Counter(json.loads(l)["grade"] for l in open(out))
    print("grade distribution:", dict(dist))

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--csv", required=True); p.add_argument("--out", default="data/incidents.jsonl")
    p.add_argument("--sample-mod", type=int, default=1)
    p.add_argument("--max-incidents", type=int, default=0)
    p.add_argument("--min-alerts", type=int, default=0,
                   help="keep ALL incidents with >= N alerts (ignores --sample-mod); use with --max-incidents to cap")
    a = p.parse_args(); main(a.csv, a.out, a.sample_mod, a.max_incidents, min_alerts=a.min_alerts)
