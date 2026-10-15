"""Generate a small GUIDE-shaped CSV so the pipeline can be tested offline.
Real data: https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction
Usage: python -m src.make_demo_data --out data/demo_guide.csv --n 300
"""
import argparse, random
import numpy as np
import pandas as pd

CATS = ["InitialAccess", "Execution", "Persistence", "CredentialAccess",
        "LateralMovement", "Exfiltration", "CommandAndControl", "Impact"]
MITRE = ["T1566", "T1059", "T1078", "T1003", "T1021", "T1041", "T1071", "T1486"]
TITLES = ["Suspicious PowerShell command line", "Anomalous sign-in activity",
          "Malware detected on endpoint", "Credential dumping attempt",
          "Suspicious inbox forwarding rule", "Unusual data upload volume"]
GRADES = ["TruePositive", "BenignPositive", "FalsePositive"]
ROLES = ["Impacted", "Related"]
ETYPES = ["Ip", "User", "Machine", "File", "Url", "Process"]

def rand_ip(r): return f"{r.randint(1,223)}.{r.randint(0,255)}.{r.randint(0,255)}.{r.randint(1,254)}"

def main(out, n, seed=7):
    r = random.Random(seed); rows = []
    for inc in range(n):
        grade = r.choices(GRADES, weights=[0.45, 0.30, 0.25])[0]
        n_alerts = r.randint(1, 5)
        t0 = pd.Timestamp("2024-06-01") + pd.Timedelta(minutes=r.randint(0, 20000))
        for a in range(n_alerts):
            k = r.randrange(len(CATS))
            alert_id = inc * 100 + a
            for _ in range(r.randint(2, 6)):
                et = r.choice(ETYPES)
                row = dict(Id=len(rows), OrgId=r.randint(0, 20), IncidentId=inc,
                           AlertId=alert_id, Timestamp=(t0 + pd.Timedelta(minutes=a*7)).isoformat(),
                           DetectorId=r.randint(0, 50), AlertTitle=r.choice(TITLES),
                           Category=CATS[k], MitreTechniques=MITRE[k] if r.random() < .8 else np.nan,
                           IncidentGrade=grade, EntityType=et, EvidenceRole=r.choice(ROLES))
                if et == "Ip": row["IpAddress"] = rand_ip(r)
                if et == "User": row["AccountName"] = f"user{r.randint(1,200)}"
                if et == "Machine": row["DeviceName"] = f"WKS-{r.randint(1,300):03d}"
                if et == "File": row["FileName"] = r.choice(["a.exe", "payload.dll", "inv.docm"]); row["Sha256"] = f"{r.getrandbits(128):032x}"
                if et == "Url": row["Url"] = f"http://bad{r.randint(1,50)}.example.net/x"
                if et == "Process": row["FileName"] = r.choice(["powershell.exe", "cmd.exe", "rundll32.exe"])
                rows.append(row)
    pd.DataFrame(rows).to_csv(out, index=False)
    print(f"wrote {len(rows)} rows / {n} incidents -> {out}")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="data/demo_guide.csv"); p.add_argument("--n", type=int, default=300)
    a = p.parse_args(); main(a.out, a.n)
