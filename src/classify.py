"""Stage 2: structured-feature baseline classifier (XGBoost) for incident triage.

Dev loop (uses ONLY the train file; org-grouped, stratified validation split):
  python -m src.classify --train data/incidents_train.jsonl

Final, one-time evaluation on the held-out test file (do not tune on this):
  python -m src.classify --train data/incidents_train.jsonl --test data/incidents_test.jsonl --eval-test

--model hgb uses scikit-learn gradient boosting instead of XGBoost (fallback).
"""
import argparse, json, os
from collections import Counter
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold
from sklearn.utils.class_weight import compute_sample_weight

from src.prep import ENTITY_NAMES

CLASSES = ["BenignPositive", "FalsePositive", "TruePositive"]  # fixed label order
TOP_MITRE, TOP_TITLES = 40, 30

def load(path):
    with open(path) as f:
        rows = [json.loads(l) for l in f]
    if rows and "entity_counts" not in rows[0]:
        raise SystemExit(f"{path} was made by an older prep.py. Re-run src.prep first.")
    return rows

class Featurizer:
    """Vocabulary (categories, top MITRE techniques, top alert titles) is fit on train only."""
    def fit(self, rows):
        cats, mit, tit = Counter(), Counter(), Counter()
        for r in rows:
            cats.update(r["categories"]); mit.update(r["mitre"])
            tit.update(str(a["title"]) for a in r["alerts"] if a["title"] is not None)
        self.cats = sorted(cats)
        self.mitre = [t for t, _ in mit.most_common(TOP_MITRE)]
        self.titles = [t for t, _ in tit.most_common(TOP_TITLES)]
        return self

    def transform(self, rows) -> pd.DataFrame:
        out = []
        for r in rows:
            f = {"n_alerts": r["n_alerts"], "n_rows": r["n_evidence_rows"],
                 "span_hours": r["time_span_hours"], "n_categories": len(r["categories"]),
                 "n_mitre": len(r["mitre"]),
                 "rows_per_alert": r["n_evidence_rows"] / max(r["n_alerts"], 1)}
            for e in ENTITY_NAMES:
                f[f"ent_{e}"] = r["entity_counts"].get(e, 0)
                f[f"crit_{e}"] = r["critical_counts"].get(e, 0)
            for c in self.cats: f[f"cat_{c}"] = int(c in r["categories"])
            for m in self.mitre: f[f"mitre_{m}"] = int(m in r["mitre"])
            tc = Counter(str(a["title"]) for a in r["alerts"] if a["title"] is not None)
            for t in self.titles: f[f"title_{t}"] = tc.get(t, 0)
            out.append(f)
        return pd.DataFrame(out)

    def to_json(self):
        return {"cats": self.cats, "mitre": self.mitre, "titles": self.titles}

def labels(rows): return np.array([CLASSES.index(r["grade"]) for r in rows])

def make_model(kind):
    if kind == "xgb":
        from xgboost import XGBClassifier
        return XGBClassifier(n_estimators=300, max_depth=5, learning_rate=0.08, subsample=0.8,
                             colsample_bytree=0.8, objective="multi:softprob",
                             eval_metric="mlogloss", tree_method="hist", random_state=42)
    from sklearn.ensemble import HistGradientBoostingClassifier
    return HistGradientBoostingClassifier(max_depth=5, learning_rate=0.08, max_iter=300, random_state=42)

def fit_model(kind, X, y):
    m = make_model(kind)
    m.fit(X, y, sample_weight=compute_sample_weight("balanced", y))  # handles class imbalance
    return m

def report(name, y_true, y_pred):
    mf1 = f1_score(y_true, y_pred, average="macro")
    print(f"\n=== {name} ===  macro-F1 = {mf1:.4f}")
    print(classification_report(y_true, y_pred, labels=range(3), target_names=CLASSES, digits=3, zero_division=0))
    print("confusion matrix (rows=true, cols=pred):")
    print(pd.DataFrame(confusion_matrix(y_true, y_pred, labels=range(3)), index=CLASSES, columns=CLASSES))
    return mf1

def split_dev(rows, y, seed=42):
    """Stratified 80/20 split, grouped by org when org ids exist (avoids same-org leakage)."""
    orgs = [r.get("org_id") for r in rows]
    if all(o is not None for o in orgs) and len(set(orgs)) >= 5:
        sp = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
        return next(sp.split(np.zeros(len(y)), y, groups=orgs)), "org-grouped"
    sp = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
    return next(sp.split(np.zeros(len(y)), y)), "stratified (no org ids)"

def main(a):
    train = load(a.train); y = labels(train)
    (tr, va), how = split_dev(train, y)
    print(f"train incidents: {len(train)} | dev split: {how} | train/val = {len(tr)}/{len(va)}")

    fz = Featurizer().fit([train[i] for i in tr])
    X_tr, X_va = fz.transform([train[i] for i in tr]), fz.transform([train[i] for i in va])
    m = fit_model(a.model, X_tr, y[tr])
    maj = np.full(len(va), np.bincount(y[tr]).argmax())
    print(f"majority-class baseline macro-F1 = {f1_score(y[va], maj, average='macro'):.4f}")
    results = {"model": a.model, "dev_split": how, "val_macro_f1": report("VALIDATION", y[va], m.predict(X_va))}

    if hasattr(m, "feature_importances_"):
        imp = pd.Series(m.feature_importances_, index=X_tr.columns).sort_values(ascending=False)
        print("\ntop features:\n", imp.head(10).round(4).to_string())

    # refit on ALL train for the final model; evaluate on test only when asked
    fz = Featurizer().fit(train); X_all = fz.transform(train)
    final = fit_model(a.model, X_all, y)
    if a.eval_test:
        test = load(a.test); yt = labels(test)
        results["test_macro_f1"] = report("TEST (held-out, run once)", yt, final.predict(fz.transform(test)))
    os.makedirs("models", exist_ok=True); os.makedirs("results", exist_ok=True)
    if a.model == "xgb": final.save_model("models/baseline_xgb.json")
    else:
        import joblib; joblib.dump(final, "models/baseline_hgb.joblib")
    json.dump({**fz.to_json(), "classes": CLASSES, "columns": list(X_all.columns)}, open("models/featurizer.json", "w"), indent=1)
    json.dump(results, open("results/baseline_metrics.json", "w"), indent=1)
    print("\nsaved models/ and results/baseline_metrics.json")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--train", default="data/incidents_train.jsonl")
    p.add_argument("--test", default="data/incidents_test.jsonl")
    p.add_argument("--eval-test", action="store_true")
    p.add_argument("--model", choices=["xgb", "hgb"], default="xgb")
    main(p.parse_args())


def baseline_predict(train_path, rows, kind="xgb"):
    """Fit on the full train file and predict `rows` (used for hybrid mode + comparison).
    Returns (class names, probability matrix)."""
    train = load(train_path)
    fz = Featurizer().fit(train)
    m = fit_model(kind, fz.transform(train), labels(train))
    proba = m.predict_proba(fz.transform(rows))
    return [CLASSES[i] for i in proba.argmax(axis=1)], proba
