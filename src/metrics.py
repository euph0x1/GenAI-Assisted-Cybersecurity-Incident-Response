"""Metrics with bootstrap confidence intervals (needed: ~150 test incidents is a small sample)."""
import numpy as np
from sklearn.metrics import f1_score, recall_score

CLASSES = ["BenignPositive", "FalsePositive", "TruePositive"]

def to_idx(names):
    """Class names -> indices; anything unparseable/None becomes -1 (counts as wrong)."""
    return np.array([CLASSES.index(n) if n in CLASSES else -1 for n in names])

def macro_f1(y_true, y_pred):
    return f1_score(y_true, y_pred, labels=[0, 1, 2], average="macro", zero_division=0)

def bootstrap_ci(y_true, y_pred, n=1000, seed=0, alpha=0.05):
    y_true, y_pred = np.asarray(y_true), np.asarray(y_pred)
    rng = np.random.default_rng(seed)
    scores = []
    for _ in range(n):
        i = rng.integers(0, len(y_true), len(y_true))
        scores.append(macro_f1(y_true[i], y_pred[i]))
    lo, hi = np.percentile(scores, [100 * alpha / 2, 100 * (1 - alpha / 2)])
    return float(macro_f1(y_true, y_pred)), float(lo), float(hi)

def per_class_recall(y_true, y_pred):
    r = recall_score(y_true, y_pred, labels=[0, 1, 2], average=None, zero_division=0)
    return {c: round(float(x), 3) for c, x in zip(CLASSES, r)}


def rate_ci(flags, n=2000, seed=0, alpha=0.05):
    """Bootstrap CI for a rate (share of True values)."""
    x = np.asarray(flags, dtype=float)
    if len(x) == 0: return float("nan"), float("nan"), float("nan")
    rng = np.random.default_rng(seed)
    means = [x[rng.integers(0, len(x), len(x))].mean() for _ in range(n)]
    lo, hi = np.percentile(means, [100 * alpha / 2, 100 * (1 - alpha / 2)])
    return float(x.mean()), float(lo), float(hi)


def wilson(k, n, z=1.96):
    """Wilson score interval for a proportion k/n (better than the normal interval for small n)."""
    import math
    if n == 0: return float("nan"), float("nan")
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return c - h, c + h
