"""Justification experiments. Read-only: no shipped model or scaler is changed.

1. Baselines   -- decision stump, depth-5 tree, logistic regression on the shipped split,
                  next to the shipped RF, with train AND test scores.
2. Same subset -- RF and AE scored on the exact rows the CNN windows are scored on.
3. Unseen days -- shipped AE (and an Isolation Forest given the same benign training rows
                  and the same 90th-percentile budget) on every CICIDS2017 day, per family.
                  Needs MachineLearningCSV.zip; skipped if it is absent.

Usage (from backend/):
    python justification_experiments.py [data/CICIDS2017/MachineLearningCSV.zip]
Writes models/justification_metrics.json (tracked by git; evidence/ is not).
"""
import json
import os
import sys

import joblib
import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.tree import DecisionTreeClassifier

from evaluate_ddos_heldout import metrics
from src.sequence_builder import build_cnn_sequences

CLEAN = "data/preprocessed/CICIDS2017_cleaned.csv"
OUT = "models/justification_metrics.json"


def ae_err(ae, X):
    return np.mean(np.square(X - ae.predict(X, batch_size=4096, verbose=0)), axis=1)


def main():
    zip_path = sys.argv[1] if len(sys.argv) > 1 else "data/CICIDS2017/MachineLearningCSV.zip"
    names = list(pd.read_csv(CLEAN, nrows=0).columns.drop("Label"))
    d = build_cnn_sequences(CLEAN, window_size=100, stride=10)
    Xtr, ytr = d["X_train_flat"], d["y_train_flat"]
    Xte, yte = d["X_test_flat"], d["y_test_flat"]
    rf = joblib.load("models/random_forest.pkl")
    ae = tf.keras.models.load_model("models/autoencoder.h5", compile=False)
    out = {"split": {"train": len(ytr), "val": len(d["y_val_flat"]), "test": len(yte), "shuffle": False}}

    # ---- 1. baselines ---------------------------------------------------------------------
    def both(m):
        return {"train": metrics(ytr, m.predict(Xtr)), "test": metrics(yte, m.predict(Xte))}

    base = {"random_forest_shipped": both(rf)}
    # Self-check: this must be the evaluation real_metrics.json reports, or nothing below is comparable.
    with open("models/real_metrics.json", encoding="utf-8") as fh:
        ref = json.load(fh)["random_forest"]["confusion_matrix"]
    got = base["random_forest_shipped"]["test"]["confusion_matrix"]
    assert got == ref, f"RF test confusion matrix {got} != real_metrics.json {ref}"

    for name, m in {"decision_stump": DecisionTreeClassifier(max_depth=1, random_state=42),
                    "decision_tree_depth5": DecisionTreeClassifier(max_depth=5, random_state=42),
                    "logistic_regression": LogisticRegression(max_iter=2000)}.items():
        base[name] = both(m.fit(Xtr, ytr))
    stump = DecisionTreeClassifier(max_depth=1, random_state=42).fit(Xtr, ytr)
    base["decision_stump"]["rule"] = {"feature": names[stump.tree_.feature[0]],
                                      "threshold_scaled": float(stump.tree_.threshold[0])}
    out["1_baselines"] = base

    # ---- 2. RF / AE on the CNN's rows -----------------------------------------------------
    idx = d["eval_idx_test"]
    assert np.array_equal(d["y_seq_test"], yte[idx])
    ben_tr = Xtr[ytr == 0]
    thr = float(np.percentile(ae_err(ae, ben_tr), 90))
    e_te = ae_err(ae, Xte)
    same = {"rows": int(len(idx)),
            "random_forest": metrics(yte[idx], rf.predict(Xte[idx])),
            "autoencoder": metrics(yte[idx], (e_te[idx] > thr).astype(int), e_te[idx])}
    if os.path.exists("models/cnn_classifier.h5"):
        cnn = tf.keras.models.load_model("models/cnn_classifier.h5", compile=False)
        same["cnn"] = metrics(yte[idx], np.argmax(cnn.predict(d["X_seq_test"], verbose=0), axis=1))
    out["2_same_subset_as_cnn"] = same

    # ---- 3. anomaly detectors: Friday test, then every day --------------------------------
    iso = IsolationForest(n_estimators=100, random_state=42, n_jobs=-1).fit(ben_tr)
    iso_thr = float(np.percentile(-iso.score_samples(ben_tr), 90))
    s_te = -iso.score_samples(Xte)
    out["3_anomaly_detectors"] = {
        "threshold_rule": "90th percentile of the score on benign TRAINING rows, for both",
        "friday_test": {"autoencoder": metrics(yte, (e_te > thr).astype(int), e_te),
                        "isolation_forest": metrics(yte, (s_te > iso_thr).astype(int), s_te)}}

    if os.path.exists(zip_path):
        from train_multiday import load_days          # also puts src/ on sys.path
        from ids_pipeline import RealTimeIDSPipeline as P
        scaler = joblib.load("models/feature_scaler.pkl")
        snames = [str(n) for n in scaler.feature_names_in_]
        assert snames == names, "scaler feature order differs from the cleaned CSV"
        days = {}
        for day, (X, y, dropped) in load_days(zip_path, snames).items():
            X = X.copy()                              # same pre-scaling fixes the live pipeline applies
            for c in P.TRAINING_ZERO_FEATURES: X[c] = 0.0
            for c in P.TRAINING_BINARY_FEATURES: X[c] = (X[c] > 0).astype(float)
            Xs = scaler.transform(X).astype(np.float32)
            e = ae_err(ae, Xs)
            flags = {"ae": e > thr, "ae_override": e / (e + thr) > 0.97,
                     "iforest": -iso.score_samples(Xs) > iso_thr, "rf": rf.predict(Xs) == 1}
            flags["ae_and_not_rf"] = flags["ae"] & ~flags["rf"]
            yv = y.to_numpy()
            ben = yv == "BENIGN"

            def rates(mask):
                return {"rows": int(mask.sum()), **{k: float(v[mask].mean()) for k, v in flags.items()}}

            row = {"is_ae_training_day": "DDos" in day, "dropped_nan_inf": dropped,
                   "benign": rates(ben),
                   "families": {f: rates(yv == f) for f in sorted(set(yv[~ben]))}}
            if ben.any() and (~ben).any():
                row["ae_roc_auc"] = float(roc_auc_score(~ben, e))
            days[day] = row
            print(f"{day:44} benign AE {row['benign']['ae']:.3f} | " + " | ".join(
                f"{f}: AE {r['ae']:.3f} IF {r['iforest']:.3f} RF {r['rf']:.3f}"
                for f, r in row["families"].items()), flush=True)
        out["3_anomaly_detectors"]["per_day_flag_rates"] = days
    else:
        print(f"Skipping per-day experiment: {zip_path} not found")

    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    for name, r in base.items():
        print(f"{name:24} train F1 {r['train']['f1_ddos']:.4f}  test F1 {r['test']['f1_ddos']:.4f}")
    for name in ("random_forest", "autoencoder", "cnn"):
        if name in same:
            print(f"same {same['rows']} rows  {name:14} F1 {same[name]['f1_ddos']:.4f}")
    print(f"Saved {OUT}")


if __name__ == "__main__":
    main()
