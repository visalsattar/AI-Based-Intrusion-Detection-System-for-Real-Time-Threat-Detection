"""Follow-up to justification_experiments.py. Read-only: no shipped model or scaler is changed.

A. Shortcut check -- RF (shipped hyper-parameters) and depth-5 tree retrained on the same split with
   Init_Win_bytes_forward, Init_Win_bytes_backward and Destination Port zeroed.
B. Fixed false-flag budgets -- AE and Isolation Forest thresholds at the 90th / 99th / 99.9th
   percentile of benign TRAINING scores; per-day benign flag rate and per-family recall.

Usage (from backend/): python justification_extra.py
Writes models/justification_extra.json.
"""
import json

import joblib
import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.ensemble import IsolationForest
from sklearn.tree import DecisionTreeClassifier

from evaluate_ddos_heldout import metrics
from src.sequence_builder import build_cnn_sequences

CLEAN = "data/preprocessed/CICIDS2017_cleaned.csv"
ZIP = "data/CICIDS2017/MachineLearningCSV.zip"
OUT = "models/justification_extra.json"
SHORTCUTS = ["Init_Win_bytes_forward", "Init_Win_bytes_backward", "Destination Port"]
PCTS = (90, 99, 99.9)


def ae_err(ae, X):
    return np.mean(np.square(X - ae.predict(X, batch_size=4096, verbose=0)), axis=1)


def main():
    names = list(pd.read_csv(CLEAN, nrows=0).columns.drop("Label"))
    d = build_cnn_sequences(CLEAN, window_size=100, stride=10)
    Xtr, ytr, Xte, yte = d["X_train_flat"], d["y_train_flat"], d["X_test_flat"], d["y_test_flat"]
    rf = joblib.load("models/random_forest.pkl")
    out = {}

    # ---- A. shortcut check -----------------------------------------------------------------
    cols = [names.index(c) for c in SHORTCUTS]
    Xtr0, Xte0 = Xtr.copy(), Xte.copy()
    Xtr0[:, cols] = 0.0
    Xte0[:, cols] = 0.0
    sc = {"zeroed": SHORTCUTS}
    for name, m in {"random_forest_same_params": rf.__class__(**rf.get_params()),
                    "decision_tree_depth5": DecisionTreeClassifier(max_depth=5, random_state=42)}.items():
        m.fit(Xtr0, ytr)
        sc[name] = {"train": metrics(ytr, m.predict(Xtr0)), "test": metrics(yte, m.predict(Xte0))}
        print(f"A {name:26} zeroed-shortcut test F1 {sc[name]['test']['f1_ddos']:.4f} "
              f"FP {sc[name]['test']['confusion_matrix']['fp']} FN {sc[name]['test']['confusion_matrix']['fn']}",
              flush=True)
    out["A_shortcut_check"] = sc

    # ---- B. fixed false-flag budgets ---------------------------------------------------------
    ae = tf.keras.models.load_model("models/autoencoder.h5", compile=False)
    ben_tr = Xtr[ytr == 0]
    iso = IsolationForest(n_estimators=100, random_state=42, n_jobs=-1).fit(ben_tr)
    tr_scores = {"ae": ae_err(ae, ben_tr), "iforest": -iso.score_samples(ben_tr)}
    thr = {k: {str(p): float(np.percentile(v, p)) for p in PCTS} for k, v in tr_scores.items()}

    from train_multiday import load_days
    from ids_pipeline import RealTimeIDSPipeline as P
    scaler = joblib.load("models/feature_scaler.pkl")
    days = {}
    for day, (X, y, dropped) in load_days(ZIP, [str(n) for n in scaler.feature_names_in_]).items():
        X = X.copy()
        for c in P.TRAINING_ZERO_FEATURES: X[c] = 0.0
        for c in P.TRAINING_BINARY_FEATURES: X[c] = (X[c] > 0).astype(float)
        Xs = scaler.transform(X).astype(np.float32)
        s = {"ae": ae_err(ae, Xs), "iforest": -iso.score_samples(Xs)}
        yv = y.to_numpy()
        ben = yv == "BENIGN"
        row = {"is_ae_training_day": "DDos" in day, "dropped_nan_inf": dropped}
        for det in ("ae", "iforest"):
            for p in PCTS:
                flag = s[det] > thr[det][str(p)]
                row[f"{det}_p{p}"] = {"benign_flag_rate": float(flag[ben].mean()) if ben.any() else None,
                                      **{f: float(flag[yv == f].mean()) for f in sorted(set(yv[~ben]))}}
        days[day] = row
        print(f"B {day[:40]:40} " + " | ".join(
            f"{det} p{p}: ben {row[f'{det}_p{p}']['benign_flag_rate']:.4f} " +
            " ".join(f"{f} {v:.3f}" for f, v in row[f'{det}_p{p}'].items() if f != 'benign_flag_rate')
            for det in ("ae", "iforest") for p in PCTS), flush=True)
    out["B_fixed_budgets"] = {"thresholds_from": "benign TRAINING rows of the shipped split",
                              "thresholds": thr, "per_day": days}
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(f"Saved {OUT}")


if __name__ == "__main__":
    main()
