import json
import os
import sys
from urllib.parse import urlsplit
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    average_precision_score
)
from sklearn.model_selection import GroupShuffleSplit

# Ensure backend root is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ml.feature_extractor import FEATURE_NAMES, URLFeatureExtractor


def train():
    data_path = os.path.join(BASE_DIR, "data", "PhishOFE.csv")
    models_dir = os.path.join(BASE_DIR, "ml")
    reports_dir = os.path.join(BASE_DIR, "ml", "reports")
    os.makedirs(reports_dir, exist_ok=True)

    print("Loading dataset from:", data_path)
    df = pd.read_csv(data_path)

    # Clean exact duplicate rows if any
    initial_count = len(df)
    df = df.drop_duplicates(subset=["URL"]).reset_index(drop=True)
    print(f"Loaded {len(df)} unique URLs (removed {initial_count - len(df)} duplicates).")

    # Extract domain for domain-grouped splitting to prevent domain leakage
    df["domain"] = df["URL"].apply(lambda u: urlsplit(u).hostname or "")

    # Split: 80% train+val, 20% test (domain-grouped)
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_val_idx, test_idx = next(gss.split(df, groups=df["domain"]))

    train_val_df = df.iloc[train_val_idx].reset_index(drop=True)
    test_df = df.iloc[test_idx].reset_index(drop=True)

    # Compute TLD frequency dictionary ONLY from train_val partition to avoid leakage
    tld_counts = train_val_df["TLD"].value_counts(normalize=True).to_dict()

    extractor = URLFeatureExtractor(tld_frequencies=tld_counts)

    print("Extracting feature matrices with balanced apex/www representation in training partition...")
    # Reflect realistic bare domain distribution in train_val: 50% of legitimate URLs presented as apex domains
    np.random.seed(42)
    aug_train_urls = []
    for u, label in zip(train_val_df["URL"], train_val_df["label"]):
        if label == 0 and "://www." in u:
            if np.random.rand() < 0.5:
                aug_train_urls.append(u.replace("://www.", "://", 1))
            else:
                aug_train_urls.append(u)
        else:
            aug_train_urls.append(u)

    X_train_val = np.array([extractor.extract_vector(u) for u in aug_train_urls])
    y_train_val = train_val_df["label"].values

    # Test partition remains completely untouched (100% held-out test distribution)
    X_test = np.array([extractor.extract_vector(u) for u in test_df["URL"]])
    y_test = test_df["label"].values

    print(f"Train/Val set: {len(X_train_val)} samples")
    print(f"Test set: {len(X_test)} samples")

    # Train Random Forest
    print("Training Random Forest Classifier (seed=42, n_estimators=100, max_depth=16)...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train_val, y_train_val)

    # Evaluation on holdout test set
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred))
    rec = float(recall_score(y_test, y_pred))
    f1 = float(f1_score(y_test, y_pred))
    roc_auc = float(roc_auc_score(y_test, y_prob))
    pr_auc = float(average_precision_score(y_test, y_prob))

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    print("\n" + "=" * 50)
    print("TEST EVALUATION RESULTS (Domain-Grouped Holdout):")
    print("=" * 50)
    print(f"Accuracy:          {acc:.4f}")
    print(f"Precision (Phish): {prec:.4f}")
    print(f"Recall (Phish):    {rec:.4f}")
    print(f"F1-Score:          {f1:.4f}")
    print(f"ROC-AUC:           {roc_auc:.4f}")
    print(f"PR-AUC:            {pr_auc:.4f}")
    print(f"False Positive Rate: {fpr:.4f}")
    print(f"Confusion Matrix:  TN={tn}, FP={fp}, FN={fn}, TP={tp}")

    # Package model artifact with its extractor and metadata
    model_artifact = {
        "model": model,
        "extractor": extractor,
        "feature_names": FEATURE_NAMES,
        "label_mapping": {0: "legitimate", 1: "phishing"}
    }

    model_path = os.path.join(models_dir, "model.joblib")
    joblib.dump(model_artifact, model_path)
    print(f"\nTrained model saved to: {model_path}")

    # Metadata record
    metadata = {
        "model_name": "PhishOFE-URL-Classifier",
        "model_type": "RandomForestClassifier",
        "version": "2.0",
        "model_path": "ml/model.joblib",
        "random_seed": 42,
        "hyperparameters": {
            "n_estimators": 100,
            "max_depth": 16,
            "min_samples_leaf": 2,
            "n_jobs": -1
        },
        "training_strategy": "Domain-Grouped Split (80/20) on unique URLs with apex/www balanced representation",
        "total_unique_urls": len(df),
        "train_samples": len(X_train_val),
        "test_samples": len(X_test),
        "feature_set": "URL-only features (Option B, Calibrated)",
        "features": FEATURE_NAMES,
        "feature_count": len(FEATURE_NAMES),
        "label_mapping": {
            "0": "legitimate",
            "1": "phishing"
        },
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "roc_auc": round(roc_auc, 4),
            "pr_auc": round(pr_auc, 4),
            "false_positive_rate": round(fpr, 4),
            "confusion_matrix": {
                "true_negative": tn,
                "false_positive": fp,
                "false_negative": fn,
                "true_positive": tp
            }
        },
        "calibration_notes": [
            "Fixed PhishOFE representation bias where 100% of benign URLs had 'www.' prefix, causing all bare apex domains to misclassify as phishing.",
            "Normalized subdomain feature extraction: 'www.' is canonical web host, not a deceptive subdomain.",
            "Represented natural apex domain distribution in training partition while keeping holdout test partition untouched."
        ],
        "limitations": [
            "URL-only model trained exclusively on lexical/structural URL features and TLD frequencies.",
            "Does not inspect HTML or execute JavaScript (safe by design, zero SSRF risk).",
            "HTML-derived PhishOFE features (e.g., HasTitle, HasPasswordField) are intentionally omitted rather than filled with arbitrary zeros."
        ]
    }

    metadata_path = os.path.join(models_dir, "model_metadata.json")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"Model metadata saved to: {metadata_path}")

    report_path = os.path.join(reports_dir, "evaluation_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return metadata


if __name__ == "__main__":
    train()
