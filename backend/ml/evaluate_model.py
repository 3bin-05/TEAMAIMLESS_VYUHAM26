import json
import os
import sys
import joblib
import numpy as np
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


def evaluate_phishtank():
    model_path = os.path.join(BASE_DIR, "ml", "model.joblib")
    phishtank_path = os.path.join(BASE_DIR, "data", "PhishTank.csv")
    reports_dir = os.path.join(BASE_DIR, "ml", "reports")
    os.makedirs(reports_dir, exist_ok=True)

    print("Loading model from:", model_path)
    artifact = joblib.load(model_path)
    model = artifact["model"]
    extractor = artifact["extractor"]

    print("Loading PhishTank dataset from:", phishtank_path)
    df_tank = pd.read_csv(phishtank_path)
    unique_urls = df_tank["url"].dropna().unique()
    print(f"Total unique verified phishing URLs in PhishTank: {len(unique_urls)}")

    # Sample 5,000 for evaluation
    eval_sample = unique_urls[:5000]
    print(f"Evaluating {len(eval_sample)} verified phishing URLs...")

    X = np.array([extractor.extract_vector(u) for u in eval_sample])
    preds = model.predict(X)
    probs = model.predict_proba(X)[:, 1]

    phishing_detected = int((preds == 1).sum())
    detection_rate = float(phishing_detected / len(eval_sample))
    mean_confidence = float(np.mean(probs))

    print("\n" + "=" * 50)
    print("PHISHTANK EXTERNAL EVALUATION:")
    print("=" * 50)
    print(f"Total Evaluated:   {len(eval_sample)}")
    print(f"Phishing Detected: {phishing_detected}")
    print(f"Detection Rate:    {detection_rate * 100:.2f}%")
    print(f"Mean Phish Conf:   {mean_confidence:.4f}")

    report = {
        "evaluation_dataset": "PhishTank.csv (Verified Phishing)",
        "sample_size": len(eval_sample),
        "phishing_detected": phishing_detected,
        "detection_rate": round(detection_rate, 4),
        "mean_phishing_confidence": round(mean_confidence, 4)
    }

    report_path = os.path.join(reports_dir, "phishtank_evaluation_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"Report saved to: {report_path}")


if __name__ == "__main__":
    evaluate_phishtank()
