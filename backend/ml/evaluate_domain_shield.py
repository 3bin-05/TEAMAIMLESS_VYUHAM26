"""
DomainShield Evaluation Benchmark & Metrics Computation (Phase 5)
Evaluates DomainShield detection performance on a curated benchmark dataset:
- Positive cases: typosquatting (substitution, insertion, deletion, transposition),
  homoglyphs, Punycode, subdomain impersonation, brand+keyword composition.
- Negative cases: official brand domains, official subdomains, benign domains with brand substrings,
  coincidental dictionary terms, unrelated standard websites.
Calculates Precision, Recall, F1-Score, False Positive Rate (FPR), and False Negative Count.

METHODOLOGY & LIMITATIONS NOTE:
This 58-case benchmark is a synthetic unit/integration validation dataset covering key
threat archetypes and benign edge cases. It verifies algorithmic correctness and logic boundaries
under controlled test patterns. It does NOT claim or imply exhaustive real-world detection
accuracy across the unbounded open internet, where novel brands, complex obfuscations, and
zero-day lookalikes constantly emerge.
"""

import json
import os
import sys
from pathlib import Path

# Add backend directory to path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.domain_shield import check_domain_impersonation

# Curated benchmark dataset
EVALUATION_DATASET = [
    # --- POSITIVE SAMPLES (Impersonation Attacks) ---
    # Typosquatting: Substitution
    {"url": "https://g00gle.com", "label": 1, "category": "substitution", "brand": "Google"},
    {"url": "https://paypa1.com/login", "label": 1, "category": "substitution", "brand": "PayPal"},
    {"url": "https://micros0ft.com", "label": 1, "category": "substitution", "brand": "Microsoft"},
    {"url": "https://amaz0n.com/orders", "label": 1, "category": "substitution", "brand": "Amazon"},
    {"url": "https://app1e.com/id", "label": 1, "category": "substitution", "brand": "Apple"},
    # Typosquatting: Insertion
    {"url": "https://gooogle.com", "label": 1, "category": "insertion", "brand": "Google"},
    {"url": "https://amazonn.com", "label": 1, "category": "insertion", "brand": "Amazon"},
    {"url": "https://netflixx.com", "label": 1, "category": "insertion", "brand": "Netflix"},
    {"url": "https://chasee.com", "label": 1, "category": "insertion", "brand": "Chase Bank"},
    # Typosquatting: Deletion
    {"url": "https://gogle.com", "label": 1, "category": "deletion", "brand": "Google"},
    {"url": "https://paypl.com", "label": 1, "category": "deletion", "brand": "PayPal"},
    {"url": "https://microsft.com", "label": 1, "category": "deletion", "brand": "Microsoft"},
    # Typosquatting: Transposition
    {"url": "https://googel.com", "label": 1, "category": "transposition", "brand": "Google"},
    {"url": "https://amzaon.com", "label": 1, "category": "transposition", "brand": "Amazon"},
    # Homoglyphs & Confusables
    {"url": "http://g\u043e\u043egle.com", "label": 1, "category": "homoglyph", "brand": "Google"}, # Cyrillic 'о'
    {"url": "http://\u0430pple.com", "label": 1, "category": "homoglyph", "brand": "Apple"},       # Cyrillic 'а'
    {"url": "http://p\u0430ypal.com", "label": 1, "category": "homoglyph", "brand": "PayPal"},     # Cyrillic 'а'
    {"url": "http://xn--pple-43d.com", "label": 1, "category": "punycode", "brand": "Apple"},      # Punycode for Cyrillic 'аpple.com'
    # Subdomain Impersonation
    {"url": "https://google.com.attacker-domain.org/login", "label": 1, "category": "subdomain", "brand": "Google"},
    {"url": "https://paypal.secure-login-gateway.net", "label": 1, "category": "subdomain", "brand": "PayPal"},
    {"url": "https://netflix.account-billing-portal.com", "label": 1, "category": "subdomain", "brand": "Netflix"},
    {"url": "https://chase.online-security-update.info", "label": 1, "category": "subdomain", "brand": "Chase Bank"},
    {"url": "https://microsoft.com.account-verify.xyz", "label": 1, "category": "subdomain", "brand": "Microsoft"},
    # Brand + Security Keyword Composition
    {"url": "https://google-security-verify.com", "label": 1, "category": "keyword_composition", "brand": "Google"},
    {"url": "https://paypal-account-update.com", "label": 1, "category": "keyword_composition", "brand": "PayPal"},
    {"url": "https://apple-id-support-login.com", "label": 1, "category": "keyword_composition", "brand": "Apple"},
    {"url": "https://microsoft-office-auth.com", "label": 1, "category": "keyword_composition", "brand": "Microsoft"},
    {"url": "https://chase-bank-security-center.com", "label": 1, "category": "keyword_composition", "brand": "Chase Bank"},

    # --- NEGATIVE SAMPLES (Legitimate / Clean) ---
    # Official brand domains
    {"url": "https://google.com", "label": 0, "category": "official", "brand": "Google"},
    {"url": "https://www.google.com", "label": 0, "category": "official", "brand": "Google"},
    {"url": "https://accounts.google.com/signin", "label": 0, "category": "official", "brand": "Google"},
    {"url": "https://mail.google.com", "label": 0, "category": "official", "brand": "Google"},
    {"url": "https://apple.com", "label": 0, "category": "official", "brand": "Apple"},
    {"url": "https://www.apple.com/shop", "label": 0, "category": "official", "brand": "Apple"},
    {"url": "https://icloud.com", "label": 0, "category": "official", "brand": "Apple"},
    {"url": "https://microsoft.com", "label": 0, "category": "official", "brand": "Microsoft"},
    {"url": "https://login.microsoftonline.com", "label": 0, "category": "official", "brand": "Microsoft"},
    {"url": "https://paypal.com", "label": 0, "category": "official", "brand": "PayPal"},
    {"url": "https://www.paypal.com/signin", "label": 0, "category": "official", "brand": "PayPal"},
    {"url": "https://github.com", "label": 0, "category": "official", "brand": "GitHub"},
    {"url": "https://amazon.com", "label": 0, "category": "official", "brand": "Amazon"},
    {"url": "https://aws.amazon.com", "label": 0, "category": "official", "brand": "Amazon"},
    {"url": "https://openai.com", "label": 0, "category": "official", "brand": "OpenAI"},
    {"url": "https://chatgpt.com", "label": 0, "category": "official", "brand": "OpenAI"},
    {"url": "https://netflix.com", "label": 0, "category": "official", "brand": "Netflix"},
    {"url": "https://chase.com", "label": 0, "category": "official", "brand": "Chase Bank"},
    {"url": "https://wellsfargo.com", "label": 0, "category": "official", "brand": "Wells Fargo"},
    {"url": "https://bankofamerica.com", "label": 0, "category": "official", "brand": "Bank of America"},
    # Benign domains containing brand substrings / coincidental words
    {"url": "https://pineapple.com", "label": 0, "category": "benign_coincidental", "brand": None},
    {"url": "https://anecdote.com", "label": 0, "category": "benign_coincidental", "brand": None},
    {"url": "https://metabolism.com", "label": 0, "category": "benign_coincidental", "brand": None},
    {"url": "https://appalachian.org", "label": 0, "category": "benign_coincidental", "brand": None},
    {"url": "https://goggles.org", "label": 0, "category": "benign_coincidental", "brand": None},
    {"url": "https://chase-the-dream.org", "label": 0, "category": "benign_coincidental", "brand": None},
    {"url": "https://example.com", "label": 0, "category": "benign_standard", "brand": None},
    {"url": "https://wikipedia.org", "label": 0, "category": "benign_standard", "brand": None},
    {"url": "https://python.org", "label": 0, "category": "benign_standard", "brand": None},
    {"url": "https://stackoverflow.com", "label": 0, "category": "benign_standard", "brand": None},
]


def run_evaluation():
    tp = 0
    fp = 0
    tn = 0
    fn = 0

    results_detail = []

    for item in EVALUATION_DATASET:
        url = item["url"]
        ground_truth = item["label"]
        res = check_domain_impersonation(url)
        predicted = 1 if res.get("impersonation_detected") is True else 0

        is_correct = (ground_truth == predicted)

        if ground_truth == 1 and predicted == 1:
            tp += 1
            verdict_type = "TP"
        elif ground_truth == 0 and predicted == 1:
            fp += 1
            verdict_type = "FP"
        elif ground_truth == 0 and predicted == 0:
            tn += 1
            verdict_type = "TN"
        else:
            fn += 1
            verdict_type = "FN"

        results_detail.append({
            "url": url,
            "category": item["category"],
            "ground_truth": ground_truth,
            "predicted": predicted,
            "verdict_type": verdict_type,
            "is_correct": is_correct,
            "matched_brand": res.get("matched_brand"),
            "confidence": res.get("confidence"),
            "techniques": res.get("detection_techniques"),
            "reasoning": res.get("reasoning")
        })

    total = len(EVALUATION_DATASET)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0

    metrics = {
        "total_samples": total,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
    }

    report = {
        "evaluation_title": "AEGIS Phase 5 DomainShield Performance Benchmark",
        "methodology_disclaimer": (
            "Synthetic validation dataset covering 58 archetypal boundary cases. "
            "Validates algorithmic implementation correctness; does not imply statistical "
            "generalizability to all arbitrary internet domains."
        ),
        "metrics": metrics,
        "details": results_detail
    }

    reports_dir = backend_dir / "ml" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_file = reports_dir / "domain_shield_evaluation_report.json"

    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("==================================================================")
    print("       AEGIS Phase 5: DomainShield Evaluation Benchmark           ")
    print("   [Synthetic Benchmark Dataset - 58 Curated Boundary Cases]      ")
    print("==================================================================")
    print(f"Total Benchmark Samples: {total}")
    print(f"True Positives (TP):     {tp}")
    print(f"False Positives (FP):    {fp}")
    print(f"True Negatives (TN):     {tn}")
    print(f"False Negatives (FN):    {fn}")
    print("------------------------------------------------------------------")
    print(f"Accuracy:                {accuracy * 100:.2f}%")
    print(f"Precision:               {precision * 100:.2f}%")
    print(f"Recall:                  {recall * 100:.2f}%")
    print(f"F1-Score:                {f1:.4f}")
    print(f"False Positive Rate:     {fpr * 100:.2f}%")
    print(f"False Negative Rate:     {fnr * 100:.2f}%")
    print("==================================================================")
    print(f"Detailed evaluation report saved to: {report_file}")

    return metrics


if __name__ == "__main__":
    run_evaluation()
