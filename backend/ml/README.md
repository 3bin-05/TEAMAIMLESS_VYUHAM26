# AEGIS Machine Learning Pipeline

This directory contains the training, evaluation, and inference pipeline for the AEGIS Phishing Detection Model.

## Dataset Inspection
- **PhishOFE Dataset**: `data/PhishOFE.csv`
  - 101,061 unique URLs.
  - 11 URL-derived features, 19 webpage content/HTML features.
  - Label distribution: 51,570 legitimate (`0`), 49,491 phishing (`1`).
  - Label mapping verified against 24,135 overlapping verified phishing URLs in PhishTank (100% mapped to label 1).
- **PhishTank Dataset**: `data/PhishTank.csv`
  - 53,353 verified, active phishing URLs used as an external zero-day benchmark.

## Feature Extraction (Option B: URL-Only Architecture)
Per Phase 2 specification Section 4, the model intentionally employs an isolated URL-only feature pipeline:
- Avoids unreliable, latency-inducing, and SSRF-prone live webpage inspection.
- Computes 11 exact lexical, structural, and TLD frequency features:
  1. `IsHTTPS` (scheme is HTTPS)
  2. `IsDomainIP` (host is IPv4/IPv6)
  3. `URLLength` (character count)
  4. `NoOfSubDomain` (subdomain depth)
  5. `NoOfDots` (dot count)
  6. `NoOfObfuscatedChar` (hyphen count)
  7. `NoOfEqual` (equals count)
  8. `NoOfQmark` (question mark count)
  9. `NoOfAmp` (ampersand count)
  10. `NoOfDigits` (digit count)
  11. `TLD_freq` (TLD frequency encoding from train partition)

## Model Architecture & Evaluation

### Version 2.0 (Calibrated Model — Current Production)
- **Algorithm**: Random Forest Classifier (100 trees, max_depth 16, min_samples_leaf 2, random_seed 42).
- **Validation**: Strict domain-grouped 80/20 train/test split on unique URLs.
- **Root Cause Remediation**:
  - Remediated the PhishOFE dataset representation bias where 100% of benign URLs had `www.` prefix, causing bare apex domains (`linkedin.com`, `github.com`, `google.com`) to misclassify as phishing.
  - Normalized subdomain feature extraction: `www.` is the canonical web host prefix, not a deceptive subdomain.
  - Balanced natural apex/www domain distribution in training partition while keeping holdout test partition untouched.
- **Holdout Test Set Performance (PhishOFE 18,747 samples)**:
  - Accuracy: **98.18%** (v1.0 was 96.48%)
  - Precision (Phishing): **99.59%** (v1.0 was 96.88%)
  - Recall (Phishing): **96.30%** (v1.0 was 95.17%)
  - F1-Score: **97.92%** (v1.0 was 96.02%)
  - ROC-AUC: **0.9976** (v1.0 was 0.9921)
  - PR-AUC: **0.9976** (v1.0 was 0.9918)
  - False Positive Rate: **0.32%** (v1.0 was 2.46% — an 87% reduction in false positives!)
- **External Real-World Phishing Verification (PhishTank 500 independent samples)**:
  - Phishing Detection Rate: **87.40%** (437/500 confirmed phishing URLs detected).
- **Independent Legitimate Domain Benchmark (31 real-world URLs)**:
  - False Positive Rate: **16.1%** (v1.0 was 58.1%).
  - Bare domains (`linkedin.com`, `google.com`, `github.com`, `microsoft.com`, `apple.com`, `amazon.com`, `python.org`, `wikipedia.org`, `cloudflare.com`, `stackoverflow.com`): **100% correctly classified as legitimate** with < 0.04 phishing probability.

### Version 1.0 (Baseline Archive — `ml/model_v1_baseline.joblib`)
- Baseline holdout test accuracy: 96.48%, precision: 96.88%, recall: 95.17%, FPR: 2.46%.
- Over-penalized bare apex domains due to raw PhishOFE `www.` representation bias. Preserved for historical comparison.
