import json
import os
import pandas as pd
import numpy as np

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

phishofe_path = os.path.join(DATA_DIR, "PhishOFE.csv")
phishtank_path = os.path.join(DATA_DIR, "PhishTank.csv")


def inspect_phishofe():
    print("=" * 60)
    print("INSPECTING PhishOFE.csv")
    print("=" * 60)

    if not os.path.exists(phishofe_path):
        print(f"File not found: {phishofe_path}")
        return {}

    df = pd.read_csv(phishofe_path)
    file_size_mb = os.path.getsize(phishofe_path) / (1024 * 1024)

    print(f"File size: {file_size_mb:.2f} MB")
    print(f"Shape: {df.shape[0]} rows, {df.shape[1]} columns")
    print("\nColumns and Types:")
    for col, dtype in zip(df.columns, df.dtypes):
        print(f"  {col}: {dtype}")

    print("\nMissing values:")
    missing = df.isnull().sum()
    print(missing[missing > 0] if (missing > 0).any() else "  No missing values found.")

    duplicates_all = df.duplicated().sum()
    duplicates_url = df.duplicated(subset=["URL"]).sum() if "URL" in df.columns else 0
    print(f"\nDuplicates: {duplicates_all} exact row duplicates, {duplicates_url} URL duplicates")

    print("\nLabel distribution:")
    label_counts = df["label"].value_counts().to_dict()
    print(label_counts)

    # Label analysis: inspect sample URLs for each label
    print("\nSample URLs for label=0:")
    sample_0 = df[df["label"] == 0]["URL"].head(10).tolist()
    for u in sample_0:
        print(f"  [0] {u}")

    print("\nSample URLs for label=1:")
    sample_1 = df[df["label"] == 1]["URL"].head(10).tolist()
    for u in sample_1:
        print(f"  [1] {u}")

    # Check known benign patterns (e.g. google, wikipedia, github, amazon, yahoo)
    benign_keywords = ["google.com", "wikipedia.org", "github.com", "microsoft.com", "amazon.com", "apple.com"]
    print("\nChecking label for major legitimate domains in PhishOFE:")
    for kw in benign_keywords:
        match = df[df["URL"].str.contains(kw, case=False, na=False)]
        if not match.empty:
            labels_for_kw = match["label"].value_counts().to_dict()
            print(f"  Domain '{kw}': matches={len(match)}, label distribution={labels_for_kw}")

    # Feature statistics comparison between label 0 and label 1
    numeric_cols = [c for c in df.select_dtypes(include=[np.number]).columns if c != "label"]
    feature_means = df.groupby("label")[numeric_cols].mean().T
    print("\nMean feature values by label (first 10 features):")
    print(feature_means.head(10))

    report = {
        "file": "PhishOFE.csv",
        "file_size_mb": round(file_size_mb, 2),
        "rows": df.shape[0],
        "columns": df.shape[1],
        "column_names": list(df.columns),
        "missing_values": missing[missing > 0].to_dict(),
        "duplicates_exact": int(duplicates_all),
        "duplicates_url": int(duplicates_url),
        "label_distribution": {str(k): int(v) for k, v in label_counts.items()},
        "sample_label_0": sample_0[:5],
        "sample_label_1": sample_1[:5],
    }

    return report, df


def inspect_phishtank(phishofe_df=None):
    print("\n" + "=" * 60)
    print("INSPECTING PhishTank.csv")
    print("=" * 60)

    if not os.path.exists(phishtank_path):
        print(f"File not found: {phishtank_path}")
        return {}

    df = pd.read_csv(phishtank_path)
    file_size_mb = os.path.getsize(phishtank_path) / (1024 * 1024)

    print(f"File size: {file_size_mb:.2f} MB")
    print(f"Shape: {df.shape[0]} rows, {df.shape[1]} columns")
    print("\nColumns and Types:")
    for col, dtype in zip(df.columns, df.dtypes):
        print(f"  {col}: {dtype}")

    print("\nMissing values:")
    missing = df.isnull().sum()
    print(missing[missing > 0] if (missing > 0).any() else "  No missing values found.")

    duplicates_url = df.duplicated(subset=["url"]).sum() if "url" in df.columns else 0
    print(f"\nDuplicates: {duplicates_url} URL duplicates")

    print("\nVerified column distribution:")
    print(df["verified"].value_counts().to_dict() if "verified" in df.columns else "N/A")

    print("\nOnline column distribution:")
    print(df["online"].value_counts().to_dict() if "online" in df.columns else "N/A")

    print("\nTop 5 targets:")
    if "target" in df.columns:
        print(df["target"].value_counts().head(5).to_dict())

    # Cross-reference with PhishOFE
    overlap_info = {}
    if phishofe_df is not None and "URL" in phishofe_df.columns and "url" in df.columns:
        ofe_urls = set(phishofe_df["URL"].str.strip().str.lower())
        tank_urls = set(df["url"].str.strip().str.lower())
        overlap = ofe_urls.intersection(tank_urls)
        print(f"\nExact URL overlap between PhishOFE and PhishTank: {len(overlap)} URLs")
        if overlap:
            sample_overlap = list(overlap)[:10]
            print("Sample overlapping URLs and their labels in PhishOFE:")
            matching_ofe = phishofe_df[phishofe_df["URL"].str.strip().str.lower().isin(sample_overlap)]
            overlap_labels = matching_ofe["label"].value_counts().to_dict()
            print(f"  Overlap label distribution in PhishOFE: {overlap_labels}")
            overlap_info = {
                "overlap_count": len(overlap),
                "overlap_label_distribution": {str(k): int(v) for k, v in overlap_labels.items()}
            }

    report = {
        "file": "PhishTank.csv",
        "file_size_mb": round(file_size_mb, 2),
        "rows": df.shape[0],
        "columns": df.shape[1],
        "column_names": list(df.columns),
        "missing_values": missing[missing > 0].to_dict(),
        "duplicates_url": int(duplicates_url),
        "verified_counts": df["verified"].value_counts().to_dict() if "verified" in df.columns else {},
        "online_counts": df["online"].value_counts().to_dict() if "online" in df.columns else {},
        "overlap_with_phishofe": overlap_info
    }

    return report


if __name__ == "__main__":
    report_ofe, df_ofe = inspect_phishofe()
    report_tank = inspect_phishtank(df_ofe)

    full_report = {
        "phishofe": report_ofe,
        "phishtank": report_tank
    }

    report_file = os.path.join(REPORTS_DIR, "dataset_inspection_report.json")
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(full_report, f, indent=2)

    print(f"\nInspection report saved to {report_file}")
