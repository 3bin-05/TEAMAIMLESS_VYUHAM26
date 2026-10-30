import json
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.services.ml_service import load_model, predict_url

LEGITIMATE_BENCHMARK_URLS = [
    # LinkedIn
    "https://linkedin.com/",
    "https://www.linkedin.com/",
    "https://linkedin.com/jobs",
    "https://www.linkedin.com/in/example",
    # GitHub
    "https://github.com/",
    "https://www.github.com/",
    "https://github.com/torvalds/linux",
    # Google
    "https://google.com/",
    "https://www.google.com/",
    "https://www.google.com/search?q=cybersecurity",
    # Microsoft
    "https://microsoft.com/",
    "https://www.microsoft.com/",
    "https://www.microsoft.com/en-us/windows",
    # Apple
    "https://apple.com/",
    "https://www.apple.com/",
    "https://www.apple.com/iphone",
    # Amazon
    "https://amazon.com/",
    "https://www.amazon.com/",
    "https://www.amazon.com/gp/bestsellers",
    # Python.org
    "https://python.org/",
    "https://www.python.org/",
    "https://www.python.org/downloads/",
    # Wikipedia
    "https://wikipedia.org/",
    "https://www.wikipedia.org/",
    "https://en.wikipedia.org/wiki/Phishing",
    # Cloudflare
    "https://cloudflare.com/",
    "https://www.cloudflare.com/",
    "https://www.cloudflare.com/learning/ddos/what-is-ddos/",
    # Stack Overflow
    "https://stackoverflow.com/",
    "https://www.stackoverflow.com/",
    "https://stackoverflow.com/questions/tagged/python"
]


def run_benchmark(output_filename="legitimate_benchmark_results.json"):
    results = []
    total = len(LEGITIMATE_BENCHMARK_URLS)
    fp_count = 0

    print(f"Evaluating {total} legitimate URLs...")
    for url in LEGITIMATE_BENCHMARK_URLS:
        res = predict_url(url)
        is_fp = (res.get("prediction") == "phishing")
        if is_fp:
            fp_count += 1
        results.append({
            "url": url,
            "prediction": res.get("prediction"),
            "phishing_probability": res.get("phishing_probability"),
            "confidence": res.get("confidence"),
            "is_false_positive": is_fp
        })

    fp_rate = fp_count / total
    summary = {
        "total_urls": total,
        "false_positive_count": fp_count,
        "legitimate_correct_count": total - fp_count,
        "false_positive_rate": round(fp_rate, 4),
        "accuracy_on_legitimate": round(1.0 - fp_rate, 4),
        "results": results
    }

    report_dir = os.path.join(BASE_DIR, "ml", "reports")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, output_filename)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"Benchmark finished: {fp_count}/{total} False Positives ({fp_rate:.1%})")
    print(f"Saved to {report_path}")
    return summary


if __name__ == "__main__":
    run_benchmark()
