"""
Sentinel ATLAS: Inter-Rater Agreement (Cohen's Kappa) Verification Suite

Validates gateway/agreement.py — the detector-vs-classifier consensus metric
that Phase 5 weight tuning reads from.
"""

import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from gateway.agreement import (
    calculate_cohens_kappa,
    interpret_kappa,
    compute_agreement,
    load_rater_labels,
)

passed = 0
failed = 0


def check(label, condition):
    global passed, failed
    if condition:
        passed += 1
        print(f"  ✅ PASS: {label}")
    else:
        failed += 1
        print(f"  ❌ FAIL: {label}")


print("=" * 75)
print("  INTER-RATER AGREEMENT (COHEN'S KAPPA) TEST SUITE")
print("=" * 75)

# -------------------------------------------------------------
print("\n🧪 TEST 1: Cohen's Kappa mathematical correctness")
# -------------------------------------------------------------
check("Total agreement -> kappa 1.0",
      calculate_cohens_kappa([1, 1, 0, 0], [1, 1, 0, 0]) == 1.0)
check("Total disagreement -> kappa -1.0",
      calculate_cohens_kappa([1, 1, 0, 0], [0, 0, 1, 1]) == -1.0)
check("All-same labels on both raters -> kappa 1.0 (no div-by-zero)",
      calculate_cohens_kappa([0, 0, 0, 0], [0, 0, 0, 0]) == 1.0)
check("Empty input -> 0.0",
      calculate_cohens_kappa([], []) == 0.0)
check("Mismatched lengths -> 0.0",
      calculate_cohens_kappa([1, 0], [1]) == 0.0)

# Hand-computed reference: Po = 0.8, Pe = 0.5, kappa = (0.8-0.5)/(1-0.5) = 0.6
det = [1, 1, 1, 1, 1, 0, 0, 0, 0, 0]
cls = [1, 1, 1, 1, 0, 1, 0, 0, 0, 0]
check("Known case computes kappa 0.6", calculate_cohens_kappa(det, cls) == 0.6)

# Chance-level agreement should land near zero
chance = calculate_cohens_kappa([1, 0, 1, 0, 1, 0, 1, 0], [1, 1, 0, 0, 1, 1, 0, 0])
check("Chance-level agreement -> kappa ~= 0.0", abs(chance) < 0.01)
print(f"     -> chance-level kappa: {chance}")

# -------------------------------------------------------------
print("\n🧪 TEST 2: Landis & Koch interpretation bands")
# -------------------------------------------------------------
check("0.90 -> almost perfect", interpret_kappa(0.90) == "almost perfect")
check("0.70 -> substantial", interpret_kappa(0.70) == "substantial")
check("0.50 -> moderate", interpret_kappa(0.50) == "moderate")
check("0.30 -> fair", interpret_kappa(0.30) == "fair")
check("0.10 -> slight", interpret_kappa(0.10) == "slight")
check("-0.50 -> poor", interpret_kappa(-0.50).startswith("poor"))

# -------------------------------------------------------------
print("\n🧪 TEST 3: Corpus loader and aggregation")
# -------------------------------------------------------------
labels = load_rater_labels()
check("load_rater_labels returns paired lists",
      len(labels["detector"]) == len(labels["classifier"]))
print(f"     -> labelled turns currently in DB: {len(labels['detector'])}")

report = compute_agreement()
check("compute_agreement returns a sample_size", "sample_size" in report)
check("compute_agreement reports an interpretation", "interpretation" in report)

if report["sample_size"] == 0:
    check("Empty corpus is reported honestly, not as kappa 0.0",
          report["cohens_kappa"] is None and report["interpretation"] == "insufficient data")
    print("     -> no labelled turns yet (expected before the gateway serves traffic)")
else:
    cm = report["confusion_matrix"]
    total = (cm["both_flagged"] + cm["detector_only"]
             + cm["classifier_only"] + cm["neither_flagged"])
    check("Confusion matrix sums to sample size", total == report["sample_size"])
    check("Kappa is within [-1.0, 1.0]", -1.0 <= report["cohens_kappa"] <= 1.0)
    print(f"     -> kappa: {report['cohens_kappa']} ({report['interpretation']})")
    print(f"     -> matrix: {cm}")

# -------------------------------------------------------------
print("\n🧪 TEST 4: The two IAA metrics are distinct and both reachable")
# -------------------------------------------------------------
from embeddings.auditor import calculate_iaa_score
from intelligence.bridge import calculate_iaa_score as bridge_iaa

check("Intent-Action Alignment is a single shared implementation",
      calculate_iaa_score is bridge_iaa)
check("Inter-Rater Agreement is a different function entirely",
      calculate_cohens_kappa is not calculate_iaa_score)

import main
routes = {r.path for r in main.app.routes if hasattr(r, "path")}
check("Agreement metric is exposed on the gateway",
      "/metrics/agreement" in routes)

print("\n" + "=" * 75)
print(f"  Results: {passed} passed, {failed} failed out of {passed + failed}")
print("  🎉 ALL AGREEMENT TESTS PASSED!" if failed == 0 else "  ⚠️ Some tests failed.")
print("=" * 75)

sys.exit(0 if failed == 0 else 1)
