"""Data Drift Detection — PSI, KS test, feature drift reports."""

import math
from typing import Dict, List


def population_stability_index(
    reference: List[float],
    current: List[float],
    bins: int = 10,
) -> float:
    """Calculate Population Stability Index between reference and current distributions."""
    if not reference or not current:
        return 0.0

    all_vals = reference + current
    min_val, max_val = min(all_vals), max(all_vals)
    if min_val == max_val:
        return 0.0

    bin_width = (max_val - min_val) / bins
    eps = 1e-6

    ref_counts = [0] * bins
    cur_counts = [0] * bins

    for v in reference:
        idx = min(int((v - min_val) / bin_width), bins - 1)
        ref_counts[idx] += 1
    for v in current:
        idx = min(int((v - min_val) / bin_width), bins - 1)
        cur_counts[idx] += 1

    ref_total = len(reference)
    cur_total = len(current)

    psi = 0.0
    for r, c in zip(ref_counts, cur_counts):
        ref_pct = (r / ref_total) + eps
        cur_pct = (c / cur_total) + eps
        psi += (cur_pct - ref_pct) * math.log(cur_pct / ref_pct)

    return round(psi, 6)


def ks_test(reference: List[float], current: List[float]) -> Dict:
    """Kolmogorov-Smirnov test for distribution comparison."""
    if not reference or not current:
        return {"statistic": 0.0, "drift_detected": False}

    ref_sorted = sorted(reference)
    cur_sorted = sorted(current)
    all_vals = sorted(set(ref_sorted + cur_sorted))

    max_diff = 0.0
    for val in all_vals:
        ref_cdf = sum(1 for v in ref_sorted if v <= val) / len(ref_sorted)
        cur_cdf = sum(1 for v in cur_sorted if v <= val) / len(cur_sorted)
        max_diff = max(max_diff, abs(ref_cdf - cur_cdf))

    n = min(len(reference), len(current))
    critical = 1.36 / math.sqrt(n) if n > 0 else 1.0

    return {
        "statistic": round(max_diff, 6),
        "critical_value": round(critical, 6),
        "drift_detected": max_diff > critical,
        "sample_sizes": {"reference": len(reference), "current": len(current)},
    }


def feature_drift_report(
    reference_data: Dict[str, List[float]],
    current_data: Dict[str, List[float]],
) -> Dict:
    """Generate drift report across all features."""
    features = {}
    drifted_count = 0

    for feature_name in reference_data:
        if feature_name not in current_data:
            continue
        ref = reference_data[feature_name]
        cur = current_data[feature_name]

        psi = population_stability_index(ref, cur)
        ks = ks_test(ref, cur)

        if psi < 0.1:
            psi_status = "stable"
        elif psi < 0.25:
            psi_status = "moderate_drift"
        else:
            psi_status = "significant_drift"

        drifted = psi_status == "significant_drift" or ks["drift_detected"]
        if drifted:
            drifted_count += 1

        features[feature_name] = {
            "psi": psi,
            "psi_status": psi_status,
            "ks_statistic": ks["statistic"],
            "ks_drift_detected": ks["drift_detected"],
            "drifted": drifted,
        }

    return {
        "total_features": len(features),
        "drifted_features": drifted_count,
        "drift_percentage": round(drifted_count / len(features) * 100, 1) if features else 0,
        "features": features,
        "overall_status": "drift_detected" if drifted_count > 0 else "stable",
    }
