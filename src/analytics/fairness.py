"""Bias & Fairness Testing — disparate impact, demographic parity, equalized odds."""

from typing import Dict, List, Optional


def compute_group_metrics(
    predictions: List[int],
    labels: List[int],
    protected_attribute: List[int],
) -> Dict:
    """Compute metrics per group for fairness analysis."""
    groups = {}
    for pred, label, group in zip(predictions, labels, protected_attribute):
        if group not in groups:
            groups[group] = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "positive_pred": 0, "total": 0}
        groups[group]["total"] += 1
        if pred == 1:
            groups[group]["positive_pred"] += 1
        if pred == 1 and label == 1:
            groups[group]["tp"] += 1
        elif pred == 1 and label == 0:
            groups[group]["fp"] += 1
        elif pred == 0 and label == 0:
            groups[group]["tn"] += 1
        elif pred == 0 and label == 1:
            groups[group]["fn"] += 1

    for g in groups:
        total = groups[g]["total"]
        groups[g]["selection_rate"] = groups[g]["positive_pred"] / total if total > 0 else 0
        tp, fn = groups[g]["tp"], groups[g]["fn"]
        groups[g]["tpr"] = tp / (tp + fn) if (tp + fn) > 0 else 0
        fp, tn = groups[g]["fp"], groups[g]["tn"]
        groups[g]["fpr"] = fp / (fp + tn) if (fp + tn) > 0 else 0
    return groups


def disparate_impact_ratio(group_metrics: Dict) -> float:
    """Calculate disparate impact ratio (4/5ths rule). Values < 0.8 indicate bias."""
    rates = [g["selection_rate"] for g in group_metrics.values() if g["selection_rate"] > 0]
    if len(rates) < 2:
        return 1.0
    return min(rates) / max(rates)


def demographic_parity_difference(group_metrics: Dict) -> float:
    """Max difference in selection rates between groups. 0 = perfect parity."""
    rates = [g["selection_rate"] for g in group_metrics.values()]
    if len(rates) < 2:
        return 0.0
    return max(rates) - min(rates)


def equalized_odds_difference(group_metrics: Dict) -> float:
    """Max difference in TPR or FPR between groups."""
    tprs = [g["tpr"] for g in group_metrics.values()]
    fprs = [g["fpr"] for g in group_metrics.values()]
    tpr_diff = max(tprs) - min(tprs) if len(tprs) >= 2 else 0
    fpr_diff = max(fprs) - min(fprs) if len(fprs) >= 2 else 0
    return max(tpr_diff, fpr_diff)


def full_fairness_report(
    predictions: List[int],
    labels: List[int],
    protected_attribute: List[int],
    group_names: Optional[Dict[int, str]] = None,
) -> Dict:
    """Generate comprehensive fairness report."""
    metrics = compute_group_metrics(predictions, labels, protected_attribute)
    di = disparate_impact_ratio(metrics)
    dp = demographic_parity_difference(metrics)
    eo = equalized_odds_difference(metrics)

    named_metrics = {}
    for k, v in metrics.items():
        name = group_names.get(k, str(k)) if group_names else str(k)
        named_metrics[name] = {
            "selection_rate": round(v["selection_rate"], 4),
            "true_positive_rate": round(v["tpr"], 4),
            "false_positive_rate": round(v["fpr"], 4),
            "total_samples": v["total"],
        }

    passed = di >= 0.8 and dp <= 0.1 and eo <= 0.1
    return {
        "disparate_impact_ratio": round(di, 4),
        "demographic_parity_difference": round(dp, 4),
        "equalized_odds_difference": round(eo, 4),
        "group_metrics": named_metrics,
        "passed": passed,
        "recommendation": "Fair" if passed else "Bias detected — review model for disparate treatment",
    }
