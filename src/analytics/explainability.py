"""Explainability Engine — feature importance and counterfactual explanations."""

from typing import Dict, List, Optional
import random


def compute_feature_importance(
    feature_names: List[str],
    feature_values: List[float],
    weights: Optional[List[float]] = None,
) -> Dict:
    """Compute weighted feature attribution scores."""
    if weights is None:
        weights = [1.0 / len(feature_names)] * len(feature_names)

    total_weight = sum(abs(w * v) for w, v in zip(weights, feature_values))
    if total_weight == 0:
        total_weight = 1.0

    contributions = []
    for name, value, weight in zip(feature_names, feature_values, weights):
        score = abs(weight * value) / total_weight
        contributions.append({
            "feature": name,
            "value": value,
            "weight": round(weight, 4),
            "contribution": round(score, 4),
            "direction": "positive" if weight * value >= 0 else "negative",
        })

    contributions.sort(key=lambda x: x["contribution"], reverse=True)
    return {"contributions": contributions, "method": "weighted_attribution"}


def generate_explanation(
    feature_names: List[str],
    feature_values: List[float],
    prediction: str,
    weights: Optional[List[float]] = None,
    num_counterfactuals: int = 3,
) -> Dict:
    """Generate a human-readable explanation with counterfactuals."""
    importance = compute_feature_importance(feature_names, feature_values, weights)
    top_features = importance["contributions"][:3]

    explanation_parts = [f"The prediction '{prediction}' was primarily influenced by:"]
    for i, feat in enumerate(top_features, 1):
        direction = "increasing" if feat["direction"] == "positive" else "decreasing"
        explanation_parts.append(
            f"  {i}. {feat['feature']} (value={feat['value']}, {direction} risk, "
            f"contribution={feat['contribution']:.1%})"
        )

    counterfactuals = []
    for _ in range(min(num_counterfactuals, len(feature_names))):
        cf_values = list(feature_values)
        idx = random.randint(0, len(feature_names) - 1)
        cf_values[idx] = cf_values[idx] * 0.5
        counterfactuals.append({
            "changed_feature": feature_names[idx],
            "original_value": feature_values[idx],
            "new_value": round(cf_values[idx], 4),
            "note": f"Reducing {feature_names[idx]} by 50% could change the outcome",
        })

    return {
        "prediction": prediction,
        "explanation": "\n".join(explanation_parts),
        "feature_importance": importance,
        "counterfactuals": counterfactuals,
    }
