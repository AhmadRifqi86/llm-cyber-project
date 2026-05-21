from typing import Dict


def calculate_overall_security_score(
        base_scores: Dict[str, float],
        lambda_val: float = 1.5,
        cvss_max: float = 10.0) -> Dict:
    """
    Compute overall system security score (0–100) from per-vulnerability CVSS scores.

    Steps (from Section 4.3.5 of the thesis):
    1. Normalize each CVSS score to [0, 1].
    2. Apply power transformation (y = x^λ) to weight high-severity findings more.
    3. Aggregate (sum) the transformed values.
    4. Map aggregated value to security score via 100 / (1 + aggregated).

    Score ranges:
        75 – 99.99 → Low Risk
        50 – 74.99 → Medium Risk
        25 – 49.99 → High Risk
         0 – 24.99 → Critical Risk
    """
    # Filter out zero-score entries
    active = {k: v for k, v in base_scores.items() if v > 0}

    # Step 1 – Normalise
    normalized: Dict[str, float] = {k: round(v / cvss_max, 4) for k, v in active.items()}

    # Step 2 – Power transform
    power_transformed: Dict[str, float] = {
        k: round(v ** lambda_val, 4) for k, v in normalized.items()
    }

    # Step 3 – Aggregate
    aggregated = sum(power_transformed.values())

    # Step 4 – Map to 0-100
    overall_score = round(100 / (1 + aggregated), 1)

    # Determine rating
    if overall_score >= 75:
        rating = 'Low Risk'
    elif overall_score >= 50:
        rating = 'Medium Risk'
    elif overall_score >= 25:
        rating = 'High Risk'
    else:
        rating = 'Critical Risk'

    print(f"\nNormalized values:")
    print(normalized)
    print(f"\nPower Transformed values:")
    print(power_transformed)
    print(f"\nAggregated value: {round(aggregated, 3)}")
    print(f"\n{'-'*50}")
    print(f"Overall Securiy Score: {overall_score}")
    print(f"Overall Security Rating: {rating}")

    return {
        'score': overall_score,
        'rating': rating,
        'normalized': normalized,
        'power_transformed': power_transformed,
        'aggregated': round(aggregated, 3),
    }
