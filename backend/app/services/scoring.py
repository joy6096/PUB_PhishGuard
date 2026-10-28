
from app.schemas import Indicator, ScanResult


def build_result(
    input_type: str,
    indicators: list[Indicator],
) -> ScanResult:
    # Calculate the score from rule-based and ML indicators.
    score = min(
        100,
        max(0, sum(max(0, item.weight) for item in indicators)),
    )

    # An ML phishing signal should not produce a low-risk result.
    has_ml_phishing_signal = any(
        item.code == "ML_PHISHING_SIGNAL"
        for item in indicators
    )

    if has_ml_phishing_signal:
        score = max(score, 30)

    # Determine risk level and verdict.
    if score >= 70:
        level = "high"
        verdict = "Potential phishing"
    elif score >= 30:
        level = "medium"
        verdict = "Needs caution"
    else:
        level = "low"
        verdict = "No strong static indicators detected"

    return ScanResult(
        input_type=input_type,
        risk_score=score,
        risk_level=level,
        verdict=verdict,
        indicators=indicators,
        recommended_actions=[
            (
                "Do not enter passwords, PINs, OTPs or payment details "
                "from an unexpected message."
            ),
            (
                "Verify the offer through a known official website "
                "or contact channel."
            ),
            "Do not open suspicious links just to test them.",
        ],
        disclaimer=(
            "Automated assessment; not a guarantee of safety "
            "or maliciousness."
        ),
    )
