
from functools import lru_cache
from pathlib import Path

import joblib
import pandas as pd

from app.ml.features import extract_features


MODEL_PATH = (
    Path(__file__).resolve().parent
    / "artifacts"
    / "url_model.joblib"
)


@lru_cache(maxsize=1)
def load_model_bundle():
    """Load the trained model once per running process."""
    if not MODEL_PATH.exists():
        return None

    return joblib.load(MODEL_PATH)


def predict_url(raw_url: str):
    """
    Return ML prediction details.
    Returns None if the model artifact is unavailable.
    """
    bundle = load_model_bundle()

    if bundle is None:
        return None

    model = bundle["model"]
    feature_columns = bundle["feature_columns"]

    features = extract_features(raw_url)
    row = pd.DataFrame(
        [[features[column] for column in feature_columns]],
        columns=feature_columns,
    )

    prediction = int(model.predict(row)[0])

    probabilities = model.predict_proba(row)[0]
    class_index = list(model.classes_).index(1)
    phishing_probability = float(probabilities[class_index])

    return {
        "prediction": "phishing" if prediction == 1 else "legitimate",
        "phishing_probability": round(phishing_probability, 4),
    }
