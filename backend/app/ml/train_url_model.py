
import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.model_selection import train_test_split


BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "PhiLegit-100K.csv"
ARTIFACT_DIR = BASE_DIR / "artifacts"
MODEL_PATH = ARTIFACT_DIR / "url_model.joblib"
REPORT_PATH = ARTIFACT_DIR / "evaluation_report.json"

RANDOM_STATE = 42


def extract_features(raw_url: str) -> dict:
    """Extract lexical URL features without visiting the URL."""
    url = str(raw_url).strip()

    try:
        parsed = urlsplit(url if "://" in url else "//" + url)
        host = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
    except ValueError:
        host, path, query = "", "", ""

    labels = [part for part in host.split(".") if part]
    digits = sum(ch.isdigit() for ch in url)
    special_chars = sum(not ch.isalnum() for ch in url)

    try:
        is_ip = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))
    except Exception:
        is_ip = False

    return {
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "underscore_count": url.count("_"),
        "slash_count": url.count("/"),
        "question_count": url.count("?"),
        "equal_count": url.count("="),
        "at_count": url.count("@"),
        "ampersand_count": url.count("&"),
        "percent_count": url.count("%"),
        "digit_count": digits,
        "digit_ratio": digits / max(len(url), 1),
        "special_char_ratio": special_chars / max(len(url), 1),
        "subdomain_count": max(len(labels) - 2, 0),
        "host_label_count": len(labels),
        "https": int(url.lower().startswith("https://")),
        "http": int(url.lower().startswith("http://")),
        "has_ip_host": int(is_ip),
        "has_punycode": int("xn--" in host),
        "has_at_symbol": int("@" in url),
        "has_double_slash_path": int("//" in path),
        "has_encoded_chars": int("%" in url),
        "has_suspicious_words": int(
            any(
                word in url.lower()
                for word in (
                    "login", "verify", "account", "secure",
                    "update", "password", "signin", "confirm",
                )
            )
        ),
        "has_shortener_domain": int(
            host in {
                "bit.ly", "tinyurl.com", "t.co", "is.gd",
                "ow.ly", "rb.gy", "cutt.ly", "buff.ly",
            }
        ),
    }


def main():
    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATA_PATH}\n"
            "Put PhiLegit-100K.csv inside app/ml/data/."
        )

    print("Loading dataset...")
    df = pd.read_csv(DATA_PATH)

    required = {"URL", "label_legit_1_phish_0"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    df = df[["URL", "label_legit_1_phish_0"]].dropna()
    df["URL"] = df["URL"].astype(str).str.strip()
    df = df[df["URL"] != ""].drop_duplicates(subset=["URL"])

    # Original dataset: 0 = phishing, 1 = legitimate.
    # Model target: 1 = phishing, 0 = legitimate.
    df["target"] = (
        df["label_legit_1_phish_0"].astype(int).map({0: 1, 1: 0})
    )

    if df["target"].isna().any():
        raise ValueError("Unexpected label found in dataset.")

    print(f"Unique usable URLs: {len(df):,}")
    print("Original labels:", Counter(df["label_legit_1_phish_0"]))

    print("Extracting URL features...")
    X = pd.DataFrame(
        [extract_features(url) for url in df["URL"]]
    )
    y = df["target"].astype(int)

    # Stratified holdout test set. Keep it separate from training.
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    print(f"Training rows: {len(X_train):,}")
    print(f"Testing rows:  {len(X_test):,}")
    print("Training Random Forest...")

    model = RandomForestClassifier(
        n_estimators=250,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    metrics = {
        "dataset": DATA_PATH.name,
        "unique_urls": int(len(df)),
        "label_mapping": {
            "model_target_1": "phishing",
            "model_target_0": "legitimate",
        },
        "split": {
            "method": "stratified random split",
            "test_size": 0.20,
            "random_state": RANDOM_STATE,
            "train_rows": int(len(X_train)),
            "test_rows": int(len(X_test)),
        },
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision_phishing": float(
            precision_score(y_test, predictions, pos_label=1, zero_division=0)
        ),
        "recall_phishing": float(
            recall_score(y_test, predictions, pos_label=1, zero_division=0)
        ),
        "f1_phishing": float(
            f1_score(y_test, predictions, pos_label=1, zero_division=0)
        ),
        "classification_report": classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["legitimate", "phishing"],
            output_dict=True,
            zero_division=0,
        ),
        "confusion_matrix": confusion_matrix(
            y_test, predictions, labels=[0, 1]
        ).tolist(),
        "feature_importance": dict(
            sorted(
                zip(X.columns, model.feature_importances_),
                key=lambda item: item[1],
                reverse=True,
            )
        ),
        "limitations": [
            "Random URL-level split may place related domains in both sets.",
            "Results on this dataset do not guarantee real-world performance.",
            "Static lexical features do not inspect website content.",
        ],
    }

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(
        {
            "model": model,
            "feature_columns": list(X.columns),
            "target_mapping": {
                "1": "phishing",
                "0": "legitimate",
            },
        },
        MODEL_PATH,
    )

    REPORT_PATH.write_text(
        json.dumps(metrics, indent=2),
        encoding="utf-8",
    )

    print("\n=== HELD-OUT TEST RESULTS ===")
    print(f"Accuracy:  {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision_phishing']:.4f}")
    print(f"Recall:    {metrics['recall_phishing']:.4f}")
    print(f"F1-score:  {metrics['f1_phishing']:.4f}")
    print("\nConfusion matrix (rows=true, columns=predicted):")
    print("Labels: 0=legitimate, 1=phishing")
    print(metrics["confusion_matrix"])
    print("\nClassification report:")
    print(
        classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["legitimate", "phishing"],
            zero_division=0,
        )
    )
    print(f"Model saved:  {MODEL_PATH}")
    print(f"Report saved: {REPORT_PATH}")


if __name__ == "__main__":
    main()
