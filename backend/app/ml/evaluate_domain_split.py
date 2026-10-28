
import json
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd
import tldextract

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.model_selection import GroupShuffleSplit

from app.ml.features import extract_features


BASE = Path(__file__).resolve().parent
DATA_PATH = BASE / "data" / "PhiLegit-100K.csv"
OUT = BASE / "artifacts" / "domain_evaluation_report.json"

RANDOM_STATE = 42
TEST_SIZE = 0.20

# Do not download a public suffix list during evaluation.
extractor = tldextract.TLDExtract(suffix_list_urls=())


def get_domain(url: str):
    """Return the registrable domain without visiting the URL."""
    try:
        raw_url = str(url).strip()

        # Support URLs with or without a scheme.
        parsed = urlsplit(
            raw_url if "://" in raw_url else "//" + raw_url
        )
        host = (parsed.hostname or "").lower().rstrip(".")

        if not host:
            return None

        # Keep IP addresses as their own groups.
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass

        # Single-label hosts remain separate groups.
        if "." not in host:
            return host

        result = extractor(host)

        # Prefer registrable domain; fall back to the host if
        # the suffix is not recognized by the local suffix data.
        domain = ".".join(
            part for part in (result.domain, result.suffix) if part
        )

        return domain or host

    except (ValueError, TypeError, AttributeError):
        return None


def main():
    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATA_PATH}\n"
            "Check that PhiLegit-100K.csv exists in app/ml/data/."
        )

    print("Loading dataset...")

    df = pd.read_csv(
        DATA_PATH,
        usecols=["URL", "label_legit_1_phish_0"],
    )

    df = df.dropna(
        subset=["URL", "label_legit_1_phish_0"]
    ).copy()

    df["URL"] = df["URL"].astype(str).str.strip()
    df = df[df["URL"] != ""].copy()
    df = df.drop_duplicates(subset=["URL"]).reset_index(drop=True)

    # Original dataset labels:
    # 0 = phishing, 1 = legitimate.
    #
    # Evaluation target:
    # 0 = legitimate, 1 = phishing.
    original_labels = pd.to_numeric(
        df["label_legit_1_phish_0"],
        errors="coerce",
    )

    df = df.loc[original_labels.isin([0, 1])].copy()
    original_labels = original_labels.loc[df.index]

    df["target"] = (original_labels == 0).astype(int)

    print("Extracting registrable domains...")
    df["domain"] = df["URL"].map(get_domain)
    df = df.dropna(subset=["domain"]).reset_index(drop=True)

    if df.empty:
        raise ValueError("No usable URLs/domains found in the dataset.")

    if df["target"].nunique() < 2:
        raise ValueError(
            "The dataset must contain both legitimate and phishing URLs."
        )

    print("Splitting by domain...")

    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
    )

    train_idx, test_idx = next(
        splitter.split(
            df,
            y=df["target"],
            groups=df["domain"],
        )
    )

    train_df = df.iloc[train_idx].copy()
    test_df = df.iloc[test_idx].copy()

    # Ensure no registrable domain occurs in both sets.
    overlap = set(train_df["domain"]) & set(test_df["domain"])

    if overlap:
        raise RuntimeError(
            f"Domain leakage detected: {len(overlap)} overlapping domains."
        )

    if train_df["target"].nunique() < 2:
        raise ValueError(
            "Training split contains only one class. "
            "Try another RANDOM_STATE or inspect the dataset."
        )

    if test_df["target"].nunique() < 2:
        raise ValueError(
            "Test split contains only one class. "
            "Try another RANDOM_STATE or inspect the dataset."
        )

    print(f"Unique URLs: {len(df):,}")
    print(f"Unique domains: {df['domain'].nunique():,}")
    print(f"Train URLs: {len(train_df):,}")
    print(f"Test URLs: {len(test_df):,}")
    print(f"Train domains: {train_df['domain'].nunique():,}")
    print(f"Test domains: {test_df['domain'].nunique():,}")
    print(f"Train/test domain overlap: {len(overlap)}")

    print("Extracting numeric URL features...")

    # FIX: extract_features() returns dictionaries.
    # Convert them to numeric DataFrames before model.fit().
    X_train = pd.DataFrame(
        [
            extract_features(url)
            for url in train_df["URL"]
        ]
    )

    if X_train.empty or len(X_train.columns) == 0:
        raise ValueError("Feature extraction returned no training features.")

    feature_columns = list(X_train.columns)

    # Force the test set to use exactly the same feature columns/order.
    X_test = pd.DataFrame(
        [
            extract_features(url)
            for url in test_df["URL"]
        ],
        columns=feature_columns,
    )

    # Ensure the extracted values are numeric.
    X_train = X_train.apply(pd.to_numeric, errors="raise").astype(float)
    X_test = X_test.apply(pd.to_numeric, errors="raise").astype(float)

    if X_train.isna().any().any() or X_test.isna().any().any():
        raise ValueError("Missing values found in extracted URL features.")

    y_train = train_df["target"].astype(int).to_numpy()
    y_test = test_df["target"].astype(int).to_numpy()

    print(f"Feature count: {len(feature_columns)}")
    print("Training domain-split Random Forest...")

    model = RandomForestClassifier(
        n_estimators=250,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    # Label 0 = legitimate, label 1 = phishing.
    matrix = confusion_matrix(
        y_test,
        predictions,
        labels=[0, 1],
    )

    metrics_report = classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["legitimate", "phishing"],
        output_dict=True,
        zero_division=0,
    )

    report = {
        "evaluation_type": "domain-wise holdout",
        "dataset": DATA_PATH.name,
        "random_state": RANDOM_STATE,
        "test_size": TEST_SIZE,
        "label_mapping": {
            "0": "legitimate",
            "1": "phishing",
        },
        "unique_urls": int(len(df)),
        "unique_domains": int(df["domain"].nunique()),
        "train_urls": int(len(train_df)),
        "test_urls": int(len(test_df)),
        "train_domains": int(train_df["domain"].nunique()),
        "test_domains": int(test_df["domain"].nunique()),
        "domain_overlap_count": int(len(overlap)),
        "feature_count": int(len(feature_columns)),
        "accuracy": float(
            accuracy_score(y_test, predictions)
        ),
        "precision_phishing": float(
            precision_score(
                y_test,
                predictions,
                pos_label=1,
                zero_division=0,
            )
        ),
        "recall_phishing": float(
            recall_score(
                y_test,
                predictions,
                pos_label=1,
                zero_division=0,
            )
        ),
        "f1_phishing": float(
            f1_score(
                y_test,
                predictions,
                pos_label=1,
                zero_division=0,
            )
        ),
        "classification_report": metrics_report,
        "confusion_matrix_rows_true_columns_predicted_labels_0_legit_1_phish":
            matrix.tolist(),
        "feature_importance": dict(
            sorted(
                zip(
                    feature_columns,
                    model.feature_importances_.tolist(),
                ),
                key=lambda item: item[1],
                reverse=True,
            )
        ),
        "limitations": [
            "Domain-wise holdout tests generalization to unseen registrable domains.",
            "Results on this dataset do not guarantee real-world performance.",
            "Static URL features do not inspect webpage content.",
            "Registrable-domain grouping depends on locally available suffix data.",
        ],
    }

    # Write only the separate domain evaluation report.
    # Do not overwrite url_model.joblib or evaluation_report.json.
    OUT.parent.mkdir(parents=True, exist_ok=True)

    OUT.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print("\n=== DOMAIN-WISE EVALUATION RESULTS ===")
    print(f"Accuracy:  {report['accuracy']:.4f}")
    print(f"Precision: {report['precision_phishing']:.4f}")
    print(f"Recall:    {report['recall_phishing']:.4f}")
    print(f"F1-score:  {report['f1_phishing']:.4f}")
    print("\nConfusion matrix (rows=true, columns=predicted):")
    print("Labels: 0=legitimate, 1=phishing")
    print(matrix.tolist())

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

    print(f"\nReport saved: {OUT}")


if __name__ == "__main__":
    main()
