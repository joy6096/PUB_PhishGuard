
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_message_scan():
    r = client.post(
        "/api/v1/scans/message",
        json={
            "text": "আপনি পুরস্কার জিতেছেন। টাকা পেতে এখনই লগইন করুন।",
            "language_hint": "bn",
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert 0 <= data["risk_score"] <= 100
    assert len(data["indicators"]) >= 1


def test_url_scan():
    r = client.post(
        "/api/v1/scans/url",
        json={
            "url": "https://pub-scholarship-example.test/login"
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert data["input_type"] == "url"
    assert 0 <= data["risk_score"] <= 100
    assert data["risk_level"] in {"low", "medium", "high"}
    assert isinstance(data["indicators"], list)


def test_url_requires_scheme():
    r = client.post(
        "/api/v1/scans/url",
        json={"url": "example.com"},
    )
    assert r.status_code == 422


def test_url_ml_indicator_when_phishing_probability_is_high(monkeypatch):
    from app.main import scan_url

    monkeypatch.setattr(
        "app.main.analyze_url",
        lambda raw: [],
    )
    monkeypatch.setattr(
        "app.main.predict_url",
        lambda raw: {
            "prediction": "phishing",
            "phishing_probability": 0.90,
        },
    )

    result = scan_url(
        __import__("app.schemas", fromlist=["UrlScanRequest"])
        .UrlScanRequest(url="https://example.test/login")
    )

    ml_indicators = [
        item for item in result.indicators
        if item.code == "ML_PHISHING_SIGNAL"
    ]

    assert len(ml_indicators) == 1
    assert ml_indicators[0].source == "ml"
    assert result.risk_score >= 30


def test_url_no_ml_indicator_below_threshold(monkeypatch):
    from app.main import scan_url
    from app.schemas import UrlScanRequest

    monkeypatch.setattr("app.main.analyze_url", lambda raw: [])
    monkeypatch.setattr(
        "app.main.predict_url",
        lambda raw: {
            "prediction": "phishing",
            "phishing_probability": 0.74,
        },
    )

    result = scan_url(
        UrlScanRequest(url="https://example.test/login")
    )

    assert not any(
        item.code == "ML_PHISHING_SIGNAL"
        for item in result.indicators
    )


def test_url_rule_based_fallback_when_ml_fails(monkeypatch):
    from app.main import scan_url
    from app.schemas import Indicator, UrlScanRequest

    rule_indicator = Indicator(
        code="TEST_RULE",
        category="url",
        severity="low",
        weight=5,
        evidence="Test rule indicator",
        explanation="Used to test fallback behavior.",
        source="rule",
    )

    monkeypatch.setattr(
        "app.main.analyze_url",
        lambda raw: [rule_indicator],
    )

    def failing_prediction(raw):
        raise RuntimeError("Simulated model failure")

    monkeypatch.setattr("app.main.predict_url", failing_prediction)

    result = scan_url(
        UrlScanRequest(url="https://example.test/login")
    )

    assert any(
        item.code == "TEST_RULE"
        for item in result.indicators
    )
    assert not any(
        item.code == "ML_PHISHING_SIGNAL"
        for item in result.indicators
    )
    assert result.risk_score == 5
