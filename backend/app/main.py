
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

from app.schemas import (
    UrlScanRequest,
    MessageScanRequest,
    EmailScanRequest,
    Indicator,
    ScanResult,
)

from app.detectors.url_rules import analyze_url
from app.detectors.message_rules import analyze_message
from app.detectors.email_rules import analyze_email
from app.detectors.eml_parser import parse_eml

from app.services.scoring import build_result
from app.ml.predict_url import predict_url


app = FastAPI(
    title="PUB PhishGuard API",
    version="0.1.0",
    description="Phishing detection prototype; passive analysis only.",
)


# CORS: allow the local Vite frontend on common development ports.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5175",
        "http://127.0.0.1:5175",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# Health check
@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "pub-phishguard-api",
        "phase": 3,
    }


# URL phishing scan: rule-based + machine learning
@app.post("/api/v1/scans/url", response_model=ScanResult)
def scan_url(payload: UrlScanRequest):
    raw = payload.url.strip()

    if not raw:
        raise HTTPException(
            status_code=422,
            detail="URL cannot be empty.",
        )

    # Step 1: Rule-based analysis
    indicators = analyze_url(raw)

    # Step 2: ML analysis; preserve rule-based results if ML fails
    try:
        ml_result = predict_url(raw)
    except Exception:
        ml_result = None

    # Step 3: Add an ML indicator only at the configured threshold
    if (
        ml_result is not None
        and ml_result.get("prediction") == "phishing"
        and ml_result.get("phishing_probability", 0.0) >= 0.75
    ):
        probability = ml_result["phishing_probability"]

        indicators.append(
            Indicator(
                code="ML_PHISHING_SIGNAL",
                category="url",
                severity="medium",
                weight=15,
                evidence=(
                    "Random Forest model estimates "
                    f"{probability:.0%} phishing probability."
                ),
                explanation=(
                    "The URL's lexical features resemble phishing URLs "
                    "in the training data. This estimate is not proof "
                    "that the URL is malicious."
                ),
                source="ml",
            )
        )

    return build_result("url", indicators)


# SMS / chat message phishing scan
@app.post("/api/v1/scans/message", response_model=ScanResult)
def scan_message(payload: MessageScanRequest):
    message_text = payload.text.strip()

    if not message_text:
        raise HTTPException(
            status_code=422,
            detail="Message text cannot be empty.",
        )

    if len(message_text) > 12000:
        raise HTTPException(
            status_code=413,
            detail="Message exceeds the allowed length.",
        )

    indicators = analyze_message(
        message_text,
        payload.language_hint,
    )

    return build_result("message", indicators)


# Email phishing scan: pasted email and headers
@app.post("/api/v1/scans/email", response_model=ScanResult)
def scan_email(payload: EmailScanRequest):
    raw_email = payload.email_text.strip()

    if not raw_email:
        raise HTTPException(
            status_code=422,
            detail="Email text cannot be empty.",
        )

    if len(raw_email) > 250000:
        raise HTTPException(
            status_code=413,
            detail="Email text exceeds the allowed length.",
        )

    indicators = analyze_email(raw_email)

    return build_result("email", indicators)


# .eml upload and email header parsing
@app.post("/api/v1/scans/email/eml")
async def scan_email_eml(file: UploadFile = File(...)):
    filename = file.filename or ""

    if not filename.lower().endswith(".eml"):
        await file.close()
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported.",
        )

    try:
        # Read at most 1 MB + 1 byte
        raw_bytes = await file.read(1_000_001)
    finally:
        await file.close()

    if not raw_bytes:
        raise HTTPException(
            status_code=400,
            detail="The uploaded .eml file is empty.",
        )

    if len(raw_bytes) > 1_000_000:
        raise HTTPException(
            status_code=413,
            detail="The .eml file must be 1 MB or smaller.",
        )

    try:
        parsed = parse_eml(raw_bytes)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail="Could not parse this .eml file.",
        ) from exc

    analysis_text = parsed.get("analysis_text", "").strip()

    if not analysis_text:
        raise HTTPException(
            status_code=422,
            detail="No readable email headers or text were found.",
        )

    indicators = analyze_email(analysis_text)
    result = build_result("email", indicators)

    # Support both Pydantic v2 and v1
    if hasattr(result, "model_dump"):
        result_data = result.model_dump()
    elif hasattr(result, "dict"):
        result_data = result.dict()
    elif isinstance(result, dict):
        result_data = result.copy()
    else:
        raise HTTPException(
            status_code=500,
            detail="Unexpected scan result format.",
        )

    result_data["email_metadata"] = {
        "filename": filename[:255],
        "headers": parsed.get("headers", {}),
        "attachments": parsed.get("attachments", []),
        "body_extracted": bool(parsed.get("body", "").strip()),
    }

    return result_data
