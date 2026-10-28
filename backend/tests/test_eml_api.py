
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def make_eml(
    *,
    include_attachment: bool = False,
) -> bytes:
    """Build synthetic email fixtures entirely in memory."""

    if include_attachment:
        return (
            b"From: Security Team <security@example.com>\r\n"
            b"Reply-To: verify@example.net\r\n"
            b"To: tester@example.org\r\n"
            b"Subject: Urgent account verification\r\n"
            b"MIME-Version: 1.0\r\n"
            b'Content-Type: multipart/mixed; boundary="test-boundary"\r\n'
            b"\r\n"
            b"--test-boundary\r\n"
            b'Content-Type: text/plain; charset="UTF-8"\r\n'
            b"\r\n"
            b"Urgent! Verify your account and provide your OTP immediately.\r\n"
            b"--test-boundary\r\n"
            b'Content-Type: application/octet-stream; name="invoice.pdf.exe"\r\n'
            b'Content-Disposition: attachment; filename="invoice.pdf.exe"\r\n'
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"SGVsbG8=\r\n"
            b"--test-boundary--\r\n"
        )

    return (
        b"From: Security Team <security@example.com>\r\n"
        b"Reply-To: verify-account@example.net\r\n"
        b"To: tester@example.org\r\n"
        b"Subject: URGENT: Account Verification Required\r\n"
        b"Date: Tue, 27 Oct 2026 10:00:00 +0000\r\n"
        b"Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: text/plain; charset="UTF-8"\r\n'
        b"\r\n"
        b"Your account will be suspended today. "
        b"Verify your account immediately and provide your OTP.\r\n"
    )


def indicator_codes(data: dict) -> set[str]:
    return {
        item["code"]
        for item in data["indicators"]
    }


def test_valid_eml_upload_returns_scan_and_metadata():
    response = client.post(
        "/api/v1/scans/email/eml",
        files={
            "file": (
                "synthetic-test.eml",
                make_eml(),
                "message/rfc822",
            )
        },
    )

    assert response.status_code == 200
    data = response.json()

    assert data["input_type"] == "email"
    assert "risk_score" in data
    assert "risk_level" in data
    assert "verdict" in data
    assert isinstance(data["indicators"], list)

    metadata = data["email_metadata"]

    assert metadata["filename"] == "synthetic-test.eml"
    assert metadata["headers"]["from"] == (
        "Security Team <security@example.com>"
    )
    assert metadata["headers"]["to"] == "tester@example.org"
    assert metadata["headers"]["reply_to"] == (
        "verify-account@example.net"
    )
    assert metadata["headers"]["subject"] == (
        "URGENT: Account Verification Required"
    )
    assert metadata["body_extracted"] is True
    assert metadata["attachments"] == []


def test_eml_upload_detects_reply_to_mismatch_and_credential_request():
    response = client.post(
        "/api/v1/scans/email/eml",
        files={
            "file": (
                "suspicious.eml",
                make_eml(),
                "message/rfc822",
            )
        },
    )

    assert response.status_code == 200

    data = response.json()
    codes = indicator_codes(data)

    assert "REPLY_TO_MISMATCH" in codes
    assert "CREDENTIAL_REQUEST" in codes
    assert "URGENT_LANGUAGE" in codes


def test_eml_upload_extracts_attachment_metadata():
    response = client.post(
        "/api/v1/scans/email/eml",
        files={
            "file": (
                "with-attachment.eml",
                make_eml(include_attachment=True),
                "message/rfc822",
            )
        },
    )

    assert response.status_code == 200

    data = response.json()
    attachments = data["email_metadata"]["attachments"]

    assert len(attachments) == 1
    assert attachments[0]["filename"] == "invoice.pdf.exe"
    assert attachments[0]["disposition"] == "attachment"
    assert data["email_metadata"]["body_extracted"] is True

    # Metadata is extracted without opening or executing the attachment.
    # Filename-based risk detection requires a separate detector rule.


def test_eml_upload_rejects_wrong_file_extension():
    response = client.post(
        "/api/v1/scans/email/eml",
        files={
            "file": (
                "message.txt",
                make_eml(),
                "text/plain",
            )
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Only .eml files are supported."
    )


def test_eml_upload_rejects_empty_file():
    response = client.post(
        "/api/v1/scans/email/eml",
        files={
            "file": (
                "empty.eml",
                b"",
                "message/rfc822",
            )
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "The uploaded .eml file is empty."
    )


def test_eml_upload_rejects_file_over_one_mb():
    response = client.post(
        "/api/v1/scans/email/eml",
        files={
            "file": (
                "oversized.eml",
                b"A" * 1_000_001,
                "message/rfc822",
            )
        },
    )

    assert response.status_code == 413
    assert response.json()["detail"] == (
        "The .eml file must be 1 MB or smaller."
    )


def test_eml_upload_rejects_file_without_readable_email_content():
    response = client.post(
        "/api/v1/scans/email/eml",
        files={
            "file": (
                "unreadable.eml",
                b"\x00\x01\x02\x03",
                "message/rfc822",
            )
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Could not parse this email file."
    )
