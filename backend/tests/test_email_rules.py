
from app.detectors.email_rules import analyze_email


def codes(raw_email):
    return {item.code for item in analyze_email(raw_email)}


def test_missing_from_header():
    result = codes(
        "Subject: Hello\n\nThis is a normal message."
    )
    assert "MISSING_FROM" in result


def test_reply_to_domain_mismatch():
    result = codes(
        "From: Support <support@example.com>\n"
        "Reply-To: attacker@evil.test\n"
        "Subject: Hello\n\n"
        "Please contact us."
    )
    assert "REPLY_TO_MISMATCH" in result


def test_spf_failure():
    result = codes(
        "From: sender@example.com\n"
        "Authentication-Results: mx.example; spf=fail\n"
        "Subject: Test\n\n"
        "Hello."
    )
    assert "SPF_FAIL" in result


def test_dkim_failure():
    result = codes(
        "From: sender@example.com\n"
        "Authentication-Results: mx.example; dkim=fail\n"
        "Subject: Test\n\n"
        "Hello."
    )
    assert "DKIM_FAIL" in result


def test_dmarc_failure():
    result = codes(
        "From: sender@example.com\n"
        "Authentication-Results: mx.example; dmarc=fail\n"
        "Subject: Test\n\n"
        "Hello."
    )
    assert "DMARC_FAIL" in result


def test_missing_authentication_results():
    result = codes(
        "From: sender@example.com\n"
        "Subject: Hello\n\n"
        "Normal message."
    )
    assert "AUTH_RESULTS_MISSING" in result


def test_urgent_language():
    result = codes(
        "From: Security <security@example.com>\n"
        "Subject: Urgent final warning\n\n"
        "Act now to avoid account suspension."
    )
    assert "URGENT_LANGUAGE" in result


def test_credential_request():
    result = codes(
        "From: Support <support@example.com>\n"
        "Subject: Verification required\n\n"
        "Please enter your password."
    )
    assert "CREDENTIAL_REQUEST" in result


def test_double_extension_attachment():
    result = codes(
        "From: sender@example.com\n"
        "Subject: Document\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/mixed; boundary=BOUNDARY\n\n"
        "--BOUNDARY\n"
        "Content-Type: text/plain\n\n"
        "Please review the attached document.\n"
        "--BOUNDARY\n"
        "Content-Type: application/octet-stream\n"
        "Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\n"
        "Content-Transfer-Encoding: base64\n\n"
        "QUJD\n"
        "--BOUNDARY--\n"
    )
    assert "DOUBLE_EXTENSION_ATTACHMENT" in result


def test_risky_attachment():
    result = codes(
        "From: sender@example.com\n"
        "Subject: Script\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/mixed; boundary=BOUNDARY\n\n"
        "--BOUNDARY\n"
        "Content-Type: text/plain\n\n"
        "Please see the file.\n"
        "--BOUNDARY\n"
        "Content-Type: application/octet-stream\n"
        "Content-Disposition: attachment; filename=\"setup.exe\"\n"
        "Content-Transfer-Encoding: base64\n\n"
        "QUJD\n"
        "--BOUNDARY--\n"
    )
    assert "RISKY_ATTACHMENT" in result
