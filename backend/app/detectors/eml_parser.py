
from email import policy
from email.parser import BytesParser
from email.message import Message
from typing import Any


MAX_EML_BYTES = 1_000_000  # 1 MB


def _header(message: Message, name: str) -> str | None:
    """Return a header as plain text, or None if it is absent."""
    value = message.get(name)
    return str(value)[:2000] if value is not None else None


def _extract_text_parts(message: Message) -> str:
    """
    Extract readable text/plain body parts only.
    Never execute attachments, follow URLs, or extract attachment files.
    """
    parts: list[str] = []

    for part in message.walk():
        if part.is_multipart():
            continue

        # Ignore attached files, including files named .txt or .html.
        if part.get_content_disposition() == "attachment":
            continue

        if part.get_content_type() != "text/plain":
            continue

        try:
            content: Any = part.get_content()
            if isinstance(content, str) and content.strip():
                parts.append(content[:100_000])
        except (LookupError, UnicodeError, ValueError):
            # Malformed or unsupported text part: skip it safely.
            continue

    return "\n\n".join(parts)[:200_000]


def parse_eml(raw_bytes: bytes) -> dict:
    """Parse an .eml file into header metadata and readable text."""

    # 1. Reject empty files.
    if not raw_bytes:
        raise ValueError("The uploaded .eml file is empty.")

    # 2. Enforce the maximum file size.
    if len(raw_bytes) > MAX_EML_BYTES:
        raise ValueError("The .eml file must be 1 MB or smaller.")

    # 3. Reject binary data containing null bytes.
    if b"\x00" in raw_bytes:
        raise ValueError("Could not parse this email file.")

    # 4. Require a header/body separator.
    # Standard email files commonly use CRLF; LF is also accepted.
    if b"\r\n\r\n" not in raw_bytes and b"\n\n" not in raw_bytes:
        raise ValueError("Could not parse this email file.")

    # 5. Parse the email safely.
    try:
        message = BytesParser(
            policy=policy.default
        ).parsebytes(raw_bytes)
    except Exception as exc:
        raise ValueError("Could not parse this email file.") from exc

    # 6. Extract attachment metadata only.
    # Never open or execute attachment contents.
    attachments = []

    for part in message.walk():
        if part.is_multipart():
            continue

        filename = part.get_filename()
        disposition = part.get_content_disposition()

        if filename or disposition == "attachment":
            safe_name = str(filename or "(unnamed attachment)")

            attachments.append({
                "filename": safe_name[:255],
                "content_type": part.get_content_type()[:120],
                "disposition": disposition or "unspecified",
            })

    # 7. Preserve original email header values for the report.
    headers = {
        "from": _header(message, "From"),
        "to": _header(message, "To"),
        "reply_to": _header(message, "Reply-To"),
        "return_path": _header(message, "Return-Path"),
        "subject": _header(message, "Subject"),
        "date": _header(message, "Date"),
        "message_id": _header(message, "Message-ID"),
        "authentication_results": _header(
            message, "Authentication-Results"
        ),
        "received_spf": _header(message, "Received-SPF"),
    }

    # 8. Extract readable plain-text body content.
    body = _extract_text_parts(message)

    # 9. Convert headers into text for the existing email detector.
    header_names = [
        ("From", "from"),
        ("To", "to"),
        ("Reply-To", "reply_to"),
        ("Return-Path", "return_path"),
        ("Subject", "subject"),
        ("Date", "date"),
        ("Message-ID", "message_id"),
        ("Authentication-Results", "authentication_results"),
        ("Received-SPF", "received_spf"),
    ]

    analysis_text = "\n".join(
        f"{header_name}: {headers[key]}"
        for header_name, key in header_names
        if headers.get(key)
    )

    if body:
        analysis_text += "\n\nEmail body:\n" + body

    # 10. Reject files with neither readable headers nor body text.
    if not analysis_text.strip():
        raise ValueError("Could not parse this email file.")

    # 11. Return extracted information for the API and frontend.
    return {
        "headers": headers,
        "body": body,
        "analysis_text": analysis_text[:250_000],
        "attachments": attachments,
    }
