from email import policy
from email.parser import Parser
from email.utils import parseaddr
import re

from app.schemas import Indicator


def _i(code, severity, weight, evidence, explanation):
    return Indicator(
        code=code,
        category="email",
        severity=severity,
        weight=weight,
        evidence=evidence,
        explanation=explanation,
        source="rule",
    )


URGENCY_PATTERNS = [
    r"\bact now\b",
    r"\bimmediately\b",
    r"\burgent\b",
    r"\baccount.{0,25}(?:suspend|locked|close)\b",
    r"\bverify.{0,25}(?:account|identity|password)\b",
    r"\bwithin \d+ hours?\b",
    r"\bfinal warning\b",
    r"\bclick here\b",
    r"\bpassword expires\b",
    r"\bঅবিলম্বে\b",
    r"\bজরুরি\b",
    r"এখনই",
    r"অ্যাকাউন্ট.{0,20}(?:বন্ধ|ব্লক|স্থগিত)",
    r"যাচাই.{0,20}(?:করুন|করতে)",
    r"পাসওয়ার্ড",
    r"ওটিপি",
]

CREDENTIAL_PATTERNS = [
    r"\b(?:send|share|confirm|provide|enter)\b.{0,35}\b(?:password|otp|pin|verification code)\b",
    r"\b(?:password|otp|pin|verification code)\b.{0,35}\b(?:required|needed|confirm|verify)\b",
    r"(?:পাসওয়ার্ড|ওটিপি|পিন).{0,30}(?:দিন|পাঠান|শেয়ার|প্রদান|লিখুন)",
]

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com",
    ".js", ".vbs", ".ps1", ".jar", ".msi",
    ".docm", ".xlsm", ".pptm",
}

DOUBLE_EXTENSION_PATTERN = re.compile(
    r"\.(?:pdf|doc|docx|xls|xlsx|jpg|jpeg|png)\."
    r"(?:exe|scr|bat|cmd|com|js|vbs|ps1|jar|msi)$",
    re.IGNORECASE,
)


def _domain(address: str) -> str:
    _, parsed = parseaddr(address)
    if "@" not in parsed:
        return ""
    return parsed.rsplit("@", 1)[-1].lower().rstrip(".")


def analyze_email(raw_email: str) -> list[Indicator]:
    """Passively analyse pasted email text. Never open links or attachments."""
    indicators = []

    try:
        message = Parser(policy=policy.default).parsestr(raw_email)
    except Exception:
        message = None

    if message is None:
        return [
            _i(
                "EMAIL_PARSE_ERROR", "medium", 10,
                "Email content could not be parsed reliably.",
                "Check the pasted email format and include its headers if available.",
            )
        ]

    from_header = str(message.get("From", ""))
    reply_to_header = str(message.get("Reply-To", ""))

    from_name, from_address = parseaddr(from_header)
    _, reply_address = parseaddr(reply_to_header)

    if not from_header:
        indicators.append(_i(
            "MISSING_FROM", "medium", 8,
            "No From header was found.",
            "The sender could not be verified from the supplied email text.",
        ))

    if reply_to_header and from_address and reply_address:
        from_domain = _domain(from_address)
        reply_domain = _domain(reply_address)

        if from_domain and reply_domain and from_domain != reply_domain:
            indicators.append(_i(
                "REPLY_TO_MISMATCH", "medium", 18,
                f"From domain: {from_domain}; Reply-To domain: {reply_domain}.",
                "Replies may go to a different domain than the visible sender. "
                "This can be legitimate, but verify unexpected messages independently.",
            ))

    # Check authentication results only when supplied in the pasted headers.
    auth_headers = " ".join(
        str(value) for value in message.get_all("Authentication-Results", [])
    ).lower()

    if auth_headers:
        for method in ("spf", "dkim", "dmarc"):
            results = re.findall(
                rf"\b{method}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b",
                auth_headers,
            )
            if any(result in {"fail", "softfail"} for result in results):
                indicators.append(_i(
                    f"{method.upper()}_FAIL", "medium", 15,
                    f"Supplied Authentication-Results header reports {method}=fail/softfail.",
                    "The supplied header reports an email authentication failure. "
                    "Headers can be forged in pasted text, so this result is not independently verified.",
                ))
            elif not results:
                indicators.append(_i(
                    f"{method.upper()}_UNKNOWN", "info", 0,
                    f"No readable {method.upper()} result was found in Authentication-Results.",
                    "The supplied headers do not provide a readable result for this method.",
                ))
    else:
        indicators.append(_i(
            "AUTH_RESULTS_MISSING", "info", 0,
            "No Authentication-Results header was supplied.",
            "SPF, DKIM and DMARC status cannot be determined from the provided text.",
        ))

    body_parts = []
    if message.is_multipart():
        for part in message.walk():
            if part.is_multipart():
                continue
            if part.get_content_disposition() == "attachment":
                continue
            try:
                content = part.get_content()
                if isinstance(content, str):
                    body_parts.append(content)
            except (LookupError, UnicodeDecodeError, AttributeError):
                continue
    else:
        try:
            content = message.get_content()
            if isinstance(content, str):
                body_parts.append(content)
        except (LookupError, UnicodeDecodeError, AttributeError):
            body_parts.append(raw_email)

    body = "\n".join(body_parts)
    combined_text = f"{from_name}\n{message.get('Subject', '')}\n{body}"
    lowered = combined_text.lower()

    urgency_matches = [
        pattern for pattern in URGENCY_PATTERNS
        if re.search(pattern, lowered, re.IGNORECASE)
    ]
    if urgency_matches:
        indicators.append(_i(
            "URGENT_LANGUAGE", "low", 8,
            f"Matched {len(urgency_matches)} urgency-related pattern(s).",
            "Urgency can pressure recipients into acting quickly. "
            "Review the sender and request before taking action.",
        ))

    credential_matches = [
        pattern for pattern in CREDENTIAL_PATTERNS
        if re.search(pattern, lowered, re.IGNORECASE)
    ]
    if credential_matches:
        indicators.append(_i(
            "CREDENTIAL_REQUEST", "high", 25,
            "Text contains language associated with requesting passwords, PINs or verification codes.",
            "Do not send passwords, PINs or OTPs in response to unexpected email requests.",
        ))

    # Inspect attachment filenames only; never open or execute attachments.
    for part in message.walk():
        filename = part.get_filename()
        if not filename:
            continue

        name = filename.strip()
        suffix = ""
        if "." in name:
            suffix = "." + name.rsplit(".", 1)[-1].lower()

        if DOUBLE_EXTENSION_PATTERN.search(name):
            indicators.append(_i(
                "DOUBLE_EXTENSION_ATTACHMENT", "high", 25,
                f"Suspicious attachment filename: {name}",
                "A filename uses a familiar-looking extension before an executable-type extension. "
                "Do not open the attachment.",
            ))
        elif suffix in RISKY_EXTENSIONS:
            indicators.append(_i(
                "RISKY_ATTACHMENT", "medium", 15,
                f"Attachment filename has a potentially risky extension: {name}",
                "This file type can contain executable content or scripts. "
                "The filename alone does not prove the file is malicious.",
            ))

    if not indicators:
        indicators.append(_i(
            "NO_STATIC_EMAIL_FLAGS", "info", 0,
            "No configured static email indicators matched.",
            "This does not prove the email is safe. Verify the sender independently.",
        ))

    return indicators
