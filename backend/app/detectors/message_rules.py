
import re
from app.schemas import Indicator


PATTERNS = [
    (
        "URGENT_ACTION",
        "medium",
        12,
        r"\b(urgent|immediately|act now|within \d+ hours|account will be blocked)\b"
        r"|জরুরি|এখনই|অবিলম্বে|অ্যাকাউন্ট বন্ধ|শেষ সুযোগ|"
        r"আজই শেষ|তাৎক্ষণিকভাবে|দ্রুত করুন|সঙ্গে সঙ্গে|"
        r"এখনি|অতি জরুরি|দেরি করবেন না",
        "The message pressures the reader to act quickly. Context still matters.",
    ),
    (
        "REWARD_BAIT",
        "medium",
        15,
        r"\b(you won|winner|prize|reward|free money|scholarship approved)\b"
        r"|পুরস্কার জিতেছেন|টাকা জিতেছেন|বৃত্তি পেয়েছেন|"
        r"স্কলারশিপ|রিওয়ার্ড|লটারি জিতেছেন|লাখ টাকা জিতেছেন|"
        r"উপহার পেয়েছেন|বিজয়ী হয়েছেন|পুরস্কার পেয়েছেন|"
        r"ফ্রি উপহার|বিনামূল্যে পুরস্কার",
        "Unexpected rewards or scholarships can be bait. Verify offers through the official organization.",
    ),
    (
        "CREDENTIAL_REQUEST",
        "high",
        20,
        r"\b(password|verify your account|login to claim|enter your credentials|otp|pin)\b"
        r"|পাসওয়ার্ড|লগইন করুন|ওটিপি|পিন নম্বর|তথ্য দিন|"
        r"গোপন নম্বর|পিন দিন|ওটিপি দিন|পাসওয়ার্ড দিন|"
        r"অ্যাকাউন্ট যাচাই|তথ্য যাচাই করুন|ভেরিফাই করুন|"
        r"ব্যক্তিগত তথ্য দিন|আপনার পিন|আপনার ওটিপি|"
        r"পাসওয়ার্ড পাঠান|লগইন তথ্য|গোপন কোড",
        "Requests for passwords, PINs or OTPs are high-risk. Never share them through message links.",
    ),
    (
        "PAYMENT_PRESSURE",
        "medium",
        15,
        r"\b(pay a fee|processing fee|send money|mobile banking)\b"
        r"|ফি পাঠান|টাকা পাঠান|বিকাশ|নগদ|উপায়|প্রসেসিং ফি|"
        r"জরিমানা দিন|টাকা জমা দিন|পেমেন্ট করুন|চার্জ পরিশোধ|"
        r"ফি পরিশোধ|টাকা পাঠিয়ে দিন|অগ্রিম টাকা|"
        r"অর্থ প্রদান করুন|পেমেন্ট সম্পন্ন করুন",
        "Unexpected payment requests should be verified through a known official contact.",
    ),
    (
        "ACCOUNT_THREAT",
        "high",
        18,
        r"\b(account (?:will be|has been) suspended|account blocked|"
        r"account will be closed|security alert|account suspension)\b"
        r"|অ্যাকাউন্ট বন্ধ হয়ে যাবে|অ্যাকাউন্ট বন্ধ করা হবে|"
        r"অ্যাকাউন্ট স্থগিত|অ্যাকাউন্ট বাতিল|অ্যাকাউন্ট ব্লক|"
        r"সেবা বন্ধ হয়ে যাবে|সংযোগ বিচ্ছিন্ন করা হবে|"
        r"অ্যাকাউন্ট বন্ধ করে দেওয়া হবে|অ্যাকাউন্ট নিষ্ক্রিয়|"
        r"আইডি বন্ধ হয়ে যাবে",
        "A threat of account suspension or service loss may be used to pressure the recipient.",
    ),
]


def analyze_message(
    text: str,
    language_hint: str = "auto",
) -> list[Indicator]:
    """
    Detect basic phishing-related phrases in English and Bangla.

    This is a rule-based detector, not a definitive phishing classifier.
    The language_hint parameter is kept for API compatibility.
    """
    found: list[Indicator] = []

    if not text or not text.strip():
        return [
            Indicator(
                code="NO_MESSAGE_RULE_MATCH",
                category="message",
                severity="info",
                weight=0,
                evidence="Empty message.",
                explanation="No message text was provided for analysis.",
                source="rule",
            )
        ]

    for code, severity, weight, pattern, explanation in PATTERNS:
        match = re.search(pattern, text, flags=re.IGNORECASE)

        if match:
            found.append(
                Indicator(
                    code=code,
                    category="message",
                    severity=severity,
                    weight=weight,
                    evidence=f"Matched phrase: {match.group(0)[:80]}",
                    explanation=explanation,
                    source="rule",
                )
            )

    if not found:
        found.append(
            Indicator(
                code="NO_MESSAGE_RULE_MATCH",
                category="message",
                severity="info",
                weight=0,
                evidence="No message phrase pattern matched.",
                explanation=(
                    "No keyword match does not prove a message is genuine. "
                    "Verify the sender and links independently."
                ),
                source="rule",
            )
        )

    return found
