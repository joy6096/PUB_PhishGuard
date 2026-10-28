
from urllib.parse import urlsplit
import ipaddress
from difflib import SequenceMatcher

from app.schemas import Indicator
from app.data.trusted_domains import TRUSTED_DOMAINS


SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "ow.ly",
    "rb.gy",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "buff.ly",
}

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "click",
    "top",
    "work",
    "country",
    "gq",
    "tk",
}

CONFUSABLE_MAP = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "7": "t",
})

BRAND_BAIT_WORDS = {
    "login",
    "secure",
    "verify",
    "account",
    "update",
    "support",
    "signin",
    "confirm",
    "auth",
    "billing",
    "wallet",
    "password",
}


def _i(code, category, severity, weight, evidence, explanation):
    return Indicator(
        code=code,
        category=category,
        severity=severity,
        weight=weight,
        evidence=evidence,
        explanation=explanation,
        source="rule",
    )


def _normalise_label(label: str) -> str:
    """Normalize common digit-based look-alike substitutions."""
    return label.lower().translate(CONFUSABLE_MAP)


def _edit_distance(a: str, b: str) -> int:
    """Calculate Levenshtein edit distance without dependencies."""
    if len(a) < len(b):
        a, b = b, a

    previous = list(range(len(b) + 1))

    for i, char_a in enumerate(a, start=1):
        current = [i]

        for j, char_b in enumerate(b, start=1):
            current.append(
                min(
                    current[j - 1] + 1,
                    previous[j] + 1,
                    previous[j - 1] + (char_a != char_b),
                )
            )

        previous = current

    return previous[-1]


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_trusted_host(host: str, trusted_domain: str) -> bool:
    """Match an exact trusted domain or its subdomains."""
    return (
        host == trusted_domain
        or host.endswith("." + trusted_domain)
    )


def _get_trusted_domains() -> list[str]:
    """Normalize and deduplicate configured reference domains."""
    domains = set()

    for domain in TRUSTED_DOMAINS:
        domain = str(domain).lower().strip().strip(".")

        if domain:
            domains.add(domain)

    return sorted(domains)


def _find_typosquatting(host: str):
    """
    Heuristically compare hostname labels with configured trusted domains.

    This is a static heuristic, not proof that a domain is malicious.
    """
    host = host.lower().strip(".")

    if not host or _is_ip_address(host):
        return None

    host_labels = host.split(".")
    best_match = None

    for trusted_domain in _get_trusted_domains():
        # An official domain and its subdomains are not automatically
        # typosquatting against that same reference domain.
        if _is_trusted_host(host, trusted_domain):
            continue

        trusted_labels = trusted_domain.split(".")
        target_label = trusted_labels[0]

        # Use the registrable-looking reference label for comparison.
        # This assumes the configured list contains ordinary domains
        # such as paypal.com, not public suffixes such as co.uk.
        target_normalized = _normalise_label(target_label)

        if len(target_normalized) < 4:
            continue

        for label in host_labels:
            candidate_original = label.lower()
            candidate_normalized = _normalise_label(candidate_original)

            if len(candidate_normalized) < 4:
                continue

            # Calculate both distances. The raw distance explains
            # the literal spelling; normalized distance detects
            # digit substitutions such as paypa1 -> paypal.
            raw_distance = _edit_distance(
                candidate_original,
                target_label,
            )

            normalized_distance = _edit_distance(
                candidate_normalized,
                target_normalized,
            )

            raw_similarity = SequenceMatcher(
                None,
                candidate_original,
                target_label,
            ).ratio()

            normalized_similarity = SequenceMatcher(
                None,
                candidate_normalized,
                target_normalized,
            ).ratio()

            confusable_match = (
                candidate_original != target_label
                and candidate_normalized == target_normalized
            )

            # Do not treat a label as a typo merely because it contains
            # a brand name as a substring. Only recognize the specific
            # bait-word combinations listed above.
            bait_match = any(
                candidate_normalized in {
                    target_normalized + word,
                    target_normalized + "-" + word,
                    word + target_normalized,
                    word + "-" + target_normalized,
                }
                for word in BRAND_BAIT_WORDS
            )

            close_typo = (
                raw_distance in (1, 2)
                and raw_similarity >= 0.78
                and abs(
                    len(candidate_original) - len(target_label)
                ) <= 2
            )

            # Exact labels should not be flagged as typosquatting.
            exact_label = candidate_original == target_label

            if exact_label:
                continue

            if not (
                confusable_match
                or close_typo
                or bait_match
            ):
                continue

            if confusable_match:
                priority = 0
            elif bait_match:
                priority = 1
            else:
                priority = 2 + raw_distance

            match = {
                "priority": priority,
                "trusted_domain": trusted_domain,
                "matched_label": candidate_original,
                "target_label": target_label,
                "raw_distance": raw_distance,
                "raw_similarity": raw_similarity,
                "normalized_distance": normalized_distance,
                "normalized_similarity": normalized_similarity,
                "confusable_match": confusable_match,
                "bait_match": bait_match,
            }

            if (
                best_match is None
                or match["priority"] < best_match["priority"]
            ):
                best_match = match

    if best_match is None:
        return None

    matched_label = best_match["matched_label"]
    trusted_domain = best_match["trusted_domain"]
    target_label = best_match["target_label"]

    raw_distance = best_match["raw_distance"]
    raw_similarity = best_match["raw_similarity"]
    normalized_distance = best_match["normalized_distance"]
    normalized_similarity = best_match["normalized_similarity"]

    if best_match["confusable_match"]:
        method = "look-alike character normalization"
    elif best_match["bait_match"]:
        method = "brand-related bait wording"
    else:
        method = "literal spelling similarity"

    evidence = (
        f"Hostname label '{matched_label}' resembles "
        f"'{target_label}' from reference domain '{trusted_domain}'. "
        f"Raw edit distance: {raw_distance}; "
        f"raw similarity: {raw_similarity:.2f}; "
        f"normalized edit distance: {normalized_distance}; "
        f"normalized similarity: {normalized_similarity:.2f}; "
        f"match method: {method}."
    )

    return _i(
        "TYPOSQUATTING",
        "url",
        "high",
        30,
        evidence,
        (
            "This hostname may imitate a trusted organisation or "
            "use brand-related wording. Similarity is only a heuristic. "
            "Verify the exact registered domain through an independent "
            "official source."
        ),
    )


def analyze_url(raw_url: str) -> list[Indicator]:
    """
    Perform passive URL analysis.

    Never opens, resolves, or fetches the submitted URL.
    """
    indicators = []
    raw_url = (raw_url or "").strip()

    if not raw_url:
        return [
            _i(
                "MALFORMED_URL",
                "url",
                "medium",
                10,
                "URL input is empty.",
                "Provide a complete URL for analysis.",
            )
        ]

    try:
        parsed = urlsplit(raw_url)
        host = (parsed.hostname or "").lower().rstrip(".")
        scheme = parsed.scheme.lower()

        # Invalid port syntax can raise ValueError.
        _ = parsed.port

    except ValueError:
        return [
            _i(
                "URL_PARSE_ERROR",
                "url",
                "high",
                35,
                "URL could not be parsed reliably.",
                (
                    "Malformed URLs can obscure the destination. "
                    "Verify the address through a trusted channel."
                ),
            )
        ]

    if not host or scheme not in {"http", "https"}:
        indicators.append(
            _i(
                "MALFORMED_URL",
                "url",
                "medium",
                10,
                "URL is missing a valid HTTP(S) scheme or hostname.",
                (
                    "Provide a complete web URL, including "
                    "http:// or https:// and a valid hostname."
                ),
            )
        )

    if scheme and scheme not in {"http", "https"}:
        indicators.append(
            _i(
                "UNUSUAL_URL_SCHEME",
                "url",
                "medium",
                12,
                f"URL uses the '{scheme}' scheme.",
                (
                    "This is not a standard HTTP or HTTPS web URL. "
                    "Treat it carefully and do not open it to test it."
                ),
            )
        )

    if scheme == "http":
        indicators.append(
            _i(
                "HTTP_SCHEME",
                "url",
                "low",
                5,
                "URL uses HTTP rather than HTTPS.",
                (
                    "HTTP does not provide HTTPS transport protection. "
                    "This alone does not mean the URL is phishing."
                ),
            )
        )

    if len(raw_url) > 100:
        indicators.append(
            _i(
                "LONG_URL",
                "url",
                "low",
                8,
                f"URL length: {len(raw_url)} characters.",
                (
                    "Long URLs can obscure the meaningful destination. "
                    "Inspect the hostname carefully."
                ),
            )
        )

    # Check only the authority; @ in the path or query is different.
    if "@" in parsed.netloc:
        indicators.append(
            _i(
                "AT_SYMBOL",
                "url",
                "medium",
                15,
                "The URL authority contains an @ symbol.",
                (
                    "The text before @ may be mistaken for the destination. "
                    "Inspect the actual hostname carefully."
                ),
            )
        )

    if host:
        is_ip = _is_ip_address(host)
        labels = [label for label in host.split(".") if label]

        if is_ip:
            indicators.append(
                _i(
                    "IP_HOST",
                    "url",
                    "high",
                    20,
                    f"Hostname is an IP address: {host}.",
                    (
                        "A raw IP host can be suspicious, "
                        "but is not proof of maliciousness by itself."
                    ),
                )
            )

        if any(label.startswith("xn--") for label in labels):
            indicators.append(
                _i(
                    "PUNYCODE_HOST",
                    "url",
                    "medium",
                    15,
                    "Hostname contains an xn-- punycode label.",
                    (
                        "Punycode may represent an internationalized domain. "
                        "Verify the exact spelling carefully."
                    ),
                )
            )

        # Do not count IP address octets as domain subdomains.
        if not is_ip and len(labels) >= 4:
            indicators.append(
                _i(
                    "MANY_SUBDOMAINS",
                    "url",
                    "low",
                    8,
                    (
                        f"Hostname contains {len(labels) - 2} "
                        "label(s) before the final two labels."
                    ),
                    (
                        "Nested subdomains can make an unrelated "
                        "domain look familiar."
                    ),
                )
            )

        if any(
            host == shortener
            or host.endswith("." + shortener)
            for shortener in SHORTENERS
        ):
            indicators.append(
                _i(
                    "URL_SHORTENER",
                    "url",
                    "medium",
                    12,
                    f"Hostname matches a known URL shortener: {host}.",
                    (
                        "Shortened URLs hide their final destination. "
                        "Verify the destination independently."
                    ),
                )
            )

        tld = labels[-1] if labels else ""

        if tld in SUSPICIOUS_TLDS:
            indicators.append(
                _i(
                    "SUSPICIOUS_TLD",
                    "url",
                    "low",
                    8,
                    f"Top-level domain is .{tld}.",
                    (
                        "A TLD alone does not establish maliciousness; "
                        "consider the full context."
                    ),
                )
            )

        typo_indicator = _find_typosquatting(host)

        if typo_indicator is not None:
            indicators.append(typo_indicator)

    if not indicators:
        indicators.append(
            _i(
                "NO_STATIC_URL_FLAGS",
                "url",
                "info",
                0,
                "No static URL indicators matched.",
                (
                    "This does not prove the URL is safe. "
                    "Verify the domain independently."
                ),
            )
        )

    return indicators
