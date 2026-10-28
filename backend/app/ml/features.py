
import re
from urllib.parse import urlsplit


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

    is_ip = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))

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
