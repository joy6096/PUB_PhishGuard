
from app.detectors.url_rules import analyze_url


def codes(url):
    return {item.code for item in analyze_url(url)}


def test_trusted_paypal_domain():
    result = analyze_url("https://paypal.com")

    assert "NO_STATIC_URL_FLAGS" in {
        item.code for item in result
    }
    assert all(item.weight == 0 for item in result)


def test_typosquatting_paypal_lookalike():
    assert "TYPOSQUATTING" in codes(
        "https://paypa1.com/login"
    )


def test_url_shortener():
    assert "URL_SHORTENER" in codes(
        "https://tinyurl.com/abc123"
    )


def test_at_symbol_in_authority():
    result = codes(
        "http://example.com@evil.test/login"
    )

    assert "HTTP_SCHEME" in result
    assert "AT_SYMBOL" in result


def test_ip_host_does_not_trigger_subdomains():
    result = codes("http://192.0.2.1/login")

    assert "HTTP_SCHEME" in result
    assert "IP_HOST" in result
    assert "MANY_SUBDOMAINS" not in result


def test_https_url_has_no_http_warning():
    assert "HTTP_SCHEME" not in codes(
        "https://paypal.com"
    )


def test_empty_url():
    assert "MALFORMED_URL" in codes("")


def test_punycode_host():
    assert "PUNYCODE_HOST" in codes(
        "https://xn--e1afmkfd.example/"
    )
