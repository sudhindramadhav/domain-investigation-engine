from app.utils.domain_utils import (
    normalize_domain,
    is_valid_domain,
    is_ip_address
)


def test_normalize_https_url():
    assert normalize_domain(
        "https://www.Example.com/login"
    ) == "example.com"


def test_normalize_hxxps():
    assert normalize_domain(
        "hxxps://Example.com:443/login"
    ) == "example.com"


def test_normalize_domain():
    assert normalize_domain(
        "www.example.com"
    ) == "example.com"


def test_valid_domain():
    assert is_valid_domain("example.com") is True


def test_invalid_domain():
    assert is_valid_domain("example") is False


def test_ip_address():
    assert is_ip_address("8.8.8.8") is True


def test_invalid_ip():
    assert is_ip_address("999.999.999.999") is False