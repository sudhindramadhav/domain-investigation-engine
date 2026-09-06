from app.services.dns_service import DNSService


def test_dns_service_returns_structure():
    service = DNSService()

    result = service.investigate("example.com")

    assert "domain" in result
    assert "a_records" in result
    assert "aaaa_records" in result
    assert "cname_records" in result
    assert "mx_records" in result
    assert "nameservers" in result


def test_dns_service_example_domain():
    service = DNSService()

    result = service.investigate("example.com")

    assert result["domain"] == "example.com"
    assert isinstance(result["a_records"], list)
    assert isinstance(result["nameservers"], list)