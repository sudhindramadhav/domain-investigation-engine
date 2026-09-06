from unittest.mock import Mock

from app.services.domain_profile_service import DomainProfileService


def test_domain_profile_investigation():

    service = DomainProfileService()

    service.infrastructure_service.investigate = Mock(
        return_value={
            "domain": "example.com",
            "ips": ["93.184.216.34"],
            "dns": {
                "a_records": ["93.184.216.34"],
                "aaaa_records": [],
                "cname_records": [],
                "mx_records": [],
                "nameservers": [
                    "ns1.example.com"
                ]
            },
            "asn": [
                {
                    "ip": "93.184.216.34",
                    "asn": "AS15133",
                    "organization": "Example Network"
                }
            ]
        }
    )

    service.rdap_service.investigate = Mock(
        return_value={
            "domain": "example.com",
            "registrar": "Example Registrar",
            "registration_date": "1995-08-14T04:00:00Z",
            "expiration_date": "2027-08-13T04:00:00Z",
            "updated_date": "2026-01-01T00:00:00Z",
            "status": [
                "client transfer prohibited"
            ],
            "nameservers": [
                "ns1.example.com"
            ],
            "registrant": None
        }
    )

    service.ssl_service.investigate = Mock(
        return_value={
            "domain": "example.com",
            "subject": {
                "commonName": "*.example.com"
            },
            "issuer": {
                "commonName": "Example CA"
            },
            "san": [
                "*.example.com",
                "example.com"
            ],
            "serial_number": "123456789",
            "version": 3,
            "valid_from": "Jan 1 00:00:00 2026 GMT",
            "valid_to": "Jan 1 00:00:00 2027 GMT",
            "fingerprint_sha256": "abc123"
        }
    )

    service.website_service.investigate = Mock(
        return_value={
            "domain": "example.com",
            "url": "https://example.com",
            "final_url": "https://example.com/",
            "status_code": 200,
            "title": "Example Corporation",
            "meta_description": "Example website",
            "text": "Example Corporation official website",
            "links": [],
            "images": [],
            "forms": [],
            "error": None
        }
    )

    service.brand_indicator_service.analyze = Mock(
        return_value={
            "title": "Example Corporation",
            "meta_description": "Example website",
            "brand_candidates": [
                "example corporation"
            ],
            "brand_keywords": [
                "official"
            ],
            "login_indicators": [],
            "logo_candidates": [],
            "favicon_candidates": [],
            "form_indicators": {
                "form_count": 0,
                "password_forms": 0,
                "email_forms": 0
            }
        }
    )

    result = service.investigate(
        "example.com"
    )

    assert result["domain"] == "example.com"

    assert "infrastructure" in result
    assert "rdap" in result
    assert "ssl" in result
    assert "website" in result
    assert "brand_indicators" in result

    assert result["infrastructure"]["ips"] == [
        "93.184.216.34"
    ]

    assert result["infrastructure"]["asn"][0]["asn"] == (
        "AS15133"
    )

    assert result["rdap"]["registrar"] == (
        "Example Registrar"
    )

    assert result["ssl"]["fingerprint_sha256"] == (
        "abc123"
    )

    assert result["website"]["status_code"] == 200

    assert result["website"]["title"] == (
        "Example Corporation"
    )

    assert result["brand_indicators"][
        "brand_candidates"
    ] == [
        "example corporation"
    ]


def test_domain_profile_services_called():

    service = DomainProfileService()

    service.infrastructure_service.investigate = Mock(
        return_value={
            "domain": "example.com",
            "ips": [],
            "dns": {},
            "asn": []
        }
    )

    service.rdap_service.investigate = Mock(
        return_value={
            "domain": "example.com",
            "registrar": None,
            "registration_date": None,
            "expiration_date": None,
            "updated_date": None,
            "status": [],
            "nameservers": [],
            "registrant": None
        }
    )

    service.ssl_service.investigate = Mock(
        return_value={
            "domain": "example.com",
            "subject": None,
            "issuer": None,
            "san": [],
            "serial_number": None,
            "version": None,
            "valid_from": None,
            "valid_to": None,
            "fingerprint_sha256": None
        }
    )

    service.website_service.investigate = Mock(
        return_value={
            "domain": "example.com",
            "url": "https://example.com",
            "final_url": "https://example.com/",
            "status_code": 200,
            "title": None,
            "meta_description": None,
            "text": "",
            "links": [],
            "images": [],
            "forms": [],
            "error": None
        }
    )

    service.brand_indicator_service.analyze = Mock(
        return_value={
            "title": None,
            "meta_description": None,
            "brand_candidates": [],
            "brand_keywords": [],
            "login_indicators": [],
            "logo_candidates": [],
            "favicon_candidates": [],
            "form_indicators": {
                "form_count": 0,
                "password_forms": 0,
                "email_forms": 0
            }
        }
    )

    service.investigate(
        "example.com"
    )

    service.infrastructure_service.investigate.assert_called_once_with(
        "example.com"
    )

    service.rdap_service.investigate.assert_called_once_with(
        "example.com"
    )

    service.ssl_service.investigate.assert_called_once_with(
        "example.com"
    )

    service.website_service.investigate.assert_called_once_with(
        "example.com"
    )

    service.brand_indicator_service.analyze.assert_called_once()