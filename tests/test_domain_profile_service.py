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

    result = service.investigate("example.com")

    assert result["domain"] == "example.com"

    assert "infrastructure" in result
    assert "rdap" in result

    assert result["infrastructure"]["ips"] == [
        "93.184.216.34"
    ]

    assert result["infrastructure"]["asn"][0]["asn"] == "AS15133"

    assert result["rdap"]["registrar"] == "Example Registrar"

    assert result["rdap"]["registration_date"] == (
        "1995-08-14T04:00:00Z"
    )


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

    service.investigate("example.com")

    service.infrastructure_service.investigate.assert_called_once_with(
        "example.com"
    )

    service.rdap_service.investigate.assert_called_once_with(
        "example.com"
    )