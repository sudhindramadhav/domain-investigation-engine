from unittest.mock import Mock

from app.services.infrastructure_service import InfrastructureService


def test_infrastructure_investigation():

    service = InfrastructureService()

    service.dns_service.investigate = Mock(
        return_value={
            "domain": "example.com",
            "a_records": ["93.184.216.34"],
            "aaaa_records": ["2606:2800:220:1:248:1893:25c8:1946"],
            "cname_records": [],
            "mx_records": [],
            "nameservers": [
                "a.iana-servers.net",
                "b.iana-servers.net"
            ]
        }
    )

    service.asn_service.lookup_many = Mock(
        return_value=[
            {
                "ip": "93.184.216.34",
                "asn": "AS15133",
                "organization": "Example Network",
                "country": "US"
            },
            {
                "ip": "2606:2800:220:1:248:1893:25c8:1946",
                "asn": "AS15133",
                "organization": "Example Network",
                "country": "US"
            }
        ]
    )

    result = service.investigate("example.com")

    assert result["domain"] == "example.com"

    assert len(result["ips"]) == 2

    assert result["ips"][0] == "93.184.216.34"

    assert len(result["asn"]) == 2

    assert result["asn"][0]["asn"] == "AS15133"


def test_infrastructure_without_ips():

    service = InfrastructureService()

    service.dns_service.investigate = Mock(
        return_value={
            "domain": "example.com",
            "a_records": [],
            "aaaa_records": [],
            "cname_records": [],
            "mx_records": [],
            "nameservers": []
        }
    )

    service.asn_service.lookup_many = Mock(
        return_value=[]
    )

    result = service.investigate("example.com")

    assert result["domain"] == "example.com"
    assert result["ips"] == []
    assert result["asn"] == []