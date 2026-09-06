from app.models.legitimate_inventory import (
    DomainInventory,
    OrganizationInventory
)
from app.services.inventory_matcher import (
    InventoryMatcher
)


def test_exact_inventory_match():

    organization = OrganizationInventory(
        organization_name="Corcept",
        brand_names=["Corcept"],
        brand_keywords=["corcept"],
        domains=[
            DomainInventory(
                domain="corcept.com",
                ips=["40.93.192.1"],
                asns=["AS8075"],
                nameservers=[
                    "ns45.worldnic.com"
                ],
                brand_names=["Corcept"],
                brand_keywords=["corcept"]
            )
        ]
    )

    suspicious_profile = {
        "domain": "corcept.com",
        "infrastructure": {
            "ips": ["40.93.192.1"],
            "asn": [
                {
                    "asn": "AS8075"
                }
            ],
            "dns": {
                "nameservers": [
                    "ns45.worldnic.com"
                ]
            }
        }
    }

    matcher = InventoryMatcher()

    result = matcher.match(
        suspicious_profile,
        organization
    )

    assert len(result["matches"]) == 1

    match = result["matches"][0]

    assert match["exact_domain_match"] is True

    assert match["infrastructure_score"] == 100

    assert match["domain_similarity"] == 100

    assert "40.93.192.1" in match["shared_ips"]

    assert "AS8075" in match["shared_asns"]

    assert (
        "ns45.worldnic.com"
        in match["shared_nameservers"]
    )


def test_similar_domain_is_detected():

    organization = OrganizationInventory(
        organization_name="Corcept",
        brand_names=["Corcept"],
        brand_keywords=["corcept"],
        domains=[
            DomainInventory(
                domain="corcept.com",
                brand_names=["Corcept"],
                brand_keywords=["corcept"]
            )
        ]
    )

    suspicious_profile = {
        "domain": "corcept-security.com",
        "infrastructure": {
            "ips": [],
            "asn": [],
            "dns": {
                "nameservers": []
            }
        }
    }

    matcher = InventoryMatcher()

    result = matcher.match(
        suspicious_profile,
        organization
    )

    match = result["matches"][0]

    assert (
        match["exact_domain_match"]
        is False
    )

    assert (
        match["domain_similarity"] > 60
    )

    assert (
        match["brand_score"] > 70
    )


def test_shared_infrastructure_is_detected():

    organization = OrganizationInventory(
        organization_name="Example",
        domains=[
            DomainInventory(
                domain="example.com",
                ips=["1.1.1.1"],
                asns=["AS123"],
                nameservers=[
                    "ns1.example.com"
                ]
            )
        ]
    )

    suspicious_profile = {
        "domain": "example-security.com",
        "infrastructure": {
            "ips": ["1.1.1.1"],
            "asn": [
                {
                    "asn": "AS123"
                }
            ],
            "dns": {
                "nameservers": [
                    "ns1.example.com"
                ]
            }
        }
    }

    matcher = InventoryMatcher()

    result = matcher.match(
        suspicious_profile,
        organization
    )

    match = result["matches"][0]

    assert "1.1.1.1" in match["shared_ips"]

    assert "AS123" in match["shared_asns"]

    assert (
        "ns1.example.com"
        in match["shared_nameservers"]
    )

    assert (
        match["infrastructure_score"]
        == 50
    )

def test_registrar_match():

    organization = OrganizationInventory(
        organization_name="Example",
        domains=[
            DomainInventory(
                domain="example.com",
                registrars=[
                    "Network Solutions, LLC"
                ]
            )
        ]
    )

    suspicious_profile = {
        "domain": "example-security.com",
        "infrastructure": {
            "ips": [],
            "asn": [],
            "dns": {
                "nameservers": []
            }
        },
        "rdap": {
            "registrar": "Network Solutions, LLC"
        },
        "ssl": {}
    }

    matcher = InventoryMatcher()

    result = matcher.match(
        suspicious_profile,
        organization
    )

    match = result["matches"][0]

    assert match["registrar_match"] is True

    assert (
        "Registrar matches legitimate inventory"
        in match["evidence"]
    )


def test_ssl_fingerprint_match():

    organization = OrganizationInventory(
        organization_name="Example",
        domains=[
            DomainInventory(
                domain="example.com",
                ssl_fingerprints=[
                    "abc123fingerprint"
                ]
            )
        ]
    )

    suspicious_profile = {
        "domain": "example-security.com",
        "infrastructure": {
            "ips": [],
            "asn": [],
            "dns": {
                "nameservers": []
            }
        },
        "rdap": {},
        "ssl": {
            "fingerprint_sha256":
                "ABC123FINGERPRINT"
        }
    }

    matcher = InventoryMatcher()

    result = matcher.match(
        suspicious_profile,
        organization
    )

    match = result["matches"][0]

    assert (
        match["ssl_fingerprint_match"]
        is True
    )

    assert (
        "SSL certificate fingerprint matches inventory"
        in match["evidence"]
    )