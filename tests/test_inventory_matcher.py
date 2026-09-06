from app.models.legitimate_inventory import (
    OrganizationInventory,
    DomainInventory
)

from app.services.inventory_matcher import InventoryMatcher


def test_exact_inventory_match():

    organization = OrganizationInventory(
        organization_name="Example",
        domains=[
            DomainInventory(
                domain="example.com"
            )
        ]
    )

    suspicious_profile = {
        "domain": "example.com",
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

    assert (
        result["best_match"]["exact_domain_match"]
        is True
    )


def test_similar_domain_is_detected():

    organization = OrganizationInventory(
        organization_name="Example",
        brand_names=["Example"],
        domains=[
            DomainInventory(
                domain="example.com",
                brand_names=["Example"]
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
        }
    }

    matcher = InventoryMatcher()

    result = matcher.match(
        suspicious_profile,
        organization
    )

    assert (
        result["best_match"]["domain_similarity"]
        > 60
    )


def test_shared_infrastructure_is_detected():

    organization = OrganizationInventory(
        organization_name="Example",
        domains=[
            DomainInventory(
                domain="example.com",
                ips=[
                    "1.1.1.1"
                ],
                asns=[
                    "AS123"
                ],
                nameservers=[
                    "ns1.example.com"
                ]
            )
        ]
    )

    suspicious_profile = {
        "domain": "example-security.com",
        "infrastructure": {
            "ips": [
                "1.1.1.1"
            ],
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

    best_match = result["best_match"]

    assert (
        "1.1.1.1"
        in best_match["shared_current_ips"]
    )

    assert (
        "AS123"
        in best_match["shared_asns"]
    )

    assert (
        "ns1.example.com"
        in best_match["shared_nameservers"]
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
        }
    }

    matcher = InventoryMatcher()

    result = matcher.match(
        suspicious_profile,
        organization
    )

    assert (
        result["best_match"]["registrar_match"]
        is True
    )


def test_ssl_fingerprint_match():

    organization = OrganizationInventory(
        organization_name="Example",
        domains=[
            DomainInventory(
                domain="example.com",
                ssl_fingerprints=[
                    "abc123"
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
        "ssl": {
            "fingerprint_sha256": "abc123"
        }
    }

    matcher = InventoryMatcher()

    result = matcher.match(
        suspicious_profile,
        organization
    )

    assert (
        result["best_match"]["ssl_fingerprint_match"]
        is True
    )


def test_passive_dns_match():

    organization = OrganizationInventory(
        organization_name="Example",
        domains=[
            DomainInventory(
                domain="example.com",
                passive_dns=[
                    "2.2.2.2"
                ]
            )
        ]
    )

    suspicious_profile = {
        "domain": "example-security.com",
        "infrastructure": {
            "ips": [
                "2.2.2.2"
            ],
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

    assert (
        "2.2.2.2"
        in result["best_match"]["shared_passive_dns"]
    )


def test_brand_impersonation_confidence():

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
        "domain": "corcept-login.com",
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

    assert (
        result["best_match"][
            "brand_impersonation_confidence"
        ]
        >= 70
    )


def test_exact_inventory_match_has_no_impersonation_confidence():

    organization = OrganizationInventory(
        organization_name="Example",
        brand_names=["Example"],
        domains=[
            DomainInventory(
                domain="example.com",
                brand_names=["Example"]
            )
        ]
    )

    suspicious_profile = {
        "domain": "example.com",
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

    assert (
        result["best_match"][
            "infrastructure_confidence"
        ]
        == 100
    )

    assert (
        result["best_match"][
            "brand_impersonation_confidence"
        ]
        == 0
    )


def test_exact_domain_verdict():

    organization = OrganizationInventory(
        organization_name="Example",
        brand_names=["Example"],
        domains=[
            DomainInventory(
                domain="example.com"
            )
        ]
    )

    suspicious_profile = {
        "domain": "example.com",
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

    assert (
        result["best_match"]["verdict"]
        == "LEGITIMATE — CONFIRMED INVENTORY MATCH"
    )


def test_brand_impersonation_verdict():

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
        "domain": "corcept-login.com",
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

    assert (
        result["best_match"]["verdict"]
        == "POSSIBLE BRAND IMPERSONATION"
    )


def test_infrastructure_match_verdict():

    organization = OrganizationInventory(
        organization_name="Example",
        domains=[
            DomainInventory(
                domain="example.com",
                ips=[
                    "1.1.1.1"
                ],
                asns=[
                    "AS123"
                ],
                nameservers=[
                    "ns1.example.com"
                ]
            )
        ]
    )

    suspicious_profile = {
        "domain": "example-security.com",
        "infrastructure": {
            "ips": [
                "1.1.1.1"
            ],
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

    assert (
        result["best_match"]["verdict"]
        == "REQUIRES INVESTIGATION"
    )


def test_no_strong_match_verdict():

    organization = OrganizationInventory(
        organization_name="Example",
        domains=[
            DomainInventory(
                domain="example.com"
            )
        ]
    )

    suspicious_profile = {
        "domain": "random-domain.net",
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

    assert (
        result["best_match"]["verdict"]
        == "NO STRONG INVENTORY MATCH"
    )