from app.models.legitimate_inventory import (
    DomainInventory,
    OrganizationInventory
)


def test_domain_inventory():

    domain = DomainInventory(
        domain="example.com",
        official_url="https://example.com",
        ips=[
            "93.184.216.34"
        ],
        asns=[
            "AS15133"
        ],
        registrars=[
            "Example Registrar"
        ],
        nameservers=[
            "ns1.example.com",
            "ns2.example.com"
        ],
        ssl_fingerprints=[
            "abc123"
        ],
        ssl_sans=[
            "example.com",
            "*.example.com"
        ],
        brand_names=[
            "Example Corporation"
        ],
        brand_keywords=[
            "example",
            "corporation"
        ]
    )

    assert domain.domain == "example.com"

    assert domain.official_url == (
        "https://example.com"
    )

    assert "93.184.216.34" in domain.ips

    assert "AS15133" in domain.asns

    assert (
        "Example Registrar"
        in domain.registrars
    )

    assert (
        "ns1.example.com"
        in domain.nameservers
    )

    assert "abc123" in (
        domain.ssl_fingerprints
    )

    assert "*.example.com" in (
        domain.ssl_sans
    )

    assert "Example Corporation" in (
        domain.brand_names
    )


def test_organization_inventory():

    domain_one = DomainInventory(
        domain="example.com",
        brand_names=[
            "Example Corporation"
        ]
    )

    domain_two = DomainInventory(
        domain="example.in",
        brand_names=[
            "Example Corporation"
        ]
    )

    organization = OrganizationInventory(
        organization_name="Example Corporation",
        brand_names=[
            "Example Corporation",
            "Example"
        ],
        brand_keywords=[
            "example"
        ],
        domains=[
            domain_one,
            domain_two
        ]
    )

    assert organization.organization_name == (
        "Example Corporation"
    )

    assert "Example" in (
        organization.brand_names
    )

    assert len(
        organization.domains
    ) == 2

    assert organization.domains[0].domain == (
        "example.com"
    )

    assert organization.domains[1].domain == (
        "example.in"
    )