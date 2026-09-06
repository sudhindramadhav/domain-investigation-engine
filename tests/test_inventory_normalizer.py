from app.models.legitimate_inventory import (
    DomainInventory,
    OrganizationInventory
)
from app.services.inventory_normalizer import (
    InventoryNormalizer
)


def test_domain_normalization():

    organization = OrganizationInventory(
        organization_name="Example",
        domains=[
            DomainInventory(
                domain="https://www.Example.com/",
                ips=[
                    "1.1.1.1",
                    "1.1.1.1",
                    "2.2.2.2"
                ],
                asns=[
                    "AS123",
                    "AS123"
                ],
                nameservers=[
                    "NS1.Example.COM.",
                    "ns1.example.com"
                ]
            )
        ]
    )

    normalizer = InventoryNormalizer()

    result = normalizer.normalize(
        organization
    )

    domain = result.domains[0]

    assert domain.domain == "example.com"

    assert domain.ips == [
        "1.1.1.1",
        "2.2.2.2"
    ]

    assert domain.asns == [
        "AS123"
    ]

    assert domain.nameservers == [
        "ns1.example.com"
    ]


def test_duplicate_domains_are_merged():

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
                ]
            ),
            DomainInventory(
                domain="www.example.com",
                ips=[
                    "2.2.2.2"
                ],
                asns=[
                    "AS456"
                ]
            )
        ]
    )

    normalizer = InventoryNormalizer()

    result = normalizer.normalize(
        organization
    )

    assert len(result.domains) == 1

    domain = result.domains[0]

    assert domain.domain == "example.com"

    assert "1.1.1.1" in domain.ips
    assert "2.2.2.2" in domain.ips

    assert "AS123" in domain.asns
    assert "AS456" in domain.asns


def test_organization_values_are_cleaned():

    organization = OrganizationInventory(
        organization_name="Example",
        brand_names=[
            "Example",
            "Example"
        ],
        brand_keywords=[
            "Example",
            "example",
            "security"
        ],
        additional_ips=[
            "1.1.1.1",
            "1.1.1.1"
        ]
    )

    normalizer = InventoryNormalizer()

    result = normalizer.normalize(
        organization
    )

    assert result.brand_names == [
        "Example"
    ]

    assert result.brand_keywords == [
        "example",
        "security"
    ]

    assert result.additional_ips == [
        "1.1.1.1"
    ]


def test_asn_normalization():

    organization = OrganizationInventory(
        organization_name="Example",
        domains=[
            DomainInventory(
                domain="example.com",
                asns=[
                    "as123",
                    "AS123",
                    "123",
                    "AS456"
                ]
            )
        ]
    )

    normalizer = InventoryNormalizer()

    result = normalizer.normalize(
        organization
    )

    domain = result.domains[0]

    assert domain.asns == [
        "AS123",
        "AS456"
    ]


def test_nameserver_normalization():

    organization = OrganizationInventory(
        organization_name="Example",
        domains=[
            DomainInventory(
                domain="example.com",
                nameservers=[
                    "NS1.Example.COM.",
                    "ns1.example.com",
                    "NS2.EXAMPLE.COM."
                ]
            )
        ]
    )

    normalizer = InventoryNormalizer()

    result = normalizer.normalize(
        organization
    )

    domain = result.domains[0]

    assert domain.nameservers == [
        "ns1.example.com",
        "ns2.example.com"
    ]