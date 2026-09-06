import json

from app.services.inventory_loader import InventoryLoader


def test_load_inventory(tmp_path):

    inventory = {
        "organization_name": "Example Corporation",
        "brand_names": [
            "Example"
        ],
        "brand_keywords": [
            "example"
        ],
        "domains": [
            {
                "domain": "example.com",
                "official_url": "https://example.com",
                "ips": [
                    "93.184.216.34"
                ],
                "asns": [
                    "AS15133"
                ],
                "registrars": [
                    "Example Registrar"
                ],
                "nameservers": [
                    "ns1.example.com"
                ]
            },
            {
                "domain": "example.in",
                "ips": [
                    "203.0.113.10"
                ],
                "asns": [
                    "AS64500"
                ]
            }
        ]
    }

    file_path = tmp_path / "inventory.json"

    file_path.write_text(
        json.dumps(inventory),
        encoding="utf-8"
    )

    loader = InventoryLoader()

    result = loader.load_json(
        file_path
    )

    assert result.organization_name == (
        "Example Corporation"
    )

    assert len(result.domains) == 2

    assert result.domains[0].domain == (
        "example.com"
    )

    assert result.domains[1].domain == (
        "example.in"
    )

    assert "AS15133" in (
        result.domains[0].asns
    )


def test_missing_inventory_file():

    loader = InventoryLoader()

    try:
        loader.load_json(
            "does_not_exist.json"
        )
        assert False
    except FileNotFoundError:
        assert True


def test_invalid_inventory():

    import tempfile

    loader = InventoryLoader()

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        delete=False,
        encoding="utf-8"
    ) as file:

        file.write(
            json.dumps(
                {
                    "domains": []
                }
            )
        )

        file_path = file.name

    try:
        loader.load_json(file_path)
        assert False
    except ValueError:
        assert True

def test_corcept_inventory_fields(tmp_path):

    import json

    inventory = {
        "organization_name": "Corcept",
        "brand_names": [
            "Corcept"
        ],
        "domains": [
            {
                "domain": "corcept.com",
                "ips": [
                    "40.93.192.1",
                    "52.101.11.13"
                ],
                "passive_dns": [
                    "166.117.64.72",
                    "151.101.2.159",
                    "35.193.101.241"
                ],
                "asns": [
                    "AS8075"
                ],
                "registrars": [
                    "Network Solutions, LLC"
                ],
                "nameservers": [
                    "ns45.worldnic.com",
                    "ns46.worldnic.com"
                ],
                "registration_date": "1999-05-13",
                "ssl": {
                    "country": "US",
                    "organization": "Amazon",
                    "common_name": "Amazon RSA 2048 M04"
                }
            }
        ]
    }

    file_path = tmp_path / "corcept.json"

    file_path.write_text(
        json.dumps(inventory),
        encoding="utf-8"
    )

    loader = InventoryLoader()

    result = loader.load_json(file_path)

    domain = result.domains[0]

    assert domain.domain == "corcept.com"

    assert len(domain.ips) == 2

    assert len(domain.passive_dns) == 3

    assert "AS8075" in domain.asns

    assert (
        "Network Solutions, LLC"
        in domain.registrars
    )

    assert (
        "ns45.worldnic.com"
        in domain.nameservers
    )

    assert domain.registration_date == (
        "1999-05-13"
    )

    assert domain.ssl["organization"] == (
        "Amazon"
    )

    assert domain.ssl["common_name"] == (
        "Amazon RSA 2048 M04"
    )