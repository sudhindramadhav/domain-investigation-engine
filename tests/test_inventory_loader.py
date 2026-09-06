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