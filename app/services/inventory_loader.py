import json
from pathlib import Path

from app.models.legitimate_inventory import (
    DomainInventory,
    OrganizationInventory
)


class InventoryLoader:

    def load_json(self, file_path):
        """
        Load organization inventory from a JSON file.
        """

        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(
                f"Inventory file not found: {file_path}"
            )

        with path.open(
            "r",
            encoding="utf-8"
        ) as file:
            data = json.load(file)

        return self._parse_organization(data)

    def _parse_organization(self, data):

        if not isinstance(data, dict):
            raise ValueError(
                "Inventory must be a JSON object"
            )

        organization_name = data.get(
            "organization_name"
        )

        if not organization_name:
            raise ValueError(
                "organization_name is required"
            )

        domains = []

        for domain_data in data.get(
            "domains",
            []
        ):

            domain = domain_data.get(
                "domain"
            )

            if not domain:
                continue

            domains.append(
                DomainInventory(
                    passive_dns=domain_data.get(
    "passive_dns",
    []
),

registration_date=domain_data.get(
    "registration_date"
),

ssl=domain_data.get(
    "ssl",
    {}
),
                    domain=domain,
                    official_url=domain_data.get(
                        "official_url"
                    ),
                    ips=domain_data.get(
                        "ips",
                        []
                    ),
                    asns=domain_data.get(
                        "asns",
                        []
                    ),
                    registrars=domain_data.get(
                        "registrars",
                        []
                    ),
                    nameservers=domain_data.get(
                        "nameservers",
                        []
                    ),
                    ssl_fingerprints=domain_data.get(
                        "ssl_fingerprints",
                        []
                    ),
                    ssl_sans=domain_data.get(
                        "ssl_sans",
                        []
                    ),
                    brand_names=domain_data.get(
                        "brand_names",
                        []
                    ),
                    brand_keywords=domain_data.get(
                        "brand_keywords",
                        []
                    ),
                    logo_urls=domain_data.get(
                        "logo_urls",
                        []
                    ),
                    favicon_urls=domain_data.get(
                        "favicon_urls",
                        []
                    ),
                    notes=domain_data.get(
                        "notes"
                    )
                )
            )

        return OrganizationInventory(
            organization_name=organization_name,
            brand_names=data.get(
                "brand_names",
                []
            ),
            brand_keywords=data.get(
                "brand_keywords",
                []
            ),
            domains=domains,
            additional_ips=data.get(
                "additional_ips",
                []
            ),
            additional_asns=data.get(
                "additional_asns",
                []
            ),
            additional_registrars=data.get(
                "additional_registrars",
                []
            ),
            additional_nameservers=data.get(
                "additional_nameservers",
                []
            ),
            notes=data.get(
                "notes"
            )
        )