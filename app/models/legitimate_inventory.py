from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class DomainInventory:
    domain: str

    official_url: Optional[str] = None

    ips: List[str] = field(
        default_factory=list
    )

    passive_dns: List[str] = field(
        default_factory=list
    )

    asns: List[str] = field(
        default_factory=list
    )

    registrars: List[str] = field(
        default_factory=list
    )

    nameservers: List[str] = field(
        default_factory=list
    )

    registration_date: Optional[str] = None

    ssl: Dict[str, Optional[str]] = field(
        default_factory=dict
    )

    ssl_fingerprints: List[str] = field(
        default_factory=list
    )

    ssl_sans: List[str] = field(
        default_factory=list
    )

    brand_names: List[str] = field(
        default_factory=list
    )

    brand_keywords: List[str] = field(
        default_factory=list
    )

    logo_urls: List[str] = field(
        default_factory=list
    )

    favicon_urls: List[str] = field(
        default_factory=list
    )

    notes: Optional[str] = None


@dataclass
class OrganizationInventory:
    organization_name: str

    brand_names: List[str] = field(
        default_factory=list
    )

    brand_keywords: List[str] = field(
        default_factory=list
    )

    domains: List[DomainInventory] = field(
        default_factory=list
    )

    additional_ips: List[str] = field(
        default_factory=list
    )

    additional_asns: List[str] = field(
        default_factory=list
    )

    additional_registrars: List[str] = field(
        default_factory=list
    )

    additional_nameservers: List[str] = field(
        default_factory=list
    )

    notes: Optional[str] = None