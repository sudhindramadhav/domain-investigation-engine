from rapidfuzz import fuzz

from app.services.inventory_normalizer import InventoryNormalizer
from app.utils.domain_utils import normalize_domain


class InventoryMatcher:

    def __init__(self):
        self.normalizer = InventoryNormalizer()

    def match(self, suspicious_profile, organization):

        organization = self.normalizer.normalize(
            organization
        )

        suspicious_domain = normalize_domain(
            suspicious_profile.get("domain", "")
        )

        results = []

        for legitimate_domain in organization.domains:

            result = self._compare_domain(
                suspicious_profile,
                suspicious_domain,
                legitimate_domain,
                organization
            )

            results.append(result)

        results.sort(
            key=lambda item: (
                item["infrastructure_score"]
                + item["brand_score"]
            ),
            reverse=True
        )

        return {
            "organization": organization.organization_name,
            "suspicious_domain": suspicious_domain,
            "matches": results
        }

    def _compare_domain(
        self,
        suspicious_profile,
        suspicious_domain,
        legitimate_domain,
        organization
    ):

        evidence = []

        exact_match = (
            suspicious_domain
            == legitimate_domain.domain
        )

        if exact_match:
            evidence.append(
                "Exact domain found in legitimate inventory"
            )

        domain_similarity = fuzz.ratio(
            suspicious_domain,
            legitimate_domain.domain
        )

        suspicious_infrastructure = (
            suspicious_profile.get(
                "infrastructure",
                {}
            )
        )

        # --------------------------------------------------
        # IP matching
        # --------------------------------------------------

        suspicious_ips = set(
            suspicious_infrastructure.get(
                "ips",
                []
            )
        )

        legitimate_ips = set(
            legitimate_domain.ips
            + legitimate_domain.passive_dns
        )

        shared_ips = (
            suspicious_ips
            & legitimate_ips
        )

        if shared_ips:
            evidence.append(
                "Shared IP infrastructure detected"
            )

        # --------------------------------------------------
        # ASN matching
        # --------------------------------------------------

        suspicious_asns = {
            item.get("asn")
            for item in suspicious_infrastructure.get(
                "asn",
                []
            )
            if item.get("asn")
        }

        legitimate_asns = set(
            legitimate_domain.asns
        )

        shared_asns = (
            suspicious_asns
            & legitimate_asns
        )

        if shared_asns:
            evidence.append(
                "Shared ASN detected"
            )

        # --------------------------------------------------
        # Nameserver matching
        # --------------------------------------------------

        suspicious_dns = (
            suspicious_infrastructure.get(
                "dns",
                {}
            )
        )

        suspicious_nameservers = set(
            suspicious_dns.get(
                "nameservers",
                []
            )
        )

        legitimate_nameservers = set(
            legitimate_domain.nameservers
        )

        shared_nameservers = (
            suspicious_nameservers
            & legitimate_nameservers
        )

        if shared_nameservers:
            evidence.append(
                "Shared nameserver infrastructure detected"
            )

        # --------------------------------------------------
        # Registrar matching
        # --------------------------------------------------

        suspicious_rdap = (
            suspicious_profile.get(
                "rdap",
                {}
            )
        )

        suspicious_registrar = (
            suspicious_rdap.get(
                "registrar"
            )
        )

        legitimate_registrars = {
            str(registrar).strip().lower()
            for registrar in (
                legitimate_domain.registrars
                or []
            )
            if registrar
        }

        registrar_match = False

        if suspicious_registrar:
            registrar_match = (
                suspicious_registrar.strip().lower()
                in legitimate_registrars
            )

        if registrar_match:
            evidence.append(
                "Registrar matches legitimate inventory"
            )

        # --------------------------------------------------
        # SSL matching
        # --------------------------------------------------

        suspicious_ssl = (
            suspicious_profile.get(
                "ssl",
                {}
            )
        )

        ssl_fingerprint_match = (
            self._ssl_fingerprint_match(
                suspicious_ssl,
                legitimate_domain
            )
        )

        ssl_san_match = (
            self._ssl_san_match(
                suspicious_ssl,
                legitimate_domain
            )
        )

        if ssl_fingerprint_match:
            evidence.append(
                "SSL certificate fingerprint matches inventory"
            )

        if ssl_san_match:
            evidence.append(
                "SSL certificate SAN matches inventory"
            )

        # --------------------------------------------------
        # Infrastructure score
        # --------------------------------------------------

        infrastructure_score = 0

        if exact_match:
            infrastructure_score += 100

        if shared_ips:
            infrastructure_score += 20

        if shared_asns:
            infrastructure_score += 15

        if shared_nameservers:
            infrastructure_score += 15

        if registrar_match:
            infrastructure_score += 10

        if ssl_fingerprint_match:
            infrastructure_score += 40

        elif ssl_san_match:
            infrastructure_score += 20

        infrastructure_score = min(
            infrastructure_score,
            100
        )

        # --------------------------------------------------
        # Brand score
        # --------------------------------------------------

        brand_score = self._calculate_brand_score(
            suspicious_domain,
            legitimate_domain,
            organization
        )

        if domain_similarity >= 90:
            evidence.append(
                "Very high domain similarity"
            )

        elif domain_similarity >= 75:
            evidence.append(
                "High domain similarity"
            )

        elif domain_similarity >= 60:
            evidence.append(
                "Moderate domain similarity"
            )

        return {
            "legitimate_domain": legitimate_domain.domain,
            "exact_domain_match": exact_match,
            "domain_similarity": round(
                domain_similarity,
                2
            ),
            "shared_ips": sorted(
                shared_ips
            ),
            "shared_asns": sorted(
                shared_asns
            ),
            "shared_nameservers": sorted(
                shared_nameservers
            ),
            "registrar_match": registrar_match,
            "ssl_fingerprint_match": (
                ssl_fingerprint_match
            ),
            "ssl_san_match": ssl_san_match,
            "infrastructure_score": (
                infrastructure_score
            ),
            "brand_score": round(
                brand_score,
                2
            ),
            "evidence": evidence
        }

    def _ssl_fingerprint_match(
        self,
        suspicious_ssl,
        legitimate_domain
    ):

        fingerprint = suspicious_ssl.get(
            "fingerprint_sha256"
        )

        if not fingerprint:
            return False

        legitimate_fingerprints = {
            str(value).strip().lower()
            for value in (
                legitimate_domain.ssl_fingerprints
                or []
            )
            if value
        }

        return (
            fingerprint.strip().lower()
            in legitimate_fingerprints
        )

    def _ssl_san_match(
        self,
        suspicious_ssl,
        legitimate_domain
    ):

        suspicious_sans = {
            str(value).strip().lower().rstrip(".")
            for value in (
                suspicious_ssl.get(
                    "san",
                    []
                )
                or []
            )
            if value
        }

        legitimate_sans = {
            str(value).strip().lower().rstrip(".")
            for value in (
                legitimate_domain.ssl_sans
                or []
            )
            if value
        }

        if not suspicious_sans:
            return False

        return bool(
            suspicious_sans
            & legitimate_sans
        )

    def _calculate_brand_score(
        self,
        suspicious_domain,
        legitimate_domain,
        organization
    ):

        brand_values = []

        brand_values.extend(
            organization.brand_names
        )

        brand_values.extend(
            organization.brand_keywords
        )

        brand_values.extend(
            legitimate_domain.brand_names
        )

        brand_values.extend(
            legitimate_domain.brand_keywords
        )

        if not brand_values:
            return 0

        suspicious_text = (
            suspicious_domain
            .replace(".", " ")
            .replace("-", " ")
            .replace("_", " ")
        )

        highest_score = 0

        for brand in brand_values:

            brand = str(
                brand
            ).strip().lower()

            if not brand:
                continue

            score = fuzz.partial_ratio(
                brand,
                suspicious_text
            )

            highest_score = max(
                highest_score,
                score
            )

        return highest_score