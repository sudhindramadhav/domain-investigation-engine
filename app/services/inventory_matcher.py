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
                item["infrastructure_confidence"]
                + item["brand_impersonation_confidence"]
            ),
            reverse=True
        )

        best_match = results[0] if results else None

        return {
            "organization": organization.organization_name,
            "suspicious_domain": suspicious_domain,
            "best_match": best_match,
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
        # Current IP matching
        # --------------------------------------------------

        suspicious_ips = set(
            suspicious_infrastructure.get(
                "ips",
                []
            )
        )

        legitimate_current_ips = set(
            legitimate_domain.ips
        )

        shared_current_ips = (
            suspicious_ips
            & legitimate_current_ips
        )

        if shared_current_ips:
            evidence.append(
                "Shared current IP infrastructure detected"
            )

        # --------------------------------------------------
        # Passive DNS matching
        # --------------------------------------------------

        legitimate_passive_ips = set(
            legitimate_domain.passive_dns
        )

        shared_passive_dns = (
            suspicious_ips
            & legitimate_passive_ips
        )

        if shared_passive_dns:
            evidence.append(
                "Shared passive DNS infrastructure detected"
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
        # Infrastructure confidence
        # --------------------------------------------------

        infrastructure_confidence = 0

        if exact_match:
            infrastructure_confidence = 100

        else:

            if shared_current_ips:
                infrastructure_confidence += 20

            if shared_passive_dns:
                infrastructure_confidence += 5

            if shared_asns:
                infrastructure_confidence += 15

            if shared_nameservers:
                infrastructure_confidence += 15

            if registrar_match:
                infrastructure_confidence += 10

            if ssl_fingerprint_match:
                infrastructure_confidence += 40

            elif ssl_san_match:
                infrastructure_confidence += 20

            infrastructure_confidence = min(
                infrastructure_confidence,
                100
            )

        # --------------------------------------------------
        # Brand impersonation confidence
        # --------------------------------------------------

        brand_score = self._calculate_brand_score(
            suspicious_domain,
            legitimate_domain,
            organization
        )

        brand_impersonation_confidence = (
            self._calculate_brand_impersonation_confidence(
                exact_match,
                domain_similarity,
                brand_score
            )
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

        # --------------------------------------------------
        # Preliminary verdict
        # --------------------------------------------------

        verdict = self._calculate_verdict(
            exact_match,
            infrastructure_confidence,
            brand_impersonation_confidence
        )

        return {
            "legitimate_domain": legitimate_domain.domain,
            "exact_domain_match": exact_match,

            "domain_similarity": round(
                domain_similarity,
                2
            ),

            "shared_current_ips": sorted(
                shared_current_ips
            ),

            "shared_passive_dns": sorted(
                shared_passive_dns
            ),

            "shared_ips": sorted(
                shared_current_ips
                | shared_passive_dns
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

            "infrastructure_confidence": (
                infrastructure_confidence
            ),

            "infrastructure_score": (
                infrastructure_confidence
            ),

            "brand_score": round(
                brand_score,
                2
            ),

            "brand_impersonation_confidence": (
                brand_impersonation_confidence
            ),

            "verdict": verdict,

            "evidence": evidence
        }

    def _calculate_verdict(
        self,
        exact_match,
        infrastructure_confidence,
        brand_impersonation_confidence
    ):

        if exact_match:
            return (
                "LEGITIMATE — "
                "CONFIRMED INVENTORY MATCH"
            )

        if (
            infrastructure_confidence >= 60
            and brand_impersonation_confidence < 60
        ):
            return (
                "LIKELY LEGITIMATE — "
                "INFRASTRUCTURE MATCH"
            )

        if (
            brand_impersonation_confidence >= 70
            and infrastructure_confidence < 60
        ):
            return (
                "POSSIBLE BRAND IMPERSONATION"
            )

        if (
            brand_impersonation_confidence >= 70
            and infrastructure_confidence >= 60
        ):
            return (
                "REQUIRES INVESTIGATION — "
                "BRAND AND INFRASTRUCTURE OVERLAP"
            )

        if (
            infrastructure_confidence >= 30
            or brand_impersonation_confidence >= 40
        ):
            return "REQUIRES INVESTIGATION"

        return "NO STRONG INVENTORY MATCH"

    def _calculate_brand_impersonation_confidence(
        self,
        exact_match,
        domain_similarity,
        brand_score
    ):

        if exact_match:
            return 0

        domain_component = (
            domain_similarity * 0.60
        )

        brand_component = (
            brand_score * 0.40
        )

        confidence = (
            domain_component
            + brand_component
        )

        return round(
            min(confidence, 100),
            2
        )

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