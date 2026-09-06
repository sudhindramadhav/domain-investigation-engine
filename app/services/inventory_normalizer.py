from app.models.legitimate_inventory import (
    OrganizationInventory,
    DomainInventory
)
from app.utils.domain_utils import normalize_domain


class InventoryNormalizer:

    def normalize(
        self,
        organization: OrganizationInventory
    ) -> OrganizationInventory:

        # Normalize organization-level values
        organization.brand_names = self._clean_list(
            organization.brand_names,
            lowercase=False
        )

        organization.brand_keywords = self._clean_list(
            organization.brand_keywords,
            lowercase=True
        )

        organization.additional_ips = self._clean_list(
            organization.additional_ips
        )

        organization.additional_asns = self._normalize_asns(
            organization.additional_asns
        )

        organization.additional_registrars = (
            self._clean_list(
                organization.additional_registrars,
                lowercase=False
            )
        )

        organization.additional_nameservers = (
            self._normalize_nameservers(
                organization.additional_nameservers
            )
        )

        # Normalize and merge domains
        normalized_domains = {}

        for domain in organization.domains:

            normalized_domain = normalize_domain(
                domain.domain
            )

            if not normalized_domain:
                continue

            domain.domain = normalized_domain

            domain.ips = self._clean_list(
                domain.ips
            )

            domain.passive_dns = self._clean_list(
                domain.passive_dns
            )

            domain.asns = self._normalize_asns(
                domain.asns
            )

            domain.registrars = self._clean_list(
                domain.registrars,
                lowercase=False
            )

            domain.nameservers = (
                self._normalize_nameservers(
                    domain.nameservers
                )
            )

            domain.ssl_fingerprints = (
                self._clean_list(
                    domain.ssl_fingerprints
                )
            )

            domain.ssl_sans = (
                self._normalize_ssl_sans(
                    domain.ssl_sans
                )
            )

            domain.brand_names = self._clean_list(
                domain.brand_names,
                lowercase=False
            )

            domain.brand_keywords = self._clean_list(
                domain.brand_keywords,
                lowercase=True
            )

            # Merge duplicate domain records
            if normalized_domain in normalized_domains:

                existing = normalized_domains[
                    normalized_domain
                ]

                existing.ips = self._merge_lists(
                    existing.ips,
                    domain.ips
                )

                existing.passive_dns = self._merge_lists(
                    existing.passive_dns,
                    domain.passive_dns
                )

                # IMPORTANT:
                # ASN values must retain uppercase AS prefix.
                existing.asns = self._merge_asns(
                    existing.asns,
                    domain.asns
                )

                existing.registrars = self._merge_lists(
                    existing.registrars,
                    domain.registrars
                )

                existing.nameservers = self._merge_lists(
                    existing.nameservers,
                    domain.nameservers
                )

                existing.ssl_fingerprints = (
                    self._merge_lists(
                        existing.ssl_fingerprints,
                        domain.ssl_fingerprints
                    )
                )

                existing.ssl_sans = self._merge_lists(
                    existing.ssl_sans,
                    domain.ssl_sans
                )

                existing.brand_names = self._merge_lists(
                    existing.brand_names,
                    domain.brand_names
                )

                existing.brand_keywords = (
                    self._merge_lists(
                        existing.brand_keywords,
                        domain.brand_keywords
                    )
                )

                if not existing.official_url:
                    existing.official_url = (
                        domain.official_url
                    )

                if not existing.registration_date:
                    existing.registration_date = (
                        domain.registration_date
                    )

                if not existing.ssl:
                    existing.ssl = domain.ssl

                if not existing.notes:
                    existing.notes = domain.notes

            else:
                normalized_domains[
                    normalized_domain
                ] = domain

        organization.domains = list(
            normalized_domains.values()
        )

        return organization

    def _clean_list(
        self,
        values,
        lowercase=True
    ):
        if not values:
            return []

        result = []
        seen = set()

        for value in values:

            if value is None:
                continue

            value = str(value).strip()

            if not value:
                continue

            cleaned = (
                value.lower()
                if lowercase
                else value
            )

            comparison_value = cleaned.lower()

            if comparison_value not in seen:
                seen.add(comparison_value)
                result.append(cleaned)

        return result

    def _normalize_asns(self, asns):
        result = []
        seen = set()

        for asn in asns or []:

            asn = str(
                asn
            ).strip().upper()

            if not asn:
                continue

            if not asn.startswith("AS"):
                asn = "AS" + asn

            if asn not in seen:
                seen.add(asn)
                result.append(asn)

        return result

    def _merge_asns(self, first, second):
        """
        Merge ASN lists while preserving the
        standard uppercase AS prefix.
        """

        return self._normalize_asns(
            list(first or [])
            + list(second or [])
        )

    def _normalize_nameservers(
        self,
        nameservers
    ):
        cleaned = []

        for nameserver in nameservers or []:

            nameserver = str(
                nameserver
            ).strip().lower()

            nameserver = nameserver.rstrip(".")

            if nameserver:
                cleaned.append(nameserver)

        return self._clean_list(
            cleaned
        )

    def _normalize_ssl_sans(
        self,
        sans
    ):
        result = []

        for san in sans or []:

            san = str(
                san
            ).strip().lower()

            san = san.rstrip(".")

            if san:
                result.append(san)

        return self._clean_list(
            result
        )

    def _merge_lists(
        self,
        first,
        second
    ):
        return self._clean_list(
            list(first or [])
            + list(second or [])
        )