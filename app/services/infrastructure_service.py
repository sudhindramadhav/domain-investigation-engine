from app.services.dns_service import DNSService
from app.services.asn_service import ASNService


class InfrastructureService:

    def __init__(self):
        self.dns_service = DNSService()
        self.asn_service = ASNService()

    def investigate(self, domain):
        # DNS investigation
        dns_result = self.dns_service.investigate(domain)

        # Combine IPv4 and IPv6 addresses
        ips = (
            dns_result.get("a_records", [])
            + dns_result.get("aaaa_records", [])
        )

        # ASN investigation for every resolved IP
        asn_results = self.asn_service.lookup_many(ips)

        return {
            "domain": domain,
            "ips": ips,
            "dns": dns_result,
            "asn": asn_results
        }