from app.services.infrastructure_service import InfrastructureService
from app.services.rdap_service import RDAPService


class DomainProfileService:

    def __init__(self):
        self.infrastructure_service = InfrastructureService()
        self.rdap_service = RDAPService()

    def investigate(self, domain):
        infrastructure = self.infrastructure_service.investigate(domain)
        rdap = self.rdap_service.investigate(domain)

        return {
            "domain": domain,
            "infrastructure": infrastructure,
            "rdap": rdap
        }