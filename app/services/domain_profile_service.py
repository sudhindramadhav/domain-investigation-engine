from app.services.infrastructure_service import InfrastructureService
from app.services.rdap_service import RDAPService
from app.services.ssl_service import SSLService


class DomainProfileService:

    def __init__(self):
        self.infrastructure_service = InfrastructureService()
        self.rdap_service = RDAPService()
        self.ssl_service = SSLService()

    def investigate(self, domain):
        infrastructure = self.infrastructure_service.investigate(domain)
        rdap = self.rdap_service.investigate(domain)
        ssl = self.ssl_service.investigate(domain)

        return {
            "domain": domain,
            "infrastructure": infrastructure,
            "rdap": rdap,
            "ssl": ssl
        }