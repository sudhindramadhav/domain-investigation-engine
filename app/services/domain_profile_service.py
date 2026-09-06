from app.services.infrastructure_service import InfrastructureService
from app.services.rdap_service import RDAPService
from app.services.ssl_service import SSLService
from app.services.website_service import WebsiteService
from app.services.brand_indicator_service import BrandIndicatorService


class DomainProfileService:

    def __init__(self):
        self.infrastructure_service = InfrastructureService()
        self.rdap_service = RDAPService()
        self.ssl_service = SSLService()
        self.website_service = WebsiteService()
        self.brand_indicator_service = BrandIndicatorService()

    def investigate(self, domain):
        infrastructure = self.infrastructure_service.investigate(
            domain
        )

        rdap = self.rdap_service.investigate(
            domain
        )

        ssl = self.ssl_service.investigate(
            domain
        )

        website = self.website_service.investigate(
            domain
        )

        brand_indicators = self.brand_indicator_service.analyze(
            website
        )

        return {
            "domain": domain,
            "infrastructure": infrastructure,
            "rdap": rdap,
            "ssl": ssl,
            "website": website,
            "brand_indicators": brand_indicators
        }