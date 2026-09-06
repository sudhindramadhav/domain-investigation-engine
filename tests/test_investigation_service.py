from unittest.mock import Mock

from app.models.legitimate_inventory import (
    OrganizationInventory,
    DomainInventory
)

from app.services.investigation_service import (
    InvestigationService
)


def test_complete_investigation():

    organization = OrganizationInventory(
        organization_name="Example",
        brand_names=[
            "Example"
        ],
        domains=[
            DomainInventory(
                domain="example.com",
                ips=[
                    "1.1.1.1"
                ],
                asns=[
                    "AS123"
                ],
                nameservers=[
                    "ns1.example.com"
                ],
                brand_names=[
                    "Example"
                ]
            )
        ]
    )

    service = InvestigationService()

    service.domain_profile_service = Mock()

    service.domain_profile_service.investigate.return_value = {
        "domain": "example.com",

        "infrastructure": {
            "ips": [
                "1.1.1.1"
            ],

            "asn": [
                {
                    "asn": "AS123"
                }
            ],

            "dns": {
                "nameservers": [
                    "ns1.example.com"
                ]
            }
        },

        "rdap": {
            "registrar": "Example Registrar"
        },

        "ssl": {
            "fingerprint_sha256": "abc123",
            "san": [
                "example.com"
            ]
        },

        "website": {
            "status_code": 200,
            "title": "Example",
            "meta_description": "Official Example website",
            "forms": [],
            "images": []
        },

        "brand_indicators": {
            "brand_candidates": [
                "Example"
            ],
            "login_indicators": [],
            "logo_candidates": [],
            "favicon_candidates": [],
            "form_indicators": {}
        }
    }

    # Mock VirusTotal
    service.virustotal_service = Mock()

    service.virustotal_service.investigate_domain.return_value = {
        "domain": "example.com",
        "available": True,
        "found": True,
        "reputation": 0,
        "analysis_stats": {
            "harmless": 70,
            "malicious": 0,
            "suspicious": 0,
            "undetected": 10,
            "timeout": 0
        },
        "malicious_count": 0,
        "suspicious_count": 0,
        "categories": {}
    }

    service.virustotal_service.calculate_maliciousness_confidence.return_value = 0

    result = service.investigate(
        "example.com",
        organization
    )

    assert result["domain"] == "example.com"

    assert (
        result["organization"]
        == "Example"
    )

    assert "profile" in result

    assert "inventory_analysis" in result

    assert "best_match" in result

    assert "summary" in result

    assert "virustotal" in result

    assert (
        result["verdict"]
        == "LEGITIMATE — CONFIRMED INVENTORY MATCH"
    )

    assert (
        result["summary"]["verdict"]
        == "LEGITIMATE — CONFIRMED INVENTORY MATCH"
    )

    assert (
        result["summary"][
            "infrastructure_confidence"
        ]
        == 100
    )

    assert (
        result["summary"][
            "brand_impersonation_confidence"
        ]
        == 0
    )

    assert (
        result["summary"][
            "maliciousness_confidence"
        ]
        == 0
    )

    assert (
        result["summary"][
            "matched_legitimate_domain"
        ]
        == "example.com"
    )

    assert (
        result["summary"][
            "website_evidence"
        ]
    )

    assert (
        result["summary"][
            "brand_evidence"
        ]
    )

    assert (
        result["summary"][
            "virustotal_evidence"
        ]
    )

    assert any(
        "Website returned HTTP 200"
        in item
        for item in result["summary"][
            "website_evidence"
        ]
    )

    assert any(
        "Example"
        in item
        for item in result["summary"][
            "brand_evidence"
        ]
    )


def test_brand_impersonation_investigation():

    organization = OrganizationInventory(
        organization_name="Corcept",
        brand_names=[
            "Corcept"
        ],
        brand_keywords=[
            "corcept"
        ],
        domains=[
            DomainInventory(
                domain="corcept.com",
                brand_names=[
                    "Corcept"
                ],
                brand_keywords=[
                    "corcept"
                ]
            )
        ]
    )

    service = InvestigationService()

    service.domain_profile_service = Mock()

    service.domain_profile_service.investigate.return_value = {
        "domain": "corcept-login.com",

        "infrastructure": {
            "ips": [],
            "asn": [],
            "dns": {
                "nameservers": []
            }
        },

        "rdap": {},

        "ssl": {},

        "website": {
            "status_code": 200,
            "title": "Corcept Login",
            "meta_description": "Secure Corcept login",

            "forms": [
                {
                    "inputs": [
                        {
                            "type": "email"
                        },
                        {
                            "type": "password"
                        }
                    ]
                }
            ],

            "images": [
                {
                    "src": "/images/corcept-logo.png",
                    "alt": "Corcept logo"
                }
            ]
        },

        "brand_indicators": {
            "brand_candidates": [
                "Corcept"
            ],

            "login_indicators": [
                "login"
            ],

            "logo_candidates": [
                "/images/corcept-logo.png"
            ],

            "favicon_candidates": [],

            "form_indicators": {
                "password_fields": 1,
                "email_fields": 1
            }
        }
    }

    service.virustotal_service = Mock()

    service.virustotal_service.investigate_domain.return_value = {
        "domain": "corcept-login.com",
        "available": True,
        "found": True,
        "reputation": -20,
        "analysis_stats": {
            "harmless": 60,
            "malicious": 5,
            "suspicious": 3,
            "undetected": 10,
            "timeout": 0
        },
        "malicious_count": 5,
        "suspicious_count": 3,
        "categories": {
            "Engine1": "phishing"
        }
    }

    service.virustotal_service.calculate_maliciousness_confidence.return_value = 8.33

    result = service.investigate(
        "corcept-login.com",
        organization
    )

    assert (
        result["domain"]
        == "corcept-login.com"
    )

    assert (
        result["organization"]
        == "Corcept"
    )

    assert (
        result["verdict"]
        == "POSSIBLE BRAND IMPERSONATION"
    )

    assert (
        result["summary"][
            "brand_impersonation_confidence"
        ]
        >= 70
    )

    assert (
        result["summary"][
            "maliciousness_confidence"
        ]
        == 8.33
    )

    assert (
        result["summary"][
            "matched_legitimate_domain"
        ]
        == "corcept.com"
    )

    assert any(
        "Password field detected"
        in item
        for item in result["summary"][
            "website_evidence"
        ]
    )

    assert any(
        "Email input field detected"
        in item
        for item in result["summary"][
            "website_evidence"
        ]
    )

    assert any(
        "Corcept"
        in item
        for item in result["summary"][
            "brand_evidence"
        ]
    )

    assert any(
        "Login/sign-in indicators"
        in item
        for item in result["summary"][
            "brand_evidence"
        ]
    )

    assert any(
        "logo"
        in item.lower()
        for item in result["summary"][
            "brand_evidence"
        ]
    )

    assert any(
        "malicious"
        in item.lower()
        for item in result["summary"][
            "virustotal_evidence"
        ]
    )


def test_no_inventory_match():

    organization = OrganizationInventory(
        organization_name="Example",
        domains=[
            DomainInventory(
                domain="example.com"
            )
        ]
    )

    service = InvestigationService()

    service.domain_profile_service = Mock()

    service.domain_profile_service.investigate.return_value = {
        "domain": "random-domain.net",

        "infrastructure": {
            "ips": [],
            "asn": [],
            "dns": {
                "nameservers": []
            }
        },

        "rdap": {},

        "ssl": {},

        "website": {
            "status_code": 404
        },

        "brand_indicators": {}
    }

    service.virustotal_service = Mock()

    service.virustotal_service.investigate_domain.return_value = {
        "domain": "random-domain.net",
        "available": True,
        "found": False,
        "error": "Domain not found in VirusTotal"
    }

    service.virustotal_service.calculate_maliciousness_confidence.return_value = 0

    result = service.investigate(
        "random-domain.net",
        organization
    )

    assert (
        result["domain"]
        == "random-domain.net"
    )

    assert (
        result["verdict"]
        == "NO STRONG INVENTORY MATCH"
    )

    assert (
        result["summary"]["verdict"]
        == "NO STRONG INVENTORY MATCH"
    )

    assert (
        result["summary"][
            "infrastructure_confidence"
        ]
        == 0
    )

    assert (
        result["summary"][
            "brand_impersonation_confidence"
        ]
        < 70
    )

    assert (
        result["summary"][
            "maliciousness_confidence"
        ]
        == 0
    )

    assert (
        result["summary"][
            "matched_legitimate_domain"
        ]
        == "example.com"
    )

    assert any(
        "HTTP 404"
        in item
        for item in result["summary"][
            "website_evidence"
        ]
    )

    assert any(
        "VirusTotal"
        in item
        for item in result["summary"][
            "virustotal_evidence"
        ]
    )

def test_high_risk_assessment():

    service = InvestigationService()

    inventory_match = {
        "best_match": {
            "infrastructure_confidence": 20,
            "brand_impersonation_confidence": 85
        }
    }

    risk = service._build_risk_assessment(
        inventory_match,
        75
    )

    assert (
        risk["risk_level"]
        == "CRITICAL"
    )

    assert (
        risk["infrastructure_confidence"]
        == 20
    )

    assert (
        risk["brand_impersonation_confidence"]
        == 85
    )

    assert (
        risk["maliciousness_confidence"]
        == 75
    )

    assert (
        "brand impersonation"
        in risk["assessment"].lower()
    )

    assert (
        "maliciousness"
        in risk["assessment"].lower()
    )


def test_high_brand_risk():

    service = InvestigationService()

    inventory_match = {
        "best_match": {
            "infrastructure_confidence": 10,
            "brand_impersonation_confidence": 90
        }
    }

    risk = service._build_risk_assessment(
        inventory_match,
        0
    )

    assert (
        risk["risk_level"]
        == "HIGH"
    )


def test_high_maliciousness_risk():

    service = InvestigationService()

    inventory_match = {
        "best_match": {
            "infrastructure_confidence": 0,
            "brand_impersonation_confidence": 20
        }
    }

    risk = service._build_risk_assessment(
        inventory_match,
        75
    )

    assert (
        risk["risk_level"]
        == "HIGH"
    )


def test_medium_risk():

    service = InvestigationService()

    inventory_match = {
        "best_match": {
            "infrastructure_confidence": 65,
            "brand_impersonation_confidence": 20
        }
    }

    risk = service._build_risk_assessment(
        inventory_match,
        0
    )

    assert (
        risk["risk_level"]
        == "MEDIUM"
    )


def test_informational_risk():

    service = InvestigationService()

    inventory_match = {
        "best_match": {
            "infrastructure_confidence": 0,
            "brand_impersonation_confidence": 0
        }
    }

    risk = service._build_risk_assessment(
        inventory_match,
        0
    )

    assert (
        risk["risk_level"]
        == "INFORMATIONAL"
    )

def test_exact_inventory_match_is_informational():

    service = InvestigationService()

    inventory_match = {
        "best_match": {
            "exact_domain_match": True,
            "infrastructure_confidence": 100,
            "brand_impersonation_confidence": 0
        }
    }

    risk = service._build_risk_assessment(
        inventory_match,
        0
    )

    assert (
        risk["risk_level"]
        == "INFORMATIONAL"
    )

    assert (
        risk["exact_inventory_match"]
        is True
    )

    assert (
        risk["infrastructure_confidence"]
        == 100
    )

    assert (
        risk["maliciousness_confidence"]
        == 0
    )

    assert (
        "exactly matches"
        in risk["assessment"].lower()
    )


def test_exact_inventory_match_overrides_high_maliciousness():

    service = InvestigationService()

    inventory_match = {
        "best_match": {
            "exact_domain_match": True,
            "infrastructure_confidence": 100,
            "brand_impersonation_confidence": 0
        }
    }

    risk = service._build_risk_assessment(
        inventory_match,
        90
    )

    assert (
        risk["risk_level"]
        == "INFORMATIONAL"
    )

    assert (
        risk["maliciousness_confidence"]
        == 90
    )


def test_non_inventory_domain_still_uses_risk_logic():

    service = InvestigationService()

    inventory_match = {
        "best_match": {
            "exact_domain_match": False,
            "infrastructure_confidence": 20,
            "brand_impersonation_confidence": 85
        }
    }

    risk = service._build_risk_assessment(
        inventory_match,
        75
    )

    assert (
        risk["risk_level"]
        == "CRITICAL"
    )

    assert (
        risk["exact_inventory_match"]
        is False
    )