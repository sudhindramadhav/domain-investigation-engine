from unittest.mock import patch

from app.main import app


# =====================================================
# Home
# =====================================================

def test_home():

    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200

    data = response.get_json()

    assert (
        data["status"]
        == "running"
    )


# =====================================================
# Health
# =====================================================

def test_health():

    client = app.test_client()

    response = client.get(
        "/api/health"
    )

    assert response.status_code == 200

    data = response.get_json()

    assert (
        data["status"]
        == "healthy"
    )


# =====================================================
# Investigation Validation
# =====================================================

def test_investigate_requires_json():

    client = app.test_client()

    response = client.post(
        "/api/investigate"
    )

    assert response.status_code == 400

    data = response.get_json()

    assert (
        "JSON"
        in data["error"]
    )


def test_investigate_requires_domain():

    client = app.test_client()

    response = client.post(
        "/api/investigate",
        json={}
    )

    assert response.status_code == 400

    data = response.get_json()

    assert (
        data["error"]
        == "domain is required"
    )


def test_investigate_rejects_non_string_domain():

    client = app.test_client()

    response = client.post(
        "/api/investigate",
        json={
            "domain": 12345
        }
    )

    assert response.status_code == 400

    data = response.get_json()

    assert (
        data["error"]
        == "domain must be a string"
    )


def test_investigate_rejects_empty_domain():

    client = app.test_client()

    response = client.post(
        "/api/investigate",
        json={
            "domain": "   "
        }
    )

    assert response.status_code == 400

    data = response.get_json()

    assert (
        data["error"]
        == "domain cannot be empty"
    )


# =====================================================
# Successful Investigation
# =====================================================

def test_investigate_success():

    mock_result = {
        "domain": "suspicious-example.com",

        "organization": "Corcept",

        "verdict": (
            "POSSIBLE BRAND IMPERSONATION"
        ),

        "summary": {
            "domain": "suspicious-example.com",
            "organization": "Corcept",
            "verdict": (
                "POSSIBLE BRAND IMPERSONATION"
            ),
            "infrastructure_confidence": 20,
            "brand_impersonation_confidence": 91.4,
            "maliciousness_confidence": 65,
            "matched_legitimate_domain": "corcept.com",
            "domain_similarity": 94.5,
            "brand_score": 98,
            "website_evidence": [],
            "brand_evidence": [],
            "virustotal_evidence": [],
            "evidence": []
        },

        "risk_assessment": {
            "risk_level": "CRITICAL",
            "infrastructure_confidence": 20,
            "brand_impersonation_confidence": 91.4,
            "maliciousness_confidence": 65,
            "exact_inventory_match": False,
            "assessment": (
                "Detected strong brand impersonation "
                "indicators and significant maliciousness "
                "evidence."
            )
        },

        "best_match": {
            "legitimate_domain": "corcept.com",
            "exact_domain_match": False,
            "domain_similarity": 94.5,
            "infrastructure_confidence": 20,
            "brand_impersonation_confidence": 91.4,
            "brand_score": 98,
            "verdict": (
                "POSSIBLE BRAND IMPERSONATION"
            ),
            "evidence": [
                "Very high domain similarity"
            ]
        },

        "profile": {
            "domain": "suspicious-example.com"
        },

        "inventory_analysis": {
            "organization": "Corcept"
        },

        "virustotal": {
            "domain": "suspicious-example.com",
            "available": True,
            "found": True,
            "malicious_count": 13,
            "suspicious_count": 4
        }
    }

    with patch(
        "app.main.InvestigationService"
    ) as mock_service:

        mock_instance = (
            mock_service.return_value
        )

        mock_instance.investigate.return_value = (
            mock_result
        )

        client = app.test_client()

        response = client.post(
            "/api/investigate",
            json={
                "domain": "suspicious-example.com"
            }
        )

    assert response.status_code == 200

    data = response.get_json()

    # ---------------------------------------------
    # Basic response
    # ---------------------------------------------

    assert (
        data["domain"]
        == "suspicious-example.com"
    )

    assert (
        data["organization"]
        == "Corcept"
    )

    assert (
        data["verdict"]
        == "POSSIBLE BRAND IMPERSONATION"
    )

    # ---------------------------------------------
    # Risk
    # ---------------------------------------------

    assert (
        data["risk"]["level"]
        == "CRITICAL"
    )

    assert (
        data["risk"][
            "infrastructure_confidence"
        ]
        == 20
    )

    assert (
        data["risk"][
            "brand_impersonation_confidence"
        ]
        == 91.4
    )

    assert (
        data["risk"][
            "maliciousness_confidence"
        ]
        == 65
    )

    # ---------------------------------------------
    # Inventory Match
    # ---------------------------------------------

    assert (
        data["inventory_match"]["domain"]
        == "corcept.com"
    )

    assert (
        data["inventory_match"]["exact_match"]
        is False
    )

    assert (
        data["inventory_match"][
            "domain_similarity"
        ]
        == 94.5
    )

    # ---------------------------------------------
    # VirusTotal
    # ---------------------------------------------

    assert (
        data["virustotal"][
            "malicious_count"
        ]
        == 13
    )

    assert (
        data["virustotal"][
            "suspicious_count"
        ]
        == 4
    )

    # ---------------------------------------------
    # Details
    # ---------------------------------------------

    assert (
        "details"
        in data
    )

    assert (
        "summary"
        in data["details"]
    )

    assert (
        "best_match"
        in data["details"]
    )

    assert (
        "profile"
        in data["details"]
    )

    assert (
        "inventory_analysis"
        in data["details"]
    )

    assert (
        "virustotal"
        in data["details"]
    )


# =====================================================
# Investigation Service Error
# =====================================================

def test_investigate_service_error():

    with patch(
        "app.main.InvestigationService"
    ) as mock_service:

        mock_instance = (
            mock_service.return_value
        )

        mock_instance.investigate.side_effect = (
            Exception(
                "Test investigation failure"
            )
        )

        client = app.test_client()

        response = client.post(
            "/api/investigate",
            json={
                "domain": "example.com"
            }
        )

    assert response.status_code == 500

    data = response.get_json()

    assert (
        "Domain investigation failed"
        in data["error"]
    )


# =====================================================
# Clean API Response Builder
# =====================================================

def test_build_api_response():

    from app.main import build_api_response

    result = {
        "domain": "suspicious-example.com",

        "organization": "Corcept",

        "verdict": (
            "POSSIBLE BRAND IMPERSONATION"
        ),

        "summary": {
            "evidence": [
                "Very high domain similarity"
            ]
        },

        "risk_assessment": {
            "risk_level": "HIGH",
            "assessment": (
                "Strong brand impersonation indicators."
            ),
            "infrastructure_confidence": 20,
            "brand_impersonation_confidence": 90,
            "maliciousness_confidence": 40
        },

        "best_match": {
            "legitimate_domain": "corcept.com",
            "exact_domain_match": False,
            "domain_similarity": 94.5
        },

        "profile": {
            "website": {
                "status_code": 200,
                "title": "Corcept Login",
                "meta_description": "Login",
                "forms": [
                    {},
                    {}
                ],
                "images": [
                    {}
                ]
            },

            "infrastructure": {
                "ips": [
                    "1.2.3.4"
                ],
                "asn": [
                    {
                        "asn": "AS12345"
                    }
                ],
                "dns": {
                    "nameservers": [
                        "ns1.example.com"
                    ]
                }
            },

            "rdap": {
                "registrar": "Example Registrar",
                "registration_date": "2020-01-01",
                "expiration_date": "2027-01-01"
            },

            "ssl": {
                "subject": {
                    "commonName": "example.com"
                },
                "issuer": {
                    "organizationName": "Example CA"
                },
                "san": [
                    "example.com"
                ],
                "fingerprint_sha256": "abc123"
            }
        },

        "inventory_analysis": {},

        "virustotal": {
            "available": True,
            "found": True,
            "malicious_count": 5,
            "suspicious_count": 2,
            "reputation": -10,
            "categories": {
                "engine": "phishing"
            }
        }
    }

    response = build_api_response(
        result
    )

    # ---------------------------------------------
    # Basic fields
    # ---------------------------------------------

    assert (
        response["domain"]
        == "suspicious-example.com"
    )

    assert (
        response["organization"]
        == "Corcept"
    )

    assert (
        response["verdict"]
        == "POSSIBLE BRAND IMPERSONATION"
    )

    # ---------------------------------------------
    # Risk
    # ---------------------------------------------

    assert (
        response["risk"]["level"]
        == "HIGH"
    )

    assert (
        response["risk"][
            "brand_impersonation_confidence"
        ]
        == 90
    )

    assert (
        response["risk"][
            "maliciousness_confidence"
        ]
        == 40
    )

    assert (
        response["risk"][
            "infrastructure_confidence"
        ]
        == 20
    )

    # ---------------------------------------------
    # Inventory
    # ---------------------------------------------

    assert (
        response["inventory_match"][
            "domain"
        ]
        == "corcept.com"
    )

    assert (
        response["inventory_match"][
            "exact_match"
        ]
        is False
    )

    assert (
        response["inventory_match"][
            "domain_similarity"
        ]
        == 94.5
    )

    # ---------------------------------------------
    # Website
    # ---------------------------------------------

    assert (
        response["website"]["status_code"]
        == 200
    )

    assert (
        response["website"]["title"]
        == "Corcept Login"
    )

    assert (
        response["website"]["meta_description"]
        == "Login"
    )

    assert (
        response["website"]["forms"]
        == 2
    )

    assert (
        response["website"]["images"]
        == 1
    )

    # ---------------------------------------------
    # Infrastructure
    # ---------------------------------------------

    assert (
        response["infrastructure"]["ips"]
        == ["1.2.3.4"]
    )

    assert (
        response["infrastructure"]["asn"][0][
            "asn"
        ]
        == "AS12345"
    )

    assert (
        response["infrastructure"][
            "nameservers"
        ]
        == ["ns1.example.com"]
    )

    # ---------------------------------------------
    # RDAP
    # ---------------------------------------------

    assert (
        response["rdap"]["registrar"]
        == "Example Registrar"
    )

    assert (
        response["rdap"]["registration_date"]
        == "2020-01-01"
    )

    assert (
        response["rdap"]["expiration_date"]
        == "2027-01-01"
    )

    # ---------------------------------------------
    # SSL
    # ---------------------------------------------

    assert (
        response["ssl"]["subject"][
            "commonName"
        ]
        == "example.com"
    )

    assert (
        response["ssl"]["issuer"][
            "organizationName"
        ]
        == "Example CA"
    )

    assert (
        response["ssl"]["san"]
        == ["example.com"]
    )

    assert (
        response["ssl"][
            "fingerprint_sha256"
        ]
        == "abc123"
    )

    # ---------------------------------------------
    # Evidence
    # ---------------------------------------------

    assert (
        response["evidence"]
        == [
            "Very high domain similarity"
        ]
    )

    # ---------------------------------------------
    # VirusTotal
    # ---------------------------------------------

    assert (
        response["virustotal"]["available"]
        is True
    )

    assert (
        response["virustotal"]["found"]
        is True
    )

    assert (
        response["virustotal"][
            "malicious_count"
        ]
        == 5
    )

    assert (
        response["virustotal"][
            "suspicious_count"
        ]
        == 2
    )

    assert (
        response["virustotal"][
            "reputation"
        ]
        == -10
    )

    assert (
        response["virustotal"][
            "categories"
        ]["engine"]
        == "phishing"
    )

    # ---------------------------------------------
    # Details
    # ---------------------------------------------

    assert (
        "details"
        in response
    )

    assert (
        "summary"
        in response["details"]
    )

    assert (
        "best_match"
        in response["details"]
    )

    assert (
        "profile"
        in response["details"]
    )

    assert (
        "inventory_analysis"
        in response["details"]
    )

    assert (
        "virustotal"
        in response["details"]
    )