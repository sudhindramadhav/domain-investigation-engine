from unittest.mock import Mock, patch

from app.services.virustotal_service import (
    VirusTotalService
)


def test_no_api_key():

    service = VirusTotalService()

    result = service.investigate_domain(
        "example.com"
    )

    assert (
        result["available"]
        is False
    )

    assert (
        "API key"
        in result["error"]
    )


def test_successful_domain_investigation():

    service = VirusTotalService(
        api_key="test-api-key"
    )

    mock_response = Mock()

    mock_response.status_code = 200

    mock_response.json.return_value = {
        "data": {
            "attributes": {
                "reputation": -10,

                "last_analysis_stats": {
                    "harmless": 60,
                    "malicious": 5,
                    "suspicious": 3,
                    "undetected": 10,
                    "timeout": 0
                },

                "categories": {
                    "Engine1": "phishing"
                }
            }
        }
    }

    with patch(
        "requests.get",
        return_value=mock_response
    ):

        result = service.investigate_domain(
            "example.com"
        )

    assert (
        result["available"]
        is True
    )

    assert (
        result["found"]
        is True
    )

    assert (
        result["domain"]
        == "example.com"
    )

    assert (
        result["malicious_count"]
        == 5
    )

    assert (
        result["suspicious_count"]
        == 3
    )

    assert (
        result["reputation"]
        == -10
    )

    assert (
        result["analysis_stats"][
            "harmless"
        ]
        == 60
    )


def test_domain_not_found():

    service = VirusTotalService(
        api_key="test-api-key"
    )

    mock_response = Mock()

    mock_response.status_code = 404

    with patch(
        "requests.get",
        return_value=mock_response
    ):

        result = service.investigate_domain(
            "unknown-domain.example"
        )

    assert (
        result["available"]
        is True
    )

    assert (
        result["found"]
        is False
    )


def test_timeout():

    service = VirusTotalService(
        api_key="test-api-key"
    )

    with patch(
        "requests.get",
        side_effect=__import__(
            "requests"
        ).exceptions.Timeout
    ):

        result = service.investigate_domain(
            "example.com"
        )

    assert (
        result["available"]
        is True
    )

    assert (
        "timed out"
        in result["error"]
    )


def test_maliciousness_confidence():

    service = VirusTotalService()

    virustotal_result = {
        "available": True,

        "found": True,

        "analysis_stats": {
            "harmless": 60,
            "malicious": 5,
            "suspicious": 3,
            "undetected": 10,
            "timeout": 0
        },

        "malicious_count": 5,

        "suspicious_count": 3
    }

    confidence = (
        service.calculate_maliciousness_confidence(
            virustotal_result
        )
    )

    assert (
        confidence == 8.33
    )


def test_zero_maliciousness_confidence():

    service = VirusTotalService()

    virustotal_result = {
        "available": True,

        "found": True,

        "analysis_stats": {
            "harmless": 70,
            "malicious": 0,
            "suspicious": 0,
            "undetected": 10,
            "timeout": 0
        },

        "malicious_count": 0,

        "suspicious_count": 0
    }

    confidence = (
        service.calculate_maliciousness_confidence(
            virustotal_result
        )
    )

    assert (
        confidence == 0
    )


def test_unavailable_virustotal_confidence():

    service = VirusTotalService()

    virustotal_result = {
        "available": False,

        "found": False
    }

    confidence = (
        service.calculate_maliciousness_confidence(
            virustotal_result
        )
    )

    assert (
        confidence == 0
    )