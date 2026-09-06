from unittest.mock import patch, Mock

from app.services.asn_service import ASNService


def test_asn_lookup():

    service = ASNService()

    mock_response = Mock()

    mock_response.json.return_value = {
        "org": "AS15169 Google LLC",
        "country": "US",
        "region": "California",
        "city": "Mountain View",
        "hostname": "example.google.com"
    }

    mock_response.raise_for_status.return_value = None

    with patch("requests.get", return_value=mock_response):

        result = service.lookup("8.8.8.8")

    assert result["ip"] == "8.8.8.8"
    assert result["asn"] == "AS15169"
    assert result["organization"] == "AS15169 Google LLC"
    assert result["country"] == "US"


def test_asn_lookup_failure():

    service = ASNService()

    with patch(
        "requests.get",
        side_effect=Exception("Network failure")
    ):

        result = service.lookup("8.8.8.8")

    assert result["ip"] == "8.8.8.8"
    assert result["asn"] is None
    assert "error" in result


def test_lookup_many():

    service = ASNService()

    with patch.object(
        service,
        "lookup",
        side_effect=[
            {
                "ip": "8.8.8.8",
                "asn": "AS15169"
            },
            {
                "ip": "1.1.1.1",
                "asn": "AS13335"
            }
        ]
    ):

        results = service.lookup_many(
            ["8.8.8.8", "1.1.1.1"]
        )

    assert len(results) == 2
    assert results[0]["asn"] == "AS15169"
    assert results[1]["asn"] == "AS13335"