from unittest.mock import Mock, patch

from app.services.rdap_service import RDAPService


MOCK_RDAP_RESPONSE = {
    "ldhName": "example.com",

    "events": [
        {
            "eventAction": "registration",
            "eventDate": "1995-08-14T04:00:00Z"
        },
        {
            "eventAction": "expiration",
            "eventDate": "2027-08-14T04:00:00Z"
        },
        {
            "eventAction": "last changed",
            "eventDate": "2026-01-01T00:00:00Z"
        }
    ],

    "status": [
        "client delete prohibited",
        "client transfer prohibited"
    ],

    "nameservers": [
        {
            "ldhName": "NS1.EXAMPLE.COM"
        },
        {
            "ldhName": "NS2.EXAMPLE.COM"
        }
    ],

    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Example Registrar"]
                ]
            ]
        },
        {
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Example Organization"],
                    ["org", {}, "text", "Example Corporation"],
                    ["email", {}, "text", "admin@example.com"]
                ]
            ]
        }
    ]
}


def test_rdap_investigation():

    service = RDAPService()

    mock_response = Mock()
    mock_response.json.return_value = MOCK_RDAP_RESPONSE
    mock_response.raise_for_status.return_value = None

    with patch(
        "requests.get",
        return_value=mock_response
    ):

        result = service.investigate("example.com")

    assert result["domain"] == "example.com"

    assert result["registrar"] == "Example Registrar"

    assert (
        result["registration_date"]
        == "1995-08-14T04:00:00Z"
    )

    assert (
        result["expiration_date"]
        == "2027-08-14T04:00:00Z"
    )

    assert (
        result["updated_date"]
        == "2026-01-01T00:00:00Z"
    )

    assert "client delete prohibited" in result["status"]

    assert result["nameservers"] == [
        "ns1.example.com",
        "ns2.example.com"
    ]


def test_rdap_registrant():

    service = RDAPService()

    mock_response = Mock()
    mock_response.json.return_value = MOCK_RDAP_RESPONSE
    mock_response.raise_for_status.return_value = None

    with patch(
        "requests.get",
        return_value=mock_response
    ):

        result = service.investigate("example.com")

    assert result["registrant"]["name"] == "Example Organization"
    assert result["registrant"]["organization"] == "Example Corporation"
    assert result["registrant"]["email"] == "admin@example.com"


def test_rdap_failure():

    service = RDAPService()

    with patch(
        "requests.get",
        side_effect=Exception("RDAP unavailable")
    ):

        result = service.investigate("example.com")

    assert result["domain"] == "example.com"
    assert result["registrar"] is None
    assert result["registration_date"] is None
    assert result["expiration_date"] is None
    assert result["nameservers"] == []
    assert "error" in result