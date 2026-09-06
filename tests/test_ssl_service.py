from unittest.mock import Mock, patch

from app.services.ssl_service import SSLService


MOCK_CERTIFICATE = {
    "subject": [
        [
            ("commonName", "*.example.com"),
            ("organizationName", "Example Corporation")
        ]
    ],
    "issuer": [
        [
            ("commonName", "Example CA"),
            ("organizationName", "Example Certificate Authority")
        ]
    ],
    "subjectAltName": [
        ("DNS", "*.example.com"),
        ("DNS", "example.com"),
        ("DNS", "www.example.com")
    ],
    "serialNumber": "123456789",
    "version": 3,
    "notBefore": "Jan  1 00:00:00 2026 GMT",
    "notAfter": "Jan  1 00:00:00 2027 GMT"
}


def test_ssl_investigation():

    service = SSLService()

    mock_secure_socket = Mock()

    mock_secure_socket.getpeercert.return_value = (
        MOCK_CERTIFICATE
    )

    mock_secure_socket.getpeercert.side_effect = [
        MOCK_CERTIFICATE,
        b"fake-certificate-data"
    ]

    mock_socket_context = Mock()

    mock_socket_context.__enter__ = Mock(
        return_value=mock_secure_socket
    )

    mock_socket_context.__exit__ = Mock(
        return_value=None
    )

    with patch(
        "socket.create_connection"
    ) as mock_connection:

        mock_connection.return_value.__enter__ = Mock(
            return_value=Mock()
        )

        mock_connection.return_value.__exit__ = Mock(
            return_value=None
        )

        with patch(
            "ssl.create_default_context"
        ) as mock_ssl_context:

            mock_ssl_context.return_value.wrap_socket.return_value = (
                mock_socket_context
            )

            result = service.investigate(
                "example.com"
            )

    assert result["domain"] == "example.com"

    assert result["subject"]["commonName"] == (
        "*.example.com"
    )

    assert result["subject"]["organizationName"] == (
        "Example Corporation"
    )

    assert result["issuer"]["commonName"] == (
        "Example CA"
    )

    assert "example.com" in result["san"]

    assert result["serial_number"] == "123456789"

    assert result["version"] == 3

    assert result["valid_from"] == (
        "Jan  1 00:00:00 2026 GMT"
    )

    assert result["valid_to"] == (
        "Jan  1 00:00:00 2027 GMT"
    )

    assert result["fingerprint_sha256"] is not None


def test_ssl_failure():

    service = SSLService()

    with patch(
        "socket.create_connection",
        side_effect=Exception(
            "Connection failed"
        )
    ):
        result = service.investigate(
            "example.com"
        )

    assert result["domain"] == "example.com"
    assert result["subject"] is None
    assert result["issuer"] is None
    assert result["san"] == []
    assert result["serial_number"] is None
    assert result["fingerprint_sha256"] is None
    assert "error" in result