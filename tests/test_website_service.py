from unittest.mock import Mock, patch

from app.services.website_service import WebsiteService


MOCK_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Example Login</title>
    <meta
        name="description"
        content="Example company login portal"
    >
</head>
<body>

    <h1>Example Corporation</h1>

    <p>Welcome to Example Corporation.</p>

    <a href="/about">About</a>

    <img
        src="/images/logo.png"
        alt="Example Corporation Logo"
    >

    <form action="/login" method="post">
        <input
            type="email"
            name="email"
            placeholder="Email"
        >

        <input
            type="password"
            name="password"
            placeholder="Password"
        >

        <input
            type="submit"
            value="Login"
        >
    </form>

</body>
</html>
"""


def create_mock_response():
    response = Mock()

    response.status_code = 200
    response.url = "https://example.com/"
    response.text = MOCK_HTML

    response.headers = {
        "Content-Type": "text/html; charset=utf-8"
    }

    return response


def test_website_investigation():

    service = WebsiteService()

    mock_response = create_mock_response()

    with patch.object(
        service,
        "_resolves_to_private_ip",
        return_value=False
    ):

        with patch(
            "requests.get",
            return_value=mock_response
        ):

            result = service.investigate(
                "example.com"
            )

    assert result["domain"] == "example.com"
    assert result["status_code"] == 200

    assert result["title"] == (
        "Example Login"
    )

    assert result["meta_description"] == (
        "Example company login portal"
    )

    assert "Example Corporation" in result["text"]

    assert len(result["links"]) == 1
    assert result["links"][0]["text"] == "About"

    assert len(result["images"]) == 1
    assert result["images"][0]["alt"] == (
        "Example Corporation Logo"
    )

    assert len(result["forms"]) == 1

    inputs = result["forms"][0]["inputs"]

    input_types = [
        field["type"]
        for field in inputs
    ]

    assert "email" in input_types
    assert "password" in input_types


def test_website_request_failure():

    service = WebsiteService()

    with patch.object(
        service,
        "_resolves_to_private_ip",
        return_value=False
    ):

        with patch(
            "requests.get",
            side_effect=Exception(
                "Connection failed"
            )
        ):

            result = service.investigate(
                "example.com"
            )

    assert result["domain"] == "example.com"
    assert result["status_code"] is None
    assert result["title"] is None
    assert result["error"] is not None


def test_private_ip_blocked():

    service = WebsiteService()

    with patch.object(
        service,
        "_resolves_to_private_ip",
        return_value=True
    ):

        result = service.investigate(
            "internal.example"
        )

    assert result["status_code"] is None

    assert result["error"] == (
        "Blocked request to private or reserved IP"
    )


def test_url_construction():

    service = WebsiteService()

    assert service._build_url(
        "example.com"
    ) == "https://example.com"

    assert service._build_url(
        "https://example.com"
    ) == "https://example.com"

    assert service._build_url(
        "http://example.com"
    ) == "http://example.com"