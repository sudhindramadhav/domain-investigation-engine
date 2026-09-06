from app.services.brand_indicator_service import (
    BrandIndicatorService
)


def test_brand_indicator_analysis():

    service = BrandIndicatorService()

    website_result = {
        "domain": "example.com",
        "title": "Example Corporation Login",
        "meta_description": (
            "Secure Example Corporation account portal"
        ),
        "text": (
            "Welcome to Example Corporation. "
            "Please login to your account and "
            "enter your email and password."
        ),
        "images": [
            {
                "src": "https://example.com/logo.png",
                "alt": "Example Corporation Logo",
                "title": "Company Logo"
            },
            {
                "src": "https://example.com/banner.jpg",
                "alt": "Banner",
                "title": ""
            }
        ],
        "forms": [
            {
                "action": "/login",
                "method": "post",
                "inputs": [
                    {
                        "type": "email",
                        "name": "email",
                        "placeholder": "Email"
                    },
                    {
                        "type": "password",
                        "name": "password",
                        "placeholder": "Password"
                    }
                ]
            }
        ]
    }

    result = service.analyze(
        website_result
    )

    assert result["title"] == (
        "Example Corporation Login"
    )

    assert result["meta_description"] == (
        "Secure Example Corporation account portal"
    )

    assert len(result["brand_candidates"]) > 0

    assert "login" in result["brand_keywords"]
    assert "secure" in result["brand_keywords"]
    assert "account" in result["brand_keywords"]
    assert "portal" in result["brand_keywords"]
    assert "password" in result["brand_keywords"]

    assert "login_text" in (
        result["login_indicators"]
    )

    assert "password_text" in (
        result["login_indicators"]
    )

    assert "password_field" in (
        result["login_indicators"]
    )

    assert "email_field" in (
        result["login_indicators"]
    )

    assert len(
        result["logo_candidates"]
    ) == 1

    assert (
        result["logo_candidates"][0]["alt"]
        == "Example Corporation Logo"
    )

    assert result["form_indicators"][
        "form_count"
    ] == 1

    assert result["form_indicators"][
        "password_forms"
    ] == 1

    assert result["form_indicators"][
        "email_forms"
    ] == 1


def test_brand_indicator_without_forms():

    service = BrandIndicatorService()

    website_result = {
        "domain": "example.com",
        "title": "Example",
        "meta_description": "",
        "text": "Example company website",
        "images": [],
        "forms": []
    }

    result = service.analyze(
        website_result
    )

    assert result["form_indicators"][
        "form_count"
    ] == 0

    assert result["form_indicators"][
        "password_forms"
    ] == 0

    assert result["form_indicators"][
        "email_forms"
    ] == 0

    assert result["logo_candidates"] == []