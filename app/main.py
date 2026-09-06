import json
import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify, request

from app.services.investigation_service import (
    InvestigationService
)
from app.services.inventory_loader import (
    InventoryLoader
)


# =====================================================
# Application Configuration
# =====================================================

load_dotenv()

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent

INVENTORY_PATH = (
    BASE_DIR
    / "data"
    / "sample_inventory.json"
)

VT_API_KEY = os.getenv(
    "VT_API_KEY"
)


# =====================================================
# Inventory
# =====================================================

def load_inventory():
    """
    Load the legitimate organization inventory.
    """

    loader = InventoryLoader()

    return loader.load_json(
        INVENTORY_PATH
    )


# =====================================================
# Health
# =====================================================

@app.route("/", methods=["GET"])
def home():

    return jsonify({
        "application": (
            "Domain Investigation & "
            "Brand Impersonation Detection Engine"
        ),
        "status": "running"
    })


@app.route(
    "/api/health",
    methods=["GET"]
)
def health():

    return jsonify({
        "status": "healthy",
        "service": "Domain Investigation Engine"
    })


# =====================================================
# Investigation Response Builder
# =====================================================

def build_api_response(result):
    """
    Convert the complete internal investigation result
    into a clean analyst-facing API response.

    The complete raw investigation is still retained
    under 'details'.
    """

    summary = result.get(
        "summary",
        {}
    )

    risk_assessment = result.get(
        "risk_assessment",
        {}
    )

    best_match = result.get(
        "best_match"
    )

    profile = result.get(
        "profile",
        {}
    )

    inventory_analysis = result.get(
        "inventory_analysis",
        {}
    )

    virustotal = result.get(
        "virustotal",
        {}
    )

    return {
        "domain": result.get(
            "domain"
        ),

        "organization": result.get(
            "organization"
        ),

        "verdict": result.get(
            "verdict"
        ),

        "risk": {
            "level": risk_assessment.get(
                "risk_level"
            ),

            "assessment": risk_assessment.get(
                "assessment"
            ),

            "infrastructure_confidence": (
                risk_assessment.get(
                    "infrastructure_confidence",
                    0
                )
            ),

            "brand_impersonation_confidence": (
                risk_assessment.get(
                    "brand_impersonation_confidence",
                    0
                )
            ),

            "maliciousness_confidence": (
                risk_assessment.get(
                    "maliciousness_confidence",
                    0
                )
            )
        },

        "inventory_match": {
            "domain": (
                best_match.get(
                    "legitimate_domain"
                )
                if best_match
                else None
            ),

            "exact_match": (
                best_match.get(
                    "exact_domain_match",
                    False
                )
                if best_match
                else False
            ),

            "domain_similarity": (
                best_match.get(
                    "domain_similarity",
                    0
                )
                if best_match
                else 0
            )
        },

        "website": {
            "status_code": profile.get(
                "website",
                {}
            ).get(
                "status_code"
            ),

            "title": profile.get(
                "website",
                {}
            ).get(
                "title"
            ),

            "meta_description": profile.get(
                "website",
                {}
            ).get(
                "meta_description"
            ),

            "forms": len(
                profile.get(
                    "website",
                    {}
                ).get(
                    "forms",
                    []
                )
            ),

            "images": len(
                profile.get(
                    "website",
                    {}
                ).get(
                    "images",
                    []
                )
            )
        },

        "infrastructure": {
            "ips": profile.get(
                "infrastructure",
                {}
            ).get(
                "ips",
                []
            ),

            "asn": profile.get(
                "infrastructure",
                {}
            ).get(
                "asn",
                []
            ),

            "nameservers": profile.get(
                "infrastructure",
                {}
            ).get(
                "dns",
                {}
            ).get(
                "nameservers",
                []
            )
        },

        "rdap": {
            "registrar": profile.get(
                "rdap",
                {}
            ).get(
                "registrar"
            ),

            "registration_date": profile.get(
                "rdap",
                {}
            ).get(
                "registration_date"
            ),

            "expiration_date": profile.get(
                "rdap",
                {}
            ).get(
                "expiration_date"
            )
        },

        "ssl": {
            "subject": profile.get(
                "ssl",
                {}
            ).get(
                "subject"
            ),

            "issuer": profile.get(
                "ssl",
                {}
            ).get(
                "issuer"
            ),

            "san": profile.get(
                "ssl",
                {}
            ).get(
                "san",
                []
            ),

            "fingerprint_sha256": profile.get(
                "ssl",
                {}
            ).get(
                "fingerprint_sha256"
            )
        },

        "evidence": summary.get(
            "evidence",
            []
        ),

        "virustotal": {
            "available": virustotal.get(
                "available",
                False
            ),

            "found": virustotal.get(
                "found",
                False
            ),

            "malicious_count": virustotal.get(
                "malicious_count",
                0
            ),

            "suspicious_count": virustotal.get(
                "suspicious_count",
                0
            ),

            "reputation": virustotal.get(
                "reputation"
            ),

            "categories": virustotal.get(
                "categories",
                {}
            )
        },

        "details": {
            "summary": summary,

            "best_match": best_match,

            "profile": profile,

            "inventory_analysis": (
                inventory_analysis
            ),

            "virustotal": virustotal
        }
    }


# =====================================================
# Domain Investigation
# =====================================================

@app.route(
    "/api/investigate",
    methods=["POST"]
)
def investigate():

    # -------------------------------------------------
    # Validate JSON
    # -------------------------------------------------

    if not request.is_json:

        return jsonify({
            "error": "Request body must be JSON"
        }), 400

    data = request.get_json(
        silent=True
    )

    if not isinstance(
        data,
        dict
    ):

        return jsonify({
            "error": "Invalid JSON request body"
        }), 400

    # -------------------------------------------------
    # Validate domain
    # -------------------------------------------------

    domain = data.get(
        "domain"
    )

    if not domain:

        return jsonify({
            "error": "domain is required"
        }), 400

    if not isinstance(
        domain,
        str
    ):

        return jsonify({
            "error": "domain must be a string"
        }), 400

    domain = domain.strip()

    if not domain:

        return jsonify({
            "error": "domain cannot be empty"
        }), 400

    # -------------------------------------------------
    # Load inventory
    # -------------------------------------------------

    try:

        organization = load_inventory()

    except FileNotFoundError:

        return jsonify({
            "error": (
                "Legitimate inventory file not found"
            )
        }), 500

    except (
        ValueError,
        json.JSONDecodeError
    ) as exc:

        return jsonify({
            "error": (
                "Invalid legitimate inventory: "
                f"{str(exc)}"
            )
        }), 500

    except Exception as exc:

        return jsonify({
            "error": (
                "Failed to load legitimate inventory: "
                f"{str(exc)}"
            )
        }), 500

    # -------------------------------------------------
    # Investigation
    # -------------------------------------------------

    try:

        service = InvestigationService(
            virustotal_api_key=VT_API_KEY
        )

        result = service.investigate(
            domain,
            organization
        )

        api_response = build_api_response(
            result
        )

        return jsonify(
            api_response
        ), 200

    except ValueError as exc:

        return jsonify({
            "error": str(exc)
        }), 400

    except Exception as exc:

        app.logger.exception(
            "Domain investigation failed"
        )

        return jsonify({
            "error": (
                "Domain investigation failed: "
                f"{str(exc)}"
            )
        }), 500


# =====================================================
# Application Entry Point
# =====================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )