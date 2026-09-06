from app.services.domain_profile_service import DomainProfileService
from app.services.inventory_matcher import InventoryMatcher
from app.services.inventory_normalizer import InventoryNormalizer
from app.services.virustotal_service import VirusTotalService


class InvestigationService:

    def __init__(
        self,
        virustotal_api_key=None
    ):
        self.domain_profile_service = (
            DomainProfileService()
        )

        self.inventory_matcher = (
            InventoryMatcher()
        )

        self.inventory_normalizer = (
            InventoryNormalizer()
        )

        self.virustotal_service = (
            VirusTotalService(
                api_key=virustotal_api_key
            )
        )

    def investigate(
        self,
        domain,
        organization
    ):
        """
        Perform a complete domain investigation.

        Investigation layers:

        1. DNS
        2. IP addresses
        3. ASN
        4. RDAP
        5. SSL
        6. Website analysis
        7. Brand indicators
        8. Legitimate inventory comparison
        9. VirusTotal analysis
        10. Risk assessment
        11. Analyst-friendly summary
        """

        organization = (
            self.inventory_normalizer.normalize(
                organization
            )
        )

        domain_profile = (
            self.domain_profile_service.investigate(
                domain
            )
        )

        inventory_match = (
            self.inventory_matcher.match(
                domain_profile,
                organization
            )
        )

        best_match = inventory_match.get(
            "best_match"
        )

        # =================================================
        # VirusTotal investigation
        # =================================================

        investigated_domain = (
            domain_profile.get(
                "domain"
            )
        )

        virustotal_result = (
            self.virustotal_service.investigate_domain(
                investigated_domain
            )
        )

        maliciousness_confidence = (
            self.virustotal_service
            .calculate_maliciousness_confidence(
                virustotal_result
            )
        )

        # =================================================
        # Final risk assessment
        # =================================================

        risk_assessment = (
            self._build_risk_assessment(
                inventory_match,
                maliciousness_confidence
            )
        )

        # =================================================
        # Analyst-friendly summary
        # =================================================

        summary = self._build_summary(
            domain_profile,
            inventory_match,
            organization,
            virustotal_result,
            maliciousness_confidence
        )

        return {
            "domain": domain_profile.get(
                "domain"
            ),

            "organization": (
                organization.organization_name
            ),

            "verdict": self._get_verdict(
                inventory_match
            ),

            "summary": summary,

            "risk_assessment": risk_assessment,

            "best_match": best_match,

            "profile": domain_profile,

            "inventory_analysis": inventory_match,

            "virustotal": virustotal_result
        }

    # =====================================================
    # VERDICT
    # =====================================================

    def _get_verdict(
        self,
        inventory_match
    ):
        best_match = inventory_match.get(
            "best_match"
        )

        if not best_match:
            return (
                "NO STRONG INVENTORY MATCH"
            )

        return best_match.get(
            "verdict",
            "REQUIRES INVESTIGATION"
        )

    # =====================================================
    # RISK ASSESSMENT
    # =====================================================

    def _build_risk_assessment(
        self,
        inventory_match,
        maliciousness_confidence
    ):
        """
        Build the final analyst-facing risk assessment.

        Exact legitimate inventory matches are treated
        as confirmed legitimate.

        Other domains are evaluated using:

        - Infrastructure confidence
        - Brand impersonation confidence
        - Maliciousness confidence
        """

        best_match = inventory_match.get(
            "best_match"
        )

        # -------------------------------------------------
        # No inventory match
        # -------------------------------------------------

        if not best_match:

            risk_level = (
                self._calculate_risk_level(
                    0,
                    0,
                    maliciousness_confidence,
                    False
                )
            )

            assessment = (
                self._build_risk_assessment_text(
                    0,
                    0,
                    maliciousness_confidence
                )
            )

            return {
                "risk_level": risk_level,

                "infrastructure_confidence": 0,

                "brand_impersonation_confidence": 0,

                "maliciousness_confidence": (
                    maliciousness_confidence
                ),

                "exact_inventory_match": False,

                "assessment": assessment
            }

        # -------------------------------------------------
        # Extract confidence values
        # -------------------------------------------------

        infrastructure_confidence = (
            best_match.get(
                "infrastructure_confidence",
                0
            )
        )

        brand_impersonation_confidence = (
            best_match.get(
                "brand_impersonation_confidence",
                0
            )
        )

        exact_inventory_match = (
            best_match.get(
                "exact_domain_match",
                False
            )
        )

        # -------------------------------------------------
        # Calculate risk
        # -------------------------------------------------

        risk_level = (
            self._calculate_risk_level(
                infrastructure_confidence,
                brand_impersonation_confidence,
                maliciousness_confidence,
                exact_inventory_match
            )
        )

        # -------------------------------------------------
        # Exact legitimate domain
        # -------------------------------------------------

        if exact_inventory_match:

            assessment = (
                "Domain exactly matches the legitimate "
                "organization inventory. "
                "Infrastructure overlap is therefore "
                "expected and does not indicate risk."
            )

        else:

            assessment = (
                self._build_risk_assessment_text(
                    infrastructure_confidence,
                    brand_impersonation_confidence,
                    maliciousness_confidence
                )
            )

        return {
            "risk_level": risk_level,

            "infrastructure_confidence": (
                infrastructure_confidence
            ),

            "brand_impersonation_confidence": (
                brand_impersonation_confidence
            ),

            "maliciousness_confidence": (
                maliciousness_confidence
            ),

            "exact_inventory_match": (
                exact_inventory_match
            ),

            "assessment": assessment
        }

    def _calculate_risk_level(
        self,
        infrastructure_confidence,
        brand_impersonation_confidence,
        maliciousness_confidence,
        exact_inventory_match=False
    ):
        """
        Calculate overall risk level.

        Exact inventory matches are explicitly treated
        as confirmed legitimate.

        For other domains, the strongest security
        signals are prioritized rather than simply
        averaging the scores.
        """

        # -------------------------------------------------
        # Exact legitimate inventory match
        # -------------------------------------------------

        if exact_inventory_match:
            return "INFORMATIONAL"

        # -------------------------------------------------
        # Critical
        # -------------------------------------------------

        if (
            brand_impersonation_confidence >= 80
            and maliciousness_confidence >= 30
        ):
            return "CRITICAL"

        # -------------------------------------------------
        # High maliciousness
        # -------------------------------------------------

        if maliciousness_confidence >= 70:
            return "HIGH"

        # -------------------------------------------------
        # High brand impersonation
        # -------------------------------------------------

        if brand_impersonation_confidence >= 80:
            return "HIGH"

        # -------------------------------------------------
        # Multiple strong indicators
        # -------------------------------------------------

        if (
            brand_impersonation_confidence >= 60
            and maliciousness_confidence >= 30
        ):
            return "HIGH"

        if (
            infrastructure_confidence >= 60
            and maliciousness_confidence >= 30
        ):
            return "HIGH"

        # -------------------------------------------------
        # Medium
        # -------------------------------------------------

        if (
            brand_impersonation_confidence >= 60
            or maliciousness_confidence >= 30
            or infrastructure_confidence >= 60
        ):
            return "MEDIUM"

        # -------------------------------------------------
        # Low
        # -------------------------------------------------

        if (
            brand_impersonation_confidence >= 40
            or maliciousness_confidence >= 10
            or infrastructure_confidence >= 30
        ):
            return "LOW"

        # -------------------------------------------------
        # Informational
        # -------------------------------------------------

        return "INFORMATIONAL"

    def _build_risk_assessment_text(
        self,
        infrastructure_confidence,
        brand_impersonation_confidence,
        maliciousness_confidence
    ):
        """
        Generate a human-readable explanation
        of the overall risk.
        """

        indicators = []

        # -------------------------------------------------
        # Brand indicators
        # -------------------------------------------------

        if brand_impersonation_confidence >= 80:

            indicators.append(
                "strong brand impersonation indicators"
            )

        elif brand_impersonation_confidence >= 60:

            indicators.append(
                "moderate-to-strong brand impersonation indicators"
            )

        elif brand_impersonation_confidence >= 40:

            indicators.append(
                "some brand similarity indicators"
            )

        # -------------------------------------------------
        # Maliciousness indicators
        # -------------------------------------------------

        if maliciousness_confidence >= 70:

            indicators.append(
                "strong maliciousness evidence"
            )

        elif maliciousness_confidence >= 30:

            indicators.append(
                "significant maliciousness evidence"
            )

        elif maliciousness_confidence >= 10:

            indicators.append(
                "some VirusTotal maliciousness indicators"
            )

        # -------------------------------------------------
        # Infrastructure indicators
        # -------------------------------------------------

        if infrastructure_confidence >= 60:

            indicators.append(
                "strong infrastructure overlap"
            )

        elif infrastructure_confidence >= 30:

            indicators.append(
                "some infrastructure overlap"
            )

        # -------------------------------------------------
        # No indicators
        # -------------------------------------------------

        if not indicators:

            return (
                "No strong risk indicators were identified "
                "from the available evidence."
            )

        # -------------------------------------------------
        # Single indicator
        # -------------------------------------------------

        if len(indicators) == 1:

            return (
                indicators[0].capitalize()
                + "."
            )

        # -------------------------------------------------
        # Multiple indicators
        # -------------------------------------------------

        return (
            "Detected "
            + ", ".join(
                indicators[:-1]
            )
            + " and "
            + indicators[-1]
            + "."
        )

    # =====================================================
    # SUMMARY
    # =====================================================

    def _build_summary(
        self,
        domain_profile,
        inventory_match,
        organization,
        virustotal_result,
        maliciousness_confidence
    ):
        best_match = inventory_match.get(
            "best_match"
        )

        website = domain_profile.get(
            "website",
            {}
        )

        brand_indicators = domain_profile.get(
            "brand_indicators",
            {}
        )

        website_evidence = (
            self._build_website_evidence(
                website
            )
        )

        brand_evidence = (
            self._build_brand_evidence(
                brand_indicators
            )
        )

        virustotal_evidence = (
            self._build_virustotal_evidence(
                virustotal_result
            )
        )

        # -------------------------------------------------
        # No inventory match
        # -------------------------------------------------

        if not best_match:

            combined_evidence = []

            combined_evidence.extend(
                website_evidence
            )

            combined_evidence.extend(
                brand_evidence
            )

            combined_evidence.extend(
                virustotal_evidence
            )

            combined_evidence = list(
                dict.fromkeys(
                    combined_evidence
                )
            )

            return {
                "domain": domain_profile.get(
                    "domain"
                ),

                "organization": (
                    organization.organization_name
                ),

                "verdict": (
                    "NO STRONG INVENTORY MATCH"
                ),

                "infrastructure_confidence": 0,

                "brand_impersonation_confidence": 0,

                "maliciousness_confidence": (
                    maliciousness_confidence
                ),

                "matched_legitimate_domain": None,

                "domain_similarity": 0,

                "brand_score": 0,

                "website_evidence": (
                    website_evidence
                ),

                "brand_evidence": (
                    brand_evidence
                ),

                "virustotal_evidence": (
                    virustotal_evidence
                ),

                "evidence": combined_evidence
            }

        # -------------------------------------------------
        # Inventory evidence
        # -------------------------------------------------

        inventory_evidence = (
            best_match.get(
                "evidence",
                []
            )
        )

        combined_evidence = []

        combined_evidence.extend(
            inventory_evidence
        )

        combined_evidence.extend(
            website_evidence
        )

        combined_evidence.extend(
            brand_evidence
        )

        combined_evidence.extend(
            virustotal_evidence
        )

        combined_evidence = list(
            dict.fromkeys(
                combined_evidence
            )
        )

        return {
            "domain": domain_profile.get(
                "domain"
            ),

            "organization": (
                organization.organization_name
            ),

            "verdict": best_match.get(
                "verdict"
            ),

            "infrastructure_confidence": (
                best_match.get(
                    "infrastructure_confidence",
                    0
                )
            ),

            "brand_impersonation_confidence": (
                best_match.get(
                    "brand_impersonation_confidence",
                    0
                )
            ),

            "maliciousness_confidence": (
                maliciousness_confidence
            ),

            "matched_legitimate_domain": (
                best_match.get(
                    "legitimate_domain"
                )
            ),

            "domain_similarity": (
                best_match.get(
                    "domain_similarity",
                    0
                )
            ),

            "brand_score": (
                best_match.get(
                    "brand_score",
                    0
                )
            ),

            "website_evidence": (
                website_evidence
            ),

            "brand_evidence": (
                brand_evidence
            ),

            "virustotal_evidence": (
                virustotal_evidence
            ),

            "evidence": combined_evidence
        }

    # =====================================================
    # WEBSITE EVIDENCE
    # =====================================================

    def _build_website_evidence(
        self,
        website
    ):
        evidence = []

        if not website:
            return evidence

        status_code = website.get(
            "status_code"
        )

        if status_code:

            evidence.append(
                f"Website returned HTTP {status_code}"
            )

        title = website.get(
            "title"
        )

        if title:

            evidence.append(
                f"Website title detected: {title}"
            )

        description = website.get(
            "meta_description"
        )

        if description:

            evidence.append(
                "Website meta description detected"
            )

        forms = website.get(
            "forms",
            []
        )

        inputs = website.get(
            "form_inputs",
            []
        )

        password_fields = 0
        email_fields = 0

        # -------------------------------------------------
        # Inspect forms
        # -------------------------------------------------

        for form in forms:

            if not isinstance(
                form,
                dict
            ):
                continue

            form_inputs = form.get(
                "inputs",
                []
            )

            for field in form_inputs:

                if not isinstance(
                    field,
                    dict
                ):
                    continue

                field_type = str(
                    field.get(
                        "type",
                        ""
                    )
                ).lower()

                if field_type == "password":

                    password_fields += 1

                if field_type == "email":

                    email_fields += 1

        # -------------------------------------------------
        # Inspect direct form inputs
        # -------------------------------------------------

        for field in inputs:

            if not isinstance(
                field,
                dict
            ):
                continue

            field_type = str(
                field.get(
                    "type",
                    ""
                )
            ).lower()

            if field_type == "password":

                password_fields += 1

            if field_type == "email":

                email_fields += 1

        # -------------------------------------------------
        # Password evidence
        # -------------------------------------------------

        if password_fields > 0:

            evidence.append(
                "Password field detected on website"
            )

        # -------------------------------------------------
        # Email evidence
        # -------------------------------------------------

        if email_fields > 0:

            evidence.append(
                "Email input field detected on website"
            )

        # -------------------------------------------------
        # Form evidence
        # -------------------------------------------------

        if forms:

            evidence.append(
                f"{len(forms)} web form(s) detected"
            )

        # -------------------------------------------------
        # Logo/image evidence
        # -------------------------------------------------

        images = website.get(
            "images",
            []
        )

        logo_count = 0

        for image in images:

            if not isinstance(
                image,
                dict
            ):
                continue

            image_text = " ".join(
                str(
                    image.get(
                        key,
                        ""
                    )
                )
                for key in [
                    "src",
                    "alt",
                    "title"
                ]
            ).lower()

            if (
                "logo" in image_text
                or "brand" in image_text
                or "company" in image_text
            ):

                logo_count += 1

        if logo_count > 0:

            evidence.append(
                "Possible brand/logo image "
                f"indicator detected ({logo_count})"
            )

        return evidence

    # =====================================================
    # BRAND EVIDENCE
    # =====================================================

    def _build_brand_evidence(
        self,
        brand_indicators
    ):
        evidence = []

        if not brand_indicators:
            return evidence

        brand_candidates = (
            brand_indicators.get(
                "brand_candidates",
                []
            )
        )

        for brand in brand_candidates:

            if brand:

                evidence.append(
                    f"Potential brand mention detected: {brand}"
                )

        # -------------------------------------------------
        # Login indicators
        # -------------------------------------------------

        login_indicators = (
            brand_indicators.get(
                "login_indicators",
                []
            )
        )

        if login_indicators:

            evidence.append(
                "Login/sign-in indicators detected"
            )

        # -------------------------------------------------
        # Logo indicators
        # -------------------------------------------------

        logo_indicators = (
            brand_indicators.get(
                "logo_candidates",
                []
            )
        )

        if logo_indicators:

            evidence.append(
                "Potential brand/logo indicator detected"
            )

        # -------------------------------------------------
        # Favicon indicators
        # -------------------------------------------------

        favicon_indicators = (
            brand_indicators.get(
                "favicon_candidates",
                []
            )
        )

        if favicon_indicators:

            evidence.append(
                "Favicon indicator detected"
            )

        # -------------------------------------------------
        # Form indicators
        # -------------------------------------------------

        form_indicators = (
            brand_indicators.get(
                "form_indicators",
                {}
            )
        )

        if isinstance(
            form_indicators,
            dict
        ):

            password_fields = (
                form_indicators.get(
                    "password_fields",
                    0
                )
            )

            email_fields = (
                form_indicators.get(
                    "email_fields",
                    0
                )
            )

            if password_fields:

                evidence.append(
                    "Brand analysis detected password input"
                )

            if email_fields:

                evidence.append(
                    "Brand analysis detected email input"
                )

        return evidence

    # =====================================================
    # VIRUSTOTAL EVIDENCE
    # =====================================================

    def _build_virustotal_evidence(
        self,
        virustotal_result
    ):
        evidence = []

        if not virustotal_result:
            return evidence

        # -------------------------------------------------
        # VirusTotal unavailable
        # -------------------------------------------------

        if not virustotal_result.get(
            "available",
            False
        ):

            evidence.append(
                "VirusTotal analysis unavailable"
            )

            return evidence

        # -------------------------------------------------
        # Domain not found
        # -------------------------------------------------

        if not virustotal_result.get(
            "found",
            False
        ):

            error = (
                virustotal_result.get(
                    "error"
                )
            )

            if error:

                evidence.append(
                    f"VirusTotal: {error}"
                )

            else:

                evidence.append(
                    "VirusTotal did not return "
                    "domain analysis"
                )

            return evidence

        # -------------------------------------------------
        # Detection counts
        # -------------------------------------------------

        malicious_count = (
            virustotal_result.get(
                "malicious_count",
                0
            )
        )

        suspicious_count = (
            virustotal_result.get(
                "suspicious_count",
                0
            )
        )

        reputation = (
            virustotal_result.get(
                "reputation"
            )
        )

        # -------------------------------------------------
        # Malicious detections
        # -------------------------------------------------

        if malicious_count > 0:

            evidence.append(
                "VirusTotal detected "
                f"{malicious_count} malicious "
                "engine result(s)"
            )

        # -------------------------------------------------
        # Suspicious detections
        # -------------------------------------------------

        if suspicious_count > 0:

            evidence.append(
                "VirusTotal detected "
                f"{suspicious_count} suspicious "
                "engine result(s)"
            )

        # -------------------------------------------------
        # No detections
        # -------------------------------------------------

        if (
            malicious_count == 0
            and suspicious_count == 0
        ):

            evidence.append(
                "VirusTotal reported no malicious "
                "or suspicious engine detections"
            )

        # -------------------------------------------------
        # Reputation
        # -------------------------------------------------

        if reputation is not None:

            evidence.append(
                f"VirusTotal reputation score: {reputation}"
            )

        # -------------------------------------------------
        # Categories
        # -------------------------------------------------

        categories = (
            virustotal_result.get(
                "categories",
                {}
            )
        )

        if categories:

            category_values = []

            for value in categories.values():

                if value:

                    category_values.append(
                        str(value)
                    )

            if category_values:

                unique_categories = list(
                    dict.fromkeys(
                        category_values
                    )
                )

                evidence.append(
                    "VirusTotal categories: "
                    + ", ".join(
                        unique_categories
                    )
                )

        return evidence