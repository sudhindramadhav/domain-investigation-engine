import re
from collections import Counter

from bs4 import BeautifulSoup


class BrandIndicatorService:

    COMMON_BRAND_TERMS = {
        "login",
        "sign in",
        "signin",
        "account",
        "secure",
        "support",
        "official",
        "portal",
        "verification",
        "verify",
        "password",
        "authentication",
    }

    def analyze(self, website_result):
        text = website_result.get("text", "") or ""
        title = website_result.get("title", "") or ""
        meta_description = (
            website_result.get("meta_description", "") or ""
        )

        combined_text = " ".join([
            title,
            meta_description,
            text
        ])

        normalized_text = self._normalize_text(
            combined_text
        )

        return {
            "title": title,
            "meta_description": meta_description,
            "brand_candidates": self._extract_brand_candidates(
                normalized_text
            ),
            "brand_keywords": self._extract_brand_keywords(
                normalized_text
            ),
            "login_indicators": self._detect_login_indicators(
                normalized_text,
                website_result
            ),
            "logo_candidates": self._extract_logo_candidates(
                website_result
            ),
            "favicon_candidates": self._extract_favicon_candidates(
                website_result
            ),
            "form_indicators": self._analyze_forms(
                website_result
            )
        }

    def _normalize_text(self, text):
        text = text.lower()
        text = re.sub(
            r"\s+",
            " ",
            text
        )

        return text.strip()

    def _extract_brand_candidates(self, text):
        """
        Extract likely organization/brand names.

        This is intentionally conservative.
        The later inventory-matching phase will provide
        the authoritative brand names.
        """

        candidates = []

        patterns = [
            r"welcome to ([a-z0-9&.' -]{2,80})",
            r"([a-z0-9&.' -]{2,80}) official",
            r"([a-z0-9&.' -]{2,80}) login",
            r"([a-z0-9&.' -]{2,80}) portal",
            r"([a-z0-9&.' -]{2,80}) support",
        ]

        for pattern in patterns:
            matches = re.findall(
                pattern,
                text,
                re.IGNORECASE
            )

            for match in matches:
                candidate = match.strip(
                    " .,-:|/"
                )

                if candidate:
                    candidates.append(candidate)

        # Remove duplicates while preserving order
        unique = []

        for candidate in candidates:
            if candidate not in unique:
                unique.append(candidate)

        return unique[:20]

    def _extract_brand_keywords(self, text):
        found = []

        for keyword in self.COMMON_BRAND_TERMS:
            if keyword in text:
                found.append(keyword)

        return sorted(found)

    def _detect_login_indicators(
        self,
        text,
        website_result
    ):
        indicators = []

        if any(
            phrase in text
            for phrase in [
                "login",
                "log in",
                "sign in",
                "signin"
            ]
        ):
            indicators.append(
                "login_text"
            )

        if any(
            phrase in text
            for phrase in [
                "password",
                "enter your password"
            ]
        ):
            indicators.append(
                "password_text"
            )

        forms = website_result.get(
            "forms",
            []
        )

        for form in forms:
            for field in form.get(
                "inputs",
                []
            ):
                field_type = (
                    field.get("type", "")
                    .lower()
                )

                field_name = (
                    field.get("name") or ""
                ).lower()

                placeholder = (
                    field.get("placeholder") or ""
                ).lower()

                field_text = " ".join([
                    field_type,
                    field_name,
                    placeholder
                ])

                if (
                    field_type == "password"
                    or "password" in field_text
                ):
                    indicators.append(
                        "password_field"
                    )

                if (
                    field_type == "email"
                    or "email" in field_text
                ):
                    indicators.append(
                        "email_field"
                    )

        return sorted(
            set(indicators)
        )

    def _extract_logo_candidates(
        self,
        website_result
    ):
        logos = []

        for image in website_result.get(
            "images",
            []
        ):
            src = image.get(
                "src",
                ""
            )

            alt = image.get(
                "alt",
                ""
            ).lower()

            title = image.get(
                "title",
                ""
            ).lower()

            combined = " ".join([
                src.lower(),
                alt,
                title
            ])

            if any(
                term in combined
                for term in [
                    "logo",
                    "brand",
                    "company"
                ]
            ):
                logos.append(image)

        return logos[:20]

    def _extract_favicon_candidates(
        self,
        website_result
    ):
        """
        The initial website service does not yet expose
        <link rel="icon"> elements, so this method currently
        returns an empty list.

        We'll add explicit favicon extraction in the next
        website-analysis enhancement.
        """

        return []

    def _analyze_forms(
        self,
        website_result
    ):
        forms = website_result.get(
            "forms",
            []
        )

        form_count = len(forms)
        password_forms = 0
        email_forms = 0

        for form in forms:
            input_types = [
                field.get(
                    "type",
                    ""
                ).lower()
                for field in form.get(
                    "inputs",
                    []
                )
            ]

            if "password" in input_types:
                password_forms += 1

            if "email" in input_types:
                email_forms += 1

        return {
            "form_count": form_count,
            "password_forms": password_forms,
            "email_forms": email_forms
        }