import requests


class VirusTotalService:

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(
        self,
        api_key=None,
        timeout=15
    ):
        self.api_key = api_key
        self.timeout = timeout

    def investigate_domain(
        self,
        domain
    ):
        """
        Investigate a domain using VirusTotal.

        Returns normalized information that can later
        be converted into a maliciousness confidence score.
        """

        if not self.api_key:
            return {
                "domain": domain,
                "available": False,
                "error": "VirusTotal API key not configured"
            }

        url = (
            f"{self.BASE_URL}/domains/"
            f"{domain}"
        )

        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout
            )

            if response.status_code == 404:
                return {
                    "domain": domain,
                    "available": True,
                    "found": False,
                    "error": "Domain not found in VirusTotal"
                }

            response.raise_for_status()

            data = response.json()

            return self._parse_domain_response(
                domain,
                data
            )

        except requests.exceptions.Timeout:
            return {
                "domain": domain,
                "available": True,
                "found": False,
                "error": "VirusTotal request timed out"
            }

        except requests.exceptions.RequestException as exc:
            return {
                "domain": domain,
                "available": True,
                "found": False,
                "error": str(exc)
            }

        except Exception as exc:
            return {
                "domain": domain,
                "available": True,
                "found": False,
                "error": str(exc)
            }

    def _parse_domain_response(
        self,
        domain,
        data
    ):
        """
        Normalize the VirusTotal domain response.
        """

        attributes = (
            data.get("data", {})
            .get("attributes", {})
        )

        last_analysis_stats = (
            attributes.get(
                "last_analysis_stats",
                {}
            )
        )

        reputation = attributes.get(
            "reputation"
        )

        categories = attributes.get(
            "categories",
            {}
        )

        return {
            "domain": domain,

            "available": True,

            "found": True,

            "reputation": reputation,

            "analysis_stats": {
                "harmless": last_analysis_stats.get(
                    "harmless",
                    0
                ),

                "malicious": last_analysis_stats.get(
                    "malicious",
                    0
                ),

                "suspicious": last_analysis_stats.get(
                    "suspicious",
                    0
                ),

                "undetected": last_analysis_stats.get(
                    "undetected",
                    0
                ),

                "timeout": last_analysis_stats.get(
                    "timeout",
                    0
                )
            },

            "categories": categories,

            "malicious_count": last_analysis_stats.get(
                "malicious",
                0
            ),

            "suspicious_count": last_analysis_stats.get(
                "suspicious",
                0
            )
        }

    def calculate_maliciousness_confidence(
        self,
        virustotal_result
    ):
        """
        Convert VirusTotal analysis results into
        a 0-100 maliciousness confidence score.

        This score is intentionally separate from:

        - infrastructure confidence
        - brand impersonation confidence
        """

        if not virustotal_result:
            return 0

        if not virustotal_result.get(
            "available",
            False
        ):
            return 0

        if not virustotal_result.get(
            "found",
            False
        ):
            return 0

        malicious_count = virustotal_result.get(
            "malicious_count",
            0
        )

        suspicious_count = virustotal_result.get(
            "suspicious_count",
            0
        )

        analysis_stats = virustotal_result.get(
            "analysis_stats",
            {}
        )

        total_engines = sum(
            analysis_stats.get(
                key,
                0
            )
            for key in [
                "harmless",
                "malicious",
                "suspicious",
                "undetected",
                "timeout"
            ]
        )

        if total_engines <= 0:
            return 0

        # Malicious detections carry the highest weight.
        malicious_score = (
            malicious_count
            / total_engines
        ) * 100

        # Suspicious detections carry half the weight.
        suspicious_score = (
            suspicious_count
            / total_engines
        ) * 50

        confidence = (
            malicious_score
            + suspicious_score
        )

        return round(
            min(confidence, 100),
            2
        )