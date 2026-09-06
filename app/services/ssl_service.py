import socket
import ssl
from datetime import datetime


class SSLService:

    def __init__(self, timeout=10):
        self.timeout = timeout

    def investigate(self, domain):
        try:
            context = ssl.create_default_context()

            with socket.create_connection(
                (domain, 443),
                timeout=self.timeout
            ) as sock:

                with context.wrap_socket(
                    sock,
                    server_hostname=domain
                ) as secure_socket:

                    certificate = secure_socket.getpeercert()
                    certificate_der = secure_socket.getpeercert(
                        binary_form=True
                    )

                    return {
                        "domain": domain,
                        "subject": self._extract_subject(
                            certificate
                        ),
                        "issuer": self._extract_issuer(
                            certificate
                        ),
                        "san": self._extract_san(
                            certificate
                        ),
                        "serial_number": certificate.get(
                            "serialNumber"
                        ),
                        "version": certificate.get(
                            "version"
                        ),
                        "valid_from": certificate.get(
                            "notBefore"
                        ),
                        "valid_to": certificate.get(
                            "notAfter"
                        ),
                        "fingerprint_sha256": (
                            self._calculate_fingerprint(
                                certificate_der
                            )
                        ),
                    }

        except Exception as exc:
            return {
                "domain": domain,
                "subject": None,
                "issuer": None,
                "san": [],
                "serial_number": None,
                "version": None,
                "valid_from": None,
                "valid_to": None,
                "fingerprint_sha256": None,
                "error": str(exc)
            }

    def _extract_subject(self, certificate):
        subject = {}

        for attribute_group in certificate.get(
            "subject", []
        ):
            for key, value in attribute_group:
                subject[key] = value

        return subject

    def _extract_issuer(self, certificate):
        issuer = {}

        for attribute_group in certificate.get(
            "issuer", []
        ):
            for key, value in attribute_group:
                issuer[key] = value

        return issuer

    def _extract_san(self, certificate):
        san = []

        for entry_type, value in certificate.get(
            "subjectAltName", []
        ):
            if entry_type == "DNS":
                san.append(value.lower())

        return san

    def _calculate_fingerprint(self, certificate_der):
        import hashlib

        return hashlib.sha256(
            certificate_der
        ).hexdigest()