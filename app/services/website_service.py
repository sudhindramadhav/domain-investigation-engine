import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


class WebsiteService:

    def __init__(self, timeout=10):
        self.timeout = timeout

    def investigate(self, domain):
        result = {
            "domain": domain,
            "url": None,
            "final_url": None,
            "status_code": None,
            "title": None,
            "meta_description": None,
            "text": "",
            "links": [],
            "images": [],
            "forms": [],
            "error": None
        }

        try:
            url = self._build_url(domain)

            if not url:
                result["error"] = "Invalid domain"
                return result

            result["url"] = url

            # SSRF protection
            if self._resolves_to_private_ip(domain):
                result["error"] = (
                    "Blocked request to private or reserved IP"
                )
                return result

            response = requests.get(
                url,
                timeout=self.timeout,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 "
                        "(compatible; DomainInvestigationEngine/1.0)"
                    )
                },
                allow_redirects=True
            )

            # Validate the final redirect destination too.
            final_hostname = urlparse(
                response.url
            ).hostname

            if final_hostname and self._resolves_to_private_ip(
                final_hostname
            ):
                result["error"] = (
                    "Blocked redirect to private or reserved IP"
                )
                return result

            result["final_url"] = response.url
            result["status_code"] = response.status_code

            content_type = response.headers.get(
                "Content-Type",
                ""
            ).lower()

            if "text/html" not in content_type:
                result["error"] = (
                    "Response is not HTML"
                )
                return result

            soup = BeautifulSoup(
                response.text,
                "html.parser"
            )

            result["title"] = (
                soup.title.get_text(
                    strip=True
                )
                if soup.title
                else None
            )

            meta_description = soup.find(
                "meta",
                attrs={"name": "description"}
            )

            if meta_description:
                result["meta_description"] = (
                    meta_description.get(
                        "content"
                    )
                )

            result["text"] = self._extract_text(
                soup
            )

            result["links"] = self._extract_links(
                soup,
                response.url
            )

            result["images"] = self._extract_images(
                soup,
                response.url
            )

            result["forms"] = self._extract_forms(
                soup
            )

            return result

        except requests.RequestException as exc:
            result["error"] = str(exc)
            return result

        except Exception as exc:
            result["error"] = str(exc)
            return result

    def _build_url(self, domain):
        domain = domain.strip()

        if not domain:
            return None

        if domain.startswith("http://"):
            return domain

        if domain.startswith("https://"):
            return domain

        return "https://" + domain

    def _resolves_to_private_ip(self, hostname):
        try:
            addresses = socket.getaddrinfo(
                hostname,
                None
            )

            for address in addresses:
                ip = address[4][0]

                parsed_ip = ipaddress.ip_address(
                    ip
                )

                if (
                    parsed_ip.is_private
                    or parsed_ip.is_loopback
                    or parsed_ip.is_link_local
                    or parsed_ip.is_reserved
                    or parsed_ip.is_multicast
                    or parsed_ip.is_unspecified
                ):
                    return True

            return False

        except Exception:
            return False

    def _extract_text(self, soup):
        for element in soup(
            ["script", "style", "noscript"]
        ):
            element.decompose()

        text = soup.get_text(
            separator=" ",
            strip=True
        )

        # Keep the response manageable.
        return text[:10000]

    def _extract_links(self, soup, base_url):
        links = []

        for anchor in soup.find_all(
            "a",
            href=True
        ):
            href = anchor.get("href")

            if not href:
                continue

            absolute_url = urljoin(
                base_url,
                href
            )

            links.append({
                "text": anchor.get_text(
                    " ",
                    strip=True
                ),
                "url": absolute_url
            })

        return links[:200]

    def _extract_images(self, soup, base_url):
        images = []

        for image in soup.find_all(
            "img"
        ):
            src = image.get("src")

            if not src:
                continue

            images.append({
                "src": urljoin(
                    base_url,
                    src
                ),
                "alt": image.get(
                    "alt",
                    ""
                ),
                "title": image.get(
                    "title",
                    ""
                )
            })

        return images[:100]

    def _extract_forms(self, soup):
        forms = []

        for form in soup.find_all(
            "form"
        ):
            inputs = []

            for field in form.find_all(
                "input"
            ):
                inputs.append({
                    "type": field.get(
                        "type",
                        "text"
                    ).lower(),
                    "name": field.get(
                        "name"
                    ),
                    "placeholder": field.get(
                        "placeholder"
                    )
                })

            forms.append({
                "action": form.get(
                    "action"
                ),
                "method": form.get(
                    "method",
                    "get"
                ).lower(),
                "inputs": inputs
            })

        return forms[:50]