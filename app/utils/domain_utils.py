import re
from urllib.parse import urlparse


def normalize_domain(value: str) -> str:
    """
    Normalize a domain or URL into a lowercase domain name.

    Examples:
        https://www.Example.com/login -> example.com
        hxxps://Example.com:443        -> example.com
        www.example.com               -> example.com
    """

    if not value:
        return ""

    value = value.strip().lower()

    # Convert hxxp/hxxps commonly used in threat intelligence
    value = value.replace("hxxps://", "https://")
    value = value.replace("hxxp://", "http://")

    # If the value does not contain a scheme,
    # add one so urlparse can process it correctly.
    if not re.match(r"^[a-z][a-z0-9+.-]*://", value):
        value = "http://" + value

    parsed = urlparse(value)

    domain = parsed.hostname

    if not domain:
        return ""

    # Remove trailing dot
    domain = domain.rstrip(".")

    # Remove www.
    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def is_valid_domain(domain: str) -> bool:
    """
    Basic domain validation.
    """

    if not domain:
        return False

    if len(domain) > 253:
        return False

    # Prevent IP addresses from being treated as domains
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain):
        return False

    pattern = (
        r"^(?=.{1,253}$)"
        r"(?:[a-z0-9]"
        r"(?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z]{2,63}$"
    )

    return bool(re.fullmatch(pattern, domain, re.IGNORECASE))


def is_ip_address(value: str) -> bool:
    """
    Determine whether the supplied value is an IPv4 address.
    """

    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    if not re.fullmatch(pattern, value.strip()):
        return False

    try:
        octets = value.split(".")
        return all(0 <= int(octet) <= 255 for octet in octets)
    except ValueError:
        return False