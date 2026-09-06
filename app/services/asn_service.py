import requests


class ASNService:

    API_URL = "https://ipinfo.io/{ip}/json"

    def __init__(self, timeout=5):
        self.timeout = timeout

    def lookup(self, ip):
        try:
            response = requests.get(
                self.API_URL.format(ip=ip),
                timeout=self.timeout
            )

            response.raise_for_status()

            data = response.json()

            return {
                "ip": ip,
                "asn": data.get("org", "").split(" ")[0] if data.get("org") else None,
                "organization": data.get("org"),
                "country": data.get("country"),
                "region": data.get("region"),
                "city": data.get("city"),
                "hostname": data.get("hostname")
            }

        except Exception:
            return {
                "ip": ip,
                "asn": None,
                "organization": None,
                "country": None,
                "region": None,
                "city": None,
                "hostname": None,
                "error": "ASN lookup failed"
            }

    def lookup_many(self, ips):
        return [self.lookup(ip) for ip in ips]