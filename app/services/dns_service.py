import dns.resolver


class DNSService:

    def __init__(self, timeout=5):
        self.timeout = timeout

    def _resolve(self, domain, record_type):
        try:
            answers = dns.resolver.resolve(
                domain,
                record_type,
                lifetime=self.timeout
            )

            return [str(answer).rstrip(".") for answer in answers]

        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.resolver.Timeout
        ):
            return []

        except Exception:
            return []

    def get_a_records(self, domain):
        return self._resolve(domain, "A")

    def get_aaaa_records(self, domain):
        return self._resolve(domain, "AAAA")

    def get_cname_records(self, domain):
        return self._resolve(domain, "CNAME")

    def get_mx_records(self, domain):
        return self._resolve(domain, "MX")

    def get_nameservers(self, domain):
        return self._resolve(domain, "NS")

    def investigate(self, domain):
        return {
            "domain": domain,
            "a_records": self.get_a_records(domain),
            "aaaa_records": self.get_aaaa_records(domain),
            "cname_records": self.get_cname_records(domain),
            "mx_records": self.get_mx_records(domain),
            "nameservers": self.get_nameservers(domain)
        }