import requests


class RDAPService:

    BOOTSTRAP_URL = "https://rdap.org/domain/{domain}"

    def __init__(self, timeout=10):
        self.timeout = timeout

    def investigate(self, domain):
        try:
            response = requests.get(
                self.BOOTSTRAP_URL.format(domain=domain),
                timeout=self.timeout,
                headers={
                    "Accept": "application/rdap+json",
                    "User-Agent": "Domain-Investigation-Engine/1.0"
                }
            )

            response.raise_for_status()

            data = response.json()

            return {
                "domain": domain,
                "registrar": self._extract_registrar(data),
                "registration_date": self._extract_event(
                    data, "registration"
                ),
                "expiration_date": self._extract_event(
                    data, "expiration"
                ),
                "updated_date": self._extract_event(
                    data, "last changed"
                ),
                "status": data.get("status", []),
                "nameservers": self._extract_nameservers(data),
                "registrant": self._extract_registrant(data),
            }

        except Exception as exc:
            return {
                "domain": domain,
                "registrar": None,
                "registration_date": None,
                "expiration_date": None,
                "updated_date": None,
                "status": [],
                "nameservers": [],
                "registrant": None,
                "error": str(exc)
            }

    def _extract_registrar(self, data):
        for entity in data.get("entities", []):

            if "registrar" not in entity.get("roles", []):
                continue

            vcard = entity.get("vcardArray", [])

            if len(vcard) < 2:
                continue

            for item in vcard[1]:
                if len(item) >= 4 and item[0] == "fn":
                    return item[3]

        return None

    def _extract_event(self, data, event_name):
        for event in data.get("events", []):
            if event.get("eventAction") == event_name:
                return event.get("eventDate")

        return None

    def _extract_nameservers(self, data):
        nameservers = []

        for nameserver in data.get("nameservers", []):
            hostname = nameserver.get("ldhName")

            if hostname:
                nameservers.append(hostname.lower())

        return nameservers

    def _extract_registrant(self, data):
        for entity in data.get("entities", []):

            if "registrant" not in entity.get("roles", []):
                continue

            vcard = entity.get("vcardArray", [])

            if len(vcard) < 2:
                continue

            registrant = {}

            for item in vcard[1]:

                if len(item) < 4:
                    continue

                field = item[0]
                value = item[3]

                if field == "fn":
                    registrant["name"] = value

                elif field == "org":
                    registrant["organization"] = value

                elif field == "email":
                    registrant["email"] = value

            return registrant

        return None