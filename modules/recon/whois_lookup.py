import whois
import requests
from typing import Dict, Any
from core.base_module import BaseModule


class WhoisLookup(BaseModule):
    """WHOIS information gathering."""

    def __init__(self):
        super().__init__("WHOIS Lookup")

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        domain = target.replace('http://', '').replace('https://', '').strip('/')

        try:
            w = whois.whois(domain)
            results = {
                'domain': domain,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'updated_date': str(w.updated_date),
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails,
                'org': w.org,
                'country': w.country,
                'state': w.state,
                'registrant': w.get('registrant_name', 'N/A'),
                'dnssec': w.dnssec,
                'raw': w.text
            }

            for key, value in results.items():
                if key != 'raw' and value:
                    self.logger.info(f"  📋 {key}: {value}")

            return results
        except Exception as e:
            return {"error": str(e)}