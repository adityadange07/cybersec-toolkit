import dns.resolver
import dns.zone
import dns.query
from typing import Dict, Any, List
from core.base_module import BaseModule


class DNSEnumerator(BaseModule):
    """Comprehensive DNS enumeration."""

    RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'PTR', 'CAA']

    def __init__(self):
        super().__init__("DNS Enumerator")

    def _query_records(self, domain: str, record_type: str) -> List[str]:
        """Query DNS records of a specific type."""
        records = []
        try:
            answers = dns.resolver.resolve(domain, record_type)
            for rdata in answers:
                records.append(str(rdata))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        except Exception as e:
            self.logger.debug(f"Error querying {record_type} for {domain}: {e}")
        return records

    def _attempt_zone_transfer(self, domain: str) -> Dict:
        """Attempt DNS zone transfer (AXFR)."""
        zone_data = {}
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            for ns in ns_records:
                ns_host = str(ns).rstrip('.')
                try:
                    self.logger.info(f"  🔄 Attempting zone transfer from {ns_host}...")
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=10))
                    zone_data[ns_host] = {
                        'status': 'SUCCESS - Zone Transfer Allowed!',
                        'records': []
                    }
                    for name, node in zone.nodes.items():
                        rdatasets = node.rdatasets
                        for rdataset in rdatasets:
                            zone_data[ns_host]['records'].append({
                                'name': str(name),
                                'type': dns.rdatatype.to_text(rdataset.rdtype),
                                'data': str(rdataset)
                            })
                    self.logger.warning(f"  ⚠️  Zone transfer SUCCESSFUL from {ns_host}!")
                except Exception:
                    zone_data[ns_host] = {'status': 'Transfer denied (secure)'}
        except Exception as e:
            self.logger.debug(f"NS lookup failed: {e}")
        return zone_data

    def _check_dnssec(self, domain: str) -> Dict:
        """Check DNSSEC configuration."""
        try:
            answers = dns.resolver.resolve(domain, 'DNSKEY')
            return {
                'enabled': True,
                'keys': [str(rdata) for rdata in answers]
            }
        except:
            return {'enabled': False, 'keys': []}

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run DNS enumeration."""
        domain = target.replace('http://', '').replace('https://', '').strip('/')

        results = {
            'domain': domain,
            'records': {},
            'zone_transfer': {},
            'dnssec': {}
        }

        # Query all record types
        self.logger.info(f"🔍 Enumerating DNS records for {domain}")
        for record_type in self.RECORD_TYPES:
            records = self._query_records(domain, record_type)
            if records:
                results['records'][record_type] = records
                self.logger.info(f"  📋 {record_type}: {', '.join(records[:3])}"
                               f"{'...' if len(records) > 3 else ''}")

        # Zone Transfer
        self.logger.info("🔄 Checking zone transfer...")
        results['zone_transfer'] = self._attempt_zone_transfer(domain)

        # DNSSEC
        self.logger.info("🔐 Checking DNSSEC...")
        results['dnssec'] = self._check_dnssec(domain)

        return results