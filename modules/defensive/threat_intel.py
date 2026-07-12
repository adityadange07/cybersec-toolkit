import requests
import json
import re
import os
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from core.base_module import BaseModule
from config.settings import config


class ThreatIntel(BaseModule):
    """
    Threat intelligence aggregator.
    Queries multiple free/API-key-based threat intel sources.
    """

    def __init__(self):
        super().__init__("Threat Intel")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config.USER_AGENT,
        })

    # ──────────────────────────────────────────────────────────────────────────
    # IP reputation
    # ──────────────────────────────────────────────────────────────────────────

    def check_abuseipdb(self, ip: str) -> Dict:
        """Check IP against AbuseIPDB (requires ABUSEIPDB_API_KEY env var)."""
        api_key = os.getenv('ABUSEIPDB_API_KEY', '')
        if not api_key:
            return {'error': 'ABUSEIPDB_API_KEY env var not set'}

        try:
            resp = self.session.get(
                'https://api.abuseipdb.com/api/v2/check',
                params={'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': True},
                headers={'Key': api_key, 'Accept': 'application/json'},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json().get('data', {})
                return {
                    'ip':               data.get('ipAddress'),
                    'abuse_score':      data.get('abuseConfidenceScore', 0),
                    'country':          data.get('countryCode'),
                    'isp':              data.get('isp'),
                    'domain':           data.get('domain'),
                    'total_reports':    data.get('totalReports', 0),
                    'last_reported':    data.get('lastReportedAt'),
                    'is_whitelisted':   data.get('isWhitelisted', False),
                    'usage_type':       data.get('usageType'),
                    'link':             f'https://www.abuseipdb.com/check/{ip}',
                    'malicious':        data.get('abuseConfidenceScore', 0) > 50,
                }
            return {'error': f'HTTP {resp.status_code}'}
        except Exception as exc:
            return {'error': str(exc)}

    def check_shodan_ip(self, ip: str) -> Dict:
        """Look up IP info on Shodan (requires SHODAN_API_KEY env var)."""
        if not config.SHODAN_API_KEY:
            return {'error': 'SHODAN_API_KEY env var not set'}

        try:
            resp = self.session.get(
                f'https://api.shodan.io/shodan/host/{ip}',
                params={'key': config.SHODAN_API_KEY},
                timeout=20,
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    'ip':           data.get('ip_str'),
                    'org':          data.get('org'),
                    'isp':          data.get('isp'),
                    'country':      data.get('country_name'),
                    'city':         data.get('city'),
                    'os':           data.get('os'),
                    'ports':        data.get('ports', []),
                    'tags':         data.get('tags', []),
                    'vulns':        list(data.get('vulns', {}).keys()),
                    'hostnames':    data.get('hostnames', []),
                    'last_update':  data.get('last_update'),
                    'link':         f'https://www.shodan.io/host/{ip}',
                }
            elif resp.status_code == 404:
                return {'found': False, 'message': 'No data for this IP on Shodan'}
            return {'error': f'HTTP {resp.status_code}'}
        except Exception as exc:
            return {'error': str(exc)}

    def check_threatfox_ip(self, ip: str) -> Dict:
        """Check IP against ThreatFox (no API key needed)."""
        try:
            resp = requests.post(
                'https://threatfox-api.abuse.ch/api/v1/',
                json={'query': 'search_ioc', 'search_term': ip},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get('query_status') == 'ok':
                    iocs = data.get('data', [])
                    return {
                        'found':        True,
                        'total':        len(iocs),
                        'iocs':         iocs[:10],
                        'malware_tags': list({i.get('malware') for i in iocs if i.get('malware')}),
                    }
                return {'found': False}
        except Exception as exc:
            return {'error': str(exc)}

    # ──────────────────────────────────────────────────────────────────────────
    # Domain / URL
    # ──────────────────────────────────────────────────────────────────────────

    def check_urlvoid(self, domain: str) -> Dict:
        """Check domain reputation on URLVoid-like free sources."""
        results = {}

        # Google Safe Browsing via VirusTotal URL lookup
        vt_key = config.VIRUSTOTAL_API_KEY
        if vt_key:
            try:
                import base64
                url_id = base64.urlsafe_b64encode(
                    f'http://{domain}/'.encode()
                ).decode().strip('=')
                resp = self.session.get(
                    f'https://www.virustotal.com/api/v3/urls/{url_id}',
                    headers={'x-apikey': vt_key},
                    timeout=20,
                )
                if resp.status_code == 200:
                    stats = resp.json()['data']['attributes']['last_analysis_stats']
                    results['virustotal'] = {
                        'malicious': stats.get('malicious', 0),
                        'phishing':  stats.get('phishing', 0),
                        'clean':     stats.get('harmless', 0),
                    }
            except Exception as exc:
                results['virustotal_error'] = str(exc)

        # ThreatFox domain lookup
        tf = self.check_threatfox_ip(domain)
        results['threatfox'] = tf

        return results

    def check_phishtank(self, url: str) -> Dict:
        """Check URL against PhishTank database."""
        try:
            resp = requests.post(
                'https://checkurl.phishtank.com/checkurl/',
                data={
                    'url':    url,
                    'format': 'json',
                },
                headers={'User-Agent': 'phishtank/python'},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json().get('results', {})
                return {
                    'is_phishing': data.get('in_database', False) and
                                   data.get('verified', False),
                    'in_database': data.get('in_database', False),
                    'verified':    data.get('verified', False),
                    'phish_id':    data.get('phish_id', ''),
                    'phish_detail_url': data.get('phish_detail_url', ''),
                }
        except Exception as exc:
            return {'error': str(exc)}

    # ──────────────────────────────────────────────────────────────────────────
    # Hash lookup
    # ──────────────────────────────────────────────────────────────────────────

    def check_malwarebazaar(self, file_hash: str) -> Dict:
        """Check hash on MalwareBazaar."""
        try:
            resp = requests.post(
                'https://mb-api.abuse.ch/api/v1/',
                data={'query': 'get_info', 'hash': file_hash},
                timeout=20,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get('query_status') == 'ok':
                    entry = data['data'][0]
                    return {
                        'found':       True,
                        'file_name':   entry.get('file_name'),
                        'file_type':   entry.get('file_type'),
                        'signature':   entry.get('signature'),
                        'tags':        entry.get('tags', []),
                        'first_seen':  entry.get('first_seen'),
                        'reporter':    entry.get('reporter'),
                        'link':        f"https://bazaar.abuse.ch/sample/{file_hash}/",
                    }
                return {'found': False}
        except Exception as exc:
            return {'error': str(exc)}

    def check_virustotal_hash(self, file_hash: str) -> Dict:
        """Check hash on VirusTotal."""
        if not config.VIRUSTOTAL_API_KEY:
            return {'error': 'VIRUSTOTAL_API_KEY not set'}
        try:
            resp = self.session.get(
                f'https://www.virustotal.com/api/v3/files/{file_hash}',
                headers={'x-apikey': config.VIRUSTOTAL_API_KEY},
                timeout=30,
            )
            if resp.status_code == 200:
                attr  = resp.json()['data']['attributes']
                stats = attr.get('last_analysis_stats', {})
                total = sum(stats.values())
                return {
                    'found':           True,
                    'malicious':       stats.get('malicious', 0),
                    'suspicious':      stats.get('suspicious', 0),
                    'harmless':        stats.get('harmless', 0),
                    'undetected':      stats.get('undetected', 0),
                    'detection_ratio': f"{stats.get('malicious', 0)}/{total}",
                    'name':            attr.get('meaningful_name', ''),
                    'type':            attr.get('type_description', ''),
                    'link':            f'https://www.virustotal.com/gui/file/{file_hash}',
                }
            elif resp.status_code == 404:
                return {'found': False}
            return {'error': f'HTTP {resp.status_code}'}
        except Exception as exc:
            return {'error': str(exc)}

    # ──────────────────────────────────────────────────────────────────────────
    # CVE lookup
    # ──────────────────────────────────────────────────────────────────────────

    def lookup_cve(self, cve_id: str) -> Dict:
        """Look up CVE details from NVD API."""
        cve_id = cve_id.upper().strip()
        if not re.match(r'^CVE-\d{4}-\d+$', cve_id):
            return {'error': f'Invalid CVE format: {cve_id}. Expected CVE-YYYY-NNNNN'}

        try:
            resp = requests.get(
                f'https://services.nvd.nist.gov/rest/json/cves/2.0',
                params={'cveId': cve_id},
                timeout=30,
            )
            if resp.status_code == 200:
                data  = resp.json()
                items = data.get('vulnerabilities', [])
                if not items:
                    return {'found': False}

                cve   = items[0]['cve']
                desc  = next(
                    (d['value'] for d in cve.get('descriptions', []) if d['lang'] == 'en'),
                    'No description'
                )
                # CVSS score
                metrics = cve.get('metrics', {})
                cvss_v3 = metrics.get('cvssMetricV31', metrics.get('cvssMetricV30', []))
                score   = None
                if cvss_v3:
                    score = cvss_v3[0].get('cvssData', {}).get('baseScore')

                return {
                    'cve_id':       cve_id,
                    'found':        True,
                    'description':  desc,
                    'cvss_score':   score,
                    'severity':     (
                        'Critical' if score and score >= 9.0 else
                        'High'     if score and score >= 7.0 else
                        'Medium'   if score and score >= 4.0 else
                        'Low'
                    ),
                    'published':    cve.get('published'),
                    'modified':     cve.get('lastModified'),
                    'references':   [r['url'] for r in cve.get('references', [])[:5]],
                    'link':         f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                }
            return {'error': f'HTTP {resp.status_code}'}
        except Exception as exc:
            return {'error': str(exc)}

    # ──────────────────────────────────────────────────────────────────────────
    # Bulk IOC scan
    # ──────────────────────────────────────────────────────────────────────────

    def bulk_ioc_check(self, iocs: List[Dict]) -> List[Dict]:
        """
        Check a list of IOCs.
        Each IOC is a dict: {'type': 'ip'|'domain'|'hash'|'url'|'cve', 'value': '...'}
        """
        results = []
        for ioc in iocs:
            ioc_type  = ioc.get('type', '').lower()
            ioc_value = ioc.get('value', '').strip()
            result    = {'type': ioc_type, 'value': ioc_value}

            self.logger.info(f"  🔍 Checking {ioc_type}: {ioc_value}")

            if ioc_type == 'ip':
                result['abuseipdb']  = self.check_abuseipdb(ioc_value)
                result['threatfox']  = self.check_threatfox_ip(ioc_value)
            elif ioc_type in ('domain', 'url'):
                result['url_check']  = self.check_urlvoid(ioc_value)
            elif ioc_type == 'hash':
                result['virustotal'] = self.check_virustotal_hash(ioc_value)
                result['malwarebazaar'] = self.check_malwarebazaar(ioc_value)
            elif ioc_type == 'cve':
                result['nvd']        = self.lookup_cve(ioc_value)

            results.append(result)
            time.sleep(0.5)  # Rate limiting

        return results

    # ──────────────────────────────────────────────────────────────────────────
    # run()
    # ──────────────────────────────────────────────────────────────────────────

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        target  : IP / domain / hash / CVE-ID / path to IOC list JSON
        kwargs:
            ioc_type : 'ip' | 'domain' | 'hash' | 'url' | 'cve' | 'bulk'
        """
        ioc_type = kwargs.get('ioc_type', 'ip')

        self.logger.info(f"🌐 Threat Intel — type: {ioc_type} → {target}")
        results: Dict[str, Any] = {
            'target':    target,
            'ioc_type':  ioc_type,
            'timestamp': datetime.now().isoformat(),
        }

        if ioc_type == 'ip':
            results['abuseipdb']  = self.check_abuseipdb(target)
            results['shodan']     = self.check_shodan_ip(target)
            results['threatfox']  = self.check_threatfox_ip(target)

        elif ioc_type == 'domain':
            results['url_check']  = self.check_urlvoid(target)
            results['threatfox']  = self.check_threatfox_ip(target)

        elif ioc_type == 'url':
            results['phishtank']  = self.check_phishtank(target)
            results['url_check']  = self.check_urlvoid(target)

        elif ioc_type == 'hash':
            results['virustotal']    = self.check_virustotal_hash(target)
            results['malwarebazaar'] = self.check_malwarebazaar(target)

        elif ioc_type == 'cve':
            results['cve'] = self.lookup_cve(target)

        elif ioc_type == 'bulk':
            # target is a path to a JSON file with IOC list
            if not os.path.exists(target):
                return {'error': f'IOC file not found: {target}'}
            with open(target, 'r') as f:
                iocs = json.load(f)
            results['bulk_results'] = self.bulk_ioc_check(iocs)

        else:
            results['error'] = f'Unknown ioc_type: {ioc_type}'

        return results