import dns.resolver
import requests
import concurrent.futures
from typing import Dict, Any, List, Set
from core.base_module import BaseModule
from config.settings import config


class SubdomainEnumerator(BaseModule):
    """Subdomain enumeration using multiple techniques."""

    def __init__(self):
        super().__init__("Subdomain Enumerator")
        self.found_subdomains: Set[str] = set()

    def _dns_bruteforce(self, domain: str, wordlist: List[str]) -> Set[str]:
        """Brute force subdomains using DNS queries."""
        found = set()

        def check_subdomain(word):
            subdomain = f"{word}.{domain}"
            try:
                answers = dns.resolver.resolve(subdomain, 'A')
                ips = [str(rdata) for rdata in answers]
                self.logger.info(f"  ✅ Found: {subdomain} -> {', '.join(ips)}")
                return subdomain, ips
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                return None, None

        with concurrent.futures.ThreadPoolExecutor(max_workers=config.MAX_THREADS) as executor:
            futures = {executor.submit(check_subdomain, word): word for word in wordlist}
            for future in concurrent.futures.as_completed(futures):
                subdomain, ips = future.result()
                if subdomain:
                    found.add(subdomain)

        return found

    def _crtsh_enum(self, domain: str) -> Set[str]:
        """Enumerate subdomains using crt.sh certificate transparency."""
        found = set()
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=config.DEFAULT_TIMEOUT)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(domain) and '*' not in sub:
                            found.add(sub)
                self.logger.info(f"  📜 crt.sh found {len(found)} subdomains")
        except Exception as e:
            self.logger.warning(f"  crt.sh lookup failed: {e}")
        return found

    def _securitytrails_enum(self, domain: str) -> Set[str]:
        """Enumerate using SecurityTrails (free tier)."""
        found = set()
        try:
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            headers = {"APIKEY": config.SHODAN_API_KEY or ""}
            if headers["APIKEY"]:
                response = requests.get(url, headers=headers, timeout=config.DEFAULT_TIMEOUT)
                if response.status_code == 200:
                    data = response.json()
                    for sub in data.get('subdomains', []):
                        found.add(f"{sub}.{domain}")
        except Exception as e:
            self.logger.debug(f"SecurityTrails lookup failed: {e}")
        return found

    def _hackertarget_enum(self, domain: str) -> Set[str]:
        """Enumerate using HackerTarget API."""
        found = set()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            response = requests.get(url, timeout=config.DEFAULT_TIMEOUT)
            if response.status_code == 200 and "error" not in response.text.lower():
                for line in response.text.splitlines():
                    parts = line.split(',')
                    if len(parts) >= 1:
                        found.add(parts[0].strip())
                self.logger.info(f"  🎯 HackerTarget found {len(found)} subdomains")
        except Exception as e:
            self.logger.debug(f"HackerTarget lookup failed: {e}")
        return found

    def _load_wordlist(self, wordlist_path: str = None) -> List[str]:
        """Load subdomain wordlist."""
        if wordlist_path and Path(wordlist_path).exists():
            with open(wordlist_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]

        # Default common subdomains
        return [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop',
            'ns1', 'ns2', 'dns', 'dns1', 'dns2', 'api', 'dev', 'staging',
            'test', 'portal', 'admin', 'blog', 'shop', 'forum', 'app',
            'mobile', 'cms', 'cdn', 'cloud', 'git', 'gitlab', 'jenkins',
            'jira', 'confluence', 'vpn', 'remote', 'secure', 'login',
            'dashboard', 'status', 'monitor', 'grafana', 'kibana',
            'elastic', 'redis', 'db', 'database', 'mysql', 'postgres',
            'mongo', 'backup', 'old', 'new', 'beta', 'alpha', 'demo',
            'docs', 'help', 'support', 'ticket', 'mx', 'mx1', 'mx2',
            'email', 'exchange', 'office', 'intranet', 'internal',
            'proxy', 'gateway', 'firewall', 'sso', 'auth', 'oauth',
            'static', 'assets', 'media', 'images', 'img', 'files',
            'download', 'upload', 'storage', 's3', 'aws', 'azure',
        ]

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run subdomain enumeration."""
        domain = target.replace('http://', '').replace('https://', '').strip('/')
        wordlist_path = kwargs.get('wordlist', None)
        methods = kwargs.get('methods', ['crtsh', 'hackertarget', 'dns'])

        all_subdomains = set()

        # Certificate Transparency
        if 'crtsh' in methods:
            self.logger.info("📜 Querying Certificate Transparency logs...")
            all_subdomains.update(self._crtsh_enum(domain))

        # HackerTarget
        if 'hackertarget' in methods:
            self.logger.info("🎯 Querying HackerTarget...")
            all_subdomains.update(self._hackertarget_enum(domain))

        # DNS Brute Force
        if 'dns' in methods:
            wordlist = self._load_wordlist(wordlist_path)
            self.logger.info(f"🔨 DNS brute forcing with {len(wordlist)} words...")
            all_subdomains.update(self._dns_bruteforce(domain, wordlist))

        self.found_subdomains = all_subdomains

        return {
            'domain': domain,
            'subdomains': sorted(list(all_subdomains)),
            'total_found': len(all_subdomains),
            'methods_used': methods
        }