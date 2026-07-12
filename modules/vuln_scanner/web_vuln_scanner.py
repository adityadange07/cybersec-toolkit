import requests
import re
import urllib.parse
from typing import Dict, Any, List
from bs4 import BeautifulSoup
from core.base_module import BaseModule
from config.settings import config


class WebVulnScanner(BaseModule):
    """Comprehensive web vulnerability scanner."""

    def __init__(self):
        super().__init__("Web Vulnerability Scanner")
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': config.USER_AGENT})
        self.vulnerabilities = []

    def _check_security_headers(self, url: str) -> Dict:
        """Check for security headers."""
        important_headers = {
            'Strict-Transport-Security': 'HSTS - Prevents downgrade attacks',
            'Content-Security-Policy': 'CSP - Prevents XSS and injection attacks',
            'X-Content-Type-Options': 'Prevents MIME-type sniffing',
            'X-Frame-Options': 'Prevents clickjacking',
            'X-XSS-Protection': 'XSS filter (legacy)',
            'Referrer-Policy': 'Controls referrer information',
            'Permissions-Policy': 'Controls browser features',
            'X-Permitted-Cross-Domain-Policies': 'Controls Flash/PDF cross-domain',
            'Cross-Origin-Embedder-Policy': 'COEP',
            'Cross-Origin-Opener-Policy': 'COOP',
            'Cross-Origin-Resource-Policy': 'CORP',
        }

        try:
            response = self.session.get(url, timeout=config.DEFAULT_TIMEOUT, verify=True)
            headers = response.headers
            results = {'present': {}, 'missing': {}, 'info_leak': {}}

            for header, description in important_headers.items():
                if header.lower() in {k.lower(): k for k in headers}:
                    actual_key = next(k for k in headers if k.lower() == header.lower())
                    results['present'][header] = {
                        'value': headers[actual_key],
                        'description': description
                    }
                else:
                    results['missing'][header] = description
                    self.vulnerabilities.append({
                        'type': 'Missing Security Header',
                        'severity': 'Medium',
                        'detail': f'Missing {header}: {description}',
                        'url': url
                    })

            # Check for information leaking headers
            leak_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version',
                          'X-AspNetMvc-Version', 'X-Generator']
            for header in leak_headers:
                if header in headers:
                    results['info_leak'][header] = headers[header]
                    self.vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'severity': 'Low',
                        'detail': f'{header}: {headers[header]}',
                        'url': url
                    })

            return results
        except Exception as e:
            return {'error': str(e)}

    def _check_ssl_tls(self, url: str) -> Dict:
        """Check SSL/TLS configuration."""
        import ssl
        import socket
        from urllib.parse import urlparse

        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)

        if parsed.scheme != 'https':
            return {'warning': 'Site not using HTTPS', 'severity': 'High'}

        results = {}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    results = {
                        'version': ssock.version(),
                        'cipher': ssock.cipher(),
                        'cert_subject': dict(x[0] for x in cert['subject']),
                        'cert_issuer': dict(x[0] for x in cert['issuer']),
                        'cert_expires': cert['notAfter'],
                        'cert_serial': cert['serialNumber'],
                        'san': cert.get('subjectAltName', []),
                    }

            # Check for weak protocols
            weak_protocols = [ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_TLSv1_1]
            # This is simplified - production should use sslyze
            results['weak_protocol_check'] = 'Requires manual verification with sslyze/testssl'

        except ssl.SSLError as e:
            results['ssl_error'] = str(e)
            self.vulnerabilities.append({
                'type': 'SSL/TLS Issue',
                'severity': 'High',
                'detail': str(e),
                'url': url
            })
        except Exception as e:
            results['error'] = str(e)

        return results

    def _crawl_forms(self, url: str) -> List[Dict]:
        """Crawl and extract forms from target."""
        forms = []
        try:
            response = self.session.get(url, timeout=config.DEFAULT_TIMEOUT)
            soup = BeautifulSoup(response.text, 'html.parser')

            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').upper(),
                    'inputs': []
                }

                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    form_data['inputs'].append({
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', ''),
                        'id': input_tag.get('id', '')
                    })

                forms.append(form_data)

        except Exception as e:
            self.logger.warning(f"Form crawling error: {e}")

        return forms

    def _check_cors(self, url: str) -> Dict:
        """Check CORS misconfiguration."""
        results = {}
        try:
            # Test with arbitrary origin
            headers = {'Origin': 'https://evil-attacker.com'}
            response = self.session.get(url, headers=headers, timeout=config.DEFAULT_TIMEOUT)

            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')

            if acao == '*':
                results['vulnerability'] = 'Wildcard CORS - Any origin allowed'
                results['severity'] = 'Medium'
            elif acao == 'https://evil-attacker.com':
                results['vulnerability'] = 'CORS reflects arbitrary origin!'
                results['severity'] = 'High'
                if acac.lower() == 'true':
                    results['severity'] = 'Critical'
                    results['vulnerability'] += ' WITH credentials!'

            results['access_control_allow_origin'] = acao
            results['access_control_allow_credentials'] = acac

            if results.get('vulnerability'):
                self.vulnerabilities.append({
                    'type': 'CORS Misconfiguration',
                    'severity': results['severity'],
                    'detail': results['vulnerability'],
                    'url': url
                })

        except Exception as e:
            results['error'] = str(e)

        return results

    def _check_cookies(self, url: str) -> List[Dict]:
        """Analyze cookie security."""
        cookie_issues = []
        try:
            response = self.session.get(url, timeout=config.DEFAULT_TIMEOUT)
            for cookie in response.cookies:
                issues = []
                if not cookie.secure:
                    issues.append('Missing Secure flag')
                if 'httponly' not in str(cookie._rest).lower():
                    issues.append('Missing HttpOnly flag')
                if not cookie.has_nonstandard_attr('SameSite'):
                    issues.append('Missing SameSite attribute')

                if issues:
                    cookie_info = {
                        'name': cookie.name,
                        'issues': issues,
                        'domain': cookie.domain,
                        'path': cookie.path,
                        'secure': cookie.secure
                    }
                    cookie_issues.append(cookie_info)
                    for issue in issues:
                        self.vulnerabilities.append({
                            'type': 'Insecure Cookie',
                            'severity': 'Medium',
                            'detail': f"Cookie '{cookie.name}': {issue}",
                            'url': url
                        })
        except Exception as e:
            self.logger.warning(f"Cookie analysis error: {e}")

        return cookie_issues

    def _check_directory_listing(self, url: str) -> Dict:
        """Check for directory listing vulnerabilities."""
        common_dirs = [
            '/admin/', '/backup/', '/config/', '/uploads/', '/images/',
            '/tmp/', '/logs/', '/data/', '/includes/', '/.git/',
            '/.svn/', '/.env', '/wp-admin/', '/phpmyadmin/',
            '/server-status', '/server-info', '/.htaccess',
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
            '/.well-known/', '/api/', '/swagger/', '/graphql'
        ]

        results = {'exposed': [], 'sensitive_files': []}

        for directory in common_dirs:
            try:
                test_url = urllib.parse.urljoin(url, directory)
                response = self.session.get(
                    test_url,
                    timeout=5,
                    allow_redirects=False
                )
                if response.status_code == 200:
                    if 'index of' in response.text.lower() or 'directory listing' in response.text.lower():
                        results['exposed'].append({
                            'path': directory,
                            'type': 'Directory Listing',
                            'status': response.status_code
                        })
                        self.vulnerabilities.append({
                            'type': 'Directory Listing',
                            'severity': 'Medium',
                            'detail': f'Directory listing enabled at {directory}',
                            'url': test_url
                        })
                    elif directory in ['/.env', '/.git/', '/.htaccess']:
                        results['sensitive_files'].append({
                            'path': directory,
                            'type': 'Sensitive File Exposure',
                            'status': response.status_code
                        })
                        self.vulnerabilities.append({
                            'type': 'Sensitive File Exposure',
                            'severity': 'High',
                            'detail': f'Sensitive file accessible at {directory}',
                            'url': test_url
                        })
            except:
                continue

        return results

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run comprehensive web vulnerability scan."""
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"

        self.logger.info(f"🌐 Starting web vulnerability scan on {target}")
        self.vulnerabilities = []

        results = {
            'target': target,
            'security_headers': {},
            'ssl_tls': {},
            'cors': {},
            'cookies': [],
            'forms': [],
            'directories': {},
            'vulnerabilities': []
        }

        # Security Headers
        self.logger.info("📋 Checking security headers...")
        results['security_headers'] = self._check_security_headers(target)

        # SSL/TLS
        self.logger.info("🔐 Checking SSL/TLS configuration...")
        results['ssl_tls'] = self._check_ssl_tls(target)

        # CORS
        self.logger.info("🌍 Checking CORS configuration...")
        results['cors'] = self._check_cors(target)

        # Cookies
        self.logger.info("🍪 Analyzing cookies...")
        results['cookies'] = self._check_cookies(target)

        # Forms
        self.logger.info("📝 Crawling forms...")
        results['forms'] = self._crawl_forms(target)

        # Directory Listing
        self.logger.info("📁 Checking directory exposure...")
        results['directories'] = self._check_directory_listing(target)

        results['vulnerabilities'] = self.vulnerabilities
        results['summary'] = {
            'total_vulnerabilities': len(self.vulnerabilities),
            'critical': len([v for v in self.vulnerabilities if v['severity'] == 'Critical']),
            'high': len([v for v in self.vulnerabilities if v['severity'] == 'High']),
            'medium': len([v for v in self.vulnerabilities if v['severity'] == 'Medium']),
            'low': len([v for v in self.vulnerabilities if v['severity'] == 'Low']),
        }

        return results