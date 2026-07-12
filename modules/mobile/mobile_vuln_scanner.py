import requests
import re
from typing import Dict, Any, List
from core.base_module import BaseModule
from config.settings import config


class MobileVulnScanner(BaseModule):
    """
    Mobile application vulnerability scanner.

    Covers:
        - API endpoint security
        - Authentication weaknesses
        - Insecure data transmission
        - Improper certificate validation
        - Exported components (via APK metadata)
    """

    def __init__(self):
        super().__init__("Mobile Vulnerability Scanner")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.USER_AGENT})

    # ── API security ──────────────────────────────────────────────────────────
    def _test_api_auth(self, base_url: str, endpoints: List[str]) -> List[Dict]:
        findings = []
        for ep in endpoints:
            url = base_url.rstrip("/") + ep
            try:
                # No auth
                r = self.session.get(url, timeout=config.DEFAULT_TIMEOUT, verify=False)
                if r.status_code == 200:
                    findings.append({
                        "type":     "Missing Authentication",
                        "endpoint": url,
                        "status":   r.status_code,
                        "severity": "Critical",
                        "detail":   "Endpoint accessible without authentication",
                    })
                    self.logger.warning(f"  🚨 No-auth access: {url}")

                # Broken object level auth — try ID manipulation
                if re.search(r"/\d+", ep):
                    for alt_id in ["0", "99999", "-1", "../../etc"]:
                        test_url = re.sub(r"/\d+", f"/{alt_id}", url)
                        r2 = self.session.get(test_url, timeout=5, verify=False)
                        if r2.status_code == 200:
                            findings.append({
                                "type":     "Broken Object Level Authorization (BOLA/IDOR)",
                                "endpoint": test_url,
                                "severity": "Critical",
                                "detail":   f"Resource accessible with ID={alt_id}",
                            })

            except Exception as e:
                self.logger.debug(f"Endpoint test error {url}: {e}")
        return findings

    # ── JWT checks ────────────────────────────────────────────────────────────
    def _check_jwt(self, token: str) -> List[Dict]:
        issues = []
        parts = token.split(".")
        if len(parts) != 3:
            return [{"issue": "Not a valid JWT format", "severity": "Info"}]
        import base64, json

        def b64_decode(s):
            s += "=" * (-len(s) % 4)
            return base64.urlsafe_b64decode(s)

        try:
            header  = json.loads(b64_decode(parts[0]))
            payload = json.loads(b64_decode(parts[1]))

            if header.get("alg") == "none":
                issues.append({"issue": "JWT alg=none — signature bypass possible",
                                "severity": "Critical"})
            if header.get("alg", "").startswith("HS"):
                issues.append({"issue": "Symmetric JWT (HS256/HS384) — secret key risk",
                                "severity": "Medium"})
            if "exp" not in payload:
                issues.append({"issue": "JWT has no expiry (exp claim missing)",
                                "severity": "High"})
        except Exception as e:
            issues.append({"issue": f"JWT decode error: {e}", "severity": "Info"})
        return issues

    # ── SSL pinning bypass check (informational) ──────────────────────────────
    def _check_ssl_pinning(self, apk_metadata: Dict = None) -> Dict:
        """
        Heuristic: look for certificate pinning patterns in APK metadata.
        Real bypass requires Frida/objection at runtime.
        """
        indicators = {
            "CertificatePinner":    "OkHttp CertificatePinner",
            "TrustManagerImpl":     "Custom TrustManager",
            "ssl_pinning":          "Generic SSL pinning reference",
            "PublicKeyPin":         "Public key pinning",
            "network_security_config": "Android Network Security Config",
        }
        found = []
        if apk_metadata:
            source_str = str(apk_metadata)
            for key, description in indicators.items():
                if key.lower() in source_str.lower():
                    found.append({"indicator": key, "description": description})

        return {
            "pinning_indicators": found,
            "pinning_detected":   len(found) > 0,
            "bypass_tools":       ["frida", "objection", "apk-mitm"] if found else [],
        }

    # ── Insecure storage checks ───────────────────────────────────────────────
    def _check_insecure_storage_patterns(self, strings_list: List[str]) -> List[Dict]:
        patterns = {
            "SharedPreferences":   "Data stored in SharedPreferences (may be world-readable)",
            "getExternalStorage":  "Data written to external storage",
            "MODE_WORLD_READABLE": "File opened in world-readable mode",
            "MODE_WORLD_WRITABLE": "File opened in world-writable mode",
            "openFileOutput":      "File output — check storage location",
        }
        issues = []
        for pattern, description in patterns.items():
            if any(pattern in s for s in strings_list):
                issues.append({
                    "pattern":     pattern,
                    "description": description,
                    "severity":    "High" if "WORLD" in pattern else "Medium",
                })
        return issues

    # ── Main ──────────────────────────────────────────────────────────────────
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        target  : base API URL  (e.g. https://api.app.com)
        kwargs  :
            endpoints     = list of API paths to test
            jwt           = JWT token to analyse
            apk_metadata  = dict from APKAnalyzer (optional)
            strings       = list of strings extracted from APK (optional)
        """
        endpoints    = kwargs.get("endpoints", [
            "/api/v1/users", "/api/v1/user/1", "/api/v1/admin",
            "/api/v1/config", "/api/user/profile",
            "/api/v1/token/refresh", "/api/logout",
        ])
        jwt          = kwargs.get("jwt", "")
        apk_metadata = kwargs.get("apk_metadata", {})
        strings      = kwargs.get("strings", [])

        results: Dict[str, Any] = {"target": target}

        # API auth
        self.logger.info("  🔑 Testing API authentication...")
        results["api_auth_issues"] = self._test_api_auth(target, endpoints)

        # JWT
        if jwt:
            self.logger.info("  🎫 Analysing JWT token...")
            results["jwt_issues"] = self._check_jwt(jwt)

        # SSL pinning
        self.logger.info("  📌 Checking SSL pinning indicators...")
        results["ssl_pinning"] = self._check_ssl_pinning(apk_metadata)

        # Insecure storage
        if strings:
            self.logger.info("  💾 Checking insecure storage patterns...")
            results["insecure_storage"] = self._check_insecure_storage_patterns(strings)

        all_issues = results["api_auth_issues"] + results.get("jwt_issues", [])
        results["summary"] = {
            "total_issues": len(all_issues),
            "critical": sum(1 for i in all_issues if i.get("severity") == "Critical"),
            "high":     sum(1 for i in all_issues if i.get("severity") == "High"),
        }
        return results