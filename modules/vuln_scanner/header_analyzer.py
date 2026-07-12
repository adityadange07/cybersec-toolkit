import requests
from typing import Dict, Any, List
from core.base_module import BaseModule
from config.settings import config


# Full header security policy database
HEADER_POLICY = {
    "Strict-Transport-Security": {
        "required":    True,
        "severity":    "High",
        "description": "Prevents protocol downgrade attacks and cookie hijacking.",
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "validators":  [
            ("max-age", "Must include max-age directive"),
            ("31536000", "max-age should be at least 1 year"),
        ],
    },
    "Content-Security-Policy": {
        "required":    True,
        "severity":    "High",
        "description": "Prevents XSS and data injection attacks.",
        "recommended": "default-src 'self'; script-src 'self'; object-src 'none'",
        "validators":  [],
    },
    "X-Content-Type-Options": {
        "required":    True,
        "severity":    "Medium",
        "description": "Prevents MIME-type sniffing.",
        "recommended": "nosniff",
        "validators":  [("nosniff", "Value must be 'nosniff'")],
    },
    "X-Frame-Options": {
        "required":    True,
        "severity":    "Medium",
        "description": "Prevents clickjacking attacks.",
        "recommended": "DENY",
        "validators":  [],
    },
    "Referrer-Policy": {
        "required":    True,
        "severity":    "Low",
        "description": "Controls referrer information leakage.",
        "recommended": "strict-origin-when-cross-origin",
        "validators":  [],
    },
    "Permissions-Policy": {
        "required":    True,
        "severity":    "Low",
        "description": "Controls browser feature access.",
        "recommended": "geolocation=(), microphone=(), camera=()",
        "validators":  [],
    },
    "Cross-Origin-Embedder-Policy": {
        "required":    False,
        "severity":    "Low",
        "description": "Controls cross-origin embedding.",
        "recommended": "require-corp",
        "validators":  [],
    },
    "Cross-Origin-Opener-Policy": {
        "required":    False,
        "severity":    "Low",
        "description": "Controls cross-origin opener relationships.",
        "recommended": "same-origin",
        "validators":  [],
    },
    "Cross-Origin-Resource-Policy": {
        "required":    False,
        "severity":    "Low",
        "description": "Controls cross-origin resource sharing.",
        "recommended": "same-origin",
        "validators":  [],
    },
    "Cache-Control": {
        "required":    False,
        "severity":    "Low",
        "description": "Controls caching behaviour.",
        "recommended": "no-store, max-age=0",
        "validators":  [],
    },
}

# Headers that should NOT be present (information leakage)
LEAK_HEADERS = {
    "Server":                "Reveals server software version",
    "X-Powered-By":          "Reveals backend technology",
    "X-AspNet-Version":      "Reveals ASP.NET version",
    "X-AspNetMvc-Version":   "Reveals ASP.NET MVC version",
    "X-Generator":           "Reveals CMS or generator",
    "X-Drupal-Cache":        "Reveals Drupal CMS",
    "X-Varnish":             "Reveals Varnish cache",
    "Via":                   "Can reveal internal proxies",
}

# CSP directive checks
UNSAFE_CSP = [
    ("unsafe-inline", "High",   "Allows inline scripts — negates XSS protection"),
    ("unsafe-eval",   "High",   "Allows eval() — dangerous for XSS"),
    ("*",             "Medium", "Wildcard source — overly permissive"),
    ("http:",         "Medium", "Allows loading from plain HTTP"),
    ("data:",         "Medium", "Allows data: URIs — can enable XSS"),
]


class HeaderAnalyzer(BaseModule):
    """Analyse HTTP response headers for security misconfigurations."""

    def __init__(self):
        super().__init__("Header Analyzer")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.USER_AGENT})

    def _fetch_headers(self, url: str) -> Dict[str, str]:
        resp = self.session.get(
            url, timeout=config.DEFAULT_TIMEOUT, verify=False, allow_redirects=True
        )
        return dict(resp.headers)

    def _normalise(self, headers: Dict) -> Dict:
        """Case-insensitive header lookup dict."""
        return {k.lower(): v for k, v in headers.items()}

    # ── Security headers ──────────────────────────────────────────────────────
    def _check_security_headers(self, headers: Dict) -> Dict:
        norm    = self._normalise(headers)
        present = {}
        missing = {}
        issues  = []

        for header, policy in HEADER_POLICY.items():
            key = header.lower()
            if key in norm:
                value = norm[key]
                present[header] = value
                # Validate value
                for expected, msg in policy.get("validators", []):
                    if expected.lower() not in value.lower():
                        issues.append({
                            "header":   header,
                            "value":    value,
                            "issue":    msg,
                            "severity": "Medium",
                        })
            else:
                if policy["required"]:
                    missing[header] = policy
                    issues.append({
                        "header":      header,
                        "issue":       f"Missing security header: {header}",
                        "severity":    policy["severity"],
                        "recommended": policy["recommended"],
                        "description": policy["description"],
                    })

        return {"present": present, "missing": missing, "issues": issues}

    # ── Information leakage ───────────────────────────────────────────────────
    def _check_info_leakage(self, headers: Dict) -> List[Dict]:
        norm   = self._normalise(headers)
        leaks  = []
        for header, reason in LEAK_HEADERS.items():
            if header.lower() in norm:
                leaks.append({
                    "header":   header,
                    "value":    norm[header.lower()],
                    "reason":   reason,
                    "severity": "Low",
                })
                self.logger.info(f"  ⚠️  Info leak: {header}: {norm[header.lower()]}")
        return leaks

    # ── CSP analysis ──────────────────────────────────────────────────────────
    def _analyze_csp(self, csp_value: str) -> Dict:
        if not csp_value:
            return {"present": False}

        issues = []
        for directive, severity, description in UNSAFE_CSP:
            if directive in csp_value:
                issues.append({
                    "directive":   directive,
                    "severity":    severity,
                    "description": description,
                })

        # Parse directives
        directives = {}
        for part in csp_value.split(";"):
            part = part.strip()
            if part:
                tokens = part.split()
                if tokens:
                    directives[tokens[0]] = tokens[1:]

        return {
            "present":     True,
            "value":       csp_value,
            "directives":  directives,
            "issues":      issues,
            "has_default": "default-src" in directives,
            "has_script":  "script-src" in directives,
            "has_object":  "object-src" in directives,
        }

    # ── CORS ─────────────────────────────────────────────────────────────────
    def _check_cors_headers(self, headers: Dict) -> Dict:
        norm  = self._normalise(headers)
        acao  = norm.get("access-control-allow-origin", "")
        acac  = norm.get("access-control-allow-credentials", "")
        acam  = norm.get("access-control-allow-methods", "")
        issues = []

        if acao == "*":
            issues.append({
                "issue":    "Wildcard CORS origin",
                "severity": "Medium",
                "detail":   "Any origin can make requests",
            })
        if acao == "*" and acac.lower() == "true":
            issues.append({
                "issue":    "Wildcard CORS with credentials",
                "severity": "Critical",
                "detail":   "Credentials allowed from any origin",
            })
        if "DELETE" in acam or "PUT" in acam:
            issues.append({
                "issue":    "Dangerous CORS methods allowed",
                "severity": "Medium",
                "detail":   f"Methods: {acam}",
            })

        return {
            "allow_origin":      acao,
            "allow_credentials": acac,
            "allow_methods":     acam,
            "issues":            issues,
        }

    # ── Cookie security ───────────────────────────────────────────────────────
    def _check_cookie_headers(self, raw_headers: Dict) -> List[Dict]:
        issues = []
        for key, value in raw_headers.items():
            if key.lower() == "set-cookie":
                cookie_issues = []
                if "secure" not in value.lower():
                    cookie_issues.append("Missing Secure flag")
                if "httponly" not in value.lower():
                    cookie_issues.append("Missing HttpOnly flag")
                if "samesite" not in value.lower():
                    cookie_issues.append("Missing SameSite attribute")
                if cookie_issues:
                    issues.append({
                        "cookie":   value.split("=")[0],
                        "issues":   cookie_issues,
                        "severity": "Medium",
                    })
        return issues

    # ── Grade calculation ─────────────────────────────────────────────────────
    def _calculate_grade(self, all_issues: List[Dict]) -> str:
        critical = sum(1 for i in all_issues if i.get("severity") == "Critical")
        high     = sum(1 for i in all_issues if i.get("severity") == "High")
        medium   = sum(1 for i in all_issues if i.get("severity") == "Medium")

        if critical > 0:            return "F"
        if high > 2:                return "D"
        if high > 0 or medium > 3:  return "C"
        if medium > 0:              return "B"
        return "A"

    # ── Main ──────────────────────────────────────────────────────────────────
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        self.logger.info(f"🔍 Analyzing HTTP headers for {target}")

        headers = self._fetch_headers(target)

        sec    = self._check_security_headers(headers)
        leaks  = self._check_info_leakage(headers)
        csp    = self._analyze_csp(headers.get("Content-Security-Policy", ""))
        cors   = self._check_cors_headers(headers)
        cookies = self._check_cookie_headers(headers)

        all_issues = (
            sec["issues"]
            + [{"severity": l["severity"], "issue": l["reason"]} for l in leaks]
            + [{"severity": i["severity"], "issue": i["issue"]} for i in cors["issues"]]
            + [{"severity": c["severity"], "issue": ", ".join(c["issues"])} for c in cookies]
        )

        grade = self._calculate_grade(all_issues)
        self.logger.info(f"  🏆 Security Grade: {grade}")

        return {
            "target":             target,
            "security_headers":   sec,
            "information_leakage": leaks,
            "csp_analysis":       csp,
            "cors":               cors,
            "cookie_issues":      cookies,
            "all_issues":         all_issues,
            "raw_headers":        headers,
            "grade":              grade,
            "summary": {
                "total_issues":   len(all_issues),
                "missing_headers": len(sec["missing"]),
                "info_leaks":     len(leaks),
                "grade":          grade,
            },
        }