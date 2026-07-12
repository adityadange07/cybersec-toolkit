import re
import requests
from typing import Dict, Any, List
from bs4 import BeautifulSoup
from core.base_module import BaseModule
from config.settings import config


# Signature database
TECH_SIGNATURES = {
    # ── Web Frameworks ────────────────────────────────────────────────────────
    "WordPress": {
        "headers": [],
        "html":    [r"wp-content", r"wp-includes", r"/wp-json/"],
        "cookies": ["wordpress_", "wp-settings-"],
        "meta":    [],
    },
    "Joomla": {
        "headers": [],
        "html":    [r"/components/com_", r"Joomla!"],
        "cookies": [],
        "meta":    [r"generator.*Joomla"],
    },
    "Drupal": {
        "headers": ["X-Generator: Drupal"],
        "html":    [r"sites/default/files", r"Drupal\.settings"],
        "cookies": ["SESS"],
        "meta":    [r"generator.*Drupal"],
    },
    "Django": {
        "headers": [],
        "html":    [r"csrfmiddlewaretoken"],
        "cookies": ["csrftoken", "sessionid"],
        "meta":    [],
    },
    "Laravel": {
        "headers": [],
        "html":    [],
        "cookies": ["laravel_session", "XSRF-TOKEN"],
        "meta":    [],
    },
    "React": {
        "headers": [],
        "html":    [r"__REACT_DEVTOOLS", r"react-root", r"data-reactroot"],
        "cookies": [],
        "meta":    [],
    },
    "Angular": {
        "headers": [],
        "html":    [r"ng-version", r"ng-app", r"\[routerLink\]"],
        "cookies": [],
        "meta":    [],
    },
    "Vue.js": {
        "headers": [],
        "html":    [r"__vue__", r"v-cloak", r"data-v-"],
        "cookies": [],
        "meta":    [],
    },
    # ── Web Servers ───────────────────────────────────────────────────────────
    "Nginx": {
        "headers": ["Server: nginx"],
        "html":    [],
        "cookies": [],
        "meta":    [],
    },
    "Apache": {
        "headers": ["Server: Apache"],
        "html":    [],
        "cookies": [],
        "meta":    [],
    },
    "IIS": {
        "headers": ["Server: Microsoft-IIS", "X-Powered-By: ASP.NET"],
        "html":    [],
        "cookies": ["ASP.NET_SessionId"],
        "meta":    [],
    },
    # ── Languages ─────────────────────────────────────────────────────────────
    "PHP": {
        "headers": ["X-Powered-By: PHP"],
        "html":    [r"\.php"],
        "cookies": ["PHPSESSID"],
        "meta":    [],
    },
    "Ruby on Rails": {
        "headers": ["X-Powered-By: Phusion Passenger"],
        "html":    [],
        "cookies": ["_session_id"],
        "meta":    [],
    },
    # ── CDN / WAF ─────────────────────────────────────────────────────────────
    "Cloudflare": {
        "headers": ["Server: cloudflare", "CF-RAY"],
        "html":    [],
        "cookies": ["__cfduid", "cf_clearance"],
        "meta":    [],
    },
    "AWS CloudFront": {
        "headers": ["X-Amz-Cf-Id", "Via: CloudFront"],
        "html":    [],
        "cookies": [],
        "meta":    [],
    },
    # ── Analytics ─────────────────────────────────────────────────────────────
    "Google Analytics": {
        "headers": [],
        "html":    [r"google-analytics\.com/analytics\.js",
                    r"gtag\(", r"UA-\d{4,}-\d"],
        "cookies": ["_ga", "_gid"],
        "meta":    [],
    },
    # ── JS Libraries ─────────────────────────────────────────────────────────
    "jQuery": {
        "headers": [],
        "html":    [r"jquery[\./]", r"jquery\.min\.js"],
        "cookies": [],
        "meta":    [],
    },
    "Bootstrap": {
        "headers": [],
        "html":    [r"bootstrap\.min\.(js|css)", r"bootstrap\.bundle"],
        "cookies": [],
        "meta":    [],
    },
}


class TechDetector(BaseModule):
    """Fingerprint technologies used by a web application."""

    def __init__(self):
        super().__init__("Tech Detector")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.USER_AGENT})

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _fetch(self, url: str) -> requests.Response | None:
        try:
            return self.session.get(url, timeout=config.DEFAULT_TIMEOUT, verify=False)
        except Exception as e:
            self.logger.warning(f"Fetch error: {e}")
            return None

    def _check_signature(self, tech: str, sig: Dict,
                          headers: Dict, html: str, cookies: List[str]) -> bool:
        # Headers
        for h in sig.get("headers", []):
            key, _, val = h.partition(":")
            if key.strip().lower() in {k.lower() for k in headers}:
                if not val or val.strip().lower() in headers.get(key.strip(), "").lower():
                    return True

        # HTML patterns
        for pattern in sig.get("html", []):
            if re.search(pattern, html, re.IGNORECASE):
                return True

        # Cookies
        for cookie in sig.get("cookies", []):
            if any(cookie.lower() in c.lower() for c in cookies):
                return True

        # Meta tags
        for pattern in sig.get("meta", []):
            if re.search(pattern, html, re.IGNORECASE):
                return True

        return False

    # ── JS file analysis ──────────────────────────────────────────────────────
    def _detect_js_libs(self, html: str) -> List[Dict]:
        """Extract JS library versions from script src attributes."""
        libs = []
        soup = BeautifulSoup(html, "html.parser")
        version_patterns = [
            (r"jquery[/-](\d+\.\d+\.\d+)", "jQuery"),
            (r"bootstrap[/-](\d+\.\d+\.\d+)", "Bootstrap"),
            (r"react[/-](\d+\.\d+\.\d+)", "React"),
            (r"angular[/-](\d+\.\d+\.\d+)", "Angular"),
            (r"vue[/-](\d+\.\d+\.\d+)", "Vue.js"),
            (r"lodash[/-](\d+\.\d+\.\d+)", "Lodash"),
            (r"moment[/-](\d+\.\d+\.\d+)", "Moment.js"),
        ]
        for tag in soup.find_all("script", src=True):
            src = tag["src"]
            for pattern, lib_name in version_patterns:
                m = re.search(pattern, src, re.IGNORECASE)
                if m:
                    libs.append({"library": lib_name, "version": m.group(1), "src": src})
        return libs

    # ── SSL / HTTPS info ──────────────────────────────────────────────────────
    def _get_ssl_info(self, hostname: str, port: int = 443) -> Dict:
        import ssl, socket
        info = {}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    info = {
                        "tls_version": ssock.version(),
                        "cipher":      ssock.cipher()[0],
                        "issuer":      dict(x[0] for x in cert.get("issuer", [])),
                        "expires":     cert.get("notAfter"),
                    }
        except Exception as e:
            info["error"] = str(e)
        return info

    # ── robots.txt / sitemap ──────────────────────────────────────────────────
    def _fetch_robots(self, base_url: str) -> str:
        resp = self._fetch(f"{base_url.rstrip('/')}/robots.txt")
        if resp and resp.status_code == 200:
            return resp.text[:2000]
        return ""

    # ── Main ──────────────────────────────────────────────────────────────────
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        self.logger.info(f"🔍 Fingerprinting technologies on {target}")

        resp = self._fetch(target)
        if resp is None:
            return {"error": "Failed to reach target"}

        headers  = dict(resp.headers)
        html     = resp.text
        cookies  = [c.name for c in resp.cookies]

        detected: List[Dict] = []
        for tech, sig in TECH_SIGNATURES.items():
            if self._check_signature(tech, sig, headers, html, cookies):
                detected.append({"technology": tech})
                self.logger.info(f"  ✅ {tech}")

        # JS library versions
        js_libs = self._detect_js_libs(html)

        # Meta tags
        soup  = BeautifulSoup(html, "html.parser")
        metas = {}
        for tag in soup.find_all("meta"):
            name    = tag.get("name") or tag.get("property") or ""
            content = tag.get("content") or ""
            if name:
                metas[name] = content

        # Server header
        server  = headers.get("Server", headers.get("server", "Unknown"))
        powered = headers.get("X-Powered-By", "")

        # SSL
        from urllib.parse import urlparse
        parsed   = urlparse(target)
        ssl_info = {}
        if parsed.scheme == "https":
            ssl_info = self._get_ssl_info(parsed.hostname)

        # Robots
        robots = self._fetch_robots(target)

        results = {
            "target":          target,
            "server":          server,
            "x_powered_by":    powered,
            "detected_tech":   detected,
            "js_libraries":    js_libs,
            "meta_tags":       metas,
            "ssl_info":        ssl_info,
            "robots_txt":      robots,
            "response_headers": headers,
            "total_detected":  len(detected) + len(js_libs),
        }
        self.logger.info(f"  📊 {results['total_detected']} technologies detected")
        return results