import ssl
import socket
import datetime
import requests
from typing import Dict, Any, List
from core.base_module import BaseModule
from config.settings import config


class SSLChecker(BaseModule):
    """Comprehensive SSL/TLS configuration checker."""

    WEAK_CIPHERS = [
        "RC4", "DES", "3DES", "MD5", "EXPORT", "NULL",
        "ANON", "aNULL", "eNULL", "LOW", "EXP",
    ]
    WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]

    def __init__(self):
        super().__init__("SSL Checker")

    # ── Certificate info ──────────────────────────────────────────────────────
    def _get_cert_info(self, hostname: str, port: int = 443) -> Dict:
        ctx  = ssl.create_default_context()
        info = {}
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert   = ssock.getpeercert()
                    cipher = ssock.cipher()
                    info = {
                        "subject":    dict(x[0] for x in cert.get("subject", [])),
                        "issuer":     dict(x[0] for x in cert.get("issuer", [])),
                        "version":    cert.get("version"),
                        "serial":     cert.get("serialNumber"),
                        "not_before": cert.get("notBefore"),
                        "not_after":  cert.get("notAfter"),
                        "san":        [v for _, v in cert.get("subjectAltName", [])],
                        "tls_version": ssock.version(),
                        "cipher_name": cipher[0],
                        "cipher_bits": cipher[2],
                        "protocol":    cipher[1],
                    }

                    # Expiry check
                    exp = datetime.datetime.strptime(
                        cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                    )
                    days_left = (exp - datetime.datetime.utcnow()).days
                    info["days_until_expiry"] = days_left
                    info["expired"]           = days_left < 0
                    info["expiring_soon"]     = 0 <= days_left <= 30

        except ssl.SSLCertVerificationError as e:
            info["cert_error"]     = str(e)
            info["self_signed"]    = "self signed" in str(e).lower()
            info["hostname_mismatch"] = "hostname" in str(e).lower()
        except Exception as e:
            info["error"] = str(e)
        return info

    # ── Protocol support ──────────────────────────────────────────────────────
    def _check_protocol(self, hostname: str, port: int,
                        protocol_const) -> bool:
        try:
            ctx = ssl.SSLContext(protocol_const)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    return True
        except Exception:
            return False

    def _check_weak_protocols(self, hostname: str, port: int) -> List[Dict]:
        issues = []
        # TLS 1.0
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.maximum_version = ssl.TLSVersion.TLSv1
            with socket.create_connection((hostname, port), timeout=5) as s:
                with ctx.wrap_socket(s, server_hostname=hostname):
                    issues.append({
                        "protocol": "TLS 1.0",
                        "severity": "High",
                        "detail":   "TLS 1.0 is deprecated (RFC 8996)",
                    })
        except Exception:
            pass

        # TLS 1.1
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            with socket.create_connection((hostname, port), timeout=5) as s:
                with ctx.wrap_socket(s, server_hostname=hostname):
                    issues.append({
                        "protocol": "TLS 1.1",
                        "severity": "Medium",
                        "detail":   "TLS 1.1 is deprecated (RFC 8996)",
                    })
        except Exception:
            pass

        return issues

    # ── HSTS check ────────────────────────────────────────────────────────────
    def _check_hsts(self, hostname: str) -> Dict:
        try:
            resp  = requests.get(
                f"https://{hostname}", timeout=10,
                headers={"User-Agent": config.USER_AGENT}, verify=False
            )
            hsts  = resp.headers.get("Strict-Transport-Security", "")
            if not hsts:
                return {"enabled": False, "severity": "High",
                        "detail": "HSTS header missing"}
            max_age = 0
            m = re.search(r"max-age=(\d+)", hsts)
            if m:
                max_age = int(m.group(1))
            return {
                "enabled":         True,
                "header":          hsts,
                "max_age_seconds": max_age,
                "includes_sub":    "includeSubDomains" in hsts,
                "preload":         "preload" in hsts,
                "max_age_ok":      max_age >= 31536000,
            }
        except Exception as e:
            return {"error": str(e)}

    # ── Certificate transparency ──────────────────────────────────────────────
    def _check_ct(self, hostname: str) -> Dict:
        try:
            url  = f"https://crt.sh/?q={hostname}&output=json"
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                entries = resp.json()
                return {
                    "ct_entries": len(entries),
                    "recent":     entries[:5] if entries else [],
                }
        except Exception as e:
            return {"error": str(e)}
        return {}

    # ── Main ──────────────────────────────────────────────────────────────────
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        import re
        from urllib.parse import urlparse

        parsed   = urlparse(target if "://" in target else f"https://{target}")
        hostname = parsed.hostname or target
        port     = parsed.port or 443

        self.logger.info(f"🔐 SSL/TLS check on {hostname}:{port}")

        results: Dict[str, Any] = {
            "target":   hostname,
            "port":     port,
            "issues":   [],
        }

        # Cert info
        self.logger.info("  📜 Fetching certificate...")
        results["certificate"] = self._get_cert_info(hostname, port)
        cert = results["certificate"]

        # Flag cert problems
        if cert.get("expired"):
            results["issues"].append({
                "type": "Expired Certificate", "severity": "Critical",
                "detail": f"Certificate expired {abs(cert['days_until_expiry'])} days ago",
            })
        if cert.get("expiring_soon"):
            results["issues"].append({
                "type": "Certificate Expiring Soon", "severity": "High",
                "detail": f"Certificate expires in {cert['days_until_expiry']} days",
            })
        if cert.get("self_signed"):
            results["issues"].append({
                "type": "Self-Signed Certificate", "severity": "High",
                "detail": "Certificate is self-signed — not trusted by browsers",
            })

        # Weak protocol check
        self.logger.info("  🔒 Checking protocol support...")
        weak = self._check_weak_protocols(hostname, port)
        results["weak_protocols"] = weak
        results["issues"].extend(weak)

        # Weak cipher check (basic — recommend sslyze for full audit)
        cipher = cert.get("cipher_name", "")
        for wc in self.WEAK_CIPHERS:
            if wc.lower() in cipher.lower():
                results["issues"].append({
                    "type": "Weak Cipher Suite", "severity": "High",
                    "detail": f"Weak cipher in use: {cipher}",
                })
                break

        # HSTS
        self.logger.info("  🛡️  Checking HSTS...")
        results["hsts"] = self._check_hsts(hostname)
        if not results["hsts"].get("enabled"):
            results["issues"].append({
                "type": "Missing HSTS", "severity": "High",
                "detail": "HTTP Strict Transport Security not configured",
            })

        # Certificate Transparency
        self.logger.info("  📋 Certificate Transparency logs...")
        results["cert_transparency"] = self._check_ct(hostname)

        results["summary"] = {
            "total_issues":    len(results["issues"]),
            "critical":        sum(1 for i in results["issues"] if i.get("severity") == "Critical"),
            "high":            sum(1 for i in results["issues"] if i.get("severity") == "High"),
            "tls_version":     cert.get("tls_version", "Unknown"),
            "days_to_expiry":  cert.get("days_until_expiry", "N/A"),
            "grade":           "F" if results["issues"] else "A",
        }

        return results