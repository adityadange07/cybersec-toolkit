import requests
import re
import json
from typing import Dict, Any, List
from core.base_module import BaseModule
from config.settings import config


class OSINTCollector(BaseModule):
    """
    Open-Source Intelligence (OSINT) gathering.

    Sources used (all public / free-tier):
        - HaveIBeenPwned  (email breach lookup)
        - Hunter.io       (email finder)
        - Shodan          (host info, needs API key)
        - GitHub          (user/org search)
        - URLScan.io      (passive URL scan)
        - FullHunt        (attack surface)
        - Pastebin        (paste search via Google dork simulation)
    """

    def __init__(self):
        super().__init__("OSINT Collector")
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": config.USER_AGENT,
            "Accept":     "application/json",
        })

    # ── Email breach lookup ───────────────────────────────────────────────────
    def _hibp_lookup(self, email: str) -> Dict:
        """Check HaveIBeenPwned for breaches."""
        try:
            url  = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            hdrs = {
                "hibp-api-key": config.HIBP_API_KEY if hasattr(config, "HIBP_API_KEY") else "",
                "User-Agent":   config.USER_AGENT,
            }
            resp = self.session.get(url, headers=hdrs, timeout=10)
            if resp.status_code == 200:
                breaches = resp.json()
                return {
                    "breached":      True,
                    "breach_count":  len(breaches),
                    "breaches":      [
                        {
                            "name":         b.get("Name"),
                            "domain":       b.get("Domain"),
                            "breach_date":  b.get("BreachDate"),
                            "pwn_count":    b.get("PwnCount"),
                            "data_classes": b.get("DataClasses"),
                        }
                        for b in breaches
                    ],
                }
            elif resp.status_code == 404:
                return {"breached": False}
            else:
                return {"error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    # ── Email finder ─────────────────────────────────────────────────────────
    def _hunter_email_finder(self, domain: str) -> Dict:
        """Find emails for a domain via Hunter.io."""
        if not config.HUNTER_API_KEY:
            return {"note": "Set HUNTER_API_KEY env var"}
        try:
            url    = "https://api.hunter.io/v2/domain-search"
            params = {"domain": domain, "api_key": config.HUNTER_API_KEY, "limit": 20}
            resp   = self.session.get(url, params=params, timeout=10)
            if resp.status_code == 200:
                data   = resp.json().get("data", {})
                emails = data.get("emails", [])
                return {
                    "domain":       domain,
                    "organization": data.get("organization"),
                    "email_count":  len(emails),
                    "emails":       [
                        {
                            "value":      e.get("value"),
                            "type":       e.get("type"),
                            "confidence": e.get("confidence"),
                            "first_name": e.get("first_name"),
                            "last_name":  e.get("last_name"),
                            "position":   e.get("position"),
                        }
                        for e in emails
                    ],
                }
            return {"error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    # ── Shodan ────────────────────────────────────────────────────────────────
    def _shodan_lookup(self, query: str) -> Dict:
        """Query Shodan for host/domain info."""
        if not config.SHODAN_API_KEY:
            return {"note": "Set SHODAN_API_KEY env var"}
        try:
            # Host lookup if IP, else search
            import socket
            try:
                ip  = socket.gethostbyname(query)
                url = f"https://api.shodan.io/shodan/host/{ip}"
                params = {"key": config.SHODAN_API_KEY}
                resp   = self.session.get(url, params=params, timeout=15)
            except socket.gaierror:
                url  = "https://api.shodan.io/shodan/host/search"
                params = {"key": config.SHODAN_API_KEY, "query": f"hostname:{query}"}
                resp   = self.session.get(url, params=params, timeout=15)

            if resp.status_code == 200:
                data = resp.json()
                return {
                    "ip":           data.get("ip_str"),
                    "org":          data.get("org"),
                    "isp":          data.get("isp"),
                    "country":      data.get("country_name"),
                    "city":         data.get("city"),
                    "open_ports":   data.get("ports", []),
                    "hostnames":    data.get("hostnames", []),
                    "tags":         data.get("tags", []),
                    "vulns":        list(data.get("vulns", {}).keys()),
                    "os":           data.get("os"),
                    "last_update":  data.get("last_update"),
                }
            return {"error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    # ── GitHub OSINT ──────────────────────────────────────────────────────────
    def _github_search(self, query: str, search_type: str = "users") -> Dict:
        """Search GitHub for users, orgs, or code."""
        try:
            url    = f"https://api.github.com/search/{search_type}"
            params = {"q": query, "per_page": 10}
            resp   = self.session.get(url, params=params, timeout=10)
            if resp.status_code == 200:
                data  = resp.json()
                items = data.get("items", [])
                return {
                    "total_count": data.get("total_count", 0),
                    "results":     [
                        {
                            "login":        i.get("login"),
                            "html_url":     i.get("html_url"),
                            "type":         i.get("type"),
                            "name":         i.get("name"),
                            "public_repos": i.get("public_repos"),
                            "followers":    i.get("followers"),
                            "location":     i.get("location"),
                            "email":        i.get("email"),
                            "bio":          i.get("bio"),
                            "company":      i.get("company"),
                        }
                        for i in items
                    ],
                }
            return {"error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    # ── URLScan.io ────────────────────────────────────────────────────────────
    def _urlscan_search(self, domain: str) -> Dict:
        """Search urlscan.io for historical scans."""
        try:
            url    = "https://urlscan.io/api/v1/search/"
            params = {"q": f"domain:{domain}", "size": 10}
            resp   = self.session.get(url, params=params, timeout=10)
            if resp.status_code == 200:
                data    = resp.json()
                results = data.get("results", [])
                return {
                    "total": data.get("total", 0),
                    "scans": [
                        {
                            "url":         r.get("page", {}).get("url"),
                            "ip":          r.get("page", {}).get("ip"),
                            "country":     r.get("page", {}).get("country"),
                            "server":      r.get("page", {}).get("server"),
                            "scan_id":     r.get("_id"),
                            "screenshot":  f"https://urlscan.io/screenshots/{r.get('_id')}.png",
                            "result_url":  f"https://urlscan.io/result/{r.get('_id')}/",
                            "indexed_at":  r.get("indexedAt"),
                        }
                        for r in results[:10]
                    ],
                }
            return {"error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    # ── Google dorks ─────────────────────────────────────────────────────────
    def _generate_dorks(self, target: str) -> List[str]:
        """Generate useful Google dork queries for the target."""
        dorks = [
            f"site:{target}",
            f"site:{target} inurl:admin",
            f"site:{target} inurl:login",
            f"site:{target} filetype:pdf",
            f"site:{target} filetype:doc OR filetype:docx",
            f"site:{target} filetype:xls OR filetype:xlsx",
            f"site:{target} filetype:sql",
            f"site:{target} filetype:env",
            f"site:{target} intext:password",
            f"site:{target} intext:\"api_key\"",
            f"site:{target} intitle:\"index of\"",
            f"\"{target}\" password site:pastebin.com",
            f"inurl:github.com \"{target}\" password",
            f"site:trello.com \"{target}\"",
            f"site:{target} ext:bak OR ext:old OR ext:backup",
            f"site:{target} \"DB_PASSWORD\" OR \"DB_USER\"",
            f"cache:{target}",
        ]
        return dorks

    # ── LinkedIn / Social ─────────────────────────────────────────────────────
    def _social_dorks(self, company: str) -> List[str]:
        """Generate social media dorks."""
        return [
            f"site:linkedin.com/in \"{company}\"",
            f"site:linkedin.com/company \"{company}\"",
            f"site:twitter.com \"{company}\"",
            f"site:facebook.com \"{company}\"",
            f"site:instagram.com \"{company}\"",
        ]

    # ── Main ──────────────────────────────────────────────────────────────────
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Run OSINT collection.

        target  : domain, IP, email, or company name
        kwargs  :
            mode   = 'domain' | 'email' | 'ip' | 'github' | 'full'
            github = github username/org
        """
        mode   = kwargs.get("mode", "domain")
        results: Dict[str, Any] = {"target": target, "mode": mode}

        if mode == "email":
            self.logger.info(f"📧 Email OSINT: {target}")
            results["breach_data"] = self._hibp_lookup(target)
            domain = target.split("@")[-1]
            results["email_finder"] = self._hunter_email_finder(domain)

        elif mode == "ip":
            self.logger.info(f"🌐 IP OSINT: {target}")
            results["shodan"] = self._shodan_lookup(target)

        elif mode == "github":
            self.logger.info(f"🐙 GitHub OSINT: {target}")
            results["github_users"] = self._github_search(target, "users")
            results["github_repos"] = self._github_search(target, "repositories")

        else:
            # domain / full
            self.logger.info(f"🕵️  Domain OSINT: {target}")
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]

            self.logger.info("  🔎 Shodan lookup...")
            results["shodan"] = self._shodan_lookup(domain)

            self.logger.info("  📧 Email finder (Hunter.io)...")
            results["email_finder"] = self._hunter_email_finder(domain)

            self.logger.info("  🌐 URLScan.io search...")
            results["urlscan"] = self._urlscan_search(domain)

            self.logger.info("  🐙 GitHub search...")
            results["github"] = self._github_search(domain, "repositories")

            self.logger.info("  🔗 Generating Google dorks...")
            results["google_dorks"] = self._generate_dorks(domain)
            results["social_dorks"] = self._social_dorks(domain)

        return results