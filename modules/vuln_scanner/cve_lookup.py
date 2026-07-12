import requests
from typing import Dict, Any, List
from core.base_module import BaseModule
from config.settings import config


class CVELookup(BaseModule):
    """
    CVE lookup using the NIST NVD API v2.

    Docs: https://nvd.nist.gov/developers/vulnerabilities
    """

    NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self):
        super().__init__("CVE Lookup")
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": config.USER_AGENT,
            "Accept":     "application/json",
        })

    # ── NVD helpers ───────────────────────────────────────────────────────────
    def _parse_cve(self, item: Dict) -> Dict:
        """Extract the most useful fields from a CVE item."""
        cve     = item.get("cve", {})
        cve_id  = cve.get("id", "")
        desc    = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
            "No description"
        )

        # CVSS scores
        metrics  = cve.get("metrics", {})
        cvss3    = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
        cvss2    = metrics.get("cvssMetricV2", [])
        score_v3 = cvss3[0]["cvssData"]["baseScore"] if cvss3 else None
        sev_v3   = cvss3[0]["cvssData"]["baseSeverity"] if cvss3 else None
        score_v2 = cvss2[0]["cvssData"]["baseScore"] if cvss2 else None
        vector   = (cvss3[0]["cvssData"].get("vectorString") if cvss3
                    else cvss2[0]["cvssData"].get("vectorString") if cvss2 else None)

        # References
        refs = [r["url"] for r in cve.get("references", [])[:5]]

        # CPE (affected software)
        cpes = []
        for config_node in cve.get("configurations", []):
            for node in config_node.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        cpes.append(match.get("criteria", ""))

        return {
            "id":               cve_id,
            "description":      desc[:500],
            "cvss_v3_score":    score_v3,
            "cvss_v3_severity": sev_v3,
            "cvss_v2_score":    score_v2,
            "cvss_vector":      vector,
            "published":        cve.get("published", ""),
            "last_modified":    cve.get("lastModified", ""),
            "references":       refs,
            "affected_cpes":    cpes[:10],
            "nvd_url":          f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }

    def _query_nvd(self, params: Dict) -> List[Dict]:
        """Query the NVD API with retry."""
        import time
        for attempt in range(config.MAX_RETRIES):
            try:
                resp = self.session.get(self.NVD_BASE, params=params, timeout=30)
                if resp.status_code == 200:
                    data  = resp.json()
                    items = data.get("vulnerabilities", [])
                    return [self._parse_cve(i) for i in items]
                elif resp.status_code == 429:
                    self.logger.warning("  Rate-limited by NVD — waiting 6 s...")
                    time.sleep(6)
                else:
                    self.logger.warning(f"  NVD HTTP {resp.status_code}")
                    return []
            except Exception as e:
                self.logger.warning(f"  NVD query error (attempt {attempt + 1}): {e}")
                time.sleep(2)
        return []

    # ── Public methods ────────────────────────────────────────────────────────
    def lookup_cve(self, cve_id: str) -> Dict:
        """Fetch a single CVE by ID."""
        cves = self._query_nvd({"cveId": cve_id})
        return cves[0] if cves else {"error": f"{cve_id} not found"}

    def search_by_keyword(self, keyword: str, results_per_page: int = 20) -> List[Dict]:
        """Search CVEs by keyword (product name, vendor, etc.)."""
        return self._query_nvd({
            "keywordSearch": keyword,
            "resultsPerPage": results_per_page,
        })

    def search_by_severity(self, severity: str,
                           results_per_page: int = 20) -> List[Dict]:
        """
        Filter CVEs by CVSS v3 severity.
        severity : CRITICAL | HIGH | MEDIUM | LOW
        """
        return self._query_nvd({
            "cvssV3Severity":  severity.upper(),
            "resultsPerPage":  results_per_page,
        })

    def search_by_cpe(self, cpe: str, results_per_page: int = 20) -> List[Dict]:
        """Search CVEs affecting a specific CPE (software/hardware)."""
        return self._query_nvd({
            "cpeName":         cpe,
            "resultsPerPage":  results_per_page,
        })

    def recent_critical(self, days: int = 7) -> List[Dict]:
        """Fetch critical CVEs published in the last N days."""
        import datetime
        end   = datetime.datetime.utcnow()
        start = end - datetime.timedelta(days=days)
        return self._query_nvd({
            "pubStartDate":   start.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate":     end.strftime("%Y-%m-%dT23:59:59.999"),
            "cvssV3Severity": "CRITICAL",
            "resultsPerPage": 20,
        })

    # ── Main ──────────────────────────────────────────────────────────────────
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        target  : CVE-ID  (e.g. CVE-2021-44228)  OR keyword  OR CPE string
        kwargs  :
            mode     = 'id' | 'keyword' | 'cpe' | 'severity' | 'recent'
            severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
            days     = int  (for 'recent' mode)
            limit    = int  (results per page)
        """
        mode     = kwargs.get("mode", "keyword")
        limit    = kwargs.get("limit", 20)
        severity = kwargs.get("severity", "HIGH")
        days     = kwargs.get("days", 7)

        results: Dict[str, Any] = {"query": target, "mode": mode}

        self.logger.info(f"🔍 CVE lookup — mode={mode}, query={target}")

        if mode == "id" or target.upper().startswith("CVE-"):
            results["cve"] = self.lookup_cve(target.upper())
            self.logger.info(
                f"  Score: {results['cve'].get('cvss_v3_score')} "
                f"{results['cve'].get('cvss_v3_severity', '')}"
            )

        elif mode == "cpe":
            cves = self.search_by_cpe(target, limit)
            results["cves"]  = cves
            results["count"] = len(cves)
            self.logger.info(f"  Found {len(cves)} CVEs for CPE {target}")

        elif mode == "severity":
            cves = self.search_by_severity(severity, limit)
            results["cves"]     = cves
            results["count"]    = len(cves)
            results["severity"] = severity
            self.logger.info(f"  Found {len(cves)} {severity} CVEs")

        elif mode == "recent":
            cves = self.recent_critical(days)
            results["cves"]  = cves
            results["count"] = len(cves)
            results["days"]  = days
            self.logger.info(f"  Found {len(cves)} critical CVEs in last {days} days")

        else:
            # keyword (default)
            cves = self.search_by_keyword(target, limit)
            results["cves"]  = cves
            results["count"] = len(cves)
            self.logger.info(f"  Found {len(cves)} CVEs matching '{target}'")

        return results