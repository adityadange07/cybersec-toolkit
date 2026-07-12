import re
import os
from typing import Dict, Any, List
from collections import Counter, defaultdict
from datetime import datetime
from core.base_module import BaseModule


class LogAnalyzer(BaseModule):
    """Security log analyzer for incident investigation."""

    ATTACK_PATTERNS = {
        'SQL Injection': [
            r"(?i)(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|drop\s+table|insert\s+into|select\s+.*from)",
            r"(?i)(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)",
        ],
        'XSS': [
            r"(?i)(<script|javascript:|onerror\s*=|onload\s*=|onclick\s*=)",
            r"(?i)(alert\s*\(|document\.cookie|document\.location)",
        ],
        'Path Traversal': [
            r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.%2e/)",
            r"(?i)(/etc/passwd|/etc/shadow|/windows/system32)",
        ],
        'Command Injection': [
            r"(\||\;|\&\&|\|\|)\s*(cat|ls|dir|whoami|id|uname|pwd)",
            r"(?i)(`[^`]+`|\$\([^)]+\))",
        ],
        'Brute Force': [
            r"(?i)(failed\s+login|authentication\s+failure|invalid\s+password|login\s+failed)",
        ],
        'Web Shell': [
            r"(?i)(c99|r57|phpspy|webshell|cmd\.php|shell\.php)",
            r"(?i)(eval\s*\(|system\s*\(|exec\s*\(|passthru\s*\()",
        ],
        'Scanner Detection': [
            r"(?i)(nikto|nmap|sqlmap|dirbuster|gobuster|burp|zap|acunetix|nessus)",
        ],
    }

    LOG_FORMATS = {
        'apache_combined': r'(?P<ip>[\d.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<url>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<size>\d+)\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)"',
        'apache_common': r'(?P<ip>[\d.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<url>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<size>\d+)',
        'nginx': r'(?P<ip>[\d.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<url>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<size>\d+)',
        'auth_log': r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+(?P<hostname>\S+)\s+(?P<service>\S+):\s+(?P<message>.*)',
    }

    def __init__(self):
        super().__init__("Log Analyzer")

    def _detect_log_format(self, line: str) -> str:
        """Auto-detect log format."""
        for format_name, pattern in self.LOG_FORMATS.items():
            if re.match(pattern, line):
                return format_name
        return 'unknown'

    def _parse_log_line(self, line: str, log_format: str) -> Dict:
        """Parse a single log line."""
        pattern = self.LOG_FORMATS.get(log_format, '')
        if pattern:
            match = re.match(pattern, line)
            if match:
                return match.groupdict()
        return {'raw': line}

    def _detect_attacks(self, log_entries: List[Dict]) -> List[Dict]:
        """Detect attack patterns in log entries."""
        attacks = []

        for entry in log_entries:
            url = entry.get('url', '') + entry.get('raw', '')
            agent = entry.get('agent', '')
            message = entry.get('message', '')
            search_text = f"{url} {agent} {message}"

            for attack_type, patterns in self.ATTACK_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, search_text):
                        attacks.append({
                            'type': attack_type,
                            'source_ip': entry.get('ip', 'Unknown'),
                            'url': entry.get('url', 'N/A'),
                            'timestamp': entry.get('timestamp', 'N/A'),
                            'matched_pattern': pattern,
                            'raw_line': entry.get('raw', search_text[:200]),
                            'severity': self._get_attack_severity(attack_type)
                        })
                        break

        return attacks

    def _get_attack_severity(self, attack_type: str) -> str:
        severity_map = {
            'SQL Injection': 'Critical',
            'XSS': 'High',
            'Path Traversal': 'High',
            'Command Injection': 'Critical',
            'Brute Force': 'Medium',
            'Web Shell': 'Critical',
            'Scanner Detection': 'Low',
        }
        return severity_map.get(attack_type, 'Medium')

    def _analyze_access_patterns(self, log_entries: List[Dict]) -> Dict:
        """Analyze access patterns for anomalies."""
        ip_counter = Counter()
        url_counter = Counter()
        status_counter = Counter()
        ip_urls = defaultdict(set)
        ip_timestamps = defaultdict(list)

        for entry in log_entries:
            ip = entry.get('ip', 'unknown')
            url = entry.get('url', 'unknown')
            status = entry.get('status', 'unknown')

            ip_counter[ip] += 1
            url_counter[url] += 1
            status_counter[status] += 1
            ip_urls[ip].add(url)
            if 'timestamp' in entry:
                ip_timestamps[ip].append(entry['timestamp'])

        # Detect anomalies
        anomalies = []

        # High request rate from single IP
        for ip, count in ip_counter.most_common(10):
            if count > 100:
                anomalies.append({
                    'type': 'High Request Rate',
                    'ip': ip,
                    'count': count,
                    'unique_urls': len(ip_urls[ip]),
                    'severity': 'High' if count > 1000 else 'Medium'
                })

        # High 4xx/5xx error rates
        error_count = sum(v for k, v in status_counter.items()
                         if str(k).startswith(('4', '5')))
        total = sum(status_counter.values())
        if total > 0 and error_count / total > 0.3:
            anomalies.append({
                'type': 'High Error Rate',
                'error_percentage': f"{error_count / total * 100:.1f}%",
                'severity': 'Medium'
            })

        return {
            'top_ips': ip_counter.most_common(20),
            'top_urls': url_counter.most_common(20),
            'status_codes': dict(status_counter),
            'anomalies': anomalies,
            'total_entries': len(log_entries)
        }

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Analyze log file."""
        if not os.path.exists(target):
            return {"error": f"File not found: {target}"}

        self.logger.info(f"📋 Analyzing log file: {target}")

        log_entries = []
        log_format = kwargs.get('format', 'auto')

        with open(target, 'r', errors='ignore') as f:
            lines = f.readlines()

        if not lines:
            return {"error": "Empty log file"}

        # Auto-detect format
        if log_format == 'auto':
            log_format = self._detect_log_format(lines[0])
            self.logger.info(f"  📝 Detected format: {log_format}")

        # Parse entries
        for line in lines:
            line = line.strip()
            if line:
                entry = self._parse_log_line(line, log_format)
                log_entries.append(entry)

        self.logger.info(f"  📊 Parsed {len(log_entries)} log entries")

        # Detect attacks
        self.logger.info("  🔍 Detecting attack patterns...")
        attacks = self._detect_attacks(log_entries)
        self.logger.info(f"  🚨 Found {len(attacks)} potential attacks")

        # Analyze access patterns
        self.logger.info("  📈 Analyzing access patterns...")
        patterns = self._analyze_access_patterns(log_entries)

        # Group attacks by type
        attack_summary = Counter(a['type'] for a in attacks)

        return {
            'file': target,
            'total_entries': len(log_entries),
            'log_format': log_format,
            'attacks': attacks,
            'attack_summary': dict(attack_summary),
            'access_patterns': patterns,
            'unique_ips': len(set(e.get('ip', '') for e in log_entries)),
        }