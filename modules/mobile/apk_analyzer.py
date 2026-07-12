import os
import hashlib
import zipfile
import json
import re
from pathlib import Path
from typing import Dict, Any, List
from core.base_module import BaseModule

try:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False


class APKAnalyzer(BaseModule):
    """Android APK static analysis tool."""

    DANGEROUS_PERMISSIONS = [
        'android.permission.READ_CONTACTS',
        'android.permission.WRITE_CONTACTS',
        'android.permission.READ_CALL_LOG',
        'android.permission.WRITE_CALL_LOG',
        'android.permission.CAMERA',
        'android.permission.RECORD_AUDIO',
        'android.permission.READ_SMS',
        'android.permission.SEND_SMS',
        'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.ACCESS_COARSE_LOCATION',
        'android.permission.READ_PHONE_STATE',
        'android.permission.CALL_PHONE',
        'android.permission.READ_EXTERNAL_STORAGE',
        'android.permission.WRITE_EXTERNAL_STORAGE',
        'android.permission.INTERNET',
        'android.permission.ACCESS_NETWORK_STATE',
        'android.permission.INSTALL_PACKAGES',
        'android.permission.SYSTEM_ALERT_WINDOW',
        'android.permission.REQUEST_INSTALL_PACKAGES',
    ]

    SECURITY_ISSUES_PATTERNS = {
        'Hardcoded URL': r'https?://[^\s"<>]+',
        'Hardcoded IP': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        'Hardcoded API Key': r'(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[=:]\s*["\']([^"\']+)',
        'Hardcoded Password': r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']+)',
        'AWS Key': r'AKIA[0-9A-Z]{16}',
        'Private Key': r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
        'SQL Query': r'(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.*(FROM|INTO|SET)',
        'Crypto Weakness': r'(?i)(DES|RC4|MD5|SHA1)[^a-zA-Z]',
        'WebView JavaScript': r'setJavaScriptEnabled\s*\(\s*true\s*\)',
        'Insecure SSL': r'(?i)(trustAllCerts|ALLOW_ALL_HOSTNAME|X509TrustManager)',
        'Debug Enabled': r'android:debuggable\s*=\s*"true"',
        'Backup Enabled': r'android:allowBackup\s*=\s*"true"',
        'Exported Component': r'android:exported\s*=\s*"true"',
    }

    def __init__(self):
        super().__init__("APK Analyzer")

    def _compute_hashes(self, filepath: str) -> Dict[str, str]:
        """Compute file hashes."""
        hashes = {}
        with open(filepath, 'rb') as f:
            content = f.read()
            hashes['md5'] = hashlib.md5(content).hexdigest()
            hashes['sha1'] = hashlib.sha1(content).hexdigest()
            hashes['sha256'] = hashlib.sha256(content).hexdigest()
        hashes['file_size'] = os.path.getsize(filepath)
        return hashes

    def _analyze_manifest(self, apk) -> Dict:
        """Analyze AndroidManifest.xml."""
        manifest_info = {
            'package': apk.get_package(),
            'version_name': apk.get_androidversion_name(),
            'version_code': apk.get_androidversion_code(),
            'min_sdk': apk.get_min_sdk_version(),
            'target_sdk': apk.get_target_sdk_version(),
            'max_sdk': apk.get_max_sdk_version(),
            'main_activity': apk.get_main_activity(),
        }

        # Activities
        manifest_info['activities'] = []
        for activity in apk.get_activities():
            manifest_info['activities'].append(activity)

        # Services
        manifest_info['services'] = list(apk.get_services())

        # Receivers
        manifest_info['receivers'] = list(apk.get_receivers())

        # Providers
        manifest_info['providers'] = list(apk.get_providers())

        return manifest_info

    def _analyze_permissions(self, apk) -> Dict:
        """Analyze permissions."""
        permissions = apk.get_permissions()
        dangerous = [p for p in permissions if p in self.DANGEROUS_PERMISSIONS]
        custom = [p for p in permissions if not p.startswith('android.permission')]

        return {
            'all_permissions': permissions,
            'dangerous_permissions': dangerous,
            'custom_permissions': custom,
            'total': len(permissions),
            'dangerous_count': len(dangerous),
            'risk_level': 'High' if len(dangerous) > 5 else 'Medium' if len(dangerous) > 2 else 'Low'
        }

    def _analyze_certificates(self, apk) -> Dict:
        """Analyze APK signing certificates."""
        certs = {}
        try:
            for cert in apk.get_certificates():
                certs = {
                    'issuer': str(cert.issuer),
                    'subject': str(cert.subject),
                    'serial_number': str(cert.serial_number),
                    'not_valid_before': str(cert.not_valid_before),
                    'not_valid_after': str(cert.not_valid_after),
                    'signature_algorithm': cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid),
                }
        except Exception as e:
            certs['error'] = str(e)
        return certs

    def _scan_for_secrets(self, apk_path: str) -> List[Dict]:
        """Scan APK contents for hardcoded secrets and security issues."""
        findings = []

        try:
            with zipfile.ZipFile(apk_path, 'r') as z:
                for file_info in z.filelist:
                    if file_info.filename.endswith(('.xml', '.json', '.properties',
                                                     '.txt', '.cfg', '.conf', '.yml',
                                                     '.yaml', '.smali', '.java')):
                        try:
                            content = z.read(file_info.filename).decode('utf-8', errors='ignore')
                            for issue_name, pattern in self.SECURITY_ISSUES_PATTERNS.items():
                                matches = re.findall(pattern, content)
                                if matches:
                                    findings.append({
                                        'issue': issue_name,
                                        'file': file_info.filename,
                                        'matches': matches[:5],  # Limit matches
                                        'severity': 'High' if 'key' in issue_name.lower() or
                                                    'password' in issue_name.lower() else 'Medium'
                                    })
                        except:
                            continue
        except Exception as e:
            self.logger.warning(f"Secret scanning error: {e}")

        return findings

    def _check_security_config(self, apk_path: str) -> Dict:
        """Check network security configuration."""
        config = {'issues': []}
        try:
            with zipfile.ZipFile(apk_path, 'r') as z:
                # Check for network_security_config.xml
                for name in z.namelist():
                    if 'network_security_config' in name:
                        content = z.read(name).decode('utf-8', errors='ignore')
                        config['has_network_security_config'] = True
                        if 'cleartextTrafficPermitted="true"' in content:
                            config['issues'].append({
                                'issue': 'Cleartext traffic permitted',
                                'severity': 'High'
                            })
                        if '<trust-anchors>' in content and 'user' in content:
                            config['issues'].append({
                                'issue': 'User certificates trusted',
                                'severity': 'Medium'
                            })
                        break
                else:
                    config['has_network_security_config'] = False
        except:
            pass
        return config

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Analyze APK file."""
        if not os.path.exists(target):
            return {"error": f"File not found: {target}"}

        if not ANDROGUARD_AVAILABLE:
            return {"error": "androguard required. Install with: pip install androguard"}

        self.logger.info(f"📱 Analyzing APK: {target}")

        results = {
            'file': target,
            'hashes': self._compute_hashes(target),
        }

        try:
            apk = APK(target)

            results['manifest'] = self._analyze_manifest(apk)
            self.logger.info(f"  📦 Package: {results['manifest']['package']}")
            self.logger.info(f"  📌 Version: {results['manifest']['version_name']}")

            results['permissions'] = self._analyze_permissions(apk)
            self.logger.info(f"  🔑 Permissions: {results['permissions']['total']} "
                           f"({results['permissions']['dangerous_count']} dangerous)")

            results['certificates'] = self._analyze_certificates(apk)

            results['security_config'] = self._check_security_config(target)

            self.logger.info("  🔍 Scanning for hardcoded secrets...")
            results['secrets'] = self._scan_for_secrets(target)
            self.logger.info(f"  ⚠️  Found {len(results['secrets'])} potential security issues")

            # Risk assessment
            risk_score = 0
            risk_score += results['permissions']['dangerous_count'] * 2
            risk_score += len(results['secrets']) * 3
            risk_score += len(results['security_config'].get('issues', [])) * 5

            results['risk_assessment'] = {
                'score': risk_score,
                'level': 'Critical' if risk_score > 20 else 'High' if risk_score > 10 else 'Medium' if risk_score > 5 else 'Low'
            }

        except Exception as e:
            results['error'] = str(e)

        return results