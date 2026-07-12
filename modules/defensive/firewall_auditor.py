import os
import subprocess
import platform
import re
from typing import Dict, Any, List
from core.base_module import BaseModule


class FirewallAuditor(BaseModule):
    """
    Firewall rule auditor — supports iptables (Linux),
    Windows Firewall (netsh), and UFW.
    """

    def __init__(self):
        super().__init__("Firewall Auditor")
        self.os_type = platform.system().lower()

    # ──────────────────────────────────────────────────────────────────────────
    # Command runner
    # ──────────────────────────────────────────────────────────────────────────

    def _run_cmd(self, cmd: List[str], timeout: int = 30) -> Dict:
        """Run a system command and return stdout/stderr."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return {
                'stdout':      result.stdout,
                'stderr':      result.stderr,
                'returncode':  result.returncode,
            }
        except FileNotFoundError:
            return {'error': f'Command not found: {cmd[0]}'}
        except subprocess.TimeoutExpired:
            return {'error': f'Command timed out: {" ".join(cmd)}'}
        except PermissionError:
            return {'error': 'Permission denied — run as root/Administrator'}
        except Exception as exc:
            return {'error': str(exc)}

    # ──────────────────────────────────────────────────────────────────────────
    # iptables (Linux)
    # ──────────────────────────────────────────────────────────────────────────

    def audit_iptables(self) -> Dict:
        """Audit iptables rules on Linux."""
        result = {'chains': {}, 'issues': [], 'raw': {}}

        # Get all chains
        for table in ['filter', 'nat', 'mangle']:
            cmd_out = self._run_cmd(['iptables', '-t', table, '-L', '-n', '-v', '--line-numbers'])
            if 'error' in cmd_out:
                result['error'] = cmd_out['error']
                return result
            result['raw'][table] = cmd_out['stdout']

        # Parse filter table
        filter_out = result['raw'].get('filter', '')
        current_chain = None
        rules = []

        for line in filter_out.splitlines():
            # Chain header
            chain_match = re.match(r'^Chain\s+(\S+)\s+\(policy\s+(\S+)', line)
            if chain_match:
                current_chain = chain_match.group(1)
                policy        = chain_match.group(2)
                result['chains'][current_chain] = {
                    'policy': policy,
                    'rules':  [],
                }

                # DROP policy is good, ACCEPT needs inspection
                if policy == 'ACCEPT' and current_chain in ('INPUT', 'FORWARD'):
                    result['issues'].append({
                        'issue':    f'Chain {current_chain} has ACCEPT default policy',
                        'severity': 'High',
                        'detail':   'Default ACCEPT allows all traffic — use DROP/REJECT',
                    })
                continue

            # Rule lines (skip header)
            if current_chain and re.match(r'^\s*\d+', line):
                parts = line.split()
                if len(parts) >= 4:
                    rule = {
                        'num':         parts[0],
                        'target':      parts[3] if len(parts) > 3 else '',
                        'protocol':    parts[4] if len(parts) > 4 else 'all',
                        'source':      parts[7] if len(parts) > 7 else 'anywhere',
                        'destination': parts[8] if len(parts) > 8 else 'anywhere',
                        'raw':         line.strip(),
                    }
                    result['chains'].setdefault(
                        current_chain, {'policy': 'N/A', 'rules': []}
                    )['rules'].append(rule)

                    # Flag overly permissive rules
                    if (rule.get('target') == 'ACCEPT' and
                        rule.get('source') in ('0.0.0.0/0', 'anywhere') and
                        rule.get('protocol') == 'all'):
                        result['issues'].append({
                            'issue':    'Overly permissive ACCEPT rule',
                            'severity': 'Medium',
                            'detail':   f"Chain {current_chain} rule {rule['num']}: {line.strip()}",
                        })

        # Check for logging rules
        filter_text = result['raw'].get('filter', '')
        if 'LOG' not in filter_text:
            result['issues'].append({
                'issue':    'No LOG rules found',
                'severity': 'Low',
                'detail':   'Consider adding logging rules for dropped packets',
            })

        return result

    # ──────────────────────────────────────────────────────────────────────────
    # UFW (Ubuntu/Debian)
    # ──────────────────────────────────────────────────────────────────────────

    def audit_ufw(self) -> Dict:
        """Audit UFW (Uncomplicated Firewall) rules."""
        result = {'status': {}, 'rules': [], 'issues': []}

        # UFW status
        status_out = self._run_cmd(['ufw', 'status', 'verbose'])
        if 'error' in status_out:
            return status_out

        raw       = status_out['stdout']
        result['raw'] = raw

        # Check if enabled
        if 'Status: active' not in raw:
            result['issues'].append({
                'issue':    'UFW is not active',
                'severity': 'High',
                'detail':   'Enable UFW: sudo ufw enable',
            })
            result['status']['enabled'] = False
            return result

        result['status']['enabled'] = True

        # Parse default policies
        for line in raw.splitlines():
            if 'Default:' in line:
                result['status']['defaults'] = line.strip()
                if 'allow (incoming)' in line.lower():
                    result['issues'].append({
                        'issue':    'Default incoming policy is ALLOW',
                        'severity': 'High',
                        'detail':   'Set: sudo ufw default deny incoming',
                    })

        # Parse rules
        rule_pattern = re.compile(
            r'^(\S+)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(.*)?$', re.IGNORECASE
        )
        for line in raw.splitlines():
            m = rule_pattern.match(line.strip())
            if m:
                rule = {
                    'port':   m.group(1),
                    'action': m.group(2),
                    'from':   m.group(3).strip() if m.group(3) else 'Anywhere',
                }
                result['rules'].append(rule)

        return result

    # ──────────────────────────────────────────────────────────────────────────
    # Windows Firewall (netsh)
    # ──────────────────────────────────────────────────────────────────────────

    def audit_windows_firewall(self) -> Dict:
        """Audit Windows Firewall using netsh."""
        result = {'profiles': {}, 'rules': [], 'issues': []}

        # Profile state
        profile_out = self._run_cmd(
            ['netsh', 'advfirewall', 'show', 'allprofiles', 'state']
        )
        if 'error' in profile_out:
            return profile_out

        result['profiles_raw'] = profile_out['stdout']

        for profile in ['Domain', 'Private', 'Public']:
            if f'{profile} Profile' in profile_out['stdout']:
                if 'OFF' in profile_out['stdout']:
                    result['issues'].append({
                        'issue':    f'{profile} profile firewall is OFF',
                        'severity': 'Critical',
                        'detail':   f'Enable: netsh advfirewall set {profile.lower()}profile state on',
                    })

        # Rules
        rules_out = self._run_cmd(
            ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all', 'verbose']
        )
        if 'error' not in rules_out:
            result['rules_raw'] = rules_out['stdout'][:5000]  # Truncate

            # Count inbound allow rules
            inbound_allow = len(re.findall(
                r'Direction:\s+In.*?Action:\s+Allow',
                rules_out['stdout'], re.DOTALL
            ))
            result['inbound_allow_rules'] = inbound_allow
            if inbound_allow > 50:
                result['issues'].append({
                    'issue':    f'Large number of inbound ALLOW rules ({inbound_allow})',
                    'severity': 'Medium',
                    'detail':   'Review and remove unnecessary inbound rules',
                })

        return result

    # ──────────────────────────────────────────────────────────────────────────
    # run()
    # ──────────────────────────────────────────────────────────────────────────

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        target  : 'auto' to detect OS, or 'iptables'|'ufw'|'windows'
        """
        fw_type = kwargs.get('fw_type', target)

        self.logger.info(f"🔥 Firewall Auditor — OS: {self.os_type} | type: {fw_type}")

        if fw_type == 'auto':
            if self.os_type == 'linux':
                # Try UFW first, then iptables
                ufw_check = self._run_cmd(['which', 'ufw'])
                fw_type   = 'ufw' if ufw_check.get('returncode') == 0 else 'iptables'
            elif self.os_type == 'windows':
                fw_type = 'windows'
            else:
                return {'error': f'Auto-detection not supported for OS: {self.os_type}'}

        if fw_type == 'iptables':
            return self.audit_iptables()
        elif fw_type == 'ufw':
            return self.audit_ufw()
        elif fw_type == 'windows':
            return self.audit_windows_firewall()
        else:
            return {'error': f'Unknown firewall type: {fw_type}. Use iptables|ufw|windows|auto'}