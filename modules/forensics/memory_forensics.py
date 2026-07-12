import os
import re
import struct
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List
from core.base_module import BaseModule


class MemoryForensics(BaseModule):
    """
    Memory dump analysis.
    Supports: string extraction, process list carving,
              network artifact recovery, credential hunting,
              YARA scanning of memory dumps.
    """

    # Patterns for artifact extraction
    IOC_PATTERNS = {
        'IPv4':          r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
        'IPv6':          r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}',
        'URL':           r'https?://[^\x00-\x1f\s"<>]{4,}',
        'Email':         r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}',
        'Windows_Path':  r'[Cc]:\\(?:[^\x00-\x1f\\/:*?"<>|]+\\)*[^\x00-\x1f\\/:*?"<>|]*',
        'Registry_Key':  r'HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)[^\x00\s]+',
        'Base64_Blob':   r'(?:[A-Za-z0-9+/]{60,}={0,2})',
        'MD5_Hash':      r'\b[0-9a-fA-F]{32}\b',
        'SHA256_Hash':   r'\b[0-9a-fA-F]{64}\b',
        'Credit_Card':   r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
        'JWT_Token':     r'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+',
        'AWS_Key':       r'AKIA[0-9A-Z]{16}',
        'Private_Key':   r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
    }

    SUSPICIOUS_STRINGS = [
        # Malware families / tools
        'mimikatz', 'meterpreter', 'cobalt strike', 'beacon',
        'metasploit', 'empire', 'powersploit', 'invoke-mimikatz',
        # Credential dumping
        'lsass', 'sekurlsa', 'logonpasswords', 'wdigest',
        'ntlmhash', 'kerberos', 'hashdump',
        # Evasion
        'amsi', 'etw', 'patchguard', 'virtualprotect',
        # C2 indicators
        'beacon', 'c2profile', 'malleable', 'cobaltstrike',
        # Ransomware
        'encrypt', 'ransom', 'bitcoin', '.onion',
        # Lateral movement
        'psexec', 'wmiexec', 'dcom', 'winrm', 'evil-winrm',
    ]

    def __init__(self):
        super().__init__("Memory Forensics")

    # ──────────────────────────────────────────────────────────────────────────
    # Basic info
    # ──────────────────────────────────────────────────────────────────────────

    def _dump_info(self, dump_path: str) -> Dict:
        """Compute basic info about the dump file."""
        size = os.path.getsize(dump_path)
        with open(dump_path, 'rb') as f:
            header = f.read(16)

        dump_types = {
            b'PAGE':  'Windows Page Dump',
            b'MDMP':  'Windows MiniDump',
            b'PAGEDUMP64': 'Windows Full Dump (64-bit)',
        }
        detected = next(
            (dt for sig, dt in dump_types.items() if header.startswith(sig)),
            'Raw / Unknown dump format'
        )

        with open(dump_path, 'rb') as f:
            content = f.read(65536)  # First 64 KB for quick hash
        quick_hash = hashlib.md5(content).hexdigest()

        return {
            'path':        dump_path,
            'size_bytes':  size,
            'size_human':  self._human_size(size),
            'type':        detected,
            'header_hex':  header.hex(),
            'quick_md5':   quick_hash,
        }

    def _human_size(self, n: int) -> str:
        for u in ['B', 'KB', 'MB', 'GB']:
            if n < 1024:
                return f'{n:.1f} {u}'
            n /= 1024
        return f'{n:.1f} TB'

    # ──────────────────────────────────────────────────────────────────────────
    # String extraction
    # ──────────────────────────────────────────────────────────────────────────

    def extract_strings(self, dump_path: str,
                        min_len: int = 6,
                        chunk_size: int = 4 * 1024 * 1024) -> Dict:
        """
        Extract printable ASCII and UTF-16LE strings from memory dump.
        Processes in chunks to handle large dumps.
        """
        ascii_strings   = set()
        unicode_strings = set()
        pattern_ascii   = re.compile(
            rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}'
        )
        pattern_unicode = re.compile(
            rb'(?:[\x20-\x7e]\x00){' + str(min_len).encode() + rb',}'
        )
        overlap = 32  # bytes to overlap between chunks

        self.logger.info(f"  📝 Extracting strings (min_len={min_len})...")

        with open(dump_path, 'rb') as f:
            buffer = b''
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                buffer += chunk
                for m in pattern_ascii.finditer(buffer):
                    ascii_strings.add(m.group(0).decode('ascii', errors='replace'))
                for m in pattern_unicode.finditer(buffer):
                    s = m.group(0).decode('utf-16-le', errors='replace')
                    if len(s) >= min_len:
                        unicode_strings.add(s)
                buffer = buffer[-overlap:]

        all_strings = list(ascii_strings | unicode_strings)
        self.logger.info(
            f"  Found {len(ascii_strings)} ASCII + {len(unicode_strings)} Unicode strings"
        )
        return {
            'total':   len(all_strings),
            'ascii':   len(ascii_strings),
            'unicode': len(unicode_strings),
            'strings': sorted(all_strings)[:2000],   # Cap for output
        }

    # ──────────────────────────────────────────────────────────────────────────
    # IOC extraction
    # ──────────────────────────────────────────────────────────────────────────

    def extract_iocs(self, dump_path: str,
                     chunk_size: int = 4 * 1024 * 1024) -> Dict:
        """Extract Indicators of Compromise from memory dump."""
        iocs: Dict[str, set] = {key: set() for key in self.IOC_PATTERNS}
        compiled = {k: re.compile(v.encode()) for k, v in self.IOC_PATTERNS.items()}

        overlap = 256
        self.logger.info("  🎯 Extracting IOCs...")

        with open(dump_path, 'rb') as f:
            buffer = b''
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                buffer += chunk
                for ioc_type, pattern in compiled.items():
                    for m in pattern.finditer(buffer):
                        try:
                            iocs[ioc_type].add(m.group(0).decode('utf-8', errors='replace'))
                        except Exception:
                            pass
                buffer = buffer[-overlap:]

        result = {}
        total  = 0
        for ioc_type, values in iocs.items():
            if values:
                result[ioc_type] = sorted(values)[:200]
                total += len(values)
                self.logger.info(f"    {ioc_type}: {len(values)} found")

        return {'total_iocs': total, 'iocs': result}

    # ──────────────────────────────────────────────────────────────────────────
    # Suspicious string search
    # ──────────────────────────────────────────────────────────────────────────

    def hunt_suspicious(self, dump_path: str,
                        chunk_size: int = 4 * 1024 * 1024) -> Dict:
        """Search for known malicious string indicators."""
        found: Dict[str, List] = {}

        patterns = [
            re.compile(re.escape(s).encode(), re.IGNORECASE)
            for s in self.SUSPICIOUS_STRINGS
        ]

        self.logger.info("  🔍 Hunting suspicious strings...")

        with open(dump_path, 'rb') as f:
            offset    = 0
            overlap   = 128
            buffer    = b''
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                buffer += chunk
                for pattern, keyword in zip(patterns, self.SUSPICIOUS_STRINGS):
                    for m in pattern.finditer(buffer):
                        abs_offset = offset + m.start()
                        found.setdefault(keyword, []).append({
                            'offset':  abs_offset,
                            'hex':     hex(abs_offset),
                            'context': buffer[
                                max(0, m.start() - 20):m.end() + 20
                            ].decode('utf-8', errors='replace'),
                        })
                offset += len(buffer) - overlap
                buffer  = buffer[-overlap:]

        # Deduplicate — keep first 10 hits per keyword
        for k in found:
            found[k] = found[k][:10]
            self.logger.warning(f"  🚨 '{k}' found {len(found[k])} time(s)")

        return {
            'keywords_found': list(found.keys()),
            'hits':           found,
            'total_hits':     sum(len(v) for v in found.values()),
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Process carving (Windows EPROCESS heuristic)
    # ──────────────────────────────────────────────────────────────────────────

    def carve_processes(self, dump_path: str,
                        chunk_size: int = 4 * 1024 * 1024) -> Dict:
        """
        Attempt to carve Windows EPROCESS-like structures.
        Looks for common process name patterns in the dump.
        Note: Full EPROCESS carving requires OS-specific offsets.
              This is a heuristic text-based approach.
        """
        # Common Windows process names to look for
        known_processes = [
            b'System', b'smss.exe', b'csrss.exe', b'wininit.exe',
            b'services.exe', b'lsass.exe', b'svchost.exe',
            b'explorer.exe', b'taskmgr.exe', b'cmd.exe',
            b'powershell.exe', b'msiexec.exe', b'rundll32.exe',
            b'regsvr32.exe', b'wscript.exe', b'cscript.exe',
            b'mshta.exe', b'notepad.exe', b'calc.exe',
        ]

        found_processes = {}
        self.logger.info("  🖥️  Carving process names...")

        with open(dump_path, 'rb') as f:
            offset  = 0
            overlap = 64
            buffer  = b''
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                buffer += chunk
                for proc in known_processes:
                    pos = 0
                    while True:
                        idx = buffer.lower().find(proc.lower(), pos)
                        if idx == -1:
                            break
                        abs_off = offset + idx
                        found_processes.setdefault(
                            proc.decode('ascii', errors='replace'), []
                        ).append(hex(abs_off))
                        pos = idx + 1
                offset += len(buffer) - overlap
                buffer  = buffer[-overlap:]

        # Summarise
        process_list = []
        for proc_name, offsets in found_processes.items():
            process_list.append({
                'name':     proc_name,
                'count':    len(offsets),
                'offsets':  offsets[:5],   # First 5 hits
            })
            self.logger.info(f"    📌 {proc_name}: {len(offsets)} reference(s)")

        return {
            'processes_found': len(process_list),
            'process_list':    sorted(process_list,
                                      key=lambda x: x['count'],
                                      reverse=True),
        }

    # ──────────────────────────────────────────────────────────────────────────
    # YARA scan
    # ──────────────────────────────────────────────────────────────────────────

    def yara_scan(self, dump_path: str, rules_path: str = None) -> List[Dict]:
        """Scan memory dump with YARA rules."""
        try:
            import yara
        except ImportError:
            return [{'error': 'yara-python not installed: pip install yara-python'}]

        DEFAULT = r"""
        rule MimikatzInMemory {
            meta: description = "Mimikatz credential dumper artefacts"
            strings:
                $s1 = "mimikatz" nocase
                $s2 = "sekurlsa" nocase
                $s3 = "logonPasswords" nocase
                $s4 = "lsass.exe" nocase
                $s5 = "WDigest"
            condition: 2 of them
        }
        rule CobaltStrikeBeacon {
            meta: description = "Cobalt Strike Beacon indicators"
            strings:
                $s1 = "beacon" nocase
                $s2 = "cobaltstrike" nocase
                $s3 = "MalleableC2" nocase
                $s4 = "%s (admin)" wide
            condition: 2 of them
        }
        rule MeterpreterInMemory {
            meta: description = "Meterpreter shellcode / stager"
            strings:
                $s1 = "meterpreter" nocase
                $s2 = "metasploit"  nocase
                $s3 = "reverse_tcp" nocase
                $s4 = "stageless"   nocase
            condition: 2 of them
        }
        rule RansomwareIndicators {
            meta: description = "Generic ransomware indicators"
            strings:
                $r1 = "encrypt" nocase
                $r2 = "ransom"  nocase
                $r3 = "bitcoin" nocase
                $r4 = ".onion"  nocase
                $r5 = "YOUR FILES" nocase
            condition: 3 of them
        }
        """

        matches = []
        try:
            rules = (
                yara.compile(filepath=rules_path)
                if rules_path and os.path.exists(rules_path)
                else yara.compile(source=DEFAULT)
            )
            yara_matches = rules.match(dump_path)
            for m in yara_matches:
                entry = {
                    'rule':    m.rule,
                    'meta':    m.meta,
                    'strings': [
                        {
                            'offset': hex(s[0]),
                            'name':   s[1],
                            'data':   s[2].decode('utf-8', errors='replace')[:80],
                        }
                        for s in m.strings[:10]
                    ],
                }
                matches.append(entry)
                self.logger.warning(f"  🚨 YARA match: {m.rule}")
        except Exception as exc:
            matches.append({'error': str(exc)})

        return matches

    # ──────────────────────────────────────────────────────────────────────────
    # run()
    # ──────────────────────────────────────────────────────────────────────────

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        target  : path to memory dump file
        kwargs:
            action     : 'info' | 'strings' | 'iocs' | 'hunt' |
                         'processes' | 'yara' | 'full'
            yara_rules : path to .yar file
            min_len    : minimum string length (default 6)
        """
        action     = kwargs.get('action', 'full')
        yara_rules = kwargs.get('yara_rules', None)
        min_len    = kwargs.get('min_len', 6)

        if not os.path.exists(target):
            return {'error': f'Dump file not found: {target}'}

        self.logger.info(f"🧠 Memory Forensics — action: {action} → {target}")

        results: Dict[str, Any] = {
            'target':    target,
            'action':    action,
            'timestamp': datetime.now().isoformat(),
        }

        if action in ('info', 'full'):
            self.logger.info("  ℹ️  Dump info...")
            results['info'] = self._dump_info(target)

        if action in ('strings', 'full'):
            results['strings'] = self.extract_strings(target, min_len=min_len)

        if action in ('iocs', 'full'):
            results['iocs'] = self.extract_iocs(target)

        if action in ('hunt', 'full'):
            results['suspicious'] = self.hunt_suspicious(target)

        if action in ('processes', 'full'):
            results['processes'] = self.carve_processes(target)

        if action in ('yara', 'full'):
            self.logger.info("  🎯 YARA scan...")
            results['yara'] = self.yara_scan(target, yara_rules)

        return results