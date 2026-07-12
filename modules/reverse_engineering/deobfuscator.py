import re
import ast
import base64
import binascii
import urllib.parse
import html
import zlib
import codecs
from typing import Dict, Any, List, Tuple
from core.base_module import BaseModule


class Deobfuscator(BaseModule):
    """
    Multi-layer deobfuscation engine.
    Supports: Base64, ROT13, XOR, URL encoding, HTML entities,
              hex/octal strings, JavaScript obfuscation, PowerShell obfuscation.
    """

    def __init__(self):
        super().__init__("Deobfuscator")
        self.layers_decoded: List[Dict] = []

    # ──────────────────────────────────────────────────────────────────────────
    # Detection helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _is_base64(self, data: str) -> bool:
        """Heuristic: valid base64 charset and correct padding."""
        data = data.strip()
        if len(data) % 4 != 0:
            data += '=' * (4 - len(data) % 4)
        try:
            if re.fullmatch(r'[A-Za-z0-9+/=\s]+', data):
                decoded = base64.b64decode(data)
                # Decoded must contain printable or binary content
                return len(decoded) > 0
        except Exception:
            pass
        return False

    def _is_hex_string(self, data: str) -> bool:
        clean = data.strip().replace(' ', '').replace('\\x', '').replace('0x', '')
        return bool(re.fullmatch(r'[0-9a-fA-F]+', clean)) and len(clean) >= 8

    def _is_url_encoded(self, data: str) -> bool:
        return '%' in data and bool(re.search(r'%[0-9a-fA-F]{2}', data))

    def _is_html_encoded(self, data: str) -> bool:
        return '&' in data and (
            bool(re.search(r'&[a-zA-Z]+;', data)) or
            bool(re.search(r'&#\d+;', data)) or
            bool(re.search(r'&#x[0-9a-fA-F]+;', data))
        )

    def _is_rot13(self, data: str) -> bool:
        """Rough heuristic: decoded text looks more English than original."""
        decoded = codecs.decode(data, 'rot_13')
        original_score = sum(c.isalpha() for c in data) / max(len(data), 1)
        decoded_score  = sum(c.isalpha() for c in decoded) / max(len(decoded), 1)
        return decoded_score > original_score and original_score > 0.4

    # ──────────────────────────────────────────────────────────────────────────
    # Decoders
    # ──────────────────────────────────────────────────────────────────────────

    def decode_base64(self, data: str) -> Tuple[bool, str]:
        """Decode standard and URL-safe Base64."""
        variants = [
            data.strip(),
            data.strip().replace('-', '+').replace('_', '/'),  # URL-safe → std
        ]
        for variant in variants:
            padded = variant + '=' * (4 - len(variant) % 4) if len(variant) % 4 else variant
            try:
                decoded_bytes = base64.b64decode(padded)
                # Try UTF-8 first, fall back to latin-1
                try:
                    return True, decoded_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    return True, decoded_bytes.decode('latin-1')
            except Exception:
                continue
        return False, data

    def decode_base64_url(self, data: str) -> Tuple[bool, str]:
        """Decode Base64-URL (RFC 4648 §5)."""
        try:
            decoded = base64.urlsafe_b64decode(
                data + '=' * (4 - len(data) % 4)
            )
            return True, decoded.decode('utf-8', errors='replace')
        except Exception:
            return False, data

    def decode_hex(self, data: str) -> Tuple[bool, str]:
        """Decode various hex representations."""
        # Handle \\x41\\x42... style
        if '\\x' in data:
            try:
                clean = data.replace('\\x', '').replace(' ', '')
                decoded = bytes.fromhex(clean).decode('utf-8', errors='replace')
                return True, decoded
            except Exception:
                pass

        # Handle 0x41 0x42... style
        hex_parts = re.findall(r'0x([0-9a-fA-F]{2})', data)
        if hex_parts:
            try:
                decoded = bytes.fromhex(''.join(hex_parts)).decode('utf-8', errors='replace')
                return True, decoded
            except Exception:
                pass

        # Plain hex string
        clean = re.sub(r'[^0-9a-fA-F]', '', data)
        if len(clean) >= 8 and len(clean) % 2 == 0:
            try:
                decoded = bytes.fromhex(clean).decode('utf-8', errors='replace')
                return True, decoded
            except Exception:
                pass

        return False, data

    def decode_url(self, data: str) -> Tuple[bool, str]:
        """Decode URL/percent encoding (handles double-encoding)."""
        try:
            decoded = urllib.parse.unquote(data)
            if decoded != data:
                # Check for double encoding
                double = urllib.parse.unquote(decoded)
                return True, double if double != decoded else decoded
        except Exception:
            pass
        return False, data

    def decode_html_entities(self, data: str) -> Tuple[bool, str]:
        """Decode HTML entities."""
        try:
            decoded = html.unescape(data)
            if decoded != data:
                return True, decoded
        except Exception:
            pass
        return False, data

    def decode_rot13(self, data: str) -> Tuple[bool, str]:
        """Decode ROT13."""
        try:
            return True, codecs.decode(data, 'rot_13')
        except Exception:
            return False, data

    def decode_xor(self, data: str, keys: List[int] = None) -> Tuple[bool, str, int]:
        """
        Try XOR brute-force with single-byte keys.
        Returns (success, decoded_text, key_used).
        """
        if keys is None:
            keys = list(range(1, 256))

        # Convert input to bytes
        if isinstance(data, str):
            try:
                raw = bytes.fromhex(data.replace(' ', '').replace('\\x', ''))
            except ValueError:
                raw = data.encode('latin-1')
        else:
            raw = data

        best_score  = 0
        best_result = ''
        best_key    = 0

        english_freq = set('etaoinshrdlcumwfgypbvkjxqzETAOINSHRDLCUMWFGYPBVKJXQZ \t\n\r')

        for key in keys:
            decoded_bytes = bytes(b ^ key for b in raw)
            try:
                decoded = decoded_bytes.decode('utf-8', errors='ignore')
            except Exception:
                continue
            score = sum(1 for c in decoded if c in english_freq)
            if score > best_score:
                best_score  = score
                best_result = decoded
                best_key    = key

        if best_score > len(raw) * 0.4:
            return True, best_result, best_key
        return False, data, 0

    def decode_octal(self, data: str) -> Tuple[bool, str]:
        """Decode octal-escaped strings (\\101 = 'A')."""
        octal_pattern = re.compile(r'\\([0-7]{1,3})')
        matches = octal_pattern.findall(data)
        if not matches:
            return False, data
        try:
            decoded = octal_pattern.sub(
                lambda m: chr(int(m.group(1), 8)), data
            )
            return True, decoded
        except Exception:
            return False, data

    def decode_unicode_escape(self, data: str) -> Tuple[bool, str]:
        """Decode unicode escapes \\u0041, \\U00000041."""
        try:
            decoded = data.encode('raw_unicode_escape').decode('unicode_escape')
            if decoded != data:
                return True, decoded
        except Exception:
            pass

        # Manual \\uXXXX
        pattern = re.compile(r'\\u([0-9a-fA-F]{4})')
        if pattern.search(data):
            try:
                decoded = pattern.sub(lambda m: chr(int(m.group(1), 16)), data)
                return True, decoded
            except Exception:
                pass

        return False, data

    def decode_charcode(self, data: str) -> Tuple[bool, str]:
        """
        Decode JavaScript String.fromCharCode(72,101,108,108,111).
        """
        pattern = re.compile(
            r'(?i)String\.fromCharCode\s*\(([0-9,\s]+)\)'
        )
        matches = pattern.findall(data)
        if not matches:
            return False, data
        try:
            decoded = data
            for match in matches:
                codes = [int(c.strip()) for c in match.split(',') if c.strip()]
                chars = ''.join(chr(c) for c in codes)
                decoded = decoded.replace(f'String.fromCharCode({match})', chars)
            return True, decoded
        except Exception:
            return False, data

    def decode_zlib(self, data: str) -> Tuple[bool, str]:
        """Decode zlib-compressed + base64-encoded data."""
        try:
            raw = base64.b64decode(data + '=' * (4 - len(data) % 4))
            decompressed = zlib.decompress(raw)
            return True, decompressed.decode('utf-8', errors='replace')
        except Exception:
            pass

        # Raw zlib without base64
        if isinstance(data, bytes):
            try:
                return True, zlib.decompress(data).decode('utf-8', errors='replace')
            except Exception:
                pass

        return False, data

    # ──────────────────────────────────────────────────────────────────────────
    # PowerShell deobfuscation
    # ──────────────────────────────────────────────────────────────────────────

    def deobfuscate_powershell(self, code: str) -> Dict:
        """
        Deobfuscate common PowerShell obfuscation patterns.
        """
        findings = {
            'original':          code,
            'techniques_found':  [],
            'decoded_strings':   [],
            'iocs':              [],
        }
        current = code

        # 1. Tick mark removal (e.g. `I`E`X)
        tick_removed = re.sub(r'`', '', current)
        if tick_removed != current:
            findings['techniques_found'].append('Tick-mark obfuscation')
            current = tick_removed

        # 2. Concatenation (e.g. 'Inv'+'oke')
        concat_pattern = re.compile(r"'([^']*)'\s*\+\s*'([^']*)'")
        while concat_pattern.search(current):
            current = concat_pattern.sub(lambda m: f"'{m.group(1)}{m.group(2)}'", current)
        if current != code:
            findings['techniques_found'].append('String concatenation')

        # 3. -join char array  e.g. ([char[]](73,69,88) -join '')
        chararray_pattern = re.compile(r'\(\s*\[char\[\]\]\s*\(([0-9,\s]+)\)\s*-join\s*[\'\"]\s*[\'"]\s*\)')
        for match in chararray_pattern.finditer(current):
            codes   = [int(c.strip()) for c in match.group(1).split(',') if c.strip()]
            decoded = ''.join(chr(c) for c in codes)
            findings['decoded_strings'].append({'method': 'char-array', 'decoded': decoded})
            current = current.replace(match.group(0), f'"{decoded}"')
        if chararray_pattern.search(code):
            findings['techniques_found'].append('Char-array encoding')

        # 4. Base64 encoded commands (-EncodedCommand / -enc)
        enc_pattern = re.compile(
            r'(?i)-(?:EncodedCommand|enc(?:odedcommand)?)\s+([A-Za-z0-9+/=]+)'
        )
        for match in enc_pattern.finditer(current):
            b64 = match.group(1)
            try:
                decoded_bytes = base64.b64decode(b64)
                decoded_str   = decoded_bytes.decode('utf-16-le', errors='replace')
                findings['decoded_strings'].append({
                    'method':  'base64-encoded-command',
                    'decoded': decoded_str,
                })
                findings['techniques_found'].append('Base64 EncodedCommand')
            except Exception:
                pass

        # 5. IEX / Invoke-Expression
        if re.search(r'(?i)(iex|invoke-expression)', current):
            findings['techniques_found'].append('Invoke-Expression (IEX)')

        # 6. Download cradles
        download_patterns = [
            (r'(?i)DownloadString\s*\(["\']([^"\']+)', 'DownloadString'),
            (r'(?i)DownloadFile\s*\(["\']([^"\']+)',   'DownloadFile'),
            (r'(?i)Invoke-WebRequest.+?-Uri\s+["\']([^"\']+)', 'Invoke-WebRequest'),
            (r'(?i)wget\s+["\']?([^\s"\']+)',           'wget'),
            (r'(?i)curl\s+["\']?([^\s"\']+)',           'curl'),
        ]
        for pat, label in download_patterns:
            for m in re.finditer(pat, current):
                findings['iocs'].append({'type': label, 'value': m.group(1)})
                findings['techniques_found'].append(f'Download cradle: {label}')

        # 7. Suspicious cmdlets
        suspicious = [
            'Add-MpPreference', 'Set-MpPreference',          # AV bypass
            'New-Object Net.WebClient',
            'System.Reflection.Assembly',                      # Reflective load
            'VirtualAlloc', 'WriteProcessMemory',             # Injection
            'Start-Process', 'cmd.exe', 'mshta',
            'regsvr32', 'rundll32', 'wscript', 'cscript',
        ]
        for sus in suspicious:
            if re.search(re.escape(sus), current, re.IGNORECASE):
                findings['iocs'].append({'type': 'Suspicious cmdlet/binary', 'value': sus})

        findings['deobfuscated'] = current
        return findings

    # ──────────────────────────────────────────────────────────────────────────
    # JavaScript deobfuscation
    # ──────────────────────────────────────────────────────────────────────────

    def deobfuscate_javascript(self, code: str) -> Dict:
        """
        Deobfuscate common JavaScript obfuscation patterns.
        """
        findings = {
            'original':         code,
            'techniques_found': [],
            'decoded_strings':  [],
            'iocs':             [],
        }
        current = code

        # 1. String.fromCharCode
        ok, decoded = self.decode_charcode(current)
        if ok:
            findings['techniques_found'].append('String.fromCharCode')
            findings['decoded_strings'].append({'method': 'charcode', 'decoded': decoded})
            current = decoded

        # 2. eval() calls
        eval_pattern = re.compile(r'\beval\s*\(([^)]+)\)')
        for match in eval_pattern.finditer(current):
            findings['techniques_found'].append('eval() call')
            findings['iocs'].append({'type': 'eval', 'value': match.group(1)[:200]})

        # 3. Hex strings in JS (\x41\x42)
        hex_str_pattern = re.compile(r'((?:\\x[0-9a-fA-F]{2})+)')
        for match in hex_str_pattern.finditer(current):
            ok, decoded_hex = self.decode_hex(match.group(1))
            if ok:
                findings['decoded_strings'].append({
                    'method':  'hex-escape',
                    'decoded': decoded_hex,
                })
                findings['techniques_found'].append('Hex escape strings')

        # 4. Unicode escapes (\u0041)
        ok, decoded_uni = self.decode_unicode_escape(current)
        if ok and decoded_uni != current:
            findings['techniques_found'].append('Unicode escape sequences')
            findings['decoded_strings'].append({'method': 'unicode-escape', 'decoded': decoded_uni})
            current = decoded_uni

        # 5. atob() — browser Base64
        atob_pattern = re.compile(r'\batob\s*\(\s*["\']([A-Za-z0-9+/=]+)["\']\s*\)')
        for match in atob_pattern.finditer(current):
            ok, decoded_b64 = self.decode_base64(match.group(1))
            if ok:
                findings['techniques_found'].append('atob() Base64')
                findings['decoded_strings'].append({'method': 'atob', 'decoded': decoded_b64})

        # 6. document.write with obfuscated content
        if re.search(r'document\.write\s*\(', current):
            findings['iocs'].append({'type': 'document.write', 'value': 'Dynamic HTML injection'})
            findings['techniques_found'].append('document.write()')

        # 7. Suspicious URLs / domains
        url_pattern = re.compile(r'https?://[^\s"\'<>]+')
        for match in url_pattern.finditer(current):
            findings['iocs'].append({'type': 'URL', 'value': match.group(0)})

        findings['deobfuscated'] = current
        return findings

    # ──────────────────────────────────────────────────────────────────────────
    # Auto-detect and multi-layer decode
    # ──────────────────────────────────────────────────────────────────────────

    def auto_decode(self, data: str, max_layers: int = 10) -> Dict:
        """
        Attempt to auto-detect encoding and decode recursively
        until no more encodings are found or max_layers is reached.
        """
        current   = data
        layers    = []
        iteration = 0

        while iteration < max_layers:
            iteration  += 1
            decoded     = False
            layer_info  = {'layer': iteration, 'method': None, 'result': None}

            # ── Priority order ────────────────────────────────────────────────
            checks = [
                ('URL encoding',       self._is_url_encoded,    self.decode_url),
                ('HTML entities',      self._is_html_encoded,   self.decode_html_entities),
                ('Unicode escape',     lambda d: '\\u' in d,    self.decode_unicode_escape),
                ('Octal escape',       lambda d: bool(re.search(r'\\[0-7]{1,3}', d)),
                                                                 self.decode_octal),
                ('Hex escape',         self._is_hex_string,     self.decode_hex),
                ('Base64',             self._is_base64,         self.decode_base64),
                ('ROT13',              self._is_rot13,          self.decode_rot13),
            ]

            for method_name, detector, decoder in checks:
                if detector(current):
                    ok, result = decoder(current)
                    if ok and result != current and len(result) > 0:
                        layer_info['method'] = method_name
                        layer_info['result'] = result[:500]  # Truncate for display
                        layers.append(layer_info)
                        current = result
                        decoded = True
                        self.logger.info(
                            f"  🔓 Layer {iteration}: {method_name} → "
                            f"{result[:80].strip()!r}{'...' if len(result) > 80 else ''}"
                        )
                        break

            if not decoded:
                self.logger.info(f"  ✅ No more encodings detected after {iteration - 1} layer(s)")
                break

        return {
            'original':     data,
            'final_result': current,
            'layers_count': len(layers),
            'layers':       layers,
            'changed':      current != data,
        }

    # ──────────────────────────────────────────────────────────────────────────
    # run()
    # ──────────────────────────────────────────────────────────────────────────

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Main entry point.

        kwargs:
            mode      : 'auto' | 'powershell' | 'javascript' | 'xor' | specific method
            xor_keys  : List[int]  (used when mode='xor')
            max_layers: int        (used when mode='auto', default 10)
        """
        mode       = kwargs.get('mode', 'auto')
        max_layers = kwargs.get('max_layers', 10)
        xor_keys   = kwargs.get('xor_keys', None)

        self.logger.info(f"🔓 Deobfuscator — mode: {mode}")
        self.logger.info(f"  Input length : {len(target)} bytes")
        self.logger.info(f"  Input preview: {target[:80].strip()!r}{'...' if len(target) > 80 else ''}")

        if mode == 'auto':
            results = self.auto_decode(target, max_layers=max_layers)

        elif mode == 'powershell':
            results = self.deobfuscate_powershell(target)

        elif mode == 'javascript':
            results = self.deobfuscate_javascript(target)

        elif mode == 'xor':
            ok, decoded, key = self.decode_xor(target, keys=xor_keys)
            results = {
                'original': target,
                'decoded':  decoded if ok else None,
                'key':      key if ok else None,
                'success':  ok,
            }
            if ok:
                self.logger.info(f"  ✅ XOR key found: 0x{key:02X} ({key})")
            else:
                self.logger.warning("  ❌ XOR brute-force found no clear-text result")

        elif mode == 'base64':
            ok, decoded = self.decode_base64(target)
            results     = {'original': target, 'decoded': decoded, 'success': ok}

        elif mode == 'hex':
            ok, decoded = self.decode_hex(target)
            results     = {'original': target, 'decoded': decoded, 'success': ok}

        elif mode == 'url':
            ok, decoded = self.decode_url(target)
            results     = {'original': target, 'decoded': decoded, 'success': ok}

        elif mode == 'rot13':
            ok, decoded = self.decode_rot13(target)
            results     = {'original': target, 'decoded': decoded, 'success': ok}

        else:
            results = {'error': f"Unknown mode: {mode}. "
                                "Use auto|powershell|javascript|xor|base64|hex|url|rot13"}

        return results