import os
import re
import struct
from typing import Dict, Any, List
from core.base_module import BaseModule


class StringExtractor(BaseModule):
    """Advanced string extraction from binaries."""

    # Interesting pattern categories
    PATTERNS = {
        "URL":          r"https?://[^\x00-\x1f\x7f \"<>]{8,}",
        "IP Address":   r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b",
        "Email":        r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
        "File Path":    r"(?:[A-Za-z]:\\|/)[^\x00-\x1f\x7f\"<>|?*]{4,}",
        "Registry Key": r"HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)[\\A-Za-z0-9_\-]+",
        "Base64":       r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
        "AWS Key":      r"AKIA[0-9A-Z]{16}",
        "Private Key":  r"-----BEGIN [A-Z ]+PRIVATE KEY-----",
        "UUID":         r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        "Domain":       r"(?:[a-z0-9\-]+\.)+(?:com|net|org|io|gov|edu|mil|co|uk|de|ru|cn){1}",
        "Hash (MD5)":   r"\b[0-9a-fA-F]{32}\b",
        "Hash (SHA256)":r"\b[0-9a-fA-F]{64}\b",
        "Mutex":        r"(?i)(?:mutex|global\\|local\\)[A-Za-z0-9_\-]{4,}",
    }

    def __init__(self):
        super().__init__("String Extractor")

    # ── Core extraction ───────────────────────────────────────────────────────
    def _extract_ascii(self, data: bytes, min_len: int = 4) -> List[Dict]:
        strings = []
        pattern = rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}"
        for m in re.finditer(pattern, data):
            strings.append({
                "string":   m.group(0).decode("ascii"),
                "offset":   hex(m.start()),
                "length":   len(m.group(0)),
                "encoding": "ASCII",
            })
        return strings

    def _extract_unicode(self, data: bytes, min_len: int = 4) -> List[Dict]:
        strings = []
        pattern = rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}"
        for m in re.finditer(pattern, data):
            decoded = m.group(0).decode("utf-16-le", errors="ignore")
            strings.append({
                "string":   decoded,
                "offset":   hex(m.start()),
                "length":   len(decoded),
                "encoding": "UTF-16LE",
            })
        return strings

    def _extract_utf8(self, data: bytes, min_len: int = 4) -> List[Dict]:
        strings = []
        try:
            text = data.decode("utf-8", errors="replace")
            for m in re.finditer(r"[\x20-\x7e\u0080-\uffff]{" + str(min_len) + r",}", text):
                s = m.group(0)
                if any(ord(c) > 127 for c in s):
                    strings.append({
                        "string":   s,
                        "offset":   hex(m.start()),
                        "length":   len(s),
                        "encoding": "UTF-8",
                    })
        except Exception:
            pass
        return strings

    # ── Categorisation ────────────────────────────────────────────────────────
    def _categorise(self, strings: List[Dict]) -> Dict[str, List[Dict]]:
        categories: Dict[str, List[Dict]] = {cat: [] for cat in self.PATTERNS}
        categories["Uncategorised"] = []

        for entry in strings:
            s         = entry["string"]
            matched   = False
            for cat, pattern in self.PATTERNS.items():
                if re.search(pattern, s, re.IGNORECASE):
                    categories[cat].append(entry)
                    matched = True
                    break
            if not matched and len(s) >= 8:
                categories["Uncategorised"].append(entry)

        return {k: v for k, v in categories.items() if v}

    # ── Stack strings (obfuscated) ────────────────────────────────────────────
    def _detect_stack_strings(self, data: bytes) -> List[str]:
        """
        Detect strings built on the stack (common obfuscation).
        Looks for sequences of single-char MOV instructions.
        (Heuristic — many false positives; use Flare FLOSS for production.)
        """
        stack_strings = []
        # Pattern: repeated  mov byte ptr [reg+offset], imm8
        pattern = rb"\xc6\x45.[\x20-\x7e]"
        matches = re.findall(pattern, data)
        if len(matches) >= 4:
            chars = [m[3:4].decode("ascii") for m in matches]
            candidate = "".join(chars)
            if len(set(candidate)) > 2:
                stack_strings.append(candidate)
        return stack_strings

    # ── Main ──────────────────────────────────────────────────────────────────
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        target   : binary file path
        kwargs   :
            min_length = minimum string length (default 4)
            encodings  = list from ['ascii','unicode','utf8'] (default all)
            categorise = True (default)
        """
        if not os.path.exists(target):
            return {"error": f"File not found: {target}"}

        min_len    = kwargs.get("min_length", 4)
        encodings  = kwargs.get("encodings", ["ascii", "unicode", "utf8"])
        categorise = kwargs.get("categorise", True)

        self.logger.info(f"📝 Extracting strings from {target}")

        with open(target, "rb") as f:
            data = f.read()

        all_strings = []
        if "ascii" in encodings:
            ascii_s = self._extract_ascii(data, min_len)
            all_strings.extend(ascii_s)
            self.logger.info(f"  ASCII strings: {len(ascii_s)}")

        if "unicode" in encodings:
            uni_s = self._extract_unicode(data, min_len)
            all_strings.extend(uni_s)
            self.logger.info(f"  Unicode strings: {len(uni_s)}")

        if "utf8" in encodings:
            utf8_s = self._extract_utf8(data, min_len)
            all_strings.extend(utf8_s)
            self.logger.info(f"  UTF-8 strings: {len(utf8_s)}")

        # De-duplicate by string value
        seen = set()
        unique = []
        for s in all_strings:
            if s["string"] not in seen:
                seen.add(s["string"])
                unique.append(s)

        results: Dict[str, Any] = {
            "file":           target,
            "total_strings":  len(unique),
            "all_strings":    unique[:500],
        }

        if categorise:
            cats = self._categorise(unique)
            results["categorised"] = cats
            results["interesting_count"] = sum(
                len(v) for k, v in cats.items() if k != "Uncategorised"
            )
            self.logger.info(
                f"  Interesting strings: {results['interesting_count']}"
            )
            for cat, items in cats.items():
                if cat != "Uncategorised" and items:
                    self.logger.info(f"  📌 {cat}: {len(items)}")

        # Stack strings
        stack = self._detect_stack_strings(data)
        results["stack_strings"] = stack
        if stack:
            self.logger.warning(f"  ⚠️  {len(stack)} potential stack string(s) detected")

        return results