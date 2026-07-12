import os
import struct
import hashlib
import math
from typing import Dict, Any, List
from collections import Counter
from pathlib import Path
from core.base_module import BaseModule

try:
    import python_magic as magic
    MAGIC_AVAILABLE = True
except ImportError:
    try:
        import magic
        MAGIC_AVAILABLE = True
    except ImportError:
        MAGIC_AVAILABLE = False


class BinaryAnalyzer(BaseModule):
    """
    General-purpose binary file analyser.
    Works on ELF, PE, Mach-O, raw shellcode, and unknown formats.
    """

    ELF_MACHINES = {
        0x03: "x86", 0x3E: "x86-64", 0x28: "ARM",
        0xB7: "AArch64", 0x02: "SPARC", 0x08: "MIPS",
    }

    MACHO_MAGIC = {
        0xFEEDFACE: "Mach-O 32-bit (little-endian)",
        0xCEFAEDFE: "Mach-O 32-bit (big-endian)",
        0xFEEDFACF: "Mach-O 64-bit (little-endian)",
        0xCFFAEDFE: "Mach-O 64-bit (big-endian)",
        0xCAFEBABE: "Mach-O Fat Binary",
    }

    def __init__(self):
        super().__init__("Binary Analyzer")

    # ── File type detection ───────────────────────────────────────────────────
    def _detect_format(self, data: bytes) -> Dict:
        info = {}

        if MAGIC_AVAILABLE:
            try:
                m = magic.Magic()
                info["description"] = m.from_buffer(data[:4096])
                info["mime"]        = magic.Magic(mime=True).from_buffer(data[:4096])
            except Exception:
                pass

        magic_bytes = data[:8]
        if magic_bytes[:2] == b"MZ":
            info["format"] = "PE (Windows Executable)"
        elif magic_bytes[:4] == b"\x7fELF":
            info["format"] = "ELF (Linux/Unix Executable)"
        elif struct.unpack("<I", magic_bytes[:4])[0] in self.MACHO_MAGIC:
            info["format"] = self.MACHO_MAGIC[struct.unpack("<I", magic_bytes[:4])[0]]
        elif magic_bytes[:4] == b"PK\x03\x04":
            info["format"] = "ZIP Archive"
        elif magic_bytes[:8] == b"\x89PNG\r\n\x1a\n":
            info["format"] = "PNG Image"
        elif magic_bytes[:3] == b"\xff\xd8\xff":
            info["format"] = "JPEG Image"
        elif magic_bytes[:4] == b"%PDF":
            info["format"] = "PDF Document"
        elif magic_bytes[:2] == b"#!":
            info["format"] = "Script (shebang)"
        else:
            info["format"] = "Unknown"

        return info

    # ── ELF analysis ──────────────────────────────────────────────────────────
    def _analyze_elf(self, data: bytes) -> Dict:
        if data[:4] != b"\x7fELF":
            return {}
        try:
            ei_class    = data[4]   # 1=32-bit, 2=64-bit
            ei_data     = data[5]   # 1=little, 2=big
            ei_type     = struct.unpack_from("<H", data, 16)[0]
            ei_machine  = struct.unpack_from("<H", data, 18)[0]

            elf_types = {1: "Relocatable", 2: "Executable",
                         3: "Shared Object", 4: "Core Dump"}
            return {
                "class":    "64-bit" if ei_class == 2 else "32-bit",
                "endian":   "Little" if ei_data == 1 else "Big",
                "type":     elf_types.get(ei_type, hex(ei_type)),
                "machine":  self.ELF_MACHINES.get(ei_machine, hex(ei_machine)),
            }
        except Exception as e:
            return {"error": str(e)}

    # ── Entropy map ───────────────────────────────────────────────────────────
    def _entropy_map(self, data: bytes, block_size: int = 1024) -> List[Dict]:
        blocks = []
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            if not block:
                break
            ctr     = Counter(block)
            length  = len(block)
            entropy = -sum((v / length) * math.log2(v / length)
                           for v in ctr.values())
            blocks.append({
                "offset":  hex(i),
                "entropy": round(entropy, 4),
                "flag":    "HIGH" if entropy > 7.0 else "MEDIUM" if entropy > 5.5 else "LOW",
            })
        return blocks

    # ── Byte frequency ────────────────────────────────────────────────────────
    def _byte_frequency(self, data: bytes) -> Dict:
        ctr = Counter(data)
        total = len(data)
        return {
            "null_byte_pct":      round(ctr.get(0, 0) / total * 100, 2),
            "printable_pct":      round(
                sum(v for k, v in ctr.items() if 0x20 <= k <= 0x7e) / total * 100, 2
            ),
            "top_bytes": [
                {"byte": hex(b), "count": c, "pct": round(c / total * 100, 2)}
                for b, c in ctr.most_common(10)
            ],
        }

    # ── Known shellcode signatures ────────────────────────────────────────────
    def _shellcode_check(self, data: bytes) -> List[Dict]:
        """Simple heuristic shellcode detection patterns."""
        patterns = [
            (b"\xfc\x48\x83\xe4\xf0", "x64 Windows shellcode prologue"),
            (b"\x6a\x60\x5a\x68\x63\x61\x6c\x63", "calc.exe shellcode"),
            (b"\x31\xc0\x31\xdb\x31\xc9\x31\xd2", "Linux x86 shellcode (zero registers)"),
            (b"\xeb\x27\x5e\x89\x76",             "JMP-CALL-POP technique"),
            (b"\xfc\xe8\x82\x00\x00\x00",         "Metasploit reverse shell stub"),
        ]
        found = []
        for sig, name in patterns:
            idx = data.find(sig)
            if idx != -1:
                found.append({"pattern": name, "offset": hex(idx)})
        return found

    # ── Main ──────────────────────────────────────────────────────────────────
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        if not os.path.exists(target):
            return {"error": f"File not found: {target}"}

        self.logger.info(f"🔬 Binary analysis of {target}")

        with open(target, "rb") as f:
            data = f.read()

        results: Dict[str, Any] = {
            "file":      target,
            "size":      len(data),
            "hashes": {
                "md5":    hashlib.md5(data).hexdigest(),
                "sha256": hashlib.sha256(data).hexdigest(),
            },
        }

        self.logger.info("  🗂️  Detecting format...")
        results["format"]       = self._detect_format(data)

        self.logger.info("  📊 Computing entropy map...")
        results["entropy_map"]  = self._entropy_map(data)
        high_entropy_blocks     = [b for b in results["entropy_map"] if b["flag"] == "HIGH"]
        results["high_entropy_blocks"] = len(high_entropy_blocks)

        self.logger.info("  🔢 Byte frequency analysis...")
        results["byte_freq"]    = self._byte_frequency(data)

        self.logger.info("  🔍 Shellcode signature check...")
        results["shellcode"]    = self._shellcode_check(data)
        if results["shellcode"]:
            self.logger.warning(
                f"  ⚠️  {len(results['shellcode'])} shellcode pattern(s) detected!"
            )

        # ELF specific
        if data[:4] == b"\x7fELF":
            self.logger.info("  🐧 ELF analysis...")
            results["elf"] = self._analyze_elf(data)

        results["summary"] = {
            "format":              results["format"].get("format", "Unknown"),
            "high_entropy_blocks": len(high_entropy_blocks),
            "shellcode_patterns":  len(results["shellcode"]),
            "risk":                "High" if results["shellcode"] or len(high_entropy_blocks) > 5 else "Low",
        }

        return results