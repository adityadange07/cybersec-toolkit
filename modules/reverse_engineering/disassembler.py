import os
from typing import Dict, Any, List
from core.base_module import BaseModule

try:
    from capstone import (
        Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_ARM64,
        CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_THUMB,
        CsError,
    )
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

try:
    import r2pipe
    R2_AVAILABLE = True
except ImportError:
    R2_AVAILABLE = False


ARCH_MAP = {
    "x86":   (CS_ARCH_X86,   CS_MODE_32),
    "x64":   (CS_ARCH_X86,   CS_MODE_64),
    "arm":   (CS_ARCH_ARM,   CS_MODE_ARM),
    "arm_t": (CS_ARCH_ARM,   CS_MODE_THUMB),
    "arm64": (CS_ARCH_ARM64, CS_MODE_ARM),
}


class Disassembler(BaseModule):
    """Disassemble binary code using Capstone and/or Radare2."""

    def __init__(self):
        super().__init__("Disassembler")

    # ── Capstone linear disassembly ───────────────────────────────────────────
    def _capstone_disasm(self, code: bytes, arch: str = "x64",
                         base_addr: int = 0x1000,
                         max_insns: int = 200) -> List[Dict]:
        if not CAPSTONE_AVAILABLE:
            return [{"error": "capstone not installed: pip install capstone"}]

        arch_mode = ARCH_MAP.get(arch, ARCH_MAP["x64"])
        md = Cs(*arch_mode)
        md.detail = True

        insns = []
        for insn in md.disasm(code, base_addr):
            insns.append({
                "address":  hex(insn.address),
                "mnemonic": insn.mnemonic,
                "op_str":   insn.op_str,
                "bytes":    insn.bytes.hex(),
                "size":     insn.size,
            })
            if len(insns) >= max_insns:
                break
        return insns

    # ── Radare2 analysis ──────────────────────────────────────────────────────
    def _r2_analyze(self, filepath: str) -> Dict:
        if not R2_AVAILABLE:
            return {"error": "r2pipe not installed: pip install r2pipe (requires radare2)"}
        try:
            r2 = r2pipe.open(filepath, flags=["-2"])
            r2.cmd("aaa")  # Analyse all

            # Functions
            functions = r2.cmdj("aflj") or []
            # Imports
            imports   = r2.cmdj("iij") or []
            # Exports
            exports   = r2.cmdj("iEj") or []
            # Strings
            strings   = r2.cmdj("izj") or []
            # Sections
            sections  = r2.cmdj("iSj") or []

            r2.quit()

            return {
                "functions": [
                    {
                        "name":    f.get("name"),
                        "offset":  hex(f.get("offset", 0)),
                        "size":    f.get("size"),
                        "complexity": f.get("cc"),
                    }
                    for f in functions[:50]
                ],
                "imports":  [{"name": i.get("name"), "plt": hex(i.get("plt", 0))}
                             for i in imports[:50]],
                "exports":  [{"name": e.get("name"), "vaddr": hex(e.get("vaddr", 0))}
                             for e in exports[:50]],
                "strings":  [{"string": s.get("string"), "vaddr": hex(s.get("vaddr", 0))}
                             for s in strings if s.get("length", 0) > 4][:100],
                "sections": [
                    {
                        "name": s.get("name"),
                        "vaddr": hex(s.get("vaddr", 0)),
                        "size": s.get("vsize"),
                        "perm": s.get("perm"),
                    }
                    for s in sections
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    # ── Hex dump ──────────────────────────────────────────────────────────────
    @staticmethod
    def _hex_dump(data: bytes, offset: int = 0, rows: int = 16) -> List[str]:
        lines = []
        for i in range(0, min(len(data), rows * 16), 16):
            chunk = data[i:i + 16]
            hex_part  = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{offset + i:08x}  {hex_part:<48}  |{ascii_part}|")
        return lines

    # ── Main ──────────────────────────────────────────────────────────────────
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        target  : binary file path OR hex string (e.g. "4889e5...")
        kwargs  :
            mode      = 'file' | 'hex' | 'r2'
            arch      = 'x64' | 'x86' | 'arm' | 'arm64'
            offset    = start offset in file (default 0)
            max_insns = max instructions to disassemble (default 200)
        """
        mode      = kwargs.get("mode", "file")
        arch      = kwargs.get("arch", "x64")
        offset    = kwargs.get("offset", 0)
        max_insns = kwargs.get("max_insns", 200)

        results: Dict[str, Any] = {"target": target, "arch": arch}

        if mode == "r2":
            if not os.path.exists(target):
                return {"error": f"File not found: {target}"}
            self.logger.info("  🔬 Radare2 analysis...")
            results["r2_analysis"] = self._r2_analyze(target)

        elif mode == "hex":
            try:
                code = bytes.fromhex(target.replace(" ", ""))
                results["disassembly"] = self._capstone_disasm(
                    code, arch, max_insns=max_insns
                )
                results["hex_dump"] = self._hex_dump(code)
            except ValueError as e:
                return {"error": f"Invalid hex string: {e}"}

        else:  # file
            if not os.path.exists(target):
                return {"error": f"File not found: {target}"}
            with open(target, "rb") as f:
                f.seek(offset)
                code = f.read()

            results["hex_dump"]     = self._hex_dump(code[:256], offset)
            results["disassembly"]  = self._capstone_disasm(
                code, arch, base_addr=offset, max_insns=max_insns
            )
            results["total_bytes"]  = len(code)
            self.logger.info(
                f"  📋 {len(results['disassembly'])} instructions disassembled"
            )

        return results