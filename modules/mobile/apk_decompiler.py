import os
import subprocess
import shutil
import zipfile
from typing import Dict, Any
from pathlib import Path
from core.base_module import BaseModule
from config.settings import config


class APKDecompiler(BaseModule):
    """
    Decompile APK files using:
        - apktool  (resources + smali)
        - jadx     (Java source reconstruction)
        - d2j-dex2jar + CFR (fallback)
    """

    def __init__(self):
        super().__init__("APK Decompiler")

    # ── Tool checks ───────────────────────────────────────────────────────────
    @staticmethod
    def _tool_available(name: str) -> bool:
        return shutil.which(name) is not None

    # ── apktool ──────────────────────────────────────────────────────────────
    def _apktool_decompile(self, apk_path: str, output_dir: str) -> Dict:
        if not self._tool_available("apktool"):
            return {"error": "apktool not found — install from https://apktool.org"}
        try:
            result = subprocess.run(
                ["apktool", "d", apk_path, "-o", output_dir, "-f"],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                smali_files = list(Path(output_dir).rglob("*.smali"))
                xml_files   = list(Path(output_dir).rglob("*.xml"))
                return {
                    "success":      True,
                    "output_dir":   output_dir,
                    "smali_files":  len(smali_files),
                    "xml_files":    len(xml_files),
                    "tool":         "apktool",
                }
            return {"error": result.stderr[:500]}
        except subprocess.TimeoutExpired:
            return {"error": "apktool timed out"}
        except Exception as e:
            return {"error": str(e)}

    # ── jadx ──────────────────────────────────────────────────────────────────
    def _jadx_decompile(self, apk_path: str, output_dir: str) -> Dict:
        jadx = shutil.which("jadx") or shutil.which("jadx-gui")
        if not jadx:
            return {"error": "jadx not found — install from https://github.com/skylot/jadx"}
        try:
            result = subprocess.run(
                ["jadx", apk_path, "-d", output_dir, "--no-res"],
                capture_output=True, text=True, timeout=300
            )
            java_files = list(Path(output_dir).rglob("*.java"))
            return {
                "success":     result.returncode == 0,
                "output_dir":  output_dir,
                "java_files":  len(java_files),
                "tool":        "jadx",
                "stderr":      result.stderr[:300] if result.returncode != 0 else "",
            }
        except subprocess.TimeoutExpired:
            return {"error": "jadx timed out — large APK?"}
        except Exception as e:
            return {"error": str(e)}

    # ── Raw zip extraction ─────────────────────────────────────────────────────
    def _extract_raw(self, apk_path: str, output_dir: str) -> Dict:
        """Extract APK as ZIP (fallback — no decompilation)."""
        try:
            with zipfile.ZipFile(apk_path, "r") as z:
                z.extractall(output_dir)
            contents = list(Path(output_dir).rglob("*"))
            return {
                "success":    True,
                "output_dir": output_dir,
                "files":      len(contents),
                "tool":       "zip_extract",
            }
        except Exception as e:
            return {"error": str(e)}

    # ── Search decompiled source ──────────────────────────────────────────────
    def _search_secrets(self, output_dir: str) -> list:
        import re
        patterns = {
            "API Key":         r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([^"\']{10,})',
            "Password":        r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})',
            "AWS Key":         r'AKIA[0-9A-Z]{16}',
            "Private Key":     r'-----BEGIN [A-Z]+ PRIVATE KEY-----',
            "Firebase URL":    r'https://[a-z0-9-]+\.firebaseio\.com',
            "Google Maps Key": r'AIza[0-9A-Za-z-_]{35}',
        }
        findings = []
        for filepath in Path(output_dir).rglob("*"):
            if filepath.suffix in (".java", ".smali", ".xml", ".json",
                                   ".properties", ".kt", ".gradle"):
                try:
                    content = filepath.read_text(errors="ignore")
                    for name, pattern in patterns.items():
                        for match in re.findall(pattern, content):
                            findings.append({
                                "type":  name,
                                "match": match if isinstance(match, str) else match[1],
                                "file":  str(filepath.relative_to(output_dir)),
                            })
                except Exception:
                    continue
        return findings

    # ── Main ──────────────────────────────────────────────────────────────────
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        target  : path to APK file
        kwargs  :
            method     = 'apktool' | 'jadx' | 'raw' | 'all'
            output_dir = output directory (default: output/decompiled/<apk_name>)
            search     = True to search for secrets in decompiled code
        """
        if not os.path.exists(target):
            return {"error": f"APK not found: {target}"}

        method     = kwargs.get("method", "all")
        search     = kwargs.get("search", True)
        apk_name   = Path(target).stem
        output_dir = kwargs.get(
            "output_dir",
            str(config.OUTPUT_DIR / "decompiled" / apk_name)
        )

        os.makedirs(output_dir, exist_ok=True)
        results: Dict[str, Any] = {"apk": target, "output_dir": output_dir}

        if method in ("apktool", "all"):
            adir = os.path.join(output_dir, "apktool")
            self.logger.info("  🔧 Running apktool...")
            results["apktool"] = self._apktool_decompile(target, adir)

        if method in ("jadx", "all"):
            jdir = os.path.join(output_dir, "jadx")
            self.logger.info("  ☕ Running jadx...")
            results["jadx"] = self._jadx_decompile(target, jdir)

        if method in ("raw", "all"):
            rdir = os.path.join(output_dir, "raw")
            self.logger.info("  📦 Extracting raw APK...")
            results["raw_extract"] = self._extract_raw(target, rdir)

        # Secret search
        if search:
            self.logger.info("  🔍 Searching for hardcoded secrets...")
            secrets = self._search_secrets(output_dir)
            results["secrets_found"] = secrets
            self.logger.info(f"  ⚠️  {len(secrets)} potential secrets found")

        return results