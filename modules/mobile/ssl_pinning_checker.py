import subprocess
import shutil
from typing import Dict, Any
from core.base_module import BaseModule


class SSLPinningChecker(BaseModule):
    """
    Detect and help bypass SSL certificate pinning in mobile apps.

    Detection : static analysis of APK strings / decompiled source
    Bypass    : generates Frida / objection commands for runtime bypass
    """

    PINNING_SIGNATURES = {
        "OkHttp CertificatePinner":   "com.squareup.okhttp3.CertificatePinner",
        "TrustKit":                   "com.datatheorem.android.trustkit",
        "Conscrypt":                  "org.conscrypt",
        "Android PinningTrustManager":"org.thoughtcrime.ssl.pinning",
        "Appcelerator Pinning":       "appcelerator",
        "iOS SecTrustEvaluate":       "SecTrustEvaluate",
        "iOS AFNetworking Pin":       "AFSecurityPolicy",
        "iOS AlamoFire Pin":          "ServerTrustPolicy",
        "Flutter:":                   "dart:io.HttpClient",
        "Xamarin":                    "Xamarin.Android.Net",
    }

    FRIDA_SCRIPTS = {
        "android_universal": """
// Universal Android SSL Pinning Bypass — Frida
// Source: https://github.com/WithSecureLabs/android-ssl-pinning-bypass
Java.perform(function() {
    var array_list = Java.use("java.util.ArrayList");
    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
        return untrustedChain;
    };

    // OkHttp3 bypass
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function() {
            console.log("OkHttp3 pinning bypass applied");
        };
    } catch(e) { console.log("OkHttp3 not found"); }

    // TrustKit bypass
    try {
        var TrustKit = Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier");
        TrustKit.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function() {
            return true;
        };
    } catch(e) { console.log("TrustKit not found"); }
});
""",
        "ios_universal": """
// Universal iOS SSL Pinning Bypass — Frida
// Source: https://github.com/nabla-c0d3/ssl-kill-switch2
Interceptor.attach(
    Module.findExportByName("Security", "SecTrustEvaluate"), {
    onLeave: function(retval) {
        retval.replace(0);
    }
});
""",
    }

    def __init__(self):
        super().__init__("SSL Pinning Checker")

    # ── Static detection ──────────────────────────────────────────────────────
    def detect_from_strings(self, strings: list) -> Dict:
        """Detect pinning from extracted APK strings."""
        detected = []
        strings_str = " ".join(strings).lower()
        for name, signature in self.PINNING_SIGNATURES.items():
            if signature.lower() in strings_str:
                detected.append({"library": name, "signature": signature})
        return {
            "detected":          detected,
            "pinning_present":   len(detected) > 0,
            "libraries":         [d["library"] for d in detected],
        }

    def detect_from_source(self, source_dir: str) -> Dict:
        """Search decompiled source for pinning patterns."""
        import os, re
        detected = []
        for root, _, files in os.walk(source_dir):
            for fname in files:
                if fname.endswith((".java", ".kt", ".smali", ".swift", ".m")):
                    path = os.path.join(root, fname)
                    try:
                        content = open(path, errors="ignore").read()
                        for name, sig in self.PINNING_SIGNATURES.items():
                            if sig.lower() in content.lower():
                                detected.append({
                                    "library": name,
                                    "file":    os.path.relpath(path, source_dir),
                                })
                    except Exception:
                        continue
        return {
            "detected":        detected,
            "pinning_present": len(detected) > 0,
        }

    # ── Bypass command generation ─────────────────────────────────────────────
    def generate_bypass_commands(self, package: str,
                                 platform: str = "android") -> Dict:
        """Generate Frida/objection bypass commands."""
        frida_available    = shutil.which("frida") is not None
        objection_available = shutil.which("objection") is not None

        script_key = f"{platform}_universal"
        frida_script = self.FRIDA_SCRIPTS.get(script_key, "")

        commands = {
            "objection": (
                f"objection --gadget {package} explore --startup-command "
                f"'android sslpinning disable'"
                if platform == "android"
                else f"objection --gadget {package} explore --startup-command "
                     f"'ios sslpinning disable'"
            ),
            "frida_cli": (
                f"frida -U -f {package} -l ssl_bypass.js --no-pause"
                if platform == "android"
                else f"frida -U -f {package} -l ssl_bypass.js"
            ),
            "frida_script": frida_script,
            "apk_mitm":    f"apk-mitm {package}.apk" if platform == "android" else "N/A",
            "tools_installed": {
                "frida":     frida_available,
                "objection": objection_available,
            },
            "setup_steps": [
                "1. Install Frida server on device: adb push frida-server /data/local/tmp/",
                "2. Start Frida server: adb shell chmod +x /data/local/tmp/frida-server && adb shell /data/local/tmp/frida-server &",
                "3. Save the frida_script above as ssl_bypass.js",
                "4. Run the frida_cli command above",
            ] if platform == "android" else [
                "1. Jailbroken device required",
                "2. Install Frida via Cydia/Sileo",
                "3. Save frida_script as ssl_bypass.js",
                "4. Run frida_cli command",
            ],
        }
        return commands

    # ── Main ──────────────────────────────────────────────────────────────────
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        target  : APK package name OR path to decompiled source directory
        kwargs  :
            platform    = 'android' | 'ios'
            strings     = list of strings from APK analysis
            source_dir  = path to decompiled source for deep scan
        """
        platform   = kwargs.get("platform", "android")
        strings    = kwargs.get("strings", [])
        source_dir = kwargs.get("source_dir", "")

        results: Dict[str, Any] = {"target": target, "platform": platform}

        if strings:
            self.logger.info("  🔍 Detecting pinning from strings...")
            results["string_detection"] = self.detect_from_strings(strings)

        if source_dir and os.path.isdir(source_dir):
            self.logger.info("  🔍 Detecting pinning from source...")
            results["source_detection"] = self.detect_from_source(source_dir)

        # Generate bypass commands
        self.logger.info("  🔓 Generating bypass commands...")
        results["bypass_commands"] = self.generate_bypass_commands(target, platform)

        # Summary
        pinning_found = (
            results.get("string_detection", {}).get("pinning_present", False)
            or results.get("source_detection", {}).get("pinning_present", False)
        )
        results["summary"] = {
            "pinning_detected": pinning_found,
            "platform":         platform,
            "bypass_possible":  True,
            "note":             "All bypasses require a rooted/jailbroken device.",
        }
        return results