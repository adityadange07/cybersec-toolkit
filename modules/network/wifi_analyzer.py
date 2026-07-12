"""
Wi-Fi Analyzer
──────────────
Uses the system's wireless interface (requires root/admin + a compatible
adapter) to enumerate nearby access points and check for weak configurations.
"""
import subprocess
import re
import platform
from typing import Dict, Any, List
from core.base_module import BaseModule


class WiFiAnalyzer(BaseModule):
    """Enumerate and assess nearby Wi-Fi networks."""

    def __init__(self):
        super().__init__("WiFi Analyzer")
        self.os = platform.system().lower()

    # ── Interface listing ─────────────────────────────────────────────────────
    def _list_interfaces(self) -> List[str]:
        ifaces = []
        try:
            if self.os == "linux":
                out = subprocess.check_output(["iwconfig"], stderr=subprocess.DEVNULL,
                                              text=True)
                ifaces = re.findall(r'^(\w+)\s+IEEE', out, re.MULTILINE)
            elif self.os == "darwin":
                out = subprocess.check_output(["networksetup", "-listallhardwareports"],
                                              text=True)
                ifaces = re.findall(r"Device:\s+(\w+)", out)
        except Exception as e:
            self.logger.warning(f"Interface listing error: {e}")
        return ifaces

    # ── Scan (Linux: iwlist / macOS: airport) ─────────────────────────────────
    def _scan_linux(self, interface: str) -> List[Dict]:
        networks = []
        try:
            subprocess.run(["ip", "link", "set", interface, "up"],
                           capture_output=True, check=False)
            raw = subprocess.check_output(
                ["iwlist", interface, "scanning"],
                stderr=subprocess.DEVNULL, text=True
            )
            # Split by Cell
            cells = re.split(r"Cell \d+ -", raw)[1:]
            for cell in cells:
                ssid     = re.search(r'ESSID:"([^"]*)"', cell)
                bssid    = re.search(r"Address:\s+([\w:]+)", cell)
                channel  = re.search(r"Channel[=:](\d+)", cell)
                freq     = re.search(r"Frequency:([\d.]+)", cell)
                quality  = re.search(r"Quality=(\d+)/(\d+)", cell)
                signal   = re.search(r"Signal level=(-?\d+)", cell)
                enc_key  = re.search(r"Encryption key:(on|off)", cell)
                wpa      = re.search(r"(WPA\d?)", cell)

                security = "Open"
                if enc_key and enc_key.group(1) == "on":
                    security = wpa.group(1) if wpa else "WEP"

                net = {
                    "ssid":     ssid.group(1) if ssid else "<hidden>",
                    "bssid":    bssid.group(1) if bssid else "N/A",
                    "channel":  int(channel.group(1)) if channel else 0,
                    "frequency": float(freq.group(1)) if freq else 0,
                    "signal_dbm": int(signal.group(1)) if signal else 0,
                    "quality":  f"{quality.group(1)}/{quality.group(2)}" if quality else "N/A",
                    "security": security,
                    "issues":   [],
                }
                # Flag weak security
                if security == "Open":
                    net["issues"].append({"issue": "Open Network", "severity": "Critical"})
                if security == "WEP":
                    net["issues"].append({"issue": "WEP — easily cracked", "severity": "Critical"})
                if security == "WPA":
                    net["issues"].append({"issue": "WPA (deprecated, prefer WPA2/3)", "severity": "High"})

                networks.append(net)
        except FileNotFoundError:
            self.logger.warning("iwlist not found — install wireless-tools")
        except PermissionError:
            self.logger.error("Root privileges required for Wi-Fi scanning")
        except Exception as e:
            self.logger.warning(f"Scan error: {e}")
        return networks

    def _scan_macos(self) -> List[Dict]:
        networks = []
        airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        try:
            raw = subprocess.check_output([airport, "-s"], text=True)
            for line in raw.strip().splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    networks.append({
                        "ssid":       parts[0],
                        "bssid":      parts[1],
                        "signal_dbm": int(parts[2]),
                        "channel":    int(parts[3]),
                        "security":   parts[-1],
                        "issues":     [],
                    })
        except Exception as e:
            self.logger.warning(f"macOS airport scan error: {e}")
        return networks

    def _check_default_ssids(self, networks: List[Dict]) -> List[Dict]:
        """Flag networks with default/common SSIDs."""
        defaults = [
            "linksys", "netgear", "dlink", "default", "home",
            "wireless", "wifi", "xfinitywifi", "att", "verizon",
            "tp-link", "asus", "huawei",
        ]
        flagged = []
        for net in networks:
            ssid_lower = net["ssid"].lower()
            if any(d in ssid_lower for d in defaults):
                flagged.append({
                    "ssid":   net["ssid"],
                    "issue":  "Default/Common SSID — may indicate default credentials",
                    "severity": "Medium",
                })
        return flagged

    # ── Main ──────────────────────────────────────────────────────────────────
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        target  : wireless interface name (e.g. wlan0, en0)
                  use 'auto' to pick the first found
        """
        interface = target

        if target == "auto" or not target:
            ifaces = self._list_interfaces()
            if not ifaces:
                return {"error": "No wireless interfaces found"}
            interface = ifaces[0]
            self.logger.info(f"  Using interface: {interface}")

        self.logger.info(f"📡 Scanning Wi-Fi networks on {interface}")

        if self.os == "linux":
            networks = self._scan_linux(interface)
        elif self.os == "darwin":
            networks = self._scan_macos()
        else:
            return {"error": f"Platform '{self.os}' not supported for Wi-Fi scan"}

        default_ssids = self._check_default_ssids(networks)
        open_nets     = [n for n in networks if n["security"] == "Open"]
        weak_sec      = [n for n in networks if n["security"] in ("WEP", "WPA")]

        return {
            "interface":       interface,
            "networks":        networks,
            "total_found":     len(networks),
            "open_networks":   open_nets,
            "weak_security":   weak_sec,
            "default_ssids":   default_ssids,
            "summary": {
                "total":     len(networks),
                "open":      len(open_nets),
                "weak":      len(weak_sec),
                "secure":    len([n for n in networks if "WPA2" in n["security"] or "WPA3" in n["security"]]),
            },
        }