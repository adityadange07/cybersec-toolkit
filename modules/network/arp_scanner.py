import socket
import struct
import ipaddress
import concurrent.futures
from typing import Dict, Any, List
from core.base_module import BaseModule
from config.settings import config

try:
    from scapy.all import Ether, ARP, srp, conf as scapy_conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ── OUI vendor table (trimmed; extend as needed) ─────────────────────────────
OUI_TABLE = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:05:69": "VMware",
    "08:00:27": "VirtualBox",
    "0A:00:27": "VirtualBox",
    "DC:A6:32": "Raspberry Pi Foundation",
    "B8:27:EB": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "00:16:3E": "Xen",
    "02:42:AC": "Docker",
    "00:1A:11": "Google",
    "94:EB:2C": "Apple",
    "F0:18:98": "Apple",
    "3C:22:FB": "Apple",
    "00:1B:63": "Apple",
    "00:23:6C": "Apple",
    "AC:BC:32": "Apple",
    "00:1D:60": "Intel",
    "8C:8D:28": "Intel",
    "00:21:6A": "Intel",
    "FC:F8:AE": "Samsung",
    "00:26:37": "Samsung",
    "9C:02:98": "Huawei",
    "00:18:82": "Huawei",
    "B4:B5:2F": "Huawei",
    "74:DA:38": "Edimax",
    "00:0F:B5": "Netgear",
    "00:14:6C": "Netgear",
    "C0:FF:D4": "Netgear",
}


def lookup_vendor(mac: str) -> str:
    """Return vendor name from MAC OUI (first 3 octets)."""
    prefix = mac[:8].upper()
    return OUI_TABLE.get(prefix, "Unknown")


class ARPScanner(BaseModule):
    """ARP-based LAN host discovery scanner."""

    def __init__(self):
        super().__init__("ARP Scanner")

    # ── Scapy ARP scan ────────────────────────────────────────────────────────
    def _scapy_arp_scan(self, network: str, timeout: int = 3) -> List[Dict]:
        scapy_conf.verb = 0
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
        try:
            ans, _ = srp(pkt, timeout=timeout, verbose=False)
        except PermissionError:
            self.logger.error("Root/Admin privileges required for ARP scan")
            return []

        hosts = []
        for _, rcv in ans:
            mac    = rcv.hwsrc
            ip     = rcv.psrc
            vendor = lookup_vendor(mac)
            hostname = ""
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass
            host = {
                "ip":       ip,
                "mac":      mac,
                "vendor":   vendor,
                "hostname": hostname,
            }
            hosts.append(host)
            self.logger.info(
                f"  🟢 {ip:18s}  {mac:20s}  {vendor:20s}  {hostname}"
            )
        return hosts

    # ── Fallback: socket-based ping ───────────────────────────────────────────
    def _socket_scan(self, network: str) -> List[Dict]:
        """TCP-connect fallback when scapy / root not available."""
        hosts = []
        try:
            net = ipaddress.ip_network(network, strict=False)
            ips = [str(h) for h in net.hosts()]
        except ValueError:
            ips = [network]

        def probe(ip):
            for port in [80, 443, 22, 445, 8080, 3389]:
                try:
                    s = socket.socket()
                    s.settimeout(0.4)
                    if s.connect_ex((ip, port)) == 0:
                        s.close()
                        hostname = ""
                        try:
                            hostname = socket.gethostbyaddr(ip)[0]
                        except Exception:
                            pass
                        return {"ip": ip, "mac": "N/A", "vendor": "N/A",
                                "hostname": hostname}
                except Exception:
                    pass
                finally:
                    try:
                        s.close()
                    except Exception:
                        pass
            return None

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=config.MAX_THREADS
        ) as ex:
            for result in ex.map(probe, ips):
                if result:
                    hosts.append(result)
                    self.logger.info(
                        f"  🟢 {result['ip']:18s}  {result['hostname']}"
                    )
        return hosts

    # ── OS fingerprint (TTL-based) ────────────────────────────────────────────
    @staticmethod
    def _guess_os(ttl: int) -> str:
        if ttl >= 128:  return "Windows"
        if ttl >= 64:   return "Linux/macOS"
        if ttl >= 255:  return "Network Device (Cisco/Juniper)"
        return "Unknown"

    # ── Main ──────────────────────────────────────────────────────────────────
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        target  : CIDR (e.g. 192.168.1.0/24)
        kwargs  : timeout=3, method='auto'|'scapy'|'socket'
        """
        timeout = kwargs.get("timeout", 3)
        method  = kwargs.get("method", "auto")

        self.logger.info(f"📡 ARP scanning {target}")

        if method == "scapy" or (method == "auto" and SCAPY_AVAILABLE):
            hosts = self._scapy_arp_scan(target, timeout)
        else:
            self.logger.info("  ℹ️  Scapy not available — using TCP-connect probe")
            hosts = self._socket_scan(target)

        return {
            "network":     target,
            "hosts":       hosts,
            "total_found": len(hosts),
            "method":      "scapy" if SCAPY_AVAILABLE and method != "socket" else "socket",
        }