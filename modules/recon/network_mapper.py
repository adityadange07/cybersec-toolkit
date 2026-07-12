import socket
import ipaddress
import concurrent.futures
from typing import Dict, Any, List
from core.base_module import BaseModule
from config.settings import config

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    from scapy.all import IP, ICMP, sr1, TCP, sr
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class NetworkMapper(BaseModule):
    """Map network topology and discover live hosts."""

    def __init__(self):
        super().__init__("Network Mapper")

    # ── Host discovery ────────────────────────────────────────────────────────
    def _icmp_ping(self, ip: str, timeout: float = 1.0) -> bool:
        """Send ICMP echo request (requires root)."""
        if not SCAPY_AVAILABLE:
            return self._tcp_ping(ip)
        try:
            pkt    = IP(dst=ip) / ICMP()
            reply  = sr1(pkt, timeout=timeout, verbose=False)
            return reply is not None
        except Exception:
            return False

    def _tcp_ping(self, ip: str, ports: List[int] = None) -> bool:
        """TCP connect ping — no root needed."""
        if ports is None:
            ports = [80, 443, 22, 445, 8080]
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                s.close()
                if result == 0:
                    return True
            except Exception:
                continue
        return False

    def _resolve_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""

    def _get_mac(self, ip: str) -> str:
        """Get MAC via ARP (LAN only, requires scapy + root)."""
        if not SCAPY_AVAILABLE:
            return ""
        try:
            from scapy.all import Ether, ARP, srp
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                timeout=1, verbose=False
            )
            if ans:
                return ans[0][1].hwsrc
        except Exception:
            pass
        return ""

    def _scan_host(self, ip: str) -> Dict:
        """Full host probe."""
        alive = self._icmp_ping(ip) or self._tcp_ping(ip)
        if not alive:
            return {}
        info = {
            "ip":       ip,
            "hostname": self._resolve_hostname(ip),
            "mac":      self._get_mac(ip),
            "alive":    True,
        }
        self.logger.info(
            f"  🟢 {ip:20s}  {info['hostname'] or '(no PTR)':40s}  {info['mac'] or '(no MAC)'}"
        )
        return info

    def _nmap_scan(self, network: str, arguments: str = "-sn") -> List[Dict]:
        """Use nmap for host discovery if available."""
        if not NMAP_AVAILABLE:
            return []
        nm = nmap.PortScanner()
        nm.scan(hosts=network, arguments=arguments)
        hosts = []
        for host in nm.all_hosts():
            hosts.append({
                "ip":       host,
                "hostname": nm[host].hostname(),
                "state":    nm[host].state(),
                "mac":      nm[host].get("addresses", {}).get("mac", ""),
                "vendor":   nm[host].get("vendor", {}),
            })
        return hosts

    # ── Topology ──────────────────────────────────────────────────────────────
    def _traceroute(self, target: str, max_hops: int = 30) -> List[Dict]:
        """Simple traceroute using scapy."""
        if not SCAPY_AVAILABLE:
            return [{"error": "scapy required for traceroute"}]
        hops = []
        try:
            for ttl in range(1, max_hops + 1):
                pkt   = IP(dst=target, ttl=ttl) / ICMP()
                reply = sr1(pkt, timeout=2, verbose=False)
                if reply is None:
                    hops.append({"hop": ttl, "ip": "*", "hostname": "*"})
                else:
                    hop_ip   = reply.src
                    hostname = self._resolve_hostname(hop_ip)
                    hops.append({"hop": ttl, "ip": hop_ip, "hostname": hostname})
                    self.logger.info(f"  {ttl:2d}  {hop_ip:20s}  {hostname}")
                    if hop_ip == target:
                        break
        except Exception as e:
            self.logger.warning(f"Traceroute error: {e}")
        return hops

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Map network.

        target  : CIDR range (e.g. 192.168.1.0/24) OR single host
        kwargs  :
            mode        = 'discovery' | 'traceroute' | 'full'
            threads     = int (default config.MAX_THREADS)
            use_nmap    = bool
        """
        mode      = kwargs.get("mode", "discovery")
        threads   = kwargs.get("threads", config.MAX_THREADS)
        use_nmap  = kwargs.get("use_nmap", NMAP_AVAILABLE)

        results: Dict[str, Any] = {"target": target, "mode": mode}

        # ── Traceroute ────────────────────────────────────────────────────────
        if mode == "traceroute":
            self.logger.info(f"🗺️  Traceroute to {target}")
            results["hops"] = self._traceroute(target)
            return results

        # ── Host discovery ────────────────────────────────────────────────────
        self.logger.info(f"🗺️  Discovering hosts in {target}")

        if use_nmap and NMAP_AVAILABLE:
            self.logger.info("  Using nmap ping scan (-sn)")
            hosts = self._nmap_scan(target)
        else:
            # Generate host list from CIDR
            try:
                network = ipaddress.ip_network(target, strict=False)
                ips = [str(h) for h in network.hosts()]
            except ValueError:
                ips = [target]

            self.logger.info(f"  Scanning {len(ips)} addresses with {threads} threads")
            hosts = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(self._scan_host, ip): ip for ip in ips}
                for fut in concurrent.futures.as_completed(futures):
                    info = fut.result()
                    if info:
                        hosts.append(info)

        results["hosts"]       = sorted(hosts, key=lambda h: h.get("ip", ""))
        results["total_found"] = len(hosts)
        self.logger.info(f"  ✅ Found {len(hosts)} live hosts")

        # Full mode adds traceroute to each host
        if mode == "full":
            for host in results["hosts"]:
                self.logger.info(f"  🔍 Traceroute → {host['ip']}")
                host["traceroute"] = self._traceroute(host["ip"], max_hops=15)

        return results