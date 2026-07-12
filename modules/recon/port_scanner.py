import socket
import concurrent.futures
from typing import Dict, Any, List, Tuple
from core.base_module import BaseModule
from config.settings import config

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False


class PortScanner(BaseModule):
    """Advanced port scanner with service detection."""

    COMMON_PORTS = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 111: 'RPCBind', 135: 'MSRPC',
        139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
        993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle',
        3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
        6379: 'Redis', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
        27017: 'MongoDB', 6443: 'Kubernetes'
    }

    def __init__(self):
        super().__init__("Port Scanner")

    def _tcp_scan_port(self, target: str, port: int, timeout: float = 1.0) -> Tuple[int, bool, str]:
        """Scan a single TCP port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result == 0:
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except:
                    banner = ""
                sock.close()
                service = self.COMMON_PORTS.get(port, 'Unknown')
                return (port, True, service, banner)
            sock.close()
            return (port, False, '', '')
        except Exception:
            return (port, False, '', '')

    def _syn_scan(self, target: str, ports: str = "1-1024") -> Dict:
        """SYN scan using python-nmap (requires nmap installed)."""
        if not NMAP_AVAILABLE:
            self.logger.warning("python-nmap not available, falling back to TCP connect scan")
            return {}

        nm = nmap.PortScanner()
        self.logger.info(f"🔍 Running SYN scan on {target} ports {ports}")
        nm.scan(target, ports, arguments='-sS -sV -O --script=banner')

        results = {}
        for host in nm.all_hosts():
            results[host] = {
                'state': nm[host].state(),
                'protocols': {}
            }

            # OS Detection
            if 'osmatch' in nm[host]:
                results[host]['os_matches'] = [
                    {'name': os['name'], 'accuracy': os['accuracy']}
                    for os in nm[host]['osmatch'][:3]
                ]

            for proto in nm[host].all_protocols():
                results[host]['protocols'][proto] = {}
                ports_list = nm[host][proto].keys()
                for port in sorted(ports_list):
                    port_info = nm[host][proto][port]
                    results[host]['protocols'][proto][port] = {
                        'state': port_info['state'],
                        'service': port_info['name'],
                        'version': port_info.get('version', ''),
                        'product': port_info.get('product', ''),
                        'extra_info': port_info.get('extrainfo', '')
                    }

        return results

    def _tcp_connect_scan(self, target: str, ports: List[int] = None,
                          max_threads: int = 100) -> Dict:
        """TCP connect scan using threading."""
        if ports is None:
            ports = list(range(1, 1025))

        open_ports = []
        self.logger.info(f"🔍 Scanning {len(ports)} ports on {target}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {
                executor.submit(self._tcp_scan_port, target, port): port
                for port in ports
            }

            for future in concurrent.futures.as_completed(futures):
                port, is_open, service, banner = future.result()
                if is_open:
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'banner': banner,
                        'state': 'open'
                    })
                    self.logger.info(
                        f"  ✅ Port {port}/{service} - OPEN"
                        f"{f' [{banner[:50]}]' if banner else ''}"
                    )

        return {
            'target': target,
            'open_ports': sorted(open_ports, key=lambda x: x['port']),
            'total_scanned': len(ports),
            'total_open': len(open_ports)
        }

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run port scan."""
        scan_type = kwargs.get('scan_type', 'tcp')
        ports = kwargs.get('ports', None)
        port_range = kwargs.get('port_range', '1-1024')

        # Resolve hostname
        try:
            ip = socket.gethostbyname(target)
            self.logger.info(f"🎯 Target: {target} ({ip})")
        except socket.gaierror:
            return {"error": f"Cannot resolve hostname: {target}"}

        if scan_type == 'syn' and NMAP_AVAILABLE:
            return self._syn_scan(ip, port_range)
        else:
            if ports is None:
                # Parse port range
                if '-' in str(port_range):
                    start, end = map(int, port_range.split('-'))
                    ports = list(range(start, end + 1))
                else:
                    ports = list(self.COMMON_PORTS.keys())
            return self._tcp_connect_scan(ip, ports)


class ServiceEnumerator(BaseModule):
    """Enumerate services on discovered ports."""

    def __init__(self):
        super().__init__("Service Enumerator")

    def grab_banner(self, target: str, port: int, timeout: float = 3.0) -> str:
        """Grab service banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))

            # Send probe based on port
            probes = {
                80: b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n",
                443: b"",
                21: b"",
                22: b"",
                25: b"EHLO test\r\n",
            }

            probe = probes.get(port, b"\r\n")
            if probe:
                sock.send(probe)

            banner = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            return banner.strip()
        except Exception as e:
            return f"Error: {str(e)}"

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Enumerate services on open ports."""
        ports = kwargs.get('ports', [22, 80, 443])
        results = {}

        for port in ports:
            banner = self.grab_banner(target, port)
            results[port] = {
                'banner': banner,
                'port': port
            }
            self.logger.info(f"Port {port}: {banner[:100]}")

        return results