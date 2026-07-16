import socket
import concurrent.futures
from typing import Dict, Any, List, Tuple
from core.base_module import BaseModule
from config.settings import config


def get_ip_for_target(target: str) -> str:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f"Cannot resolve hostname: {target}")


def grab_banner(target: str, port: int, timeout: float = 3.0) -> str:
    """Grab service banner from target:port with improved error handling."""
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


class ServiceEnumerator(BaseModule):
    """Enumerate services on discovered ports."""

    def __init__(self):
        super().__init__("Service Enumerator")

    def _scan_port(self, target: str, port: int) -> Tuple[int, str]:
        """Scan a single port and return banner."""
        try:
            ip = get_ip_for_target(target)
            banner = grab_banner(ip, port)
            return port, banner
        except Exception as e:
            return port, f"Error: {str(e)}"

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Enumerate services on open ports."""
        ports = kwargs.get('ports', [22, 80, 443])
        max_threads = kwargs.get('max_threads', config.MAX_THREADS)
        results = {}

        self.logger.info(f"🔍 Scanning {len(ports)} ports on {target}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(self._scan_port, target, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(futures):
                port, banner = future.result()
                results[port] = {
                    'banner': banner,
                    'port': port
                }
                self.logger.info(f"  📡 Port {port}: {banner[:100] if banner and not banner.startswith('Error:') else 'No data'}")

        return {
            'target': target,
            'services': results,
            'total_ports_scanned': len(ports),
            'successful_scans': len([b for b in results.values() if b['banner'] and not b['banner'].startswith('Error:')])
        }



def create_module_file(file_path: str, file_content: str) -> None:
    """Create a module file with proper directory structure."""
    from pathlib import Path
    Path(file_path).parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, 'w') as f:
        f.write(file_content)