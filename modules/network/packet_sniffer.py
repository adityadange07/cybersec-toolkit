from typing import Dict, Any
from core.base_module import BaseModule

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, ARP, Raw, wrpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PacketSniffer(BaseModule):
    """Network packet sniffer and analyzer."""

    def __init__(self):
        super().__init__("Packet Sniffer")
        self.captured_packets = []
        self.stats = {
            'total': 0, 'tcp': 0, 'udp': 0, 'dns': 0,
            'arp': 0, 'http': 0, 'https': 0, 'other': 0
        }

    def _packet_callback(self, packet):
        """Process each captured packet."""
        self.stats['total'] += 1
        packet_info = {'summary': packet.summary()}

        if IP in packet:
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            packet_info['protocol'] = packet[IP].proto

        if TCP in packet:
            self.stats['tcp'] += 1
            packet_info['src_port'] = packet[TCP].sport
            packet_info['dst_port'] = packet[TCP].dport
            packet_info['flags'] = str(packet[TCP].flags)

            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                self.stats['http'] += 1
                if Raw in packet:
                    try:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        if 'HTTP' in payload:
                            packet_info['http_data'] = payload[:500]
                    except:
                        pass

            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                self.stats['https'] += 1

        elif UDP in packet:
            self.stats['udp'] += 1
            packet_info['src_port'] = packet[UDP].sport
            packet_info['dst_port'] = packet[UDP].dport

            if DNS in packet:
                self.stats['dns'] += 1
                if packet[DNS].qd:
                    packet_info['dns_query'] = packet[DNS].qd.qname.decode()
                if packet[DNS].an:
                    packet_info['dns_answer'] = str(packet[DNS].an.rdata)

        elif ARP in packet:
            self.stats['arp'] += 1
            packet_info['arp_op'] = 'Request' if packet[ARP].op == 1 else 'Reply'
            packet_info['arp_src'] = packet[ARP].psrc
            packet_info['arp_dst'] = packet[ARP].pdst

        self.captured_packets.append(packet_info)

        # Live display
        if self.stats['total'] % 10 == 0:
            self.logger.info(f"  📦 Captured: {self.stats['total']} packets "
                           f"(TCP:{self.stats['tcp']} UDP:{self.stats['udp']} "
                           f"DNS:{self.stats['dns']} ARP:{self.stats['arp']})")

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run packet sniffer."""
        if not SCAPY_AVAILABLE:
            return {"error": "scapy is required. Install with: pip install scapy"}

        interface = kwargs.get('interface', None)
        count = kwargs.get('count', 100)
        timeout = kwargs.get('timeout', 30)
        bpf_filter = kwargs.get('filter', '')
        output_pcap = kwargs.get('output', None)

        self.logger.info(f"📡 Starting packet capture (count={count}, timeout={timeout}s)")
        if bpf_filter:
            self.logger.info(f"  🔍 Filter: {bpf_filter}")

        try:
            packets = sniff(
                iface=interface,
                count=count,
                timeout=timeout,
                filter=bpf_filter,
                prn=self._packet_callback,
                store=True
            )

            # Save to pcap if requested
            if output_pcap:
                wrpcap(output_pcap, packets)
                self.logger.info(f"💾 Saved {len(packets)} packets to {output_pcap}")

        except PermissionError:
            return {"error": "Root/Admin privileges required for packet capture"}
        except Exception as e:
            return {"error": str(e)}

        return {
            'statistics': self.stats,
            'packets': self.captured_packets[-50:],  # Last 50 packets
            'total_captured': len(self.captured_packets)
        }


class ARPScanner(BaseModule):
    """ARP-based network scanner for host discovery."""

    def __init__(self):
        super().__init__("ARP Scanner")

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Scan network using ARP."""
        if not SCAPY_AVAILABLE:
            return {"error": "scapy is required"}

        from scapy.all import Ether, ARP, srp

        self.logger.info(f"📡 ARP scanning network: {target}")

        try:
            arp_request = ARP(pdst=target)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request

            answered, _ = srp(packet, timeout=3, verbose=False)

            hosts = []
            for sent, received in answered:
                host = {
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'vendor': self._lookup_vendor(received.hwsrc)
                }
                hosts.append(host)
                self.logger.info(f"  🖥️  {host['ip']} - {host['mac']} ({host['vendor']})")

            return {
                'network': target,
                'hosts': hosts,
                'total_hosts': len(hosts)
            }
        except PermissionError:
            return {"error": "Root/Admin privileges required"}

    def _lookup_vendor(self, mac: str) -> str:
        """Lookup MAC vendor (basic)."""
        # In production, use a MAC vendor database
        prefix = mac[:8].upper().replace(':', '-')
        common_vendors = {
            '00-50-56': 'VMware',
            '08-00-27': 'VirtualBox',
            'DC-A6-32': 'Raspberry Pi',
            'B8-27-EB': 'Raspberry Pi',
            '00-0C-29': 'VMware',
        }
        return common_vendors.get(prefix, 'Unknown')