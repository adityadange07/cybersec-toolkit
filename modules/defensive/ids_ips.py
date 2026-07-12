import re
import time
import threading
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, Any, List, Callable
from core.base_module import BaseModule

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class IDSEngine(BaseModule):
    """
    Lightweight signature and anomaly-based IDS/IPS engine.
    Monitors live traffic or analyses PCAP-like packet lists.
    """

    # ── Signature rules ───────────────────────────────────────────────────────
    SIGNATURE_RULES = [
        {
            'id':          'SIG-001',
            'name':        'Port Scan Detection',
            'description': 'Multiple ports accessed from single source in short time',
            'severity':    'Medium',
            'type':        'anomaly',
        },
        {
            'id':          'SIG-002',
            'name':        'Brute Force SSH',
            'description': 'High rate of TCP SYN to port 22',
            'severity':    'High',
            'type':        'anomaly',
            'port':        22,
        },
        {
            'id':          'SIG-003',
            'name':        'Brute Force RDP',
            'description': 'High rate of TCP SYN to port 3389',
            'severity':    'High',
            'type':        'anomaly',
            'port':        3389,
        },
        {
            'id':          'SIG-004',
            'name':        'SQL Injection Attempt',
            'description': 'HTTP payload contains SQL injection patterns',
            'severity':    'Critical',
            'type':        'signature',
            'pattern':     rb"(?i)(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|drop\s+table)",
        },
        {
            'id':          'SIG-005',
            'name':        'XSS Attempt',
            'description': 'HTTP payload contains XSS patterns',
            'severity':    'High',
            'type':        'signature',
            'pattern':     rb'(?i)(<script|javascript:|onerror\s*=|onload\s*=)',
        },
        {
            'id':          'SIG-006',
            'name':        'Directory Traversal',
            'description': 'Path traversal attempt detected',
            'severity':    'High',
            'type':        'signature',
            'pattern':     rb'(\.\./|\.\.\\|%2e%2e%2f)',
        },
        {
            'id':          'SIG-007',
            'name':        'Command Injection',
            'description': 'Shell command injection attempt',
            'severity':    'Critical',
            'type':        'signature',
            'pattern':     rb'(?i)(\||\;)\s*(cat|ls|dir|whoami|id|uname|pwd|wget|curl)',
        },
        {
            'id':          'SIG-008',
            'name':        'ICMP Flood',
            'description': 'High volume ICMP packets from single source',
            'severity':    'Medium',
            'type':        'anomaly',
        },
        {
            'id':          'SIG-009',
            'name':        'Large Payload',
            'description': 'Abnormally large packet payload (possible buffer overflow)',
            'severity':    'Medium',
            'type':        'anomaly',
            'threshold':   65000,
        },
        {
            'id':          'SIG-010',
            'name':        'Null Byte Injection',
            'description': 'Null byte in HTTP request',
            'severity':    'High',
            'type':        'signature',
            'pattern':     b'\x00',
        },
    ]

    def __init__(self):
        super().__init__("IDS/IPS Engine")
        self.alerts:          List[Dict]           = []
        self.packet_count:    int                  = 0
        self.running:         bool                 = False
        self.alert_callbacks: List[Callable]       = []

        # Anomaly tracking
        self._ip_ports:        defaultdict = defaultdict(set)          # ip → {ports}
        self._ip_timestamps:   defaultdict = defaultdict(deque)        # ip → timestamps
        self._icmp_count:      defaultdict = defaultdict(int)          # ip → count
        self._port_syn_count:  defaultdict = defaultdict(lambda: defaultdict(int))

        # Thresholds
        self.PORT_SCAN_THRESHOLD  = 20    # unique ports / 10 seconds
        self.BRUTE_FORCE_THRESHOLD = 10   # SYNs / 5 seconds to same port
        self.ICMP_FLOOD_THRESHOLD  = 100  # ICMP packets / 10 seconds
        self.TIME_WINDOW           = 10   # seconds

    # ──────────────────────────────────────────────────────────────────────────
    # Alert management
    # ──────────────────────────────────────────────────────────────────────────

    def _raise_alert(self, rule: Dict, src_ip: str,
                     dst_ip: str = '', extra: str = '') -> None:
        alert = {
            'id':          rule['id'],
            'name':        rule['name'],
            'description': rule['description'],
            'severity':    rule['severity'],
            'src_ip':      src_ip,
            'dst_ip':      dst_ip,
            'extra':       extra,
            'timestamp':   datetime.now().isoformat(),
            'packet_no':   self.packet_count,
        }
        self.alerts.append(alert)

        level = {
            'Critical': '🚨',
            'High':     '🔴',
            'Medium':   '🟡',
            'Low':      '🟢',
        }.get(rule['severity'], '⚠️')

        self.logger.warning(
            f"{level} ALERT [{rule['id']}] {rule['name']} | "
            f"src={src_ip} dst={dst_ip} | {extra}"
        )

        for cb in self.alert_callbacks:
            try:
                cb(alert)
            except Exception:
                pass

    def add_alert_callback(self, callback: Callable) -> None:
        """Register a function to call when an alert fires."""
        self.alert_callbacks.append(callback)

    # ──────────────────────────────────────────────────────────────────────────
    # Packet analysis
    # ──────────────────────────────────────────────────────────────────────────

    def _cleanup_old_entries(self, ip: str, window: float) -> None:
        """Remove timestamps older than the time window."""
        now  = time.time()
        dq   = self._ip_timestamps[ip]
        while dq and now - dq[0] > window:
            dq.popleft()

    def analyze_packet(self, pkt) -> None:
        """Process a single scapy packet through all rules."""
        self.packet_count += 1
        now = time.time()

        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        # Track timestamps
        self._ip_timestamps[src_ip].append(now)
        self._cleanup_old_entries(src_ip, self.TIME_WINDOW)

        # ── TCP checks ────────────────────────────────────────────────────────
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            flags = int(pkt[TCP].flags)
            SYN   = 0x02

            # Track ports (port scan detection)
            self._ip_ports[src_ip].add(dport)
            if len(self._ip_ports[src_ip]) > self.PORT_SCAN_THRESHOLD:
                rule = next(r for r in self.SIGNATURE_RULES if r['id'] == 'SIG-001')
                self._raise_alert(
                    rule, src_ip, dst_ip,
                    f"Scanned {len(self._ip_ports[src_ip])} unique ports"
                )
                self._ip_ports[src_ip].clear()  # Reset to avoid repeated alerts

            # Brute force detection (SYN flood on specific port)
            if flags & SYN:
                self._port_syn_count[src_ip][dport] += 1
                for rule in self.SIGNATURE_RULES:
                    if rule.get('port') == dport:
                        count = self._port_syn_count[src_ip][dport]
                        if count >= self.BRUTE_FORCE_THRESHOLD:
                            self._raise_alert(
                                rule, src_ip, dst_ip,
                                f"{count} SYNs to port {dport}"
                            )
                            self._port_syn_count[src_ip][dport] = 0

            # Payload inspection
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                self._check_payload_signatures(payload, src_ip, dst_ip)

                # Large payload
                if len(payload) > 65000:
                    rule = next(r for r in self.SIGNATURE_RULES if r['id'] == 'SIG-009')
                    self._raise_alert(
                        rule, src_ip, dst_ip,
                        f"Payload size: {len(payload)} bytes"
                    )

        # ── ICMP flood check ──────────────────────────────────────────────────
        if pkt.haslayer(ICMP):
            self._icmp_count[src_ip] += 1
            if self._icmp_count[src_ip] >= self.ICMP_FLOOD_THRESHOLD:
                rule = next(r for r in self.SIGNATURE_RULES if r['id'] == 'SIG-008')
                self._raise_alert(
                    rule, src_ip, dst_ip,
                    f"{self._icmp_count[src_ip]} ICMP packets"
                )
                self._icmp_count[src_ip] = 0

    def _check_payload_signatures(self, payload: bytes,
                                   src_ip: str, dst_ip: str) -> None:
        """Match payload against signature rules."""
        sig_rules = [r for r in self.SIGNATURE_RULES
                     if r['type'] == 'signature' and 'pattern' in r]
        for rule in sig_rules:
            pattern = rule['pattern']
            if isinstance(pattern, bytes):
                if re.search(pattern, payload):
                    match_ctx = payload[:100].decode('utf-8', errors='replace')
                    self._raise_alert(rule, src_ip, dst_ip, f"Match: {match_ctx!r}")

    # ──────────────────────────────────────────────────────────────────────────
    # Live capture
    # ──────────────────────────────────────────────────────────────────────────

    def start_live_monitoring(self, interface: str = None,
                               bpf_filter: str      = '',
                               count:      int      = 0,
                               timeout:    int      = 60) -> Dict:
        """Start live packet capture and IDS analysis."""
        if not SCAPY_AVAILABLE:
            return {'error': 'scapy not installed: pip install scapy'}

        self.running = True
        self.alerts  = []
        self.logger.info(
            f"🛡️  IDS started — interface: {interface or 'default'} | "
            f"timeout: {timeout}s | filter: {bpf_filter or 'none'}"
        )

        try:
            sniff(
                iface=interface,
                filter=bpf_filter,
                count=count,
                timeout=timeout,
                prn=self.analyze_packet,
                store=False,
            )
        except PermissionError:
            return {'error': 'Root privileges required for live capture'}
        except Exception as exc:
            return {'error': str(exc)}
        finally:
            self.running = False

        return self._build_report()

    # ──────────────────────────────────────────────────────────────────────────
    # Offline analysis
    # ──────────────────────────────────────────────────────────────────────────

    def analyze_pcap(self, pcap_path: str) -> Dict:
        """Analyze a saved PCAP file."""
        if not SCAPY_AVAILABLE:
            return {'error': 'scapy not installed'}
        if not os.path.exists(pcap_path):
            return {'error': f'PCAP not found: {pcap_path}'}

        from scapy.all import rdpcap
        self.alerts  = []
        packets      = rdpcap(pcap_path)
        self.logger.info(f"📂 Analyzing PCAP: {pcap_path} ({len(packets)} packets)")

        for pkt in packets:
            self.analyze_packet(pkt)

        return self._build_report()

    # ──────────────────────────────────────────────────────────────────────────
    # Report
    # ──────────────────────────────────────────────────────────────────────────

    def _build_report(self) -> Dict:
        severity_counts: Dict[str, int] = defaultdict(int)
        for a in self.alerts:
            severity_counts[a['severity']] += 1

        top_sources: Dict[str, int] = defaultdict(int)
        for a in self.alerts:
            top_sources[a['src_ip']] += 1

        return {
            'total_packets_analyzed': self.packet_count,
            'total_alerts':           len(self.alerts),
            'severity_breakdown':     dict(severity_counts),
            'top_source_ips':         sorted(
                top_sources.items(), key=lambda x: x[1], reverse=True
            )[:10],
            'alerts':                 self.alerts,
        }

    # ──────────────────────────────────────────────────────────────────────────
    # run()
    # ──────────────────────────────────────────────────────────────────────────

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        target  : network interface name OR path to PCAP file
        kwargs:
            mode       : 'live' | 'pcap'
            bpf_filter : BPF filter string (live mode)
            count      : packet count limit (0 = unlimited)
            timeout    : seconds to capture (live mode)
        """
        mode       = kwargs.get('mode', 'live')
        bpf_filter = kwargs.get('bpf_filter', '')
        count      = kwargs.get('count', 0)
        timeout    = kwargs.get('timeout', 60)

        self.logger.info(f"🛡️  IDS/IPS Engine — mode: {mode}")

        if mode == 'live':
            return self.start_live_monitoring(
                interface  = target if target != 'auto' else None,
                bpf_filter = bpf_filter,
                count      = count,
                timeout    = timeout,
            )
        elif mode == 'pcap':
            return self.analyze_pcap(target)
        else:
            return {'error': f'Unknown mode: {mode}. Use live or pcap'}