import time
import threading
from typing import Dict, Any, List
from core.base_module import BaseModule

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class BandwidthMonitor(BaseModule):
    """Real-time network bandwidth and connection monitor."""

    def __init__(self):
        super().__init__("Bandwidth Monitor")
        self._running   = False
        self._samples: List[Dict] = []

    @staticmethod
    def _bytes_human(n: float) -> str:
        for unit in ["B/s", "KB/s", "MB/s", "GB/s"]:
            if n < 1024:
                return f"{n:.2f} {unit}"
            n /= 1024
        return f"{n:.2f} TB/s"

    # ── Snapshot ──────────────────────────────────────────────────────────────
    def _snapshot(self, iface: str = None) -> Dict:
        if not PSUTIL_AVAILABLE:
            return {"error": "psutil not installed"}
        counters = psutil.net_io_counters(pernic=True)
        if iface and iface in counters:
            c = counters[iface]
            return {
                "interface":     iface,
                "bytes_sent":    c.bytes_sent,
                "bytes_recv":    c.bytes_recv,
                "packets_sent":  c.packets_sent,
                "packets_recv":  c.packets_recv,
                "err_in":        c.errin,
                "err_out":       c.errout,
                "drop_in":       c.dropin,
                "drop_out":      c.dropout,
                "timestamp":     time.time(),
            }
        # All interfaces aggregate
        c = psutil.net_io_counters()
        return {
            "interface":    "all",
            "bytes_sent":   c.bytes_sent,
            "bytes_recv":   c.bytes_recv,
            "packets_sent": c.packets_sent,
            "packets_recv": c.packets_recv,
            "timestamp":    time.time(),
        }

    def _monitor_loop(self, iface: str, interval: float, duration: float):
        end   = time.time() + duration
        prev  = self._snapshot(iface)
        while self._running and time.time() < end:
            time.sleep(interval)
            curr = self._snapshot(iface)
            dt   = curr["timestamp"] - prev["timestamp"]
            sent = (curr["bytes_sent"] - prev["bytes_sent"]) / dt
            recv = (curr["bytes_recv"] - prev["bytes_recv"]) / dt
            sample = {
                "timestamp":  curr["timestamp"],
                "upload":     self._bytes_human(sent),
                "download":   self._bytes_human(recv),
                "upload_raw": sent,
                "download_raw": recv,
            }
            self._samples.append(sample)
            self.logger.info(
                f"  ↑ {sample['upload']:14s}  ↓ {sample['download']}"
            )
            prev = curr

    # ── Active connections ────────────────────────────────────────────────────
    def _active_connections(self) -> List[Dict]:
        if not PSUTIL_AVAILABLE:
            return []
        conns = []
        for c in psutil.net_connections(kind="inet"):
            try:
                proc = psutil.Process(c.pid).name() if c.pid else "Unknown"
            except Exception:
                proc = "Unknown"
            conns.append({
                "protocol": "TCP" if c.type.name == "SOCK_STREAM" else "UDP",
                "local":    f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                "remote":   f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                "status":   c.status,
                "pid":      c.pid,
                "process":  proc,
            })
        return conns

    # ── Interface list ────────────────────────────────────────────────────────
    def _list_interfaces(self) -> List[Dict]:
        if not PSUTIL_AVAILABLE:
            return []
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        ifaces = []
        for name, addr_list in addrs.items():
            st = stats.get(name)
            ifaces.append({
                "name":    name,
                "is_up":   st.isup if st else False,
                "speed_mbps": st.speed if st else 0,
                "mtu":     st.mtu if st else 0,
                "addresses": [
                    {"family": str(a.family.name), "address": a.address}
                    for a in addr_list
                ],
            })
        return ifaces

    # ── Main ──────────────────────────────────────────────────────────────────
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        target  : interface name (e.g. eth0, wlan0) or 'all'
        kwargs  :
            mode     = 'monitor' | 'connections' | 'interfaces'
            duration = seconds to monitor (default 30)
            interval = sample interval in seconds (default 1)
        """
        mode     = kwargs.get("mode", "monitor")
        duration = kwargs.get("duration", 30)
        interval = kwargs.get("interval", 1)
        iface    = target if target != "all" else None

        if not PSUTIL_AVAILABLE:
            return {"error": "psutil not installed: pip install psutil"}

        if mode == "interfaces":
            return {"interfaces": self._list_interfaces()}

        elif mode == "connections":
            conns = self._active_connections()
            self.logger.info(f"  🔌 {len(conns)} active connections")
            return {"connections": conns, "total": len(conns)}

        else:
            self.logger.info(
                f"📊 Monitoring bandwidth on '{target}' for {duration}s "
                f"(interval {interval}s)"
            )
            self._running = True
            self._samples = []
            self._monitor_loop(iface, interval, duration)
            self._running = False

            if not self._samples:
                return {"error": "No samples collected"}

            uploads   = [s["upload_raw"] for s in self._samples]
            downloads = [s["download_raw"] for s in self._samples]

            return {
                "interface": target,
                "duration":  duration,
                "samples":   self._samples,
                "summary": {
                    "avg_upload":   self._bytes_human(sum(uploads) / len(uploads)),
                    "avg_download": self._bytes_human(sum(downloads) / len(downloads)),
                    "max_upload":   self._bytes_human(max(uploads)),
                    "max_download": self._bytes_human(max(downloads)),
                    "total_samples": len(self._samples),
                },
            }