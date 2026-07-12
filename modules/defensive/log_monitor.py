import os
import re
import time
import threading
from pathlib import Path
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, Any, List, Callable, Optional
from core.base_module import BaseModule

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False


class LogMonitor(BaseModule):
    """
    Real-time log file monitor with pattern alerting.
    Watches log files for suspicious entries and raises alerts.
    """

    DEFAULT_PATTERNS = [
        {
            'name':     'Failed Login',
            'pattern':  re.compile(
                r'(?i)(failed password|authentication failure|'
                r'invalid user|failed login|login failed)',
                re.IGNORECASE
            ),
            'severity': 'Medium',
            'count_threshold': 5,  # Alert after N occurrences per window
            'time_window':     60,  # seconds
        },
        {
            'name':     'Successful Root Login',
            'pattern':  re.compile(r'(?i)(accepted.+root|root.+accepted)', re.IGNORECASE),
            'severity': 'High',
            'count_threshold': 1,
            'time_window':     3600,
        },
        {
            'name':     'Sudo Usage',
            'pattern':  re.compile(r'sudo:\s+\S+\s+:.*COMMAND=', re.IGNORECASE),
            'severity': 'Low',
            'count_threshold': 10,
            'time_window':     300,
        },
        {
            'name':     'SSH Brute Force',
            'pattern':  re.compile(
                r'(?i)(too many authentication|maximum authentication attempts)',
                re.IGNORECASE
            ),
            'severity': 'High',
            'count_threshold': 1,
            'time_window':     60,
        },
        {
            'name':     'Service Crash',
            'pattern':  re.compile(
                r'(?i)(segfault|core dumped|killed process|out of memory)',
                re.IGNORECASE
            ),
            'severity': 'Medium',
            'count_threshold': 1,
            'time_window':     300,
        },
        {
            'name':     'Privilege Escalation',
            'pattern':  re.compile(
                r'(?i)(escalat|setuid|su -|su root|sudo su)',
                re.IGNORECASE
            ),
            'severity': 'High',
            'count_threshold': 3,
            'time_window':     300,
        },
        {
            'name':     'Web Attack',
            'pattern':  re.compile(
                r'(?i)(union\s+select|<script|\.\.\/|etc\/passwd|'
                r'cmd\.exe|powershell|wget\s+http|curl\s+http)',
                re.IGNORECASE
            ),
            'severity': 'Critical',
            'count_threshold': 1,
            'time_window':     60,
        },
        {
            'name':     'Firewall Block',
            'pattern':  re.compile(
                r'(?i)(blocked|denied|dropped|rejected)',
                re.IGNORECASE
            ),
            'severity': 'Low',
            'count_threshold': 100,
            'time_window':     60,
        },
    ]

    def __init__(self):
        super().__init__("Log Monitor")
        self.alerts:      List[Dict]     = []
        self.running:     bool           = False
        self.callbacks:   List[Callable] = []
        # Pattern hit counters: {pattern_name: deque of timestamps}
        self._hit_counts: Dict[str, deque] = defaultdict(deque)

    # ──────────────────────────────────────────────────────────────────────────
    # Alert
    # ──────────────────────────────────────────────────────────────────────────

    def _raise_alert(self, pattern_cfg: Dict, line: str,
                     filepath: str, count: int) -> None:
        alert = {
            'name':       pattern_cfg['name'],
            'severity':   pattern_cfg['severity'],
            'file':       filepath,
            'line':       line.strip()[:300],
            'count':      count,
            'threshold':  pattern_cfg['count_threshold'],
            'timestamp':  datetime.now().isoformat(),
        }
        self.alerts.append(alert)

        level = {'Critical': '🚨', 'High': '🔴', 'Medium': '🟡', 'Low': '🟢'}.get(
            pattern_cfg['severity'], '⚠️'
        )
        self.logger.warning(
            f"{level} [{pattern_cfg['severity']}] {pattern_cfg['name']} "
            f"(×{count} in {pattern_cfg['time_window']}s) | {filepath}"
        )

        for cb in self.callbacks:
            try:
                cb(alert)
            except Exception:
                pass

    def add_callback(self, fn: Callable) -> None:
        self.callbacks.append(fn)

    # ──────────────────────────────────────────────────────────────────────────
    # Pattern matching
    # ──────────────────────────────────────────────────────────────────────────

    def _process_line(self, line: str, filepath: str,
                      patterns: List[Dict]) -> None:
        """Match a single log line against all patterns."""
        now = time.time()
        for cfg in patterns:
            if cfg['pattern'].search(line):
                name   = cfg['name']
                window = cfg['time_window']
                hits   = self._hit_counts[name]

                # Prune old hits
                while hits and now - hits[0] > window:
                    hits.popleft()

                hits.append(now)
                count = len(hits)

                if count >= cfg['count_threshold']:
                    self._raise_alert(cfg, line, filepath, count)
                    self._hit_counts[name].clear()   # Reset after alert

    # ──────────────────────────────────────────────────────────────────────────
    # Tail file (real-time)
    # ──────────────────────────────────────────────────────────────────────────

    def tail_file(self, filepath: str,
                  patterns:  List[Dict] = None,
                  duration:  int        = 60) -> Dict:
        """
        Tail a log file and apply pattern matching in real-time.
        Similar to `tail -f` with IDS pattern matching.
        """
        if patterns is None:
            patterns = self.DEFAULT_PATTERNS

        if not os.path.exists(filepath):
            return {'error': f'File not found: {filepath}'}

        self.logger.info(f"👁️  Monitoring: {filepath} (duration: {duration}s)")
        self.running    = True
        start_time      = time.time()
        lines_processed = 0

        try:
            with open(filepath, 'r', errors='ignore') as f:
                # Seek to end
                f.seek(0, 2)
                while self.running and (time.time() - start_time) < duration:
                    line = f.readline()
                    if line:
                        self._process_line(line, filepath, patterns)
                        lines_processed += 1
                    else:
                        time.sleep(0.1)
        except KeyboardInterrupt:
            self.logger.info("  ⏹️  Monitoring stopped by user")
        except Exception as exc:
            return {'error': str(exc)}
        finally:
            self.running = False

        return {
            'file':             filepath,
            'duration_seconds': int(time.time() - start_time),
            'lines_processed':  lines_processed,
            'total_alerts':     len(self.alerts),
            'alerts':           self.alerts,
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Scan existing file
    # ──────────────────────────────────────────────────────────────────────────

    def scan_file(self, filepath: str,
                  patterns: List[Dict] = None) -> Dict:
        """Scan an existing log file for pattern matches."""
        if patterns is None:
            patterns = self.DEFAULT_PATTERNS

        if not os.path.exists(filepath):
            return {'error': f'File not found: {filepath}'}

        self.logger.info(f"🔍 Scanning log file: {filepath}")
        self.alerts     = []
        lines_processed = 0

        with open(filepath, 'r', errors='ignore') as f:
            for line in f:
                self._process_line(line, filepath, patterns)
                lines_processed += 1

        severity_counts: Dict[str, int] = defaultdict(int)
        for a in self.alerts:
            severity_counts[a['severity']] += 1

        return {
            'file':             filepath,
            'lines_processed':  lines_processed,
            'total_alerts':     len(self.alerts),
            'severity_summary': dict(severity_counts),
            'alerts':           self.alerts,
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Watch directory
    # ──────────────────────────────────────────────────────────────────────────

    def watch_directory(self, directory: str,
                        patterns:  List[Dict] = None,
                        duration:  int        = 300) -> Dict:
        """
        Watch a directory for new/modified log files using watchdog.
        """
        if not WATCHDOG_AVAILABLE:
            return {'error': 'watchdog not installed: pip install watchdog'}

        if patterns is None:
            patterns = self.DEFAULT_PATTERNS

        monitor_ref = self

        class LogHandler(FileSystemEventHandler):
            def on_modified(self, event):
                if not event.is_directory and event.src_path.endswith('.log'):
                    monitor_ref.logger.info(f"  📄 Modified: {event.src_path}")
                    monitor_ref.scan_file(event.src_path, patterns)

            def on_created(self, event):
                if not event.is_directory:
                    monitor_ref.logger.info(f"  ✨ New file: {event.src_path}")

        observer = Observer()
        observer.schedule(LogHandler(), directory, recursive=True)
        observer.start()

        self.logger.info(f"👁️  Watching directory: {directory} ({duration}s)")

        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            pass
        finally:
            observer.stop()
            observer.join()

        return {
            'directory':    directory,
            'duration':     duration,
            'total_alerts': len(self.alerts),
            'alerts':       self.alerts,
        }

    # ──────────────────────────────────────────────────────────────────────────
    # run()
    # ──────────────────────────────────────────────────────────────────────────

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        target  : log file path or directory
        kwargs:
            mode     : 'scan' | 'tail' | 'watch'
            duration : seconds for tail/watch mode (default 60)
        """
        mode     = kwargs.get('mode', 'scan')
        duration = kwargs.get('duration', 60)

        self.logger.info(f"📋 Log Monitor — mode: {mode} → {target}")

        if mode == 'scan':
            return self.scan_file(target)
        elif mode == 'tail':
            return self.tail_file(target, duration=duration)
        elif mode == 'watch':
            return self.watch_directory(target, duration=duration)
        else:
            return {'error': f'Unknown mode: {mode}. Use scan|tail|watch'}