import os
import hashlib
import struct
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
from core.base_module import BaseModule


class DiskForensics(BaseModule):
    """
    Disk image and filesystem forensics.
    Supports: raw image analysis, partition table parsing,
              deleted file detection, slack space analysis.
    """

    # Common file signatures (magic bytes)
    FILE_SIGNATURES = {
        # Images
        b'\xff\xd8\xff':         ('JPEG', '.jpg'),
        b'\x89PNG\r\n\x1a\n':   ('PNG',  '.png'),
        b'GIF87a':               ('GIF',  '.gif'),
        b'GIF89a':               ('GIF',  '.gif'),
        b'BM':                   ('BMP',  '.bmp'),
        # Documents
        b'%PDF':                 ('PDF',  '.pdf'),
        b'\xd0\xcf\x11\xe0':    ('OLE/Office', '.doc/.xls/.ppt'),
        b'PK\x03\x04':          ('ZIP/DOCX/XLSX', '.zip'),
        b'PK\x05\x06':          ('ZIP Empty', '.zip'),
        # Executables
        b'MZ':                   ('PE Executable', '.exe/.dll'),
        b'\x7fELF':              ('ELF Binary',    '.elf'),
        # Archives
        b'\x1f\x8b':            ('GZip',  '.gz'),
        b'BZh':                  ('BZip2', '.bz2'),
        b'7z\xbc\xaf\x27\x1c': ('7-Zip', '.7z'),
        b'Rar!':                 ('RAR',   '.rar'),
        # Media
        b'ID3':                  ('MP3',  '.mp3'),
        b'fLaC':                 ('FLAC', '.flac'),
        b'\x00\x00\x00\x20ftyp':('MP4',  '.mp4'),
        # Database
        b'SQLite format 3':      ('SQLite DB', '.db/.sqlite'),
        # Scripts
        b'#!/':                  ('Script/Shebang', '.sh/.py'),
    }

    MBR_PARTITION_TYPES = {
        0x00: 'Empty',
        0x01: 'FAT12',
        0x04: 'FAT16 < 32MB',
        0x05: 'Extended',
        0x06: 'FAT16',
        0x07: 'NTFS / exFAT',
        0x0B: 'FAT32',
        0x0C: 'FAT32 (LBA)',
        0x0E: 'FAT16 (LBA)',
        0x0F: 'Extended (LBA)',
        0x82: 'Linux Swap',
        0x83: 'Linux',
        0x8E: 'Linux LVM',
        0xA8: 'macOS X',
        0xAF: 'macOS X HFS+',
        0xEE: 'GPT Protective MBR',
        0xEF: 'EFI System Partition',
        0xFB: 'VMware VMFS',
        0xFC: 'VMware Swap',
    }

    def __init__(self):
        super().__init__("Disk Forensics")

    # ──────────────────────────────────────────────────────────────────────────
    # Hashing
    # ──────────────────────────────────────────────────────────────────────────

    def hash_image(self, image_path: str,
                   algorithms: List[str] = None) -> Dict[str, str]:
        """Compute forensic hashes of a disk image (chunked for large files)."""
        if algorithms is None:
            algorithms = ['md5', 'sha1', 'sha256']

        hashers = {alg: hashlib.new(alg) for alg in algorithms}
        size    = 0
        chunk   = 1024 * 1024  # 1 MB

        self.logger.info(f"  🔑 Hashing image: {image_path}")
        with open(image_path, 'rb') as f:
            while True:
                data = f.read(chunk)
                if not data:
                    break
                for h in hashers.values():
                    h.update(data)
                size += len(data)

        hashes = {alg: h.hexdigest() for alg, h in hashers.items()}
        hashes['size_bytes'] = size
        hashes['size_human'] = self._human_size(size)
        return hashes

    def _human_size(self, size: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"

    # ──────────────────────────────────────────────────────────────────────────
    # MBR / Partition table
    # ──────────────────────────────────────────────────────────────────────────

    def parse_mbr(self, image_path: str) -> Dict:
        """Parse Master Boot Record and partition table."""
        result = {
            'mbr_found': False,
            'partitions': [],
            'bootstrap_hash': None,
            'disk_signature': None,
        }

        try:
            with open(image_path, 'rb') as f:
                mbr = f.read(512)

            if len(mbr) < 512:
                result['error'] = 'File too small to contain MBR'
                return result

            # MBR signature
            if mbr[510:512] != b'\x55\xaa':
                result['error'] = 'MBR signature (0x55AA) not found'
                return result

            result['mbr_found']       = True
            result['bootstrap_hash']  = hashlib.md5(mbr[:446]).hexdigest()
            result['disk_signature']  = mbr[440:444].hex()

            # Parse 4 primary partition entries (16 bytes each, offset 446)
            for i in range(4):
                offset = 446 + i * 16
                entry  = mbr[offset:offset + 16]
                if len(entry) < 16:
                    break

                status      = entry[0]
                part_type   = entry[4]
                lba_start   = struct.unpack_from('<I', entry, 8)[0]
                lba_size    = struct.unpack_from('<I', entry, 12)[0]

                if lba_size == 0:
                    continue

                partition = {
                    'index':       i + 1,
                    'status':      '0x80 (Bootable)' if status == 0x80 else hex(status),
                    'type_id':     hex(part_type),
                    'type_name':   self.MBR_PARTITION_TYPES.get(part_type, 'Unknown'),
                    'lba_start':   lba_start,
                    'lba_size':    lba_size,
                    'size_bytes':  lba_size * 512,
                    'size_human':  self._human_size(lba_size * 512),
                    'offset_bytes': lba_start * 512,
                }
                result['partitions'].append(partition)
                self.logger.info(
                    f"  💾 Partition {i + 1}: {partition['type_name']} "
                    f"| Start: {lba_start} | Size: {partition['size_human']}"
                )

        except Exception as exc:
            result['error'] = str(exc)

        return result

    # ──────────────────────────────────────────────────────────────────────────
    # File carving
    # ──────────────────────────────────────────────────────────────────────────

    def carve_files(self, image_path: str,
                    output_dir: str = 'output/carved',
                    signatures: Dict = None) -> Dict:
        """
        Carve files from raw image using magic bytes.
        Only header-based carving (no footer detection for brevity).
        """
        os.makedirs(output_dir, exist_ok=True)

        if signatures is None:
            signatures = self.FILE_SIGNATURES

        self.logger.info(f"  🔪 Carving files from {image_path}")

        carved   = []
        chunk    = 1024 * 1024   # 1 MB read window
        overlap  = 16            # bytes to carry over (max sig length)
        offset   = 0
        file_idx = 0

        sig_list = [(sig, ft, ext) for sig, (ft, ext) in signatures.items()]
        max_sig  = max(len(s[0]) for s in sig_list)

        try:
            with open(image_path, 'rb') as f:
                buffer = b''
                while True:
                    data = f.read(chunk)
                    if not data:
                        break
                    buffer += data

                    # Search for signatures
                    for sig, file_type, ext in sig_list:
                        pos = 0
                        while True:
                            idx = buffer.find(sig, pos)
                            if idx == -1:
                                break

                            abs_offset = offset + idx
                            # Extract up to 10 MB per carved file
                            carved_data = buffer[idx: idx + 10 * 1024 * 1024]

                            out_filename = (
                                f"{output_dir}/carved_{file_idx:04d}"
                                f"_0x{abs_offset:08X}{ext.split('/')[0]}"
                            )

                            with open(out_filename, 'wb') as out:
                                out.write(carved_data)

                            entry = {
                                'index':      file_idx,
                                'type':       file_type,
                                'extension':  ext,
                                'offset':     abs_offset,
                                'offset_hex': hex(abs_offset),
                                'filename':   out_filename,
                                'size_bytes': len(carved_data),
                                'md5':        hashlib.md5(carved_data).hexdigest(),
                            }
                            carved.append(entry)
                            self.logger.info(
                                f"    ✂️  [{file_idx:04d}] {file_type} "
                                f"@ 0x{abs_offset:08X} → {out_filename}"
                            )
                            file_idx += 1
                            pos = idx + len(sig)

                    # Keep overlap for cross-chunk signatures
                    offset += len(buffer) - overlap
                    buffer  = buffer[-overlap:]

        except PermissionError:
            return {'error': 'Permission denied reading image'}
        except Exception as exc:
            return {'error': str(exc)}

        self.logger.info(f"  ✅ Carved {file_idx} files → {output_dir}")

        return {
            'image':         image_path,
            'output_dir':    output_dir,
            'total_carved':  file_idx,
            'files':         carved,
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Slack space
    # ──────────────────────────────────────────────────────────────────────────

    def analyze_slack_space(self, directory: str,
                            cluster_size: int = 4096) -> Dict:
        """
        Estimate file slack space in a directory.
        Slack = allocated clusters - actual file size.
        """
        total_slack  = 0
        file_details = []

        for root, _, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                try:
                    actual_size    = os.path.getsize(filepath)
                    clusters_used  = (actual_size + cluster_size - 1) // cluster_size
                    allocated_size = clusters_used * cluster_size
                    slack          = allocated_size - actual_size

                    if slack > 0:
                        total_slack += slack
                        file_details.append({
                            'file':      filepath,
                            'size':      actual_size,
                            'allocated': allocated_size,
                            'slack':     slack,
                        })
                except (OSError, PermissionError):
                    continue

        return {
            'directory':       directory,
            'cluster_size':    cluster_size,
            'total_slack':     total_slack,
            'total_slack_hr':  self._human_size(total_slack),
            'files_with_slack': len(file_details),
            'details':         sorted(file_details,
                                      key=lambda x: x['slack'],
                                      reverse=True)[:50],
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Timeline
    # ──────────────────────────────────────────────────────────────────────────

    def build_timeline(self, directory: str,
                       start_ts: float = None,
                       end_ts:   float = None) -> Dict:
        """Build MAC(b) timeline for all files in directory."""
        events = []

        for root, dirs, files in os.walk(directory):
            for name in files + dirs:
                path = os.path.join(root, name)
                try:
                    st = os.stat(path)
                    for ts, event_type in [
                        (st.st_mtime, 'Modified'),
                        (st.st_atime, 'Accessed'),
                        (st.st_ctime, 'Changed/Created'),
                    ]:
                        if start_ts and ts < start_ts:
                            continue
                        if end_ts and ts > end_ts:
                            continue
                        events.append({
                            'timestamp':    ts,
                            'datetime':     datetime.fromtimestamp(ts).isoformat(),
                            'event':        event_type,
                            'path':         path,
                            'size':         st.st_size,
                            'is_directory': os.path.isdir(path),
                        })
                except (OSError, PermissionError):
                    continue

        events.sort(key=lambda x: x['timestamp'])
        return {
            'directory':   directory,
            'total_events': len(events),
            'timeline':    events,
            'earliest':    events[0]['datetime']  if events else None,
            'latest':      events[-1]['datetime'] if events else None,
        }

    # ──────────────────────────────────────────────────────────────────────────
    # run()
    # ──────────────────────────────────────────────────────────────────────────

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        target  : path to disk image OR directory
        kwargs:
            action : 'hash' | 'mbr' | 'carve' | 'slack' | 'timeline' | 'full'
            output_dir : str
        """
        action     = kwargs.get('action', 'full')
        output_dir = kwargs.get('output_dir', 'output/disk_forensics')

        if not os.path.exists(target):
            return {'error': f'Target not found: {target}'}

        self.logger.info(f"💿 Disk Forensics — action: {action} → {target}")

        results: Dict[str, Any] = {
            'target': target,
            'action': action,
            'timestamp': datetime.now().isoformat(),
        }

        if action in ('hash', 'full'):
            self.logger.info("  🔑 Computing image hashes...")
            results['hashes'] = self.hash_image(target)

        if action in ('mbr', 'full') and os.path.isfile(target):
            self.logger.info("  📋 Parsing MBR / partition table...")
            results['mbr'] = self.parse_mbr(target)

        if action in ('carve', 'full') and os.path.isfile(target):
            self.logger.info("  ✂️  Carving files...")
            results['carved'] = self.carve_files(
                target, output_dir=os.path.join(output_dir, 'carved')
            )

        if action in ('slack', 'full') and os.path.isdir(target):
            self.logger.info("  🗂️  Analyzing slack space...")
            results['slack'] = self.analyze_slack_space(target)

        if action in ('timeline', 'full'):
            scan_target = target if os.path.isdir(target) else os.path.dirname(target)
            self.logger.info(f"  📅 Building timeline for {scan_target}...")
            results['timeline'] = self.build_timeline(scan_target)

        return results