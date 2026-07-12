import os
import hashlib
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional
from core.base_module import BaseModule


class FileCarver(BaseModule):
    """
    Advanced file carver with header/footer detection,
    fragmented file reconstruction hints, and entropy analysis.
    """

    # (header, footer, max_size_bytes, extension)
    CARVE_RULES: List[Tuple] = [
        # Images
        (b'\xff\xd8\xff',            b'\xff\xd9',           15_000_000, '.jpg'),
        (b'\x89PNG\r\n\x1a\n',      b'IEND\xaeB`\x82',     10_000_000, '.png'),
        (b'GIF87a',                   b'\x00\x3b',            5_000_000, '.gif'),
        (b'GIF89a',                   b'\x00\x3b',            5_000_000, '.gif'),
        (b'BM',                       None,                   50_000_000, '.bmp'),
        # Documents
        (b'%PDF',                     b'%%EOF',              50_000_000, '.pdf'),
        (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', None,        50_000_000, '.doc'),
        (b'PK\x03\x04',              b'PK\x05\x06',         50_000_000, '.zip'),
        # Executables
        (b'MZ',                       None,                  100_000_000, '.exe'),
        (b'\x7fELF',                  None,                  100_000_000, '.elf'),
        # Archives
        (b'\x1f\x8b\x08',            None,                   50_000_000, '.gz'),
        (b'Rar!\x1a\x07',            None,                   50_000_000, '.rar'),
        (b'7z\xbc\xaf\x27\x1c',     None,                   50_000_000, '.7z'),
        # Database
        (b'SQLite format 3\x00',     None,                  500_000_000, '.db'),
        # Media
        (b'ID3',                      None,                   50_000_000, '.mp3'),
        (b'\x00\x00\x00\x18ftyp',   None,                  500_000_000, '.mp4'),
        (b'\x00\x00\x00\x20ftyp',   None,                  500_000_000, '.mp4'),
        # Scripts / text
        (b'#!/bin/bash',              None,                    1_000_000, '.sh'),
        (b'#!/usr/bin/env python',    None,                    1_000_000, '.py'),
        (b'#!/usr/bin/python',        None,                    1_000_000, '.py'),
        # Email
        (b'From ',                    None,                    5_000_000, '.eml'),
        (b'Return-Path:',             None,                    5_000_000, '.eml'),
    ]

    def __init__(self):
        super().__init__("File Carver")

    # ──────────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _human_size(self, n: int) -> str:
        for u in ['B', 'KB', 'MB', 'GB']:
            if n < 1024:
                return f'{n:.1f} {u}'
            n /= 1024
        return f'{n:.1f} TB'

    def _entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        from collections import Counter
        import math
        freq    = Counter(data)
        length  = len(data)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    def _verify_jpeg(self, data: bytes) -> bool:
        return data[:3] == b'\xff\xd8\xff' and data[-2:] == b'\xff\xd9'

    def _verify_png(self, data: bytes) -> bool:
        return data[:8] == b'\x89PNG\r\n\x1a\n' and b'IEND' in data[-12:]

    def _verify_pdf(self, data: bytes) -> bool:
        return data[:4] == b'%PDF' and b'%%EOF' in data[-20:]

    def _verify_zip(self, data: bytes) -> bool:
        return data[:4] == b'PK\x03\x04'

    def _verify_file(self, ext: str, data: bytes) -> bool:
        """Basic file integrity verification after carving."""
        verifiers = {
            '.jpg': self._verify_jpeg,
            '.png': self._verify_png,
            '.pdf': self._verify_pdf,
            '.zip': self._verify_zip,
        }
        verifier = verifiers.get(ext)
        if verifier:
            try:
                return verifier(data)
            except Exception:
                return False
        return True  # No verifier → assume OK

    # ──────────────────────────────────────────────────────────────────────────
    # Core carving
    # ──────────────────────────────────────────────────────────────────────────

    def carve(self, source_path: str,
              output_dir:  str,
              rules:       List[Tuple] = None,
              chunk_size:  int = 4 * 1024 * 1024) -> Dict:
        """
        Carve files from source using header/footer signatures.
        """
        os.makedirs(output_dir, exist_ok=True)

        if rules is None:
            rules = self.CARVE_RULES

        self.logger.info(f"✂️  Carving from {source_path} → {output_dir}")
        self.logger.info(f"   Rules loaded: {len(rules)}")

        carved   = []
        file_idx = 0

        # Load full file into memory (or chunk for very large images)
        file_size = os.path.getsize(source_path)
        self.logger.info(f"   Source size: {self._human_size(file_size)}")

        with open(source_path, 'rb') as f:
            data = f.read()

        for header, footer, max_size, ext in rules:
            offset = 0
            while True:
                start = data.find(header, offset)
                if start == -1:
                    break

                if footer:
                    end = data.find(footer, start + len(header))
                    if end == -1:
                        # No footer found — use max_size
                        end = min(start + max_size, len(data))
                    else:
                        end += len(footer)
                else:
                    end = min(start + max_size, len(data))

                carved_data = data[start:end]

                # Minimum sanity check
                if len(carved_data) < 16:
                    offset = start + 1
                    continue

                # Verify integrity
                valid   = self._verify_file(ext, carved_data)
                entropy = self._entropy(carved_data[:4096])

                filename = (
                    f"{output_dir}/carved_{file_idx:05d}"
                    f"_0x{start:08X}{ext}"
                )
                with open(filename, 'wb') as out_f:
                    out_f.write(carved_data)

                entry = {
                    'index':      file_idx,
                    'extension':  ext,
                    'offset':     start,
                    'offset_hex': hex(start),
                    'size_bytes': len(carved_data),
                    'size_human': self._human_size(len(carved_data)),
                    'md5':        hashlib.md5(carved_data).hexdigest(),
                    'sha256':     hashlib.sha256(carved_data).hexdigest(),
                    'entropy':    round(entropy, 4),
                    'verified':   valid,
                    'filename':   filename,
                }
                carved.append(entry)

                status = '✅' if valid else '⚠️'
                self.logger.info(
                    f"  {status} [{file_idx:05d}] {ext} "
                    f"@ 0x{start:08X} ({self._human_size(len(carved_data))})"
                )
                file_idx += 1
                offset    = start + len(header)

        # Summary by type
        type_counts: Dict[str, int] = {}
        for c in carved:
            type_counts[c['extension']] = type_counts.get(c['extension'], 0) + 1

        self.logger.info(f"  ✅ Total carved: {file_idx}")
        for ext, cnt in sorted(type_counts.items()):
            self.logger.info(f"     {ext}: {cnt}")

        return {
            'source':        source_path,
            'output_dir':    output_dir,
            'total_carved':  file_idx,
            'by_type':       type_counts,
            'files':         carved,
            'timestamp':     datetime.now().isoformat(),
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Deleted file search (NTFS / FAT hint)
    # ──────────────────────────────────────────────────────────────────────────

    def find_deleted_markers(self, source_path: str) -> Dict:
        """
        Look for patterns that indicate recently deleted files.
        On NTFS, deleted $MFT entries have 'FILE' signature with a zero flag.
        On FAT, directory entries start with 0xE5 when deleted.
        """
        markers = {
            'ntfs_deleted_mft': [],
            'fat_deleted':      [],
        }

        self.logger.info("  🗑️  Scanning for deleted file markers...")

        MFT_SIG = b'FILE'
        sector_size = 512

        with open(source_path, 'rb') as f:
            data = f.read()

        # NTFS deleted MFT entries
        offset = 0
        while True:
            idx = data.find(MFT_SIG, offset)
            if idx == -1:
                break
            # Check allocation flag bytes 22-23 (0 = not in use / deleted)
            flag_offset = idx + 22
            if flag_offset + 2 <= len(data):
                flag = struct.unpack_from('<H', data, flag_offset)[0]
                if flag == 0x0000:  # Deleted file record
                    markers['ntfs_deleted_mft'].append({
                        'offset':     idx,
                        'offset_hex': hex(idx),
                    })
            offset = idx + 4

        # FAT deleted entries (0xE5 as first byte of 8.3 filename)
        e5_pattern = re.compile(b'\xe5[\x20-\x7e]{10}[\x00-\xff]' * 1)
        for m in e5_pattern.finditer(data):
            markers['fat_deleted'].append({
                'offset':     m.start(),
                'offset_hex': hex(m.start()),
                'raw':        m.group(0).hex(),
            })

        markers['ntfs_deleted_mft'] = markers['ntfs_deleted_mft'][:100]
        markers['fat_deleted']       = markers['fat_deleted'][:100]

        self.logger.info(
            f"  Found {len(markers['ntfs_deleted_mft'])} NTFS deleted + "
            f"{len(markers['fat_deleted'])} FAT deleted markers"
        )
        return markers

    # ──────────────────────────────────────────────────────────────────────────
    # run()
    # ──────────────────────────────────────────────────────────────────────────

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        target  : path to binary file / disk image
        kwargs:
            action      : 'carve' | 'deleted' | 'full'
            output_dir  : output directory for carved files
        """
        action     = kwargs.get('action', 'carve')
        output_dir = kwargs.get('output_dir', 'output/carved_files')

        if not os.path.exists(target):
            return {'error': f'File not found: {target}'}

        self.logger.info(f"✂️  File Carver — action: {action} → {target}")

        results: Dict[str, Any] = {
            'target':    target,
            'action':    action,
            'timestamp': datetime.now().isoformat(),
        }

        import struct  # Ensure available for inner methods

        if action in ('carve', 'full'):
            results['carved'] = self.carve(target, output_dir)

        if action in ('deleted', 'full'):
            results['deleted_markers'] = self.find_deleted_markers(target)

        return results