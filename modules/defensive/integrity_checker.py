import os
import hashlib
import json
import time
from pathlib import Path
from typing import Dict, Any
from datetime import datetime
from core.base_module import BaseModule


class IntegrityChecker(BaseModule):
    """File integrity monitoring system (FIM)."""

    def __init__(self):
        super().__init__("File Integrity Checker")
        self.baseline_file = Path("output/integrity_baseline.json")

    def _hash_file(self, filepath: str) -> Dict:
        """Compute hash and metadata for a file."""
        try:
            stat = os.stat(filepath)
            with open(filepath, 'rb') as f:
                content = f.read()
            return {
                'sha256': hashlib.sha256(content).hexdigest(),
                'md5': hashlib.md5(content).hexdigest(),
                'size': stat.st_size,
                'modified': stat.st_mtime,
                'permissions': oct(stat.st_mode),
                'last_checked': datetime.now().isoformat()
            }
        except (PermissionError, FileNotFoundError) as e:
            return {'error': str(e)}

    def _scan_directory(self, directory: str, extensions: list = None) -> Dict:
        """Scan directory and hash all files."""
        file_hashes = {}
        for root, dirs, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                if extensions:
                    if not any(filepath.endswith(ext) for ext in extensions):
                        continue
                file_hashes[filepath] = self._hash_file(filepath)
        return file_hashes

    def create_baseline(self, directory: str, **kwargs) -> Dict:
        """Create integrity baseline."""
        extensions = kwargs.get('extensions', None)
        self.logger.info(f"📸 Creating baseline for: {directory}")

        baseline = {
            'created': datetime.now().isoformat(),
            'directory': directory,
            'files': self._scan_directory(directory, extensions)
        }

        with open(self.baseline_file, 'w') as f:
            json.dump(baseline, f, indent=2)

        self.logger.info(f"  ✅ Baseline created with {len(baseline['files'])} files")
        return baseline

    def check_integrity(self, directory: str, **kwargs) -> Dict:
        """Check files against baseline."""
        if not self.baseline_file.exists():
            return {"error": "No baseline found. Create one first."}

        with open(self.baseline_file, 'r') as f:
            baseline = json.load(f)

        current = self._scan_directory(directory, kwargs.get('extensions'))

        changes = {
            'modified': [],
            'added': [],
            'deleted': [],
            'unchanged': 0
        }

        # Check existing files
        for filepath, current_info in current.items():
            if filepath in baseline['files']:
                baseline_info = baseline['files'][filepath]
                if current_info.get('sha256') != baseline_info.get('sha256'):
                    changes['modified'].append({
                        'file': filepath,
                        'old_hash': baseline_info.get('sha256'),
                        'new_hash': current_info.get('sha256'),
                        'old_size': baseline_info.get('size'),
                        'new_size': current_info.get('size')
                    })
                    self.logger.warning(f"  ⚠️  MODIFIED: {filepath}")
                else:
                    changes['unchanged'] += 1
            else:
                changes['added'].append({
                    'file': filepath,
                    'hash': current_info.get('sha256'),
                    'size': current_info.get('size')
                })
                self.logger.warning(f"  ➕ NEW FILE: {filepath}")

        # Check for deleted files
        for filepath in baseline['files']:
            if filepath not in current:
                changes['deleted'].append({'file': filepath})
                self.logger.warning(f"  ➖ DELETED: {filepath}")

        changes['summary'] = {
            'total_files': len(current),
            'modified_count': len(changes['modified']),
            'added_count': len(changes['added']),
            'deleted_count': len(changes['deleted']),
            'unchanged_count': changes['unchanged'],
            'integrity_status': 'COMPROMISED' if changes['modified'] or changes['added'] or changes['deleted'] else 'INTACT'
        }

        return changes

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run integrity check."""
        action = kwargs.get('action', 'check')

        if action == 'baseline':
            return self.create_baseline(target, **kwargs)
        elif action == 'check':
            return self.check_integrity(target, **kwargs)
        else:
            return {"error": f"Unknown action: {action}"}