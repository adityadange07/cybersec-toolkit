import hashlib
import os
import json
import csv
import requests
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.base_module import BaseModule
from config.settings import config


class HashAnalyzer(BaseModule):
    """
    Hash computation, comparison, and threat-intel lookup.
    Supports: MD5, SHA-1, SHA-256, SHA-512, fuzzy (ssdeep via pySSDeep).
    """

    # Known-bad hashes (demo set — real tools use threat-intel feeds)
    KNOWN_MALICIOUS: Dict[str, str] = {
        '44d88612fea8a8f36de82e1278abb02f': 'EICAR test file (MD5)',
        '3395856ce81f2b7382dee72602f798b642f14d4': 'EICAR test file (SHA-1)',
        '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f':
            'EICAR test file (SHA-256)',
    }

    def __init__(self):
        super().__init__("Hash Analyzer")

    # ──────────────────────────────────────────────────────────────────────────
    # Compute
    # ──────────────────────────────────────────────────────────────────────────

    def compute_file_hashes(self, filepath: str,
                             algorithms: List[str] = None) -> Dict[str, str]:
        """Compute multiple hashes for a single file."""
        if algorithms is None:
            algorithms = ['md5', 'sha1', 'sha256', 'sha512']

        hashes: Dict[str, str] = {}
        chunk = 1024 * 1024  # 1 MB

        hashers = {alg: hashlib.new(alg) for alg in algorithms}

        with open(filepath, 'rb') as f:
            while True:
                data = f.read(chunk)
                if not data:
                    break
                for h in hashers.values():
                    h.update(data)

        for alg, h in hashers.items():
            hashes[alg] = h.hexdigest()

        # pySSDeep fuzzy hash
        try:
            import pySSDeep as ssdeep
            hashes['ssdeep'] = ssdeep.get_fuzzy_file(filepath)
        except ImportError:
            hashes['ssdeep'] = 'pySSDeep not installed'
        except Exception as exc:
            hashes['ssdeep'] = f'Error: {exc}'

        hashes['file_size'] = os.path.getsize(filepath)
        hashes['filename']  = os.path.basename(filepath)
        return hashes

    def compute_string_hash(self, data: str,
                             algorithms: List[str] = None) -> Dict[str, str]:
        """Compute hashes for a raw string."""
        if algorithms is None:
            algorithms = ['md5', 'sha1', 'sha256']
        encoded = data.encode('utf-8')
        return {
            alg: hashlib.new(alg, encoded).hexdigest()
            for alg in algorithms
        }

    def compute_directory_hashes(self, directory: str,
                                  recursive: bool = True,
                                  workers:   int   = 8) -> Dict[str, Any]:
        """Compute hashes for all files in a directory (multi-threaded)."""
        files = []
        if recursive:
            for root, _, fnames in os.walk(directory):
                for fname in fnames:
                    files.append(os.path.join(root, fname))
        else:
            files = [
                os.path.join(directory, f)
                for f in os.listdir(directory)
                if os.path.isfile(os.path.join(directory, f))
            ]

        results: Dict[str, Any] = {}
        self.logger.info(f"  🔑 Hashing {len(files)} files with {workers} workers...")

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_file = {
                executor.submit(self.compute_file_hashes, fp): fp
                for fp in files
            }
            for future in as_completed(future_to_file):
                fp = future_to_file[future]
                try:
                    results[fp] = future.result()
                except Exception as exc:
                    results[fp] = {'error': str(exc)}

        return {
            'directory':   directory,
            'total_files': len(files),
            'hashes':      results,
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Comparison
    # ──────────────────────────────────────────────────────────────────────────

    def compare_files(self, file1: str, file2: str) -> Dict:
        """Compare two files by hash."""
        h1 = self.compute_file_hashes(file1)
        h2 = self.compute_file_hashes(file2)

        matches  = {}
        differs  = {}
        for alg in ('md5', 'sha1', 'sha256', 'sha512'):
            if alg in h1 and alg in h2:
                if h1[alg] == h2[alg]:
                    matches[alg] = h1[alg]
                else:
                    differs[alg] = {'file1': h1[alg], 'file2': h2[alg]}

        identical = len(differs) == 0

        # Fuzzy similarity via ssdeep
        similarity = -1
        try:
            import pySSDeep as ssdeep
            if 'ssdeep' in h1 and 'ssdeep' in h2:
                similarity = ssdeep.compare(h1['ssdeep'], h2['ssdeep'])
        except ImportError:
            pass

        return {
            'file1':              file1,
            'file2':              file2,
            'identical':          identical,
            'matching_hashes':    matches,
            'differing_hashes':   differs,
            'ssdeep_similarity':  similarity,
            'similarity_label':   (
                'Identical'   if similarity == 100 else
                'Very Similar' if similarity > 70  else
                'Similar'      if similarity > 40  else
                'Different'    if similarity >= 0  else
                'N/A'
            ),
        }

    def compare_hash_sets(self, set1_path: str, set2_path: str) -> Dict:
        """
        Compare two hash sets (CSV or JSON) to find common / unique hashes.
        Useful for comparing baseline vs current state.
        """
        def load_hash_set(path: str) -> Dict[str, str]:
            hset = {}
            ext  = Path(path).suffix.lower()
            with open(path, 'r') as f:
                if ext == '.json':
                    data = json.load(f)
                    if isinstance(data, dict):
                        hset = {v.get('sha256', ''): k for k, v in data.items()
                                if isinstance(v, dict)}
                    elif isinstance(data, list):
                        hset = {entry.get('sha256', ''): entry.get('filename', '')
                                for entry in data if isinstance(entry, dict)}
                elif ext == '.csv':
                    reader = csv.DictReader(f)
                    for row in reader:
                        hset[row.get('sha256', row.get('hash', ''))] = (
                            row.get('filename', row.get('file', ''))
                        )
            return hset

        set1 = load_hash_set(set1_path)
        set2 = load_hash_set(set2_path)

        common  = {h: (set1[h], set2[h]) for h in set1 if h in set2}
        only_s1 = {h: set1[h] for h in set1 if h not in set2}
        only_s2 = {h: set2[h] for h in set2 if h not in set1}

        return {
            'set1_path':    set1_path,
            'set2_path':    set2_path,
            'set1_count':   len(set1),
            'set2_count':   len(set2),
            'common':       list(common.values())[:100],
            'only_in_set1': list(only_s1.values())[:100],
            'only_in_set2': list(only_s2.values())[:100],
            'common_count': len(common),
            'set1_unique':  len(only_s1),
            'set2_unique':  len(only_s2),
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Threat intel lookups
    # ──────────────────────────────────────────────────────────────────────────

    def check_known_bad(self, file_hash: str) -> Dict:
        """Check hash against local known-bad list."""
        h = file_hash.lower().strip()
        if h in self.KNOWN_MALICIOUS:
            return {
                'found':       True,
                'description': self.KNOWN_MALICIOUS[h],
                'source':      'local_blocklist',
            }
        return {'found': False}

    def lookup_virustotal(self, file_hash: str) -> Dict:
        """Look up file hash on VirusTotal v3 API."""
        if not config.VIRUSTOTAL_API_KEY:
            return {'error': 'VIRUSTOTAL_API_KEY env var not set'}

        url     = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {'x-apikey': config.VIRUSTOTAL_API_KEY}
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            if resp.status_code == 200:
                attr  = resp.json()['data']['attributes']
                stats = attr.get('last_analysis_stats', {})
                total = sum(stats.values())
                return {
                    'found':           True,
                    'malicious':       stats.get('malicious', 0),
                    'suspicious':      stats.get('suspicious', 0),
                    'harmless':        stats.get('harmless', 0),
                    'undetected':      stats.get('undetected', 0),
                    'total_engines':   total,
                    'detection_ratio': f"{stats.get('malicious', 0)}/{total}",
                    'name':            attr.get('meaningful_name', ''),
                    'type':            attr.get('type_description', ''),
                    'link':            f'https://www.virustotal.com/gui/file/{file_hash}',
                }
            elif resp.status_code == 404:
                return {'found': False, 'message': 'Not in VT database'}
            else:
                return {'error': f'HTTP {resp.status_code}: {resp.text[:200]}'}
        except requests.RequestException as exc:
            return {'error': str(exc)}

    def lookup_malwarebazaar(self, file_hash: str) -> Dict:
        """Look up hash on MalwareBazaar (no API key required)."""
        url  = 'https://mb-api.abuse.ch/api/v1/'
        data = {'query': 'get_info', 'hash': file_hash}
        try:
            resp = requests.post(url, data=data, timeout=20)
            if resp.status_code == 200:
                result = resp.json()
                if result.get('query_status') == 'ok':
                    entry = result['data'][0]
                    return {
                        'found':       True,
                        'filename':    entry.get('file_name', ''),
                        'file_type':   entry.get('file_type', ''),
                        'signature':   entry.get('signature', ''),
                        'tags':        entry.get('tags', []),
                        'first_seen':  entry.get('first_seen', ''),
                        'reporter':    entry.get('reporter', ''),
                        'link':        f"https://bazaar.abuse.ch/sample/{file_hash}/",
                    }
                return {'found': False, 'status': result.get('query_status')}
        except requests.RequestException as exc:
            return {'error': str(exc)}

    # ──────────────────────────────────────────────────────────────────────────
    # Export
    # ──────────────────────────────────────────────────────────────────────────

    def export_hash_list(self, directory: str,
                         output_path: str,
                         fmt: str = 'csv') -> str:
        """Export all file hashes from a directory to CSV or JSON."""
        dir_hashes = self.compute_directory_hashes(directory)
        records    = []

        for filepath, hashes in dir_hashes['hashes'].items():
            record = {'filepath': filepath}
            record.update(hashes)
            records.append(record)

        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

        if fmt == 'csv':
            if records:
                keys = ['filepath', 'filename', 'file_size',
                        'md5', 'sha1', 'sha256', 'sha512', 'ssdeep']
                with open(output_path, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=keys, extrasaction='ignore')
                    writer.writeheader()
                    writer.writerows(records)
        elif fmt == 'json':
            with open(output_path, 'w') as f:
                json.dump({'exported': datetime.now().isoformat(),
                           'records': records}, f, indent=2)

        self.logger.info(f"  💾 Exported {len(records)} hashes → {output_path}")
        return output_path

    # ──────────────────────────────────────────────────────────────────────────
    # run()
    # ──────────────────────────────────────────────────────────────────────────

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        target  : file path, directory path, or raw hash string
        kwargs:
            action      : 'file' | 'directory' | 'string' | 'compare' |
                          'lookup' | 'export'
            compare_to  : second file/directory path (for compare)
            algorithms  : list of hash algorithms
            output_path : export output path
            fmt         : 'csv' | 'json' (export format)
            vt_lookup   : bool — query VirusTotal
            mb_lookup   : bool — query MalwareBazaar
        """
        action      = kwargs.get('action', 'file')
        compare_to  = kwargs.get('compare_to', None)
        algorithms  = kwargs.get('algorithms', ['md5', 'sha1', 'sha256', 'sha512'])
        output_path = kwargs.get('output_path', 'output/hashes.csv')
        fmt         = kwargs.get('fmt', 'csv')
        vt_lookup   = kwargs.get('vt_lookup', False)
        mb_lookup   = kwargs.get('mb_lookup', True)

        self.logger.info(f"#️⃣  Hash Analyzer — action: {action} → {target}")
        results: Dict[str, Any] = {
            'target':    target,
            'action':    action,
            'timestamp': datetime.now().isoformat(),
        }

        if action == 'file':
            if not os.path.isfile(target):
                return {'error': f'File not found: {target}'}
            hashes = self.compute_file_hashes(target, algorithms)
            results['hashes'] = hashes
            results['known_bad'] = self.check_known_bad(hashes.get('sha256', ''))
            if vt_lookup:
                results['virustotal'] = self.lookup_virustotal(hashes['sha256'])
            if mb_lookup:
                results['malwarebazaar'] = self.lookup_malwarebazaar(hashes['sha256'])

        elif action == 'directory':
            if not os.path.isdir(target):
                return {'error': f'Directory not found: {target}'}
            results.update(self.compute_directory_hashes(target))

        elif action == 'string':
            results['hashes'] = self.compute_string_hash(target, algorithms)

        elif action == 'compare':
            if not compare_to:
                return {'error': 'compare_to path required for compare action'}
            if os.path.isfile(target) and os.path.isfile(compare_to):
                results['comparison'] = self.compare_files(target, compare_to)
            else:
                results['comparison'] = self.compare_hash_sets(target, compare_to)

        elif action == 'lookup':
            # target is treated as a hash string
            results['known_bad']     = self.check_known_bad(target)
            if vt_lookup:
                results['virustotal']    = self.lookup_virustotal(target)
            if mb_lookup:
                results['malwarebazaar'] = self.lookup_malwarebazaar(target)

        elif action == 'export':
            if not os.path.isdir(target):
                return {'error': f'Directory not found: {target}'}
            exported = self.export_hash_list(target, output_path, fmt)
            results['exported_to'] = exported

        else:
            results['error'] = f"Unknown action: {action}"

        return results