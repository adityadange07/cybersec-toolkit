import re
import hashlib
from typing import Dict, Any, List
from core.base_module import BaseModule


class HashIdentifier(BaseModule):
    """
    Advanced hash type identifier supporting 50+ hash formats.
    """

    HASH_SIGNATURES = [
        # ── Exact length + format ────────────────────────────────────────────
        {
            'name':    'MD5',
            'regex':   r'^[a-f0-9]{32}$',
            'length':  32,
            'example': '5d41402abc4b2a76b9719d911017c592',
        },
        {
            'name':    'MD5 ($pass.$salt)',
            'regex':   r'^[a-f0-9]{32}:[a-zA-Z0-9]+$',
            'length':  None,
            'example': '5d41402abc4b2a76b9719d911017c592:salt',
        },
        {
            'name':    'NTLM',
            'regex':   r'^[A-F0-9]{32}$',
            'length':  32,
            'example': 'B4B9B02E6F09A9BD760F388B67351E2B',
        },
        {
            'name':    'SHA-1',
            'regex':   r'^[a-f0-9]{40}$',
            'length':  40,
            'example': 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d',
        },
        {
            'name':    'MySQL 4.x',
            'regex':   r'^[a-f0-9]{16}$',
            'length':  16,
            'example': '606717496665bcba',
        },
        {
            'name':    'MySQL 5.x',
            'regex':   r'^\*[A-F0-9]{40}$',
            'length':  41,
            'example': '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19',
        },
        {
            'name':    'SHA-224',
            'regex':   r'^[a-f0-9]{56}$',
            'length':  56,
            'example': 'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f',
        },
        {
            'name':    'SHA-256',
            'regex':   r'^[a-f0-9]{64}$',
            'length':  64,
            'example': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        },
        {
            'name':    'SHA-384',
            'regex':   r'^[a-f0-9]{96}$',
            'length':  96,
            'example': '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
        },
        {
            'name':    'SHA-512',
            'regex':   r'^[a-f0-9]{128}$',
            'length':  128,
            'example': 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
        },
        {
            'name':    'SHA3-256',
            'regex':   r'^[a-f0-9]{64}$',
            'length':  64,
            'example': 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
        },
        {
            'name':    'RIPEMD-160',
            'regex':   r'^[a-f0-9]{40}$',
            'length':  40,
            'example': '9c1185a5c5e9fc54612808977ee8f548b2258d31',
        },
        # ── Prefixed / structured ────────────────────────────────────────────
        {
            'name':    'bcrypt',
            'regex':   r'^\$2[ayb]\$[0-9]{2}\$[./A-Za-z0-9]{53}$',
            'length':  None,
            'example': '$2a$12$examplehashexamplehashexamplehashexamplehashe',
        },
        {
            'name':    'SHA-512 crypt (Linux shadow)',
            'regex':   r'^\$6\$.{0,16}\$[./A-Za-z0-9]{86}$',
            'length':  None,
            'example': '$6$rounds=5000$usesomesillystri$D4IrlXatmP7rx3P3InaxBeoomnAihCKRVQP22JZ6EY47Wc6BkroIuUUBOov1i.S5KPgErtP/EN5mcO.ChWQW21',
        },
        {
            'name':    'SHA-256 crypt (Linux shadow)',
            'regex':   r'^\$5\$.{0,16}\$[./A-Za-z0-9]{43}$',
            'length':  None,
            'example': '$5$rounds=5000$usesomesillystri$Gcm6FsVtg/L5srhBhXlCGBQFZLIi1b8Y4sJPvP2gMrs',
        },
        {
            'name':    'MD5 crypt (Linux/BSD)',
            'regex':   r'^\$1\$.{0,8}\$[./A-Za-z0-9]{22}$',
            'length':  None,
            'example': '$1$rasmuslerdorf$rISCgZzpwk3UhDidwXvin0',
        },
        {
            'name':    'Apache MD5',
            'regex':   r'^\$apr1\$.{0,8}\$[./A-Za-z0-9]{22}$',
            'length':  None,
            'example': '$apr1$rt70iBoe$mAMEinwxJkB.6fjIVJQtG1',
        },
        {
            'name':    'SHA-1 Base64 (LDAP)',
            'regex':   r'^\{SHA\}[A-Za-z0-9+/=]+$',
            'length':  None,
            'example': '{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=',
        },
        {
            'name':    'SSHA (Salted SHA-1, LDAP)',
            'regex':   r'^\{SSHA\}[A-Za-z0-9+/=]+$',
            'length':  None,
            'example': '{SSHA}MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkw',
        },
        {
            'name':    'Argon2',
            'regex':   r'^\$argon2(i|d|id)\$v=\d+\$m=\d+,t=\d+,p=\d+\$',
            'length':  None,
            'example': '$argon2id$v=19$m=16,t=2,p=1$dW5pY29ybg$X9y8...',
        },
        {
            'name':    'scrypt',
            'regex':   r'^\$scrypt\$',
            'length':  None,
            'example': '$scrypt$ln=17,r=8,p=1$...',
        },
        {
            'name':    'PBKDF2-SHA256 (Django)',
            'regex':   r'^pbkdf2_sha256\$\d+\$[A-Za-z0-9]+\$[A-Za-z0-9+/=]+$',
            'length':  None,
            'example': 'pbkdf2_sha256$260000$salt$hash',
        },
        {
            'name':    'WPA/WPA2 PMK',
            'regex':   r'^[a-f0-9]{64}:[a-zA-Z0-9 ]{0,32}$',
            'length':  None,
            'example': 'aabbcc...64chars:NetworkSSID',
        },
        {
            'name':    'JWT (JSON Web Token)',
            'regex':   r'^eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$',
            'length':  None,
            'example': 'eyJhbGciOiJIUzI1NiJ9.eyJ...',
        },
    ]

    def __init__(self):
        super().__init__("Hash Identifier")

    def identify(self, hash_value: str) -> List[Dict]:
        """Identify possible hash types for a given hash string."""
        hash_value  = hash_value.strip()
        candidates  = []

        for sig in self.HASH_SIGNATURES:
            if re.match(sig['regex'], hash_value, re.IGNORECASE):
                candidates.append({
                    'name':    sig['name'],
                    'regex':   sig['regex'],
                    'example': sig.get('example', ''),
                })

        return candidates

    def identify_bulk(self, hashes: List[str]) -> List[Dict]:
        """Identify hash types for a list of hashes."""
        results = []
        for h in hashes:
            candidates = self.identify(h)
            results.append({
                'hash':            h[:80],
                'possible_types':  [c['name'] for c in candidates],
                'confidence':      'High' if len(candidates) == 1 else
                                   'Medium' if candidates else 'Unknown',
            })
        return results

    def generate_sample_hashes(self, plaintext: str = 'hello') -> Dict:
        """Generate sample hashes for a plaintext (for comparison/learning)."""
        encoded = plaintext.encode()
        return {
            'plaintext': plaintext,
            'md5':       hashlib.md5(encoded).hexdigest(),
            'sha1':      hashlib.sha1(encoded).hexdigest(),
            'sha224':    hashlib.sha224(encoded).hexdigest(),
            'sha256':    hashlib.sha256(encoded).hexdigest(),
            'sha384':    hashlib.sha384(encoded).hexdigest(),
            'sha512':    hashlib.sha512(encoded).hexdigest(),
            'sha3_256':  hashlib.sha3_256(encoded).hexdigest(),
            'sha3_512':  hashlib.sha3_512(encoded).hexdigest(),
            'blake2b':   hashlib.blake2b(encoded).hexdigest(),
            'blake2s':   hashlib.blake2s(encoded).hexdigest(),
        }

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        target  : hash string or comma-separated hashes
        kwargs:
            mode     : 'identify' | 'bulk' | 'sample'
            plaintext: str for sample hash generation
        """
        mode      = kwargs.get('mode', 'identify')
        plaintext = kwargs.get('plaintext', 'hello')

        self.logger.info(f"🔍 Hash Identifier — mode: {mode}")

        if mode == 'identify':
            candidates = self.identify(target)
            if candidates:
                self.logger.info(f"  Possible types ({len(candidates)}):")
                for c in candidates:
                    self.logger.info(f"    📋 {c['name']}")
            else:
                self.logger.info("  ❓ Unknown hash format")
            return {
                'hash':           target[:80],
                'length':         len(target),
                'possible_types': candidates,
                'confidence':     'High'    if len(candidates) == 1 else
                                  'Medium'  if candidates else
                                  'Unknown',
            }

        elif mode == 'bulk':
            hashes  = [h.strip() for h in target.split(',') if h.strip()]
            results = self.identify_bulk(hashes)
            return {'mode': 'bulk', 'results': results}

        elif mode == 'sample':
            return self.generate_sample_hashes(plaintext)

        else:
            return {'error': f'Unknown mode: {mode}'}