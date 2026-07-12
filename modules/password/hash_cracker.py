import hashlib
import itertools
import string
import time
from typing import Dict, Any, Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.base_module import BaseModule


class HashIdentifier(BaseModule):
    """Identify hash types."""

    HASH_PATTERNS = {
        32: ['MD5', 'NTLM', 'MD4'],
        40: ['SHA-1', 'RIPEMD-160'],
        56: ['SHA-224'],
        64: ['SHA-256', 'SHA3-256'],
        96: ['SHA-384', 'SHA3-384'],
        128: ['SHA-512', 'SHA3-512'],
        16: ['MySQL 3.x'],
        41: ['MySQL 5.x (starts with *)'],
    }

    def __init__(self):
        super().__init__("Hash Identifier")

    def identify(self, hash_value: str) -> list:
        """Identify possible hash types."""
        hash_value = hash_value.strip()
        length = len(hash_value)

        # Check if hex
        try:
            int(hash_value, 16)
            is_hex = True
        except ValueError:
            is_hex = False

        # Check for specific formats
        if hash_value.startswith('$2a$') or hash_value.startswith('$2b$'):
            return ['bcrypt']
        if hash_value.startswith('$6$'):
            return ['SHA-512 crypt']
        if hash_value.startswith('$5$'):
            return ['SHA-256 crypt']
        if hash_value.startswith('$1$'):
            return ['MD5 crypt']
        if hash_value.startswith('$apr1$'):
            return ['Apache MD5']
        if hash_value.startswith('*') and len(hash_value) == 41:
            return ['MySQL 5.x']

        if is_hex:
            return self.HASH_PATTERNS.get(length, ['Unknown'])
        return ['Unknown format']

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        possible_types = self.identify(target)
        self.logger.info(f"Hash: {target}")
        self.logger.info(f"Possible types: {', '.join(possible_types)}")
        return {
            'hash': target,
            'length': len(target),
            'possible_types': possible_types
        }


class HashCracker(BaseModule):
    """Hash cracker supporting dictionary and brute force attacks."""

    HASH_FUNCTIONS = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512,
        'sha224': hashlib.sha224,
        'sha384': hashlib.sha384,
    }

    def __init__(self):
        super().__init__("Hash Cracker")
        self.attempts = 0
        self.found = False

    def _hash_password(self, password: str, hash_type: str) -> str:
        """Hash a password with the specified algorithm."""
        hash_func = self.HASH_FUNCTIONS.get(hash_type)
        if hash_func:
            return hash_func(password.encode('utf-8')).hexdigest()
        return ""

    def _dictionary_attack(self, target_hash: str, hash_type: str,
                           wordlist_path: str) -> Optional[str]:
        """Perform dictionary attack."""
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if self.found:
                        break
                    password = line.strip()
                    self.attempts += 1
                    if self._hash_password(password, hash_type) == target_hash.lower():
                        self.found = True
                        return password
                    if self.attempts % 100000 == 0:
                        self.logger.info(f"  🔄 Tried {self.attempts:,} passwords...")
        except FileNotFoundError:
            self.logger.error(f"Wordlist not found: {wordlist_path}")
        return None

    def _brute_force(self, target_hash: str, hash_type: str,
                     charset: str = None, max_length: int = 6) -> Optional[str]:
        """Perform brute force attack."""
        if charset is None:
            charset = string.ascii_lowercase + string.digits

        for length in range(1, max_length + 1):
            self.logger.info(f"  🔨 Trying length {length}...")
            for candidate in itertools.product(charset, repeat=length):
                if self.found:
                    break
                password = ''.join(candidate)
                self.attempts += 1
                if self._hash_password(password, hash_type) == target_hash.lower():
                    self.found = True
                    return password
                if self.attempts % 500000 == 0:
                    self.logger.info(f"  🔄 Tried {self.attempts:,} combinations...")
        return None

    def _rule_based_mutations(self, word: str) -> List[str]:
        """Generate password mutations."""
        mutations = [
            word,
            word.capitalize(),
            word.upper(),
            word.lower(),
            word + '123',
            word + '!',
            word + '1',
            word + '2024',
            word + '2023',
            word.replace('a', '@'),
            word.replace('e', '3'),
            word.replace('i', '1'),
            word.replace('o', '0'),
            word.replace('s', '$'),
            word[::-1],
            word + word,
        ]

        # Add number suffixes
        for i in range(100):
            mutations.append(f"{word}{i}")

        return list(set(mutations))

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Crack hash."""
        hash_type = kwargs.get('hash_type', 'md5')
        attack = kwargs.get('attack', 'dictionary')
        wordlist = kwargs.get('wordlist', 'wordlists/common.txt')
        max_length = kwargs.get('max_length', 6)
        use_rules = kwargs.get('rules', True)

        self.attempts = 0
        self.found = False
        start_time = time.time()

        # Auto-detect hash type
        identifier = HashIdentifier()
        possible_types = identifier.identify(target)
        self.logger.info(f"🔑 Hash: {target}")
        self.logger.info(f"📝 Possible types: {', '.join(possible_types)}")

        result = None

        if attack == 'dictionary':
            self.logger.info(f"📖 Starting dictionary attack with {wordlist}")
            result = self._dictionary_attack(target, hash_type, wordlist)

            # Try with rules/mutations if basic dictionary failed
            if not result and use_rules:
                self.logger.info("📖 Trying with rule-based mutations...")
                try:
                    with open(wordlist, 'r', errors='ignore') as f:
                        words = [line.strip() for line in f][:10000]  # Limit
                    for word in words:
                        if self.found:
                            break
                        for mutation in self._rule_based_mutations(word):
                            self.attempts += 1
                            if self._hash_password(mutation, hash_type) == target.lower():
                                result = mutation
                                self.found = True
                                break
                except:
                    pass

        elif attack == 'bruteforce':
            self.logger.info(f"🔨 Starting brute force (max length: {max_length})")
            result = self._brute_force(target, hash_type, max_length=max_length)

        elapsed = time.time() - start_time

        if result:
            self.logger.info(f"  ✅ CRACKED! Password: {result}")
        else:
            self.logger.info(f"  ❌ Hash not cracked after {self.attempts:,} attempts")

        return {
            'hash': target,
            'hash_type': hash_type,
            'cracked': result is not None,
            'password': result,
            'attempts': self.attempts,
            'time_seconds': round(elapsed, 2),
            'speed': f"{self.attempts / elapsed:.0f} hashes/sec" if elapsed > 0 else "N/A"
        }