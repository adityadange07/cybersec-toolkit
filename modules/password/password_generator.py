import secrets
import string
import math
import re
from typing import Dict, Any, List
from core.base_module import BaseModule


class PasswordGenerator(BaseModule):
    """
    Cryptographically secure password and passphrase generator.
    """

    # EFF large wordlist (truncated — real use: download full list)
    EFF_WORDS = [
        'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb',
        'abstract', 'absurd', 'abuse', 'access', 'accident', 'account',
        'accuse', 'achieve', 'acid', 'acoustic', 'acquire', 'across', 'action',
        'actor', 'actual', 'adapt', 'addict', 'address', 'adjust', 'admit',
        'adult', 'advance', 'advice', 'aerobic', 'afford', 'afraid', 'again',
        'agency', 'agent', 'agree', 'ahead', 'alarm', 'album', 'alert',
        'alien', 'alley', 'allow', 'almost', 'alone', 'alpha', 'already',
        'alter', 'always', 'amateur', 'amazing', 'among', 'amount', 'amused',
        'analyst', 'anchor', 'ancient', 'anger', 'angle', 'angry', 'animal',
        'ankle', 'announce', 'annual', 'answer', 'antenna', 'antique', 'anxiety',
        'apart', 'appear', 'apple', 'approve', 'april', 'arcade', 'arctic',
        'argue', 'arise', 'armor', 'army', 'around', 'arrange', 'arrest',
        'arrive', 'arrow', 'artist', 'aspect', 'assault', 'asset', 'assist',
        'assume', 'asthma', 'athlete', 'atom', 'attack', 'attend', 'attitude',
        'attract', 'auction', 'audit', 'august', 'aunt', 'author', 'auto',
        'autumn', 'average', 'avocado', 'avoid', 'awake', 'aware', 'away',
        'awesome', 'awful', 'awkward', 'axis', 'baby', 'bacon', 'badge',
        'balance', 'bamboo', 'banana', 'banner', 'barely', 'bargain', 'barrel',
        'base', 'basic', 'basket', 'battle', 'beach', 'beauty', 'because',
        'become', 'before', 'behave', 'believe', 'below', 'bench', 'benefit',
        'benefit', 'between', 'beyond', 'bicycle', 'bitter', 'blanket', 'blast',
        'bleak', 'blend', 'bless', 'blind', 'blood', 'blossom', 'blouse',
        'blue', 'blur', 'bonus', 'boil', 'border', 'bottom', 'bounce', 'brain',
        'brave', 'bridge', 'brief', 'bright', 'bring', 'brisk', 'broken',
        'bronze', 'broom', 'brown', 'brush', 'bubble', 'budget', 'build',
        'burden', 'burger', 'burst', 'butter', 'buyer', 'cable', 'camera',
        'cancel', 'candy', 'canvas', 'canyon', 'capable', 'capital', 'captain',
        'carbon', 'carpet', 'carry', 'castle', 'casual', 'catalog', 'catch',
        'ceiling', 'chaos', 'chapter', 'charge', 'cheap', 'check', 'cheese',
        'cherry', 'chicken', 'chief', 'child', 'choice', 'cinema', 'circle',
        'citizen', 'clamp', 'clarify', 'clean', 'clever', 'client', 'climate',
        'clinic', 'clock', 'close', 'cloud', 'coastal', 'cobalt', 'coconut',
        'coffee', 'collect', 'comet', 'comfort', 'comic', 'common', 'company',
    ]

    def __init__(self):
        super().__init__("Password Generator")

    # ──────────────────────────────────────────────────────────────────────────
    # Entropy calculation
    # ──────────────────────────────────────────────────────────────────────────

    def _entropy_bits(self, pool_size: int, length: int) -> float:
        """Calculate password entropy in bits."""
        return length * math.log2(pool_size) if pool_size > 1 else 0

    def _entropy_label(self, bits: float) -> str:
        if bits >= 128: return 'Extremely Strong 🟢'
        if bits >= 80:  return 'Very Strong 🟢'
        if bits >= 60:  return 'Strong 🟡'
        if bits >= 40:  return 'Moderate 🟠'
        return 'Weak 🔴'

    # ──────────────────────────────────────────────────────────────────────────
    # Generators
    # ──────────────────────────────────────────────────────────────────────────

    def generate_password(self,
                          length:       int  = 20,
                          use_upper:    bool = True,
                          use_lower:    bool = True,
                          use_digits:   bool = True,
                          use_symbols:  bool = True,
                          exclude_chars: str = '',
                          count:         int = 1) -> List[Dict]:
        """Generate random secure passwords."""
        pool = ''
        if use_upper:   pool += string.ascii_uppercase
        if use_lower:   pool += string.ascii_lowercase
        if use_digits:  pool += string.digits
        if use_symbols: pool += string.punctuation

        # Remove excluded characters
        if exclude_chars:
            pool = ''.join(c for c in pool if c not in exclude_chars)

        if not pool:
            return [{'error': 'No character pool available'}]

        results = []
        for _ in range(count):
            # Guarantee at least one char from each selected class
            pwd = []
            if use_upper   and string.ascii_uppercase:
                pwd.append(secrets.choice([c for c in string.ascii_uppercase
                                           if c not in exclude_chars]))
            if use_lower   and string.ascii_lowercase:
                pwd.append(secrets.choice([c for c in string.ascii_lowercase
                                           if c not in exclude_chars]))
            if use_digits  and string.digits:
                pwd.append(secrets.choice([c for c in string.digits
                                           if c not in exclude_chars]))
            if use_symbols and string.punctuation:
                pwd.append(secrets.choice([c for c in string.punctuation
                                           if c not in exclude_chars]))

            remaining = length - len(pwd)
            pwd      += [secrets.choice(pool) for _ in range(remaining)]
            secrets.SystemRandom().shuffle(pwd)

            password    = ''.join(pwd)
            entropy     = self._entropy_bits(len(pool), length)
            results.append({
                'password':     password,
                'length':       length,
                'entropy_bits': round(entropy, 1),
                'strength':     self._entropy_label(entropy),
                'pool_size':    len(pool),
            })

        return results

    def generate_passphrase(self,
                             words:      int  = 6,
                             separator:  str  = '-',
                             capitalize: bool = True,
                             add_number: bool = True,
                             add_symbol: bool = True,
                             count:       int = 1) -> List[Dict]:
        """Generate diceware-style passphrases."""
        wordlist = self.EFF_WORDS
        results  = []

        for _ in range(count):
            chosen = [secrets.choice(wordlist) for _ in range(words)]
            if capitalize:
                chosen = [w.capitalize() for w in chosen]

            parts = list(chosen)
            if add_number:
                parts.append(str(secrets.randbelow(9999)).zfill(4))
            if add_symbol:
                parts.append(secrets.choice('!@#$%^&*'))

            passphrase = separator.join(parts)
            entropy    = words * math.log2(len(wordlist))

            results.append({
                'passphrase':   passphrase,
                'words':        chosen,
                'entropy_bits': round(entropy, 1),
                'strength':     self._entropy_label(entropy),
            })

        return results

    def generate_pin(self, length: int = 6, count: int = 1) -> List[Dict]:
        """Generate secure numeric PIN."""
        results = []
        for _ in range(count):
            pin     = ''.join([str(secrets.randbelow(10)) for _ in range(length)])
            entropy = self._entropy_bits(10, length)
            results.append({
                'pin':          pin,
                'length':       length,
                'entropy_bits': round(entropy, 1),
            })
        return results

    def generate_api_key(self, prefix: str = '',
                          length: int  = 40,
                          count:  int  = 1) -> List[Dict]:
        """Generate API keys (hex-based, URL-safe)."""
        results = []
        alphabet = string.ascii_letters + string.digits
        for _ in range(count):
            key = ''.join(secrets.choice(alphabet) for _ in range(length))
            if prefix:
                key = f'{prefix}_{key}'
            results.append({
                'api_key':      key,
                'length':       len(key),
                'entropy_bits': round(self._entropy_bits(len(alphabet), length), 1),
            })
        return results

    def generate_uuid(self, count: int = 1) -> List[str]:
        """Generate UUID v4."""
        import uuid
        return [str(uuid.uuid4()) for _ in range(count)]

    # ──────────────────────────────────────────────────────────────────────────
    # Strength checker
    # ──────────────────────────────────────────────────────────────────────────

    def check_strength(self, password: str) -> Dict:
        """Evaluate strength of a given password."""
        score    = 0
        feedback = []

        # Length
        ln = len(password)
        if ln >= 20:
            score += 30
        elif ln >= 16:
            score += 20
        elif ln >= 12:
            score += 10
        elif ln < 8:
            feedback.append('Too short — use at least 12 characters')

        # Character classes
        has_upper   = bool(re.search(r'[A-Z]', password))
        has_lower   = bool(re.search(r'[a-z]', password))
        has_digit   = bool(re.search(r'\d',    password))
        has_symbol  = bool(re.search(r'[^A-Za-z\d]', password))

        if has_upper:  score += 10
        else:          feedback.append('Add uppercase letters')
        if has_lower:  score += 10
        else:          feedback.append('Add lowercase letters')
        if has_digit:  score += 10
        else:          feedback.append('Add numbers')
        if has_symbol: score += 20
        else:          feedback.append('Add special characters')

        # Entropy estimate
        pool = 0
        if has_upper:  pool += 26
        if has_lower:  pool += 26
        if has_digit:  pool += 10
        if has_symbol: pool += 32
        entropy = self._entropy_bits(pool, ln) if pool else 0
        score  += min(20, int(entropy / 6))

        # Common patterns
        common_patterns = [
            (r'(.)\1{2,}', 'Repeated characters'),
            (r'(?i)(password|passwd|qwerty|abc123|123456)', 'Common password pattern'),
            (r'\b(19|20)\d{2}\b', 'Year-like sequence'),
            (r'(012|123|234|345|456|567|678|789|890)', 'Sequential numbers'),
            (r'(abc|bcd|cde|def|efg)', 'Sequential letters'),
        ]
        for pat, msg in common_patterns:
            if re.search(pat, password, re.IGNORECASE):
                score -= 10
                feedback.append(f'Avoid: {msg}')

        score = max(0, min(100, score))

        return {
            'password':     password,
            'length':       ln,
            'score':        score,
            'label':        (
                'Very Strong' if score >= 80 else
                'Strong'      if score >= 60 else
                'Moderate'    if score >= 40 else
                'Weak'        if score >= 20 else
                'Very Weak'
            ),
            'entropy_bits': round(entropy, 1),
            'has_upper':    has_upper,
            'has_lower':    has_lower,
            'has_digit':    has_digit,
            'has_symbol':   has_symbol,
            'feedback':     feedback,
        }

    # ──────────────────────────────────────────────────────────────────────────
    # run()
    # ──────────────────────────────────────────────────────────────────────────

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        target  : 'password' | 'passphrase' | 'pin' | 'apikey' | 'uuid' | 'check'
        kwargs:
            length      : int
            count       : int
            words       : int (passphrase)
            separator   : str (passphrase)
            check_value : str (strength check input)
        """
        mode     = kwargs.get('mode', target)
        length   = kwargs.get('length', 20)
        count    = kwargs.get('count', 5)
        words    = kwargs.get('words', 6)
        separator = kwargs.get('separator', '-')
        check_val = kwargs.get('check_value', '')

        self.logger.info(f"🔐 Password Generator — mode: {mode}")

        if mode == 'password':
            results = self.generate_password(
                length       = length,
                use_upper    = kwargs.get('use_upper',   True),
                use_lower    = kwargs.get('use_lower',   True),
                use_digits   = kwargs.get('use_digits',  True),
                use_symbols  = kwargs.get('use_symbols', True),
                exclude_chars= kwargs.get('exclude', ''),
                count        = count,
            )
            for r in results:
                self.logger.info(f"  🔑 {r['password']} [{r['strength']}]")
            return {'mode': mode, 'results': results}

        elif mode == 'passphrase':
            results = self.generate_passphrase(
                words      = words,
                separator  = separator,
                capitalize = kwargs.get('capitalize', True),
                add_number = kwargs.get('add_number', True),
                add_symbol = kwargs.get('add_symbol', True),
                count      = count,
            )
            for r in results:
                self.logger.info(f"  🔑 {r['passphrase']} [{r['strength']}]")
            return {'mode': mode, 'results': results}

        elif mode == 'pin':
            results = self.generate_pin(length=length, count=count)
            return {'mode': mode, 'results': results}

        elif mode == 'apikey':
            results = self.generate_api_key(
                prefix = kwargs.get('prefix', ''),
                length = length,
                count  = count,
            )
            return {'mode': mode, 'results': results}

        elif mode == 'uuid':
            uuids = self.generate_uuid(count=count)
            return {'mode': mode, 'results': uuids}

        elif mode == 'check':
            pwd    = check_val or target
            result = self.check_strength(pwd)
            self.logger.info(
                f"  📊 Score: {result['score']}/100 | {result['label']}"
            )
            if result['feedback']:
                for fb in result['feedback']:
                    self.logger.info(f"    💡 {fb}")
            return {'mode': mode, 'result': result}

        else:
            return {'error': f'Unknown mode: {mode}'}