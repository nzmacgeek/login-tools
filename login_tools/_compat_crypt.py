"""
SHA-512 crypt ($6$) compatibility layer.

Uses the stdlib `crypt` module when available (Python < 3.13).
Falls back to a pure-Python SHA-512-crypt implementation for Python 3.13+.

Reference: https://www.akkadia.org/docs/sha-crypt.txt
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import struct

try:
    import crypt as _crypt_module  # type: ignore[import]
    _HAVE_STDLIB_CRYPT = True
except ImportError:
    _HAVE_STDLIB_CRYPT = False

# SHA-crypt base64 alphabet (NOT standard base64)
_B64_CHARS = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

# SHA-512 byte permutation groups: (b2, b1, b0) for _b64_from_24bit
# Positions 0-62 in 21 triples, then byte 63 separately.
_SHA512_PERMUTATION: list[tuple[int, int, int]] = [
    (0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4),
    (47, 5, 26), (6, 27, 48), (28, 49, 7), (50, 8, 29), (9, 30, 51),
    (31, 52, 10), (53, 11, 32), (12, 33, 54), (34, 55, 13), (56, 14, 35),
    (15, 36, 57), (37, 58, 16), (59, 17, 38), (18, 39, 60), (40, 61, 19),
    (62, 20, 41),
]


def _b64_from_24bit(b2: int, b1: int, b0: int, n: int) -> str:
    """
    Encode up to 3 bytes into *n* SHA-crypt base64 characters.
    Extracts 6 bits at a time from the LSB side of the 24-bit value.
    """
    value = (b2 << 16) | (b1 << 8) | b0
    result: list[str] = []
    for _ in range(n):
        result.append(_B64_CHARS[value & 0x3F])
        value >>= 6
    return ''.join(result)


def _make_salt_str(rounds: int | None = None) -> str:
    """
    Generate $6$[rounds=N$]<16-char-salt> prefix (no trailing $).
    Uses secrets for cryptographic randomness.
    """
    raw = secrets.token_bytes(12)
    salt_chars = ''.join(_B64_CHARS[b % 64] for b in raw)[:16]
    if rounds is not None and rounds != 5000:
        return f'$6$rounds={rounds}${salt_chars}'
    return f'$6${salt_chars}'


def _parse_sha512_prefix(salt_or_hash: str) -> tuple[int, str]:
    """
    Parse $6$[rounds=N$]salt from a salt string or full hash.
    Returns (rounds, raw_salt_string) where raw_salt_string has no leading/trailing $.
    Raises ValueError on invalid format.
    """
    if not salt_or_hash.startswith('$6$'):
        raise ValueError(f'Not a SHA-512 crypt string: {salt_or_hash!r}')
    rest = salt_or_hash[3:]  # strip $6$

    explicit_rounds = False
    if rest.startswith('rounds='):
        explicit_rounds = True
        try:
            rounds_part, rest = rest.split('$', 1)
            rounds = int(rounds_part[7:])  # after 'rounds='
            if rounds < 1000 or rounds > 999_999_999:
                raise ValueError(f'rounds out of range: {rounds}')
        except ValueError as exc:
            raise ValueError(f'Invalid rounds specification in {salt_or_hash!r}') from exc
    else:
        rounds = 5000

    # salt is everything up to the next '$' (or end)
    salt = rest.split('$')[0]
    if not salt:
        raise ValueError(f'Empty salt in {salt_or_hash!r}')
    return rounds, salt, explicit_rounds


def _sha512_crypt_pure(password: str, salt_or_hash: str) -> str:
    """
    Full SHA-512 crypt implementation per https://www.akkadia.org/docs/sha-crypt.txt
    """
    rounds, salt, explicit_rounds = _parse_sha512_prefix(salt_or_hash)
    salt = salt[:16]  # SHA-crypt spec: salt is at most 16 characters

    pw_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')

    # Steps 4-8: Compute digest B = SHA512(password + salt + password)
    digest_b = hashlib.sha512(pw_bytes + salt_bytes + pw_bytes).digest()

    # Compute digest A: password + salt + bit-processed digest_b
    ctx_a = hashlib.sha512()
    ctx_a.update(pw_bytes)    # add password
    ctx_a.update(salt_bytes)  # add salt
    # For each bit of pw_len (LSB→MSB): bit=1 → add full digest_b; bit=0 → add password
    pw_len = len(pw_bytes)
    n = pw_len
    while n > 0:
        if n & 1:
            ctx_a.update(digest_b)
        else:
            ctx_a.update(pw_bytes)
        n >>= 1
    digest_a = ctx_a.digest()

    # Steps 12-15: Produce p_str (length = len(password))
    ctx_p = hashlib.sha512()
    for _ in range(pw_len):
        ctx_p.update(pw_bytes)
    digest_p = ctx_p.digest()
    # Repeat digest_p to cover pw_len bytes
    full, rem = divmod(pw_len, 64)
    p_str = digest_p * full + digest_p[:rem]

    # Steps 16-19: Produce s_str (length = len(salt))
    salt_len = len(salt_bytes)
    ctx_s = hashlib.sha512()
    repeat_count = 16 + digest_a[0]
    for _ in range(repeat_count):
        ctx_s.update(salt_bytes)
    digest_s = ctx_s.digest()
    full, rem = divmod(salt_len, 64)
    s_str = digest_s * full + digest_s[:rem]

    # Step 20: Run `rounds` iterations
    prev_digest = digest_a
    for i in range(rounds):
        ctx_c = hashlib.sha512()
        if i % 2 == 1:    # odd
            ctx_c.update(p_str)
        else:              # even
            ctx_c.update(prev_digest)
        if i % 7 != 0:
            ctx_c.update(s_str)
        if i % 2 == 1:    # odd
            ctx_c.update(prev_digest)
        else:              # even
            ctx_c.update(p_str)
        prev_digest = ctx_c.digest()

    final = prev_digest

    # Step 21: Encode the final 64 bytes
    encoded_parts: list[str] = []
    for b2, b1, b0 in _SHA512_PERMUTATION:
        encoded_parts.append(_b64_from_24bit(final[b2], final[b1], final[b0], 4))
    # Last byte (index 63): 2 chars only
    encoded_parts.append(_b64_from_24bit(0, 0, final[63], 2))
    encoded = ''.join(encoded_parts)

    # Reconstruct full hash string
    if explicit_rounds or rounds != 5000:
        return f'$6$rounds={rounds}${salt}${encoded}'
    return f'$6${salt}${encoded}'


def hash_password(password: str, salt: str | None = None, rounds: int = 5000) -> str:
    """
    Hash a password using SHA-512 crypt ($6$ format).

    If *salt* is None, generates a fresh cryptographic salt.
    If *salt* is a full existing hash (starts with $6$), uses its embedded salt
    (suitable for password verification).
    Returns the complete $6$[rounds=N$]salt$hash string.
    """
    if _HAVE_STDLIB_CRYPT:
        if salt is None:
            if rounds == 5000:
                salt = _crypt_module.mksalt(_crypt_module.METHOD_SHA512)
            else:
                salt = _crypt_module.mksalt(_crypt_module.METHOD_SHA512, rounds=rounds)
        return _crypt_module.crypt(password, salt)
    # Pure-Python path
    if salt is None:
        salt = _make_salt_str(rounds if rounds != 5000 else None)
    return _sha512_crypt_pure(password, salt)


def verify_password(password: str, hashed: str) -> bool:
    """
    Verify *password* against *hashed*.

    Returns False immediately for locked/disabled accounts without computing
    anything (prevents timing oracle on account state).
    Uses hmac.compare_digest for constant-time comparison.
    """
    if not hashed or hashed in ('!', '!!', '*') or hashed.startswith('!'):
        return False
    try:
        candidate = hash_password(password, hashed)
    except ValueError:
        return False
    return hmac.compare_digest(candidate, hashed)
