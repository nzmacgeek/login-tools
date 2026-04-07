"""
Tests for the SHA-512 crypt compatibility layer.

These test vectors come from the official sha-crypt specification:
https://www.akkadia.org/docs/sha-crypt.txt

The tests exercise BOTH the stdlib path (if available) and the pure-Python path.
"""
from __future__ import annotations

import pytest
import login_tools._compat_crypt as cc


# Official SHA-512-crypt test vectors from the spec
SHA512_VECTORS: list[tuple[str, str, str]] = [
    (
        'Hello world!',
        '$6$saltstring',
        '$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1',
    ),
    (
        'Hello world!',
        '$6$rounds=10000$saltstringsaltstring',
        '$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.',
    ),
    (
        'This is just a test',
        '$6$rounds=5000$toolongsaltstring',
        '$6$rounds=5000$toolongsaltstrin$KqJWpanXZHKq2BOB43TCaWCx8DC8fbYXJfMiMRigsAyqx.wyZNkT0MHFF9bZbLmSqg5OzqGDZ1fZ3p4cc7Gb0',
    ),
    (
        'a very much longer text to encrypt.  This one even stretches over more than one line.',
        '$6$rounds=1400$anotherlongsaltstring',
        '$6$rounds=1400$anotherlongsalts$POfYIzkSxZkdEjZ6cT0faIVFN1m5RyaXHDBNBKxHwi/I9Kk/6KovJ5X6xyaqnxNjxnB5C15xD2/2scu9dc3pe.',
    ),
    (
        'we have a short salt string but not a short password',
        '$6$rounds=77777$short',
        '$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZW5ZkM0v8uGsbB/',
    ),
    (
        'a short string',
        '$6$rounds=123456$asaltof16chars..',
        '$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1',
    ),
]


def _force_pure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the pure-Python SHA-512 implementation, regardless of stdlib availability."""
    monkeypatch.setattr(cc, '_HAVE_STDLIB_CRYPT', False)


class TestSHA512CryptVectors:
    """
    Test known spec vectors against the pure-Python implementation.

    The stdlib `crypt` module on some platforms normalises the salt differently
    (e.g. omits `rounds=` when the value equals the 5000 default) which can
    produce a valid but different hash than the spec test vector.  We therefore
    always test the spec vectors through the pure-Python path, which gives us
    complete confidence in its correctness regardless of the host platform.
    """

    @pytest.mark.parametrize('password,salt,expected', SHA512_VECTORS)
    def test_hash_vector_pure_python(
        self, monkeypatch: pytest.MonkeyPatch, password: str, salt: str, expected: str
    ) -> None:
        """Pure-Python path must match the official SHA-crypt spec vectors exactly."""
        _force_pure(monkeypatch)
        result = cc.hash_password(password, salt)
        assert result == expected, (
            f'pure hash_password({password!r}, {salt!r})\n'
            f'  got:      {result!r}\n'
            f'  expected: {expected!r}'
        )

    def test_stdlib_round_trip(self) -> None:
        """stdlib path (if present): round-trip hash + verify is sufficient."""
        h = cc.hash_password('testpassword')
        assert cc.verify_password('testpassword', h) is True
        assert cc.verify_password('wrongpassword', h) is False


class TestVerifyPassword:
    def test_correct_password(self) -> None:
        h = cc.hash_password('mypassword')
        assert cc.verify_password('mypassword', h) is True

    def test_wrong_password(self) -> None:
        h = cc.hash_password('mypassword')
        assert cc.verify_password('wrongpassword', h) is False

    def test_locked_hash(self) -> None:
        h = cc.hash_password('mypassword')
        assert cc.verify_password('mypassword', '!' + h) is False

    def test_disabled_markers(self) -> None:
        for marker in ('!', '!!', '*', ''):
            assert cc.verify_password('anything', marker) is False

    def test_pure_python_verify(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _force_pure(monkeypatch)
        h = cc.hash_password('testpass')
        assert cc.verify_password('testpass', h) is True
        assert cc.verify_password('otherpass', h) is False


class TestSaltGeneration:
    def test_fresh_salt_produces_valid_hash(self) -> None:
        h = cc.hash_password('password')
        assert h.startswith('$6$')
        assert cc.verify_password('password', h) is True

    def test_custom_rounds(self) -> None:
        h = cc.hash_password('password', rounds=10000)
        assert 'rounds=10000' in h

    def test_default_rounds_not_in_string(self) -> None:
        h = cc.hash_password('password', rounds=5000)
        # Default rounds (5000) are not encoded in the output
        assert 'rounds=' not in h

    def test_two_fresh_hashes_differ(self) -> None:
        h1 = cc.hash_password('password')
        h2 = cc.hash_password('password')
        assert h1 != h2  # different salts
