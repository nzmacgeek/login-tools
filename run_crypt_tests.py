"""Quick test runner for SHA-512 crypt vectors."""
import sys
import os

# Force pure Python path
import login_tools._compat_crypt as cc
cc._HAVE_STDLIB_CRYPT = False

VECTORS = [
    ('Hello world!', '$6$saltstring',
     '$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1'),
    ('Hello world!', '$6$rounds=10000$saltstringsaltstring',
     '$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.'),
    ('This is just a test', '$6$rounds=5000$toolongsaltstring',
     '$6$rounds=5000$toolongsaltstrin$KqJWpanXZHKq2BOB43TCaWCx8DC8fbYXJfMiMRigsAyqx.wyZNkT0MHFF9bZbLmSqg5OzqGDZ1fZ3p4cc7Gb0'),
]

all_pass = True
for pw, salt, expected in VECTORS:
    result = cc.hash_password(pw, salt)
    if result == expected:
        print(f'PASS: {salt[:30]}...')
    else:
        print(f'FAIL: {salt[:30]}...')
        print(f'  got:      {result}')
        print(f'  expected: {expected}')
        all_pass = False

# Test round-trip
h = cc.hash_password('testpassword')
assert cc.verify_password('testpassword', h), "Round-trip failed"
assert not cc.verify_password('wrong', h), "Wrong password should fail"
print('PASS: round-trip verify')

sys.exit(0 if all_pass else 1)
