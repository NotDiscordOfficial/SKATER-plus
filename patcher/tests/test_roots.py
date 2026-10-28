#!/usr/bin/env python3
"""Exercise the certificate importer through its compiled C interface."""

import base64
import ctypes
from pathlib import Path
import re
import subprocess
import sys
import tempfile

lib = ctypes.CDLL(sys.argv[1])
lib.root_pem_check.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p,
                               ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
lib.root_bundle_contains.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p]
lib.root_extra_at.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t,
                             ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
lib.root_remove_extra.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint]


def check(pem):
    fingerprint = ctypes.create_string_buffer(32)
    subject = ctypes.create_string_buffer(192)
    error = ctypes.c_char_p()
    result = lib.root_pem_check(pem, len(pem), fingerprint, subject, len(subject), ctypes.byref(error))
    return result, fingerprint.raw


def generate(directory, name, ca):
    certificate = directory / (name + '.pem')
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', str(directory / (name + '.key')), '-out', str(certificate),
                    '-days', '1', '-subj', '/CN=' + name,
                    '-addext', 'basicConstraints=critical,CA:' + ca],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return certificate.read_bytes()


with tempfile.TemporaryDirectory() as temporary:
    directory = Path(temporary)
    root = generate(directory, 'Test root', 'TRUE')
    leaf = generate(directory, 'Test server', 'FALSE')
    result, fingerprint = check(root)
    assert result == 0
    assert lib.root_bundle_contains(root, len(root), fingerprint) == 1
    assert lib.root_bundle_contains(b'', 0, fingerprint) == 0
    assert check(leaf)[0] != 0
    assert check(root + root)[0] != 0
    assert check(root + b'junk')[0] != 0
    assert check(root + b'\0')[0] != 0
    assert check(b'A' * 8193)[0] != 0
    assert check((directory / 'Test root.key').read_bytes())[0] != 0
    der = bytearray(base64.b64decode(re.search(
        rb'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', root, re.S)[1]))
    der[-1] ^= 1
    tampered = b'-----BEGIN CERTIFICATE-----\n' + base64.b64encode(der) + b'\n-----END CERTIFICATE-----\n'
    assert check(tampered)[0] != 0
    project = Path(__file__).resolve().parents[2]
    ec_root = (project / 'vendor/root-certificates/sectigo-e46.pem').read_bytes()
    assert check(ec_root)[0] == 0
    assert lib.root_bundle_contains(b'# comment\n' + root + ec_root,
                                   len(b'# comment\n' + root + ec_root), check(ec_root)[1]) == 1
    base = b'unchanged built-in certificate bundle\n'
    bundle = ctypes.create_string_buffer(base + root + ec_root)
    size = ctypes.c_size_t(len(base + root + ec_root))
    offset, length = ctypes.c_size_t(), ctypes.c_size_t()
    assert lib.root_extra_at(bundle, size.value, len(base), 1, ctypes.byref(offset), ctypes.byref(length)) == 1
    assert bundle.raw[offset.value:offset.value + length.value].startswith(b'-----BEGIN CERTIFICATE-----')
    original = bundle.raw
    assert lib.root_remove_extra(bundle, ctypes.byref(size), len(base), 2) != 0
    assert bundle.raw == original
    assert lib.root_remove_extra(bundle, ctypes.byref(size), len(base), 0) == 0
    remaining = bundle.raw[:size.value]
    assert remaining.startswith(base)
    assert lib.root_bundle_contains(remaining, len(remaining), fingerprint) == 0
    assert lib.root_bundle_contains(remaining, len(remaining), check(ec_root)[1]) == 1
    assert lib.root_remove_extra(bundle, ctypes.byref(size), len(base), 0) == 0
    assert bundle.raw[:size.value] == base

print('PASS root import: RSA/EC roots, CA constraint, self-signature, duplicate detection')
print('PASS rejected server certificate, tampered signature, chains, keys, oversized and malformed PEM')
print('PASS individual certificate removal preserves other roots and restores exact base after last removal')
