#!/usr/bin/env python3
"""Regression controls for the former vulnerable private-RSA call path."""
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('rsa_scope', Path(__file__).with_name('check-rsa-scope.py'))
scope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scope)


class RsaScopeTests(unittest.TestCase):
    def test_rejects_previous_private_decryption(self):
        self.assertTrue(scope.violations('private_key\n .inner()\n .decrypt(padding, ciphertext)'))
        self.assertTrue(scope.violations('key.inner( ).sign_with_rng(&mut rng, padding, digest)'))

    def test_rejects_private_operation_imports(self):
        for source in ('use rsa::hazmat;', 'use rsa::Pkcs1v15Sign;', 'use rsa::pss::{SigningKey};'):
            with self.subTest(source=source):
                self.assertTrue(scope.violations(source))

    def test_allows_public_operations_and_native_backend(self):
        self.assertFalse(scope.violations('public_key.inner().encrypt(&mut rng, padding, plaintext)'))
        self.assertFalse(scope.violations('let key = PrivateDecryptingKey::from_pkcs8(der.as_bytes())?; key.decrypt(&OAEP_SHA512_MGF1SHA512, ciphertext, &mut plaintext, None)'))


if __name__ == '__main__':
    unittest.main()
