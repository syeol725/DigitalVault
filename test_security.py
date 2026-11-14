import tempfile
import unittest
from pathlib import Path

from digital_vault import Vault, derive_key, encrypt, decrypt


class DigitalVaultSecurityTests(unittest.TestCase):
    def test_authenticated_encryption_detects_tampering(self):
        key = derive_key("test-password-123", b"0123456789abcdef")
        sealed = encrypt(key, b"private payload", b"test-context")
        self.assertEqual(decrypt(key, sealed, b"test-context"), b"private payload")
        damaged = sealed[:-1] + bytes([sealed[-1] ^ 1])
        with self.assertRaises(Exception):
            decrypt(key, damaged, b"test-context")
        with self.assertRaises(Exception):
            decrypt(key, sealed, b"wrong-context")

    def test_vault_password_change_and_master_key_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vault = Vault(root / "vault")
            vault.create("initial-password-123")

            source = root / "sample.txt"
            source.write_text("DigitalVault test document", encoding="utf-8")
            vault.add_document(source)

            file_id = next(iter(vault.index))
            original_key = vault.key
            vault.change_password("initial-password-123", "updated-password-456")
            self.assertEqual(vault.key, original_key)

            reopened = Vault(root / "vault")
            self.assertTrue(reopened.login("updated-password-456"))
            self.assertEqual(len(reopened.index), 1)

            reopened.rotate_master_key()
            self.assertNotEqual(reopened.key, original_key)

            new_session = Vault(root / "vault")
            self.assertTrue(new_session.login("updated-password-456"))
            info = new_session.index[file_id]
            aad = ("DigitalVault:document:v2:" + file_id).encode()
            plaintext = decrypt(
                new_session.key,
                (new_session.docs / (file_id + ".bin")).read_bytes(),
                aad,
            )
            self.assertEqual(plaintext, b"DigitalVault test document")

    def test_kdf_rejects_untrusted_parameters(self):
        with self.assertRaises(ValueError):
            derive_key("password", b"0123456789abcdef",
                       {"name": "scrypt", "n": 2**20, "r": 8, "p": 1, "dklen": 32})


if __name__ == "__main__":
    unittest.main()
