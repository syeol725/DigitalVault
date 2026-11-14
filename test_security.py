import contextlib
import io
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
            recovery_key = vault.recovery_key_display

            source = root / "sample.txt"
            source.write_text("DigitalVault test document", encoding="utf-8")
            vault.add_document(source)

            file_id = next(iter(vault.index))
            original_key = vault.key
            vault.change_password("initial-password-123", "updated-password-456")
            self.assertEqual(vault.key, original_key)
            changed_meta = __import__("json").loads((root / "vault" / "vault.json").read_text(encoding="utf-8"))
            self.assertIn("recovery_wrapped_key", changed_meta)

            reopened = Vault(root / "vault")
            self.assertTrue(reopened.login("updated-password-456"))
            self.assertEqual(len(reopened.index), 1)

            reopened.rotate_master_key("updated-password-456", recovery_key)
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
            self.assertTrue(new_session.integrity_check())
            audit_output = io.StringIO()
            with contextlib.redirect_stdout(audit_output):
                new_session.show_security_log()
            self.assertIn("document_added", audit_output.getvalue())
            self.assertIn("master_key_rotated", audit_output.getvalue())
            self.assertTrue(new_session.recover_with_key(
                recovery_key, "recovered-after-rotation-987"
            ))
            after_recovery = Vault(root / "vault")
            self.assertTrue(after_recovery.login("recovered-after-rotation-987"))

    def test_kdf_rejects_untrusted_parameters(self):
        with self.assertRaises(ValueError):
            derive_key("password", b"0123456789abcdef",
                       {"name": "scrypt", "n": 2**20, "r": 8, "p": 1, "dklen": 32})


    def test_recovery_key_resets_password_without_changing_documents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vault = Vault(root / "vault")
            vault.create("initial-password-123")
            recovery_key = vault.recovery_key_display
            source = root / "recover.txt"
            source.write_text("recovery test", encoding="utf-8")
            vault.add_document(source)

            reopened = Vault(root / "vault")
            self.assertTrue(reopened.recover_with_key(
                recovery_key, "replacement-password-789"
            ))
            session = Vault(root / "vault")
            self.assertTrue(session.login("replacement-password-789"))
            self.assertEqual(len(session.index), 1)
            self.assertTrue(session.integrity_check())


    def test_backup_merge_keeps_open_vault_and_existing_documents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_vault = Vault(root / "source")
            source_vault.create("source-backup-password-123")
            source_file = root / "shared.txt"
            source_file.write_text("from backup", encoding="utf-8")
            source_vault.add_document(source_file)
            backup = root / "source-backup.zip"
            source_vault.create_backup(backup)

            target_vault = Vault(root / "target")
            target_vault.create("target-password-456")
            target_file = root / "shared.txt"
            target_file.write_text("already in target", encoding="utf-8")
            target_vault.add_document(target_file)
            original_id = next(iter(target_vault.index))

            merged = target_vault.merge_backup(backup, "source-backup-password-123")
            self.assertEqual(merged, 1)
            self.assertIsNotNone(target_vault.key)
            self.assertEqual(len(target_vault.index), 2)
            self.assertIn(original_id, target_vault.index)
            self.assertEqual(
                {item["name"] for item in target_vault.index.values()},
                {"shared.txt", "shared (복원 1).txt"},
            )
            self.assertTrue(target_vault.integrity_check())

            reopened = Vault(root / "target")
            self.assertTrue(reopened.login("target-password-456"))
            self.assertEqual(len(reopened.index), 2)

    def test_backup_restore_preserves_encrypted_vault(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vault = Vault(root / "vault")
            vault.create("backup-password-123")
            source = root / "backup.txt"
            source.write_text("backup payload", encoding="utf-8")
            vault.add_document(source)
            backup = root / "vault-backup.zip"
            self.assertGreaterEqual(vault.create_backup(backup), 3)

            restored_path = Vault.restore_backup(backup, root / "restored-vault")
            restored = Vault(restored_path)
            self.assertTrue(restored.login("backup-password-123"))
            self.assertTrue(restored.integrity_check())
            self.assertEqual(len(restored.index), 1)


if __name__ == "__main__":
    unittest.main()
