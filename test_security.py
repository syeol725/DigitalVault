import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from digital_vault import Vault, derive_key, encrypt, decrypt


class DigitalVaultSecurityTests(unittest.TestCase):
    def test_menu_uses_letters_and_normalizes_case(self):
        from digital_vault import normalize_menu_choice
        self.assertEqual(normalize_menu_choice(" a "), "A")
        self.assertEqual(normalize_menu_choice("N"), "N")
        self.assertEqual(normalize_menu_choice("14"), "14")

    def test_continue_prompt_has_bounded_decisions(self):
        from digital_vault import continue_decision
        for answer in ("y", "Y", "yes", "예", "ㅇ"):
            self.assertEqual(continue_decision(answer), "continue")
        for answer in ("n", "N", "no", "아니오", "아니요", "ㄴ"):
            self.assertEqual(continue_decision(answer), "exit")
        for answer in ("", "maybe", "계속", "1"):
            self.assertEqual(continue_decision(answer), "invalid")

    def test_main_menu_displays_a_to_n_without_auto_lock(self):
        from digital_vault import show_main_menu
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            show_main_menu(3)
        rendered = output.getvalue()
        self.assertIn("DigitalVault  |  문서 3개", rendered)
        self.assertIn("A 추가", rendered)
        self.assertIn("N 금고 정보", rendered)
        self.assertIn("0 잠금 및 종료", rendered)
        self.assertNotIn("=" * 20, rendered)
        self.assertNotIn("자동 잠금", rendered)
        self.assertNotIn("남은 시간", rendered)
        self.assertNotIn("선택:", rendered)

    def test_read_input_waits_without_timeout(self):
        from unittest.mock import patch
        from digital_vault import read_input
        with patch("builtins.input", return_value="n"):
            self.assertEqual(read_input("계속하시겠습니까? (y/n): "), "n")

    def test_document_list_is_aligned_sorted_and_shows_total_size(self):
        from digital_vault import Vault, display_width
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docs = root / "documents"
            docs.mkdir()
            (docs / "id-a.bin").write_bytes(b"12345")
            (docs / "id-b.bin").write_bytes(b"1234567")

            vault = Vault.__new__(Vault)
            vault.docs = docs
            vault.index = {
                "id-a": {"name": "zeta.pdf", "extension": ".pdf"},
                "id-b": {"name": "Alpha 보고서.docx", "extension": ".docx"},
            }
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                vault.list_documents()

            rendered = output.getvalue()
            self.assertLess(rendered.index("Alpha 보고서.docx"), rendered.index("zeta.pdf"))
            self.assertIn("DOCX", rendered)
            self.assertIn("PDF", rendered)
            self.assertIn("총 2개  |  12 B", rendered)
            self.assertIn("번호", rendered)
            self.assertIn("파일명", rendered)
            self.assertIn("암호화 크기", rendered)
            rows = rendered.splitlines()
            header = next(line for line in rows if "번호" in line and "파일명" in line)
            data = next(line for line in rows if "Alpha 보고서.docx" in line)
            self.assertEqual(display_width(header), display_width(data))

    def test_long_document_name_is_truncated_by_display_width(self):
        from digital_vault import display_width, truncate_display
        shortened = truncate_display("아주 긴 문서 파일 이름 보고서.pdf", 12)
        self.assertLessEqual(display_width(shortened), 12)
        self.assertTrue(shortened.endswith("…"))


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

    def test_lock_then_new_session_can_log_in_again(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory) / "vault"
            first = Vault(folder)
            first.create("relogin-password-123")
            source = Path(directory) / "relogin.txt"
            source.write_text("still here", encoding="utf-8")
            first.add_document(source)

            first.lock()
            self.assertIsNone(first.key)
            self.assertEqual(first.index, {})

            second = Vault(folder)
            self.assertTrue(second.login("relogin-password-123"))
            self.assertEqual(len(second.index), 1)
            self.assertTrue(second.integrity_check())

    def test_gui_clear_resets_tree_reference_before_relogin(self):
        from digital_vault_gui import DigitalVaultApp

        class FakeRoot:
            def winfo_children(self):
                return []

        app = DigitalVaultApp.__new__(DigitalVaultApp)
        app.root = FakeRoot()
        app.tree = object()
        app._clear()
        self.assertIsNone(app.tree)

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

    def test_backup_contains_only_required_vault_data(self):
        import zipfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vault = Vault(root / "vault")
            vault.create("backup-password-123")
            source = root / "backup.txt"
            source.write_text("backup payload", encoding="utf-8")
            vault.add_document(source)
            (vault.folder / "security.log").write_text("audit record", encoding="ascii")

            backup = root / "vault-backup.zip"
            vault.create_backup(backup)

            with zipfile.ZipFile(backup, "r") as archive:
                names = set(archive.namelist())
            self.assertIn("vault.json", names)
            self.assertIn("index.bin", names)
            self.assertIn("backup_manifest.json", names)
            self.assertIn("documents/" + next(iter(vault.index)) + ".bin", names)
            self.assertNotIn("security.log", names)
            self.assertFalse(any(name.lower().endswith(("readme.md", ".exe", ".py"))
                                 for name in names))

    def test_backup_overwrite_requires_confirmation_flag(self):
        import zipfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vault = Vault(root / "vault")
            vault.create("backup-password-123")
            backup = root / "vault-backup.zip"
            vault.create_backup(backup)

            with self.assertRaises(FileExistsError):
                vault.create_backup(backup)

            backup.write_bytes(b"old backup placeholder")
            count = vault.create_backup(backup, overwrite=True)
            self.assertGreaterEqual(count, 2)
            with zipfile.ZipFile(backup, "r") as archive:
                self.assertIn("backup_manifest.json", archive.namelist())
                self.assertIn("vault.json", archive.namelist())

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
