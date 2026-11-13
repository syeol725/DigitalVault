#!/usr/bin/env python3
"""DigitalVault Portable - cross-platform encrypted USB document vault."""

import base64
import getpass
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

APP_NAME = "DigitalVault"
DATA_DIR_NAME = "DigitalVaultData"
SUPPORTED_EXTENSIONS = {".pdf", ".docx", ".txt", ".pptx", ".xlsx", ".jpg", ".jpeg", ".png"}
MAX_LOGIN_TRIES = 5
LOCK_SECONDS = 60
MAGIC = b"DVLT1"


def app_directory() -> Path:
    """Return the folder containing the executable, or this source file."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def default_vault_directory() -> Path:
    return app_directory() / DATA_DIR_NAME


def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    return MAGIC + nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def decrypt(key: bytes, blob: bytes) -> bytes:
    if len(blob) < len(MAGIC) + 12 + 16 or not blob.startswith(MAGIC):
        raise ValueError("암호화 파일 형식이 올바르지 않습니다.")
    nonce = blob[len(MAGIC):len(MAGIC) + 12]
    ciphertext = blob[len(MAGIC) + 12:]
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(path.name + "." + secrets.token_hex(6) + ".tmp")
    try:
        with open(temp_path, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, path)
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass


def atomic_json(path: Path, obj: dict) -> None:
    atomic_write(path, json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8"))


class Vault:
    def __init__(self, folder: Path):
        self.folder = folder
        self.docs = folder / "documents"
        self.meta_file = folder / "vault.json"
        self.index_file = folder / "index.bin"
        self.lock_file = folder / "login_state.json"
        self.key = None
        self.index = {}
        self.folder.mkdir(parents=True, exist_ok=True)
        self.docs.mkdir(parents=True, exist_ok=True)

    @property
    def exists(self) -> bool:
        return self.meta_file.exists()

    def create(self, password: str) -> None:
        if self.exists:
            raise ValueError("이미 금고가 존재합니다.")
        salt = secrets.token_bytes(16)
        master_key = secrets.token_bytes(32)
        wrapped_key = encrypt(derive_key(password, salt), master_key)
        atomic_json(self.meta_file, {
            "version": 1,
            "kdf": "scrypt",
            "salt": base64.b64encode(salt).decode("ascii"),
            "wrapped_key": base64.b64encode(wrapped_key).decode("ascii"),
        })
        self.key = master_key
        self.index = {}
        self.save_index()
        atomic_json(self.lock_file, {"tries": 0, "until": 0})

    def lock_remaining(self) -> int:
        try:
            state = json.loads(self.lock_file.read_text(encoding="utf-8"))
            return max(0, int(state.get("until", 0)) - int(time.time()))
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return 0

    def login(self, password: str) -> bool:
        remaining = self.lock_remaining()
        if remaining:
            print(f"로그인 제한 중입니다. {remaining}초 후 다시 시도하세요.")
            return False

        try:
            meta = json.loads(self.meta_file.read_text(encoding="utf-8"))
            salt = base64.b64decode(meta["salt"], validate=True)
            wrapped = base64.b64decode(meta["wrapped_key"], validate=True)
            master_key = decrypt(derive_key(password, salt), wrapped)
            if len(master_key) != 32:
                raise ValueError("마스터 키 길이가 올바르지 않습니다.")
            self.key = master_key
            self.index = self.load_index()
            atomic_json(self.lock_file, {"tries": 0, "until": 0})
            return True
        except Exception:
            try:
                state = json.loads(self.lock_file.read_text(encoding="utf-8"))
            except Exception:
                state = {"tries": 0, "until": 0}
            tries = int(state.get("tries", 0)) + 1
            if tries >= MAX_LOGIN_TRIES:
                atomic_json(self.lock_file, {
                    "tries": 0,
                    "until": int(time.time()) + LOCK_SECONDS,
                })
                print(f"로그인 {MAX_LOGIN_TRIES}회 실패: {LOCK_SECONDS}초간 잠깁니다.")
            else:
                atomic_json(self.lock_file, {"tries": tries, "until": 0})
                print(f"비밀번호가 올바르지 않습니다. 남은 횟수: {MAX_LOGIN_TRIES - tries}")
            return False

    def load_index(self) -> dict:
        if not self.index_file.exists():
            return {}
        raw = decrypt(self.key, self.index_file.read_bytes())
        parsed = json.loads(raw.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("금고 색인 데이터가 손상되었습니다.")
        return parsed

    def save_index(self) -> None:
        raw = json.dumps(self.index, ensure_ascii=False).encode("utf-8")
        atomic_write(self.index_file, encrypt(self.key, raw))

    def add_document(self, source: Path) -> None:
        source = source.expanduser().resolve()
        if not source.is_file():
            raise FileNotFoundError(f"파일을 찾을 수 없습니다: {source}")
        if source.suffix.lower() not in SUPPORTED_EXTENSIONS:
            raise ValueError("지원하지 않는 파일 형식입니다.")
        file_id = secrets.token_hex(16)
        encrypted = encrypt(self.key, source.read_bytes())
        atomic_write(self.docs / f"{file_id}.bin", encrypted)
        self.index[file_id] = {
            "name": source.name,
            "extension": source.suffix.lower(),
        }
        try:
            self.save_index()
        except Exception:
            (self.docs / f"{file_id}.bin").unlink(missing_ok=True)
            raise
        print(f"'{source.name}' 문서를 암호화해 저장했습니다.")

    def list_documents(self):
        if not self.index:
            print("저장된 문서가 없습니다.")
            return
        for number, info in enumerate(self.index.values(), 1):
            print(f"{number}. {info['name']}")

    def choose_file_id(self):
        items = list(self.index.items())
        if not items:
            print("저장된 문서가 없습니다.")
            return None
        self.list_documents()
        try:
            number = int(input("문서 번호: ").strip())
        except ValueError:
            return None
        return items[number - 1][0] if 1 <= number <= len(items) else None

    def decrypted_bytes(self, file_id: str) -> bytes:
        return decrypt(self.key, (self.docs / f"{file_id}.bin").read_bytes())

    def export_document(self):
        file_id = self.choose_file_id()
        if not file_id:
            print("문서 선택이 취소되었거나 번호가 올바르지 않습니다.")
            return
        info = self.index[file_id]
        destination_text = input("내보낼 전체 파일 경로: ").strip().strip('"')
        if not destination_text:
            print("경로가 입력되지 않았습니다.")
            return
        destination = Path(destination_text).expanduser()
        if not destination.suffix:
            destination = destination.with_suffix(info["extension"])
        if destination.exists():
            print("같은 이름의 파일이 이미 있습니다. 다른 경로를 입력하세요.")
            return
        destination.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(destination, self.decrypted_bytes(file_id))
        print(f"복호화 파일 저장 완료: {destination}")

    def open_document(self):
        file_id = self.choose_file_id()
        if not file_id:
            print("문서 선택이 취소되었거나 번호가 올바르지 않습니다.")
            return
        info = self.index[file_id]
        temp_dir = Path(tempfile.mkdtemp(prefix="digital_vault_"))
        temp_file = temp_dir / info["name"]
        try:
            temp_file.write_bytes(self.decrypted_bytes(file_id))
            if sys.platform.startswith("win"):
                os.startfile(str(temp_file))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(temp_file)])
            else:
                subprocess.Popen(["xdg-open", str(temp_file)])
            input("문서를 확인한 뒤 Enter를 누르면 임시 파일 정리를 시도합니다.")
        except FileNotFoundError:
            print("파일 열기 프로그램을 찾지 못했습니다. 문서를 내보내기 기능으로 저장하세요.")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
        print("임시 파일 정리를 시도했습니다. 다른 앱이 복사본을 만들었을 수 있으므로 확인하세요.")

    def delete_document(self):
        file_id = self.choose_file_id()
        if not file_id:
            print("문서 선택이 취소되었거나 번호가 올바르지 않습니다.")
            return
        name = self.index[file_id]["name"]
        if input(f"'{name}' 문서를 삭제할까요? (y/n): ").strip().lower() == "y":
            (self.docs / f"{file_id}.bin").unlink(missing_ok=True)
            del self.index[file_id]
            self.save_index()
            print("문서를 삭제했습니다.")

    def change_password(self, old_password: str, new_password: str) -> None:
        meta = json.loads(self.meta_file.read_text(encoding="utf-8"))
        salt = base64.b64decode(meta["salt"], validate=True)
        wrapped = base64.b64decode(meta["wrapped_key"], validate=True)
        master_key = decrypt(derive_key(old_password, salt), wrapped)
        new_salt = secrets.token_bytes(16)
        new_wrapped = encrypt(derive_key(new_password, new_salt), master_key)
        atomic_json(self.meta_file, {
            "version": 1,
            "kdf": "scrypt",
            "salt": base64.b64encode(new_salt).decode("ascii"),
            "wrapped_key": base64.b64encode(new_wrapped).decode("ascii"),
        })
        print("비밀번호를 변경했습니다.")

    def lock(self):
        self.key = None
        self.index = {}
        print("금고를 잠갔습니다. 암호화된 문서는 USB에 그대로 남아 있습니다.")


def prompt_new_password() -> str:
    while True:
        password = getpass.getpass("새 비밀번호(12자 이상 권장): ")
        if len(password) < 8:
            print("비밀번호는 최소 8자 이상이어야 합니다.")
            continue
        confirm = getpass.getpass("비밀번호 확인: ")
        if password != confirm:
            print("비밀번호가 일치하지 않습니다.")
            continue
        return password


def main():
    print("=" * 48)
    print(" DigitalVault Portable")
    print("=" * 48)
    print(f"프로그램 위치: {app_directory()}")
    print(f"기본 금고 위치: {default_vault_directory()}")
    folder_text = input("금고 저장 폴더 (Enter=USB의 기본 폴더): ").strip().strip('"')
    folder = Path(folder_text).expanduser() if folder_text else default_vault_directory()
    vault = Vault(folder)

    if not vault.exists:
        print("새 금고를 생성합니다.")
        vault.create(prompt_new_password())

    while not vault.login(getpass.getpass("비밀번호: ")):
        if vault.lock_remaining():
            return

    try:
        while vault.key is not None:
            print("\n1. 문서 추가  2. 문서 목록  3. 문서 열기")
            print("4. 문서 내보내기  5. 문서 삭제  6. 비밀번호 변경")
            print("7. 금고 잠그기  0. 종료")
            choice = input("선택: ").strip()

            if choice == "1":
                source = input("추가할 파일 경로: ").strip().strip('"')
                if source:
                    try:
                        vault.add_document(Path(source))
                    except Exception as exc:
                        print(f"문서 추가 실패: {exc}")
            elif choice == "2":
                vault.list_documents()
            elif choice == "3":
                vault.open_document()
            elif choice == "4":
                vault.export_document()
            elif choice == "5":
                vault.delete_document()
            elif choice == "6":
                old = getpass.getpass("현재 비밀번호: ")
                new = prompt_new_password()
                try:
                    vault.change_password(old, new)
                except Exception:
                    print("현재 비밀번호가 올바르지 않습니다.")
            elif choice in ("7", "0"):
                vault.lock()
                break
            else:
                print("메뉴 번호를 다시 선택하세요.")
    except (KeyboardInterrupt, EOFError):
        print("\n프로그램을 종료합니다.")
        vault.lock()


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\n종료되었습니다.")
