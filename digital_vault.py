#!/usr/bin/env python3
"""DigitalVault Portable - Windows 10/11 USB document vault."""

import base64
import getpass
import hashlib
import json
import os
import secrets
import shutil
import sys
import tempfile
import time
import zipfile
from io import BytesIO
from datetime import datetime, timezone
from pathlib import Path
from tkinter import Tk, filedialog

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

EXTENSIONS = {".pdf", ".docx", ".txt", ".pptx", ".xlsx", ".jpg", ".jpeg", ".png"}
MAX_TRIES = 5
LOCK_SECONDS = 60
FORMAT_VERSION = 2
KDF_PARAMS = {"name": "scrypt", "n": 2**17, "r": 8, "p": 1, "dklen": 32}
KDF_MAXMEM = 256 * 1024 * 1024
IDLE_TIMEOUT_SECONDS = 300
WRAP_AAD = b"DigitalVault:master-key:v2"
INDEX_AAD = b"DigitalVault:index:v2"


# ---------- 논리 게이트 ----------
def AND(a, b):
    return int(bool(a) and bool(b))


def OR(a, b):
    return int(bool(a) or bool(b))


def NOT(a):
    return int(not bool(a))


def XOR(a, b):
    return int(bool(a) != bool(b))


def NAND(a, b):
    return NOT(AND(a, b))


def NOR(a, b):
    return NOT(OR(a, b))


def XNOR(a, b):
    return NOT(XOR(a, b))


def can_open(password_ok, storage_ok, lock_ok):
    # 금고 개방 조건: 비밀번호 AND 저장소 AND 잠금 해제
    return AND(AND(password_ok, storage_ok), lock_ok)


# ---------- 공통 도구 ----------
def write_json(path, data):
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    os.replace(temp, path)


def derive_key(password, salt, params=None):
    params = params or KDF_PARAMS
    if params.get("name") != "scrypt":
        raise ValueError("지원하지 않는 키 파생 알고리즘입니다.")
    n, r, p, dklen = int(params["n"]), int(params["r"]), int(params["p"]), int(params["dklen"])
    if n != 2**17 or r != 8 or p != 1 or dklen != 32:
        raise ValueError("유효하지 않은 KDF 설정입니다.")
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                          dklen=dklen, maxmem=KDF_MAXMEM)


def encrypt(key, data, aad=None):
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, data, aad)


def decrypt(key, data, aad=None):
    if len(data) < 13:
        raise ValueError("암호화 데이터가 손상되었습니다.")
    return AESGCM(key).decrypt(data[:12], data[12:], aad)


def timed_input(prompt, timeout):
    """메뉴 입력을 제한 시간 동안 기다립니다. 시간 초과 시 None을 반환합니다."""
    print(prompt, end="", flush=True)
    deadline, chars = time.monotonic() + timeout, []
    if os.name == "nt":
        import msvcrt
        while time.monotonic() < deadline:
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                code = ord(ch)
                if code in (10, 13):
                    print()
                    return "".join(chars)
                if code == 3:
                    raise KeyboardInterrupt
                if code == 8:
                    if chars:
                        chars.pop()
                        print(chr(8) + " " + chr(8), end="", flush=True)
                elif ch.isprintable():
                    chars.append(ch)
                    print(ch, end="", flush=True)
            else:
                time.sleep(0.05)
    else:
        import select
        import termios
        import tty
        if not sys.stdin.isatty():
            return input()
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while time.monotonic() < deadline:
                ready, _, _ = select.select([sys.stdin], [], [], 0.1)
                if not ready:
                    continue
                ch = os.read(fd, 1).decode("utf-8", errors="ignore")
                if not ch:
                    continue
                code = ord(ch)
                if code in (10, 13):
                    print()
                    return "".join(chars)
                if code in (8, 127):
                    if chars:
                        chars.pop()
                        print(chr(8) + " " + chr(8), end="", flush=True)
                elif code == 3:
                    raise KeyboardInterrupt
                elif ch.isprintable():
                    chars.append(ch)
                    print(ch, end="", flush=True)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    print()
    print("입력 대기 시간이 초과되어 금고를 잠급니다.")
    return None


def read_input(prompt):
    value = timed_input(prompt, IDLE_TIMEOUT_SECONDS)
    if value is None:
        raise TimeoutError("미사용 시간이 초과되어 금고를 잠급니다.")
    return value


def atomic_write(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(path.name + ".tmp")
    try:
        temp_path.write_bytes(data)
        os.replace(temp_path, path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def app_directory():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    if "__file__" in globals():
        return Path(__file__).resolve().parent
    # Google Colab 등 __file__이 없는 대화형 환경의 테스트용 경로
    return Path.cwd()


def default_vault_directory():
    return app_directory() / "DigitalVaultData"


def masked_password(prompt, timeout=None):
    """실제 문자를 숨기고 별표로 표시합니다. timeout 초과 시 None을 반환합니다."""
    print(prompt, end="", flush=True)
    deadline = None if timeout is None else time.monotonic() + timeout

    if os.name == "nt":
        import msvcrt
        chars = []
        while True:
            if deadline is not None and time.monotonic() >= deadline:
                print()
                print("입력 대기 시간이 초과되어 금고를 잠급니다.")
                return None
            if not msvcrt.kbhit():
                time.sleep(0.05)
                continue
            char = msvcrt.getwch()
            code = ord(char)
            if code in (10, 13):
                print()
                return "".join(chars)
            if code == 3:
                raise KeyboardInterrupt
            if code == 8:
                if chars:
                    chars.pop()
                    print(chr(8) + " " + chr(8), end="", flush=True)
                continue
            if code in (0, 224):
                msvcrt.getwch()
                continue
            if char.isprintable():
                chars.append(char)
                print("*", end="", flush=True)

    if sys.stdin.isatty():
        import codecs
        import select
        import termios
        import tty

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        chars = []
        decoder = codecs.getincrementaldecoder("utf-8")()
        try:
            tty.setcbreak(fd)
            input_settings = termios.tcgetattr(fd)
            input_settings[3] &= ~termios.ECHO
            termios.tcsetattr(fd, termios.TCSADRAIN, input_settings)
            while True:
                wait = 0.1
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        print()
                        print("입력 대기 시간이 초과되어 금고를 잠급니다.")
                        return None
                    wait = min(wait, remaining)
                ready, _, _ = select.select([fd], [], [], wait)
                if not ready:
                    continue
                raw = os.read(fd, 1)
                if raw in (bytes([13]), bytes([10])):
                    print()
                    return "".join(chars)
                if raw == bytes([3]):
                    raise KeyboardInterrupt
                if raw == bytes([4]):
                    raise EOFError
                if raw in (bytes([127]), bytes([8])):
                    if chars:
                        chars.pop()
                        sys.stdout.write(chr(8) + " " + chr(8))
                        sys.stdout.flush()
                    decoder.reset()
                    continue
                char = decoder.decode(raw)
                if char and char.isprintable():
                    chars.append(char)
                    sys.stdout.write("*")
                    sys.stdout.flush()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    if timeout is not None:
        return getpass.getpass(prompt)
    return getpass.getpass(prompt)

def prompt_new_password(timeout=None):
    while True:
        password = masked_password("새 비밀번호: ", timeout)
        if password is None:
            raise TimeoutError("미사용 시간이 초과되어 금고를 잠급니다.")

        if len(password) < 8:
            print("비밀번호는 8자 이상이어야 합니다. 다시 입력하세요.")
            continue

        confirm = masked_password("비밀번호 확인: ", timeout)
        if confirm is None:
            raise TimeoutError("미사용 시간이 초과되어 금고를 잠급니다.")
        if password != confirm:
            print("비밀번호가 일치하지 않습니다.")
            continue

        return password


# ---------- 금고 ----------
class Vault:
    def __init__(self, folder):
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)
        self.docs = self.folder / "documents"
        self.docs.mkdir(exist_ok=True)
        self.meta_file = self.folder / "vault.json"
        self.index_file = self.folder / "index.bin"
        self.lock_file = self.folder / "login_state.json"
        self.key = None
        self.index = {}
        self.temp_prefix = "digitalvault_" + hashlib.sha256(
            str(self.folder.resolve()).encode("utf-8")
        ).hexdigest()[:12] + "_"
        self.cleanup_stale_temp_files()

    @property
    def exists(self):
        return self.meta_file.exists()

    def create(self, password):
        if self.meta_file.exists():
            raise ValueError("이미 금고가 존재합니다.")

        salt = secrets.token_bytes(16)
        master = secrets.token_bytes(32)
        wrap_key = derive_key(password, salt)
        wrapped = encrypt(wrap_key, master, WRAP_AAD)
        recovery_key = secrets.token_urlsafe(32)
        recovery_salt = secrets.token_bytes(16)
        recovery_wrapped = encrypt(
            derive_key(recovery_key, recovery_salt), master,
            b"DigitalVault:recovery-key:v1"
        )
        write_json(self.meta_file, {
            "format_version": FORMAT_VERSION,
            "kdf": KDF_PARAMS,
            "salt": base64.b64encode(salt).decode("ascii"),
            "wrapped_key": base64.b64encode(wrapped).decode("ascii"),
            "recovery_salt": base64.b64encode(recovery_salt).decode("ascii"),
            "recovery_wrapped_key": base64.b64encode(recovery_wrapped).decode("ascii"),
        })
        self.key, self.index = master, {}
        self.recovery_key_display = recovery_key
        self.save_index()

    def lock_status(self):
        if not self.lock_file.exists():
            return 0
        try:
            state = json.loads(self.lock_file.read_text(encoding="utf-8"))
            return max(0, int(state.get("until", 0)) - int(time.time()))
        except (ValueError, OSError, TypeError):
            return 0

    def login(self, password):
        remaining = self.lock_status()
        if remaining:
            print(f"로그인 제한 중입니다. {remaining}초 후 다시 시도하세요.")
            return False

        try:
            meta = json.loads(self.meta_file.read_text(encoding="utf-8"))
            if meta.get("format_version") != FORMAT_VERSION:
                raise ValueError("지원하지 않는 금고 포맷입니다.")
            salt = base64.b64decode(meta["salt"], validate=True)
            wrapped = base64.b64decode(meta["wrapped_key"], validate=True)
            master = decrypt(derive_key(password, salt, meta.get("kdf")), wrapped, WRAP_AAD)
            if len(master) != 32:
                raise ValueError("잘못된 금고 키입니다.")
        except Exception:
            try:
                state = json.loads(self.lock_file.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                state = {"tries": 0}

            tries = int(state.get("tries", 0)) + 1
            if tries >= MAX_TRIES:
                write_json(
                    self.lock_file,
                    {"tries": 0, "until": int(time.time()) + LOCK_SECONDS},
                )
                print(f"로그인 {MAX_TRIES}회 실패: {LOCK_SECONDS}초간 잠깁니다.")
            else:
                write_json(self.lock_file, {"tries": tries, "until": 0})
                print(f"비밀번호가 틀렸습니다. 남은 횟수: {MAX_TRIES - tries}")
            return False

        self.key = master
        self.index = self.load_index()
        write_json(self.lock_file, {"tries": 0, "until": 0})
        self.log_event("login_success")
        return True

    def load_index(self):
        if not self.index_file.exists():
            return {}
        return json.loads(
            decrypt(self.key, self.index_file.read_bytes(), INDEX_AAD).decode("utf-8")
        )

    def save_index(self):
        data = json.dumps(self.index, ensure_ascii=False).encode("utf-8")
        atomic_write(self.index_file, encrypt(self.key, data, INDEX_AAD))

    def cleanup_stale_temp_files(self):
        cutoff = time.time() - 24 * 60 * 60
        for item in Path(tempfile.gettempdir()).glob(self.temp_prefix + "*"):
            try:
                if item.is_dir() and item.stat().st_mtime < cutoff:
                    shutil.rmtree(item, ignore_errors=True)
            except OSError:
                pass

    def rotate_master_key(self, password, recovery_key=None):
        """새 마스터 키로 재암호화하고 메타데이터까지 함께 교체합니다."""
        if self.key is None:
            raise RuntimeError("잠금 해제된 금고에서만 실행할 수 있습니다.")

        meta = json.loads(self.meta_file.read_text(encoding="utf-8"))
        salt = base64.b64decode(meta["salt"], validate=True)
        wrapped = base64.b64decode(meta["wrapped_key"], validate=True)
        verified_master = decrypt(
            derive_key(password, salt, meta.get("kdf")), wrapped, WRAP_AAD
        )
        if not secrets.compare_digest(verified_master, self.key):
            raise ValueError("현재 비밀번호가 올바르지 않습니다.")

        new_key = secrets.token_bytes(32)
        new_salt = secrets.token_bytes(16)
        new_wrapped = encrypt(derive_key(password, new_salt), new_key, WRAP_AAD)
        new_meta = {
            "format_version": FORMAT_VERSION,
            "kdf": KDF_PARAMS,
            "salt": base64.b64encode(new_salt).decode("ascii"),
            "wrapped_key": base64.b64encode(new_wrapped).decode("ascii"),
        }
        if meta.get("recovery_salt") and meta.get("recovery_wrapped_key"):
            if not recovery_key:
                raise ValueError("복구 키가 있어야 마스터 키 재발급 후에도 복구 기능을 유지할 수 있습니다.")
            recovery_salt = base64.b64decode(meta["recovery_salt"], validate=True)
            old_recovery_master = decrypt(
                derive_key(recovery_key, recovery_salt),
                base64.b64decode(meta["recovery_wrapped_key"], validate=True),
                b"DigitalVault:recovery-key:v1"
            )
            if not secrets.compare_digest(old_recovery_master, self.key):
                raise ValueError("복구 키가 올바르지 않습니다.")
            new_meta["recovery_salt"] = meta["recovery_salt"]
            new_meta["recovery_wrapped_key"] = base64.b64encode(
                encrypt(derive_key(recovery_key, recovery_salt), new_key,
                        b"DigitalVault:recovery-key:v1")
            ).decode("ascii")

        stage = self.folder / (".rotation-" + secrets.token_hex(8))
        staged_docs = stage / "documents"
        backup_docs = self.folder / (".documents-backup-" + secrets.token_hex(8))
        staged_docs.mkdir(parents=True)
        old_index, old_meta = stage / "index.old", stage / "vault.old"
        staged_index, staged_meta = stage / "index.new", stage / "vault.new"
        audit_path = self.folder / "security.log"
        old_audit, staged_audit = stage / "security.old", stage / "security.new"
        try:
            for file_id in self.index:
                aad = ("DigitalVault:document:v2:" + file_id).encode()
                plain = decrypt(
                    self.key, (self.docs / (file_id + ".bin")).read_bytes(), aad
                )
                atomic_write(
                    staged_docs / (file_id + ".bin"),
                    encrypt(new_key, plain, aad),
                )

            index_data = json.dumps(self.index, ensure_ascii=False).encode("utf-8")
            atomic_write(staged_index, encrypt(new_key, index_data, INDEX_AAD))
            write_json(staged_meta, new_meta)
            if self.index_file.exists():
                shutil.copy2(self.index_file, old_index)
            shutil.copy2(self.meta_file, old_meta)
            if audit_path.exists():
                converted = []
                for line in audit_path.read_text(encoding="ascii").splitlines():
                    record = decrypt(self.key, base64.b64decode(line, validate=True),
                                     b"DigitalVault:audit:v1")
                    converted.append(base64.b64encode(
                        encrypt(new_key, record, b"DigitalVault:audit:v1")
                    ).decode("ascii"))
                atomic_write(staged_audit, ("\n".join(converted) + "\n").encode("ascii"))
                shutil.copy2(audit_path, old_audit)

            self.docs.rename(backup_docs)
            try:
                staged_docs.rename(self.docs)
                os.replace(staged_index, self.index_file)
                os.replace(staged_meta, self.meta_file)
                if staged_audit.exists():
                    os.replace(staged_audit, audit_path)
            except Exception:
                if self.docs.exists():
                    shutil.rmtree(self.docs, ignore_errors=True)
                if backup_docs.exists():
                    backup_docs.rename(self.docs)
                if old_index.exists():
                    os.replace(old_index, self.index_file)
                if old_meta.exists():
                    os.replace(old_meta, self.meta_file)
                if old_audit.exists():
                    os.replace(old_audit, audit_path)
                raise

            shutil.rmtree(backup_docs, ignore_errors=True)
            self.key = new_key
            print("마스터 키를 재발급하고 문서·인덱스·키 메타데이터를 갱신했습니다.")
        finally:
            shutil.rmtree(stage, ignore_errors=True)

    def add_document(self, source=None):
        if not source:
            try:
                root = Tk()
                root.withdraw()
                try:
                    source = filedialog.askopenfilename(
                        title="금고에 추가할 문서 선택",
                        filetypes=[
                            (
                                "지원 문서",
                                "*.pdf *.docx *.txt *.pptx *.xlsx *.jpg *.jpeg *.png",
                            ),
                            ("모든 파일", "*.*"),
                        ],
                    )
                finally:
                    root.destroy()
            except Exception:
                print("GUI 환경을 사용할 수 없습니다.")
                source = read_input("추가할 파일 경로: ").strip().strip('"')

        if not source:
            print("파일 선택이 취소되었습니다.")
            return

        source = Path(str(source).strip().strip('"').strip("'")).expanduser()
        if not source.exists() or not source.is_file():
            print(f"파일이 존재하지 않습니다: {source}")
            return
        if source.suffix.lower() not in EXTENSIONS:
            print("지원하지 않는 파일 형식입니다.")
            return

        try:
            file_id = secrets.token_hex(12)
            encrypted = encrypt(self.key, source.read_bytes(),
                                 ("DigitalVault:document:v2:" + file_id).encode())
            atomic_write(self.docs / (file_id + ".bin"), encrypted)

            self.index[file_id] = {
                "name": source.name,
                "extension": source.suffix.lower(),
            }
            self.save_index()
            self.log_event("document_added")
            print(f"'{source.name}' 문서를 금고에 저장했습니다.")
        except Exception as error:
            print("저장 오류:", error)

    def list_documents(self):
        if not self.index:
            print("저장된 문서가 없습니다.")
            return

        print("\n===== 저장된 문서 목록 =====")
        print("{:<5}{:<30}{:<8}{:>12}".format("번호", "파일명", "형식", "암호화 크기"))
        print("-" * 58)
        items = sorted(self.index.items(), key=lambda item: item[1]["name"].casefold())
        for number, (file_id, info) in enumerate(items, 1):
            path = self.docs / (file_id + ".bin")
            size = path.stat().st_size if path.exists() else 0
            print("{:<5}{:<30}{:<8}{:>10,} B".format(
                number, info["name"][:28], info["extension"], size
            ))
        print("-" * 58)
        print("총 문서: {}개".format(len(items)))

    def choose_id(self):
        items = sorted(self.index.items(), key=lambda item: item[1]["name"].casefold())
        if not items:
            print("저장된 문서가 없습니다.")
            return None

        self.list_documents()
        try:
            number = int(read_input("문서 번호: "))
            if 1 <= number <= len(items):
                return items[number - 1][0]
        except ValueError:
            pass

        print("올바른 번호가 아닙니다.")
        return None

    def export_document(self):
        file_id = self.choose_id()
        if not file_id:
            return

        info = self.index[file_id]
        original_ext = info["extension"]

        root = None
        try:
            root = Tk()
            root.withdraw()
            destination_text = filedialog.asksaveasfilename(
                title="문서를 내보낼 위치 선택",
                initialfile=info["name"],
                defaultextension=original_ext,
                filetypes=[
                    (f"원본 형식 (*{original_ext})", f"*{original_ext}"),
                    ("모든 파일", "*.*"),
                ],
                confirmoverwrite=False,
            )
        except Exception as error:
            print(f"저장 위치 선택 창을 열 수 없습니다: {error}")
            return
        finally:
            if root is not None:
                root.destroy()

        if not destination_text:
            print("문서 내보내기를 취소했습니다.")
            return

        destination = Path(destination_text).expanduser()

        if destination.suffix.lower() != original_ext.lower():
            if destination.suffix:
                print("원본 문서와 확장자가 다릅니다.")
                return
            destination = destination.with_suffix(original_ext)

        if destination.exists():
            answer = read_input(
                "같은 이름의 파일이 있습니다. 덮어쓸까요? (y/n): "
            ).strip().lower()
            if answer != "y":
                print("저장을 취소했습니다.")
                return

        try:
            data = decrypt(
                self.key,
                (self.docs / (file_id + ".bin")).read_bytes(),
                ("DigitalVault:document:v2:" + file_id).encode(),
            )
            atomic_write(destination, data)
            print(f"문서 내보내기 완료: {destination}")
            print("내보낸 파일은 금고 외부에 일반 파일로 저장됩니다.")
        except Exception as error:
            print(f"문서 내보내기 중 오류가 발생했습니다: {error}")

    def open_document(self):
        file_id = self.choose_id()
        if not file_id:
            return

        temp_dir = None
        try:
            info = self.index[file_id]
            data = decrypt(
                self.key,
                (self.docs / (file_id + ".bin")).read_bytes(),
                ("DigitalVault:document:v2:" + file_id).encode(),
            )

            temp_dir = Path(tempfile.mkdtemp(prefix=self.temp_prefix))
            try: os.chmod(temp_dir, 0o700)
            except OSError: pass
            temp_file = temp_dir / Path(info["name"]).name
            temp_file.write_bytes(data)
            try: os.chmod(temp_file, 0o600)
            except OSError: pass

            os.startfile(str(temp_file))
            read_input(
                "문서 확인을 마친 후 Enter를 누르면 임시 파일이 정리됩니다."
            )
        except Exception as error:
            print(f"문서를 여는 중 오류가 발생했습니다: {error}")
        finally:
            if temp_dir is not None:
                shutil.rmtree(temp_dir, ignore_errors=True)
                print("임시 파일 정리를 마쳤습니다.")

    def delete_document(self):
        if not self.index:
            print("저장된 문서가 없습니다.")
            return

        items = list(self.index.items())
        self.list_documents()

        raw_numbers = read_input(
            "삭제할 문서 번호 (여러 개는 쉼표로 구분): "
        ).strip()

        if not raw_numbers:
            print("삭제를 취소했습니다.")
            return

        try:
            numbers = [int(value.strip()) for value in raw_numbers.split(",")]
            if not numbers or any(
                number < 1 or number > len(items) for number in numbers
            ):
                raise ValueError
        except ValueError:
            print("올바른 문서 번호를 입력하세요.")
            return

        # 같은 번호를 여러 번 입력해도 한 번만 처리합니다.
        selected_ids = [items[number - 1][0] for number in dict.fromkeys(numbers)]
        selected_names = [self.index[file_id]["name"] for file_id in selected_ids]

        print("\n삭제할 문서:")
        for name in selected_names:
            print(f"- {name}")

        answer = read_input(
            f"선택한 문서 {len(selected_ids)}개를 삭제할까요? (y/n): "
        ).strip().lower()

        if answer != "y":
            print("삭제를 취소했습니다.")
            return

        for file_id in selected_ids:
            (self.docs / (file_id + ".bin")).unlink(missing_ok=True)
            del self.index[file_id]

        self.save_index()
        self.log_event("document_deleted")
        print(f"문서 {len(selected_ids)}개를 삭제했습니다.")

    def change_password(self, old_password, new_password):
        try:
            meta = json.loads(self.meta_file.read_text(encoding="utf-8"))
            if meta.get("format_version") != FORMAT_VERSION:
                raise ValueError("지원하지 않는 금고 포맷입니다.")
            salt = base64.b64decode(meta["salt"], validate=True)
            wrapped = base64.b64decode(meta["wrapped_key"], validate=True)
            master = decrypt(
                derive_key(old_password, salt, meta.get("kdf")), wrapped, WRAP_AAD
            )

            new_salt = secrets.token_bytes(16)
            new_wrapped = encrypt(derive_key(new_password, new_salt), master, WRAP_AAD)
            meta.update({
                "format_version": FORMAT_VERSION,
                "kdf": KDF_PARAMS,
                "salt": base64.b64encode(new_salt).decode("ascii"),
                "wrapped_key": base64.b64encode(new_wrapped).decode("ascii"),
            })
            write_json(self.meta_file, meta)
            self.log_event("password_changed")
            print("비밀번호를 변경했습니다.")
        except Exception:
            print("비밀번호 변경에 실패했습니다. 현재 비밀번호를 확인하세요.")


    def setup_recovery_key(self, password):
        meta = json.loads(self.meta_file.read_text(encoding="utf-8"))
        salt = base64.b64decode(meta["salt"], validate=True)
        master = decrypt(derive_key(password, salt, meta.get("kdf")),
                         base64.b64decode(meta["wrapped_key"], validate=True), WRAP_AAD)
        if not secrets.compare_digest(master, self.key):
            raise ValueError("현재 비밀번호가 올바르지 않습니다.")
        recovery_key = secrets.token_urlsafe(32)
        recovery_salt = secrets.token_bytes(16)
        recovery_wrapped = encrypt(derive_key(recovery_key, recovery_salt), master,
                                   b"DigitalVault:recovery-key:v1")
        meta["recovery_salt"] = base64.b64encode(recovery_salt).decode("ascii")
        meta["recovery_wrapped_key"] = base64.b64encode(recovery_wrapped).decode("ascii")
        self._write_meta_atomic(meta)
        self.log_event("recovery_key_issued")
        return recovery_key

    def _write_meta_atomic(self, meta):
        temp = self.meta_file.with_name(self.meta_file.name + ".tmp")
        temp.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temp, self.meta_file)

    def recover_with_key(self, recovery_key, new_password):
        meta = json.loads(self.meta_file.read_text(encoding="utf-8"))
        if not meta.get("recovery_salt") or not meta.get("recovery_wrapped_key"):
            raise ValueError("복구 키가 설정되어 있지 않습니다.")
        recovery_salt = base64.b64decode(meta["recovery_salt"], validate=True)
        master = decrypt(derive_key(recovery_key, recovery_salt),
                         base64.b64decode(meta["recovery_wrapped_key"], validate=True),
                         b"DigitalVault:recovery-key:v1")
        if len(master) != 32:
            raise ValueError("복구 키가 올바르지 않습니다.")
        index = json.loads(decrypt(master, self.index_file.read_bytes(), INDEX_AAD))
        new_salt = secrets.token_bytes(16)
        meta["salt"] = base64.b64encode(new_salt).decode("ascii")
        meta["kdf"] = KDF_PARAMS
        meta["wrapped_key"] = base64.b64encode(
            encrypt(derive_key(new_password, new_salt), master, WRAP_AAD)
        ).decode("ascii")
        self._write_meta_atomic(meta)
        self.key, self.index = master, index
        write_json(self.lock_file, {"tries": 0, "until": 0})
        self.log_event("password_recovered")
        return True

    def log_event(self, event):
        if self.key is None:
            return
        record = {
            "time": datetime.now(timezone.utc).isoformat(),
            "event": str(event)[:64]
        }
        sealed = encrypt(self.key, json.dumps(record).encode("utf-8"),
                         b"DigitalVault:audit:v1")
        with (self.folder / "security.log").open("a", encoding="ascii") as stream:
            stream.write(base64.b64encode(sealed).decode("ascii") + "\n")

    def show_security_log(self):
        path = self.folder / "security.log"
        if not path.exists():
            print("보안 기록이 없습니다.")
            return
        for number, line in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
            try:
                record = json.loads(decrypt(
                    self.key, base64.b64decode(line, validate=True),
                    b"DigitalVault:audit:v1"
                ))
                print("{}  {}  {}".format(number, record["time"], record["event"]))
            except Exception:
                print("{}  [읽을 수 없는 기록]".format(number))
        print("※ USB 내부 기록은 완전한 위변조 방지를 보장하지 않습니다.")

    def integrity_check(self):
        print("\n===== 금고 무결성 검사 =====")
        try:
            meta = json.loads(self.meta_file.read_text(encoding="utf-8"))
            if meta.get("format_version") != FORMAT_VERSION:
                raise ValueError("지원하지 않는 금고 포맷입니다.")
            index = json.loads(decrypt(self.key, self.index_file.read_bytes(), INDEX_AAD))
            if not isinstance(index, dict):
                raise ValueError("인덱스 형식이 올바르지 않습니다.")
        except Exception as error:
            print(f"[오류] 금고 메타데이터 또는 인덱스: {error}")
            return False
        failures = []
        for file_id, info in index.items():
            try:
                path = self.docs / (file_id + ".bin")
                aad = ("DigitalVault:document:v2:" + file_id).encode()
                decrypt(self.key, path.read_bytes(), aad)
                print(f"[정상] {info.get('name', file_id)}")
            except Exception as error:
                failures.append((info.get("name", file_id), str(error)))
                print(f"[확인 필요] {info.get('name', file_id)}")
        print(f"검사 문서: {len(index)}개 / 이상 항목: {len(failures)}개")
        return not failures

    def create_backup(self, destination):
        destination = Path(destination).expanduser()
        if destination.exists():
            raise FileExistsError("기존 백업 파일을 덮어쓰지 않습니다.")
        files = [self.meta_file, self.index_file] + sorted(self.docs.glob("*.bin"))
        audit_path = self.folder / "security.log"
        if audit_path.exists():
            files.append(audit_path)
        manifest = {}
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in files:
                name = path.relative_to(self.folder).as_posix()
                data = path.read_bytes()
                manifest[name] = hashlib.sha256(data).hexdigest()
                archive.writestr(name, data)
            archive.writestr("backup_manifest.json", json.dumps({
                "format": 1, "created_utc": datetime.now(timezone.utc).isoformat(),
                "files": manifest
            }, indent=2))
        atomic_write(destination, buffer.getvalue())
        self.log_event("backup_created")
        return len(files)

    @staticmethod
    def restore_backup(archive_path, destination):
        archive_path, destination = Path(archive_path), Path(destination)
        if destination.exists():
            raise FileExistsError("복원 대상 폴더가 이미 존재합니다.")
        stage = destination.with_name(destination.name + ".restore-" + secrets.token_hex(6))
        try:
            with zipfile.ZipFile(archive_path, "r") as archive:
                names = archive.namelist()
                if len(names) != len(set(names)):
                    raise ValueError("백업에 중복 경로가 있습니다.")
                if any(name.startswith("/") or ".." in Path(name).parts for name in names):
                    raise ValueError("안전하지 않은 백업 경로입니다.")
                manifest = json.loads(archive.read("backup_manifest.json"))
                expected = manifest.get("files", {})
                if "vault.json" not in expected or "index.bin" not in expected:
                    raise ValueError("필수 금고 파일이 없습니다.")
                stage.mkdir(parents=True)
                for name, digest in expected.items():
                    data = archive.read(name)
                    if not secrets.compare_digest(hashlib.sha256(data).hexdigest(), digest):
                        raise ValueError("백업 파일 해시가 일치하지 않습니다: " + name)
                    target = stage / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(data)
            stage.rename(destination)
        except Exception:
            shutil.rmtree(stage, ignore_errors=True)
            raise
        return destination

    def search_documents(self):
        query = read_input("검색할 파일명: ").strip().casefold()
        found = sorted((info["name"] for info in self.index.values()
                        if query in info["name"].casefold()), key=str.casefold)
        if not found:
            print("검색 결과가 없습니다.")
        else:
            for number, name in enumerate(found, 1):
                print(f"{number}. {name}")

    def rename_document(self):
        file_id = self.choose_id()
        if not file_id:
            return
        old_name = self.index[file_id]["name"]
        new_name = read_input("새 문서 이름: ").strip()
        if not new_name or Path(new_name).name != new_name:
            print("올바른 파일 이름을 입력하세요.")
            return
        ext = self.index[file_id]["extension"]
        if Path(new_name).suffix.lower() != ext:
            new_name = Path(new_name).stem + ext
        if any(k != file_id and v["name"].casefold() == new_name.casefold()
               for k, v in self.index.items()):
            print("같은 이름의 문서가 이미 있습니다.")
            return
        self.index[file_id]["name"] = new_name
        self.save_index()
        print(f"문서 이름 변경: {old_name} -> {new_name}")

    def show_vault_info(self):
        total = sum((self.docs / (key + ".bin")).stat().st_size
                    for key in self.index if (self.docs / (key + ".bin")).exists())
        meta = json.loads(self.meta_file.read_text(encoding="utf-8"))
        print("\n===== 금고 정보 =====")
        print("암호화: AES-256-GCM")
        print("키 파생: scrypt")
        print(f"포맷 버전: {FORMAT_VERSION}")
        print(f"저장 문서: {len(self.index)}개")
        print(f"암호화 데이터 용량: {total:,} bytes")
        print("복구 키: " + ("설정됨" if meta.get("recovery_wrapped_key") else "미설정"))

    def lock(self):
        self.key = None
        self.index = {}
        print("금고를 잠갔습니다. 저장된 문서는 USB에 그대로 보관됩니다.")


# ---------- 실행 ----------
def main():
    print("=" * 48)
    print(" DigitalVault Portable")
    print("=" * 48)
    print(f"프로그램 위치: {app_directory()}")
    print(f"기본 금고 위치: {default_vault_directory()}")

    folder_text = input(
        "금고 저장 폴더 (Enter=USB의 기본 폴더): "
    ).strip().strip('"')

    folder = (
        Path(folder_text).expanduser()
        if folder_text
        else default_vault_directory()
    )
    vault = Vault(folder)

    if not vault.exists:
        print("새 금고를 생성합니다.")
        vault.create(prompt_new_password())

    if getattr(vault, "recovery_key_display", None):
        print("\n[중요] 복구 키를 별도 장소에 보관하세요. 다시 표시되지 않습니다.")
        print("복구 키:", vault.recovery_key_display)

    while True:
        entered = masked_password("비밀번호 (복구하려면 R 입력): ")
        if entered.strip().lower() == "r":
            try:
                recovery = masked_password("복구 키: ")
                vault.recover_with_key(recovery, prompt_new_password())
                print("복구가 완료되었습니다.")
                break
            except Exception as error:
                print("복구에 실패했습니다:", error)
                return
        if vault.login(entered):
            break
        if vault.lock_status():
            return

    print("\n금고 잠금 해제 완료.")

    try:
        while vault.key is not None:
            print("\n" + "=" * 54)
            print("                 DigitalVault")
            print("=" * 54)
            print(" [ 문서 관리 ]")
            print("  1. 문서 추가          2. 문서 목록")
            print("  3. 문서 열기          4. 문서 내보내기")
            print("  5. 문서 삭제          6. 문서 검색")
            print("  7. 문서 이름 변경")
            print("-" * 54)
            print(" [ 보안 관리 ]")
            print("  8. 비밀번호 변경      9. 마스터 키 재발급")
            print(" 10. 복구 키 발급       11. 보안 기록 확인")
            print("-" * 54)
            print(" [ 금고 관리 ]")
            print(" 12. 금고 백업          13. 금고 복원")
            print(" 14. 무결성 검사        15. 금고 정보")
            print("-" * 54)
            print("  0. 금고 잠금 및 종료")
            print(f"  ※ {IDLE_TIMEOUT_SECONDS // 60}분간 미사용 시 자동 잠금")
            print("=" * 54)

            choice = timed_input("선택: ", IDLE_TIMEOUT_SECONDS)
            if choice is None:
                vault.lock()
                break
            choice = choice.strip()
            if choice == "0":
                vault.lock()
                break
            elif choice == "1":
                vault.add_document()
            elif choice == "2":
                vault.list_documents()
            elif choice == "3":
                vault.open_document()
            elif choice == "4":
                vault.export_document()
            elif choice == "5":
                vault.delete_document()
            elif choice == "6":
                vault.search_documents()
            elif choice == "7":
                vault.rename_document()
            elif choice == "8":
                old = masked_password("현재 비밀번호: ")
                new = prompt_new_password()
                vault.change_password(old, new)
            elif choice == "9":
                answer = read_input("마스터 키를 재발급할까요? (y/n): ").strip().lower()
                if answer == "y":
                    current = masked_password("현재 비밀번호: ")
                    meta = json.loads(vault.meta_file.read_text(encoding="utf-8"))
                    recovery = None
                    if meta.get("recovery_wrapped_key"):
                        recovery = masked_password("복구 키 (복구 기능 유지용): ")
                    vault.rotate_master_key(current, recovery)
                else:
                    print("마스터 키 재발급을 취소했습니다.")
            elif choice == "10":
                current = masked_password("현재 비밀번호: ")
                recovery = vault.setup_recovery_key(current)
                print("\n새 복구 키 (한 번만 표시):")
                print(recovery)
                print("별도 장소에 안전하게 보관하세요.")
            elif choice == "11":
                vault.show_security_log()
            elif choice == "12":
                destination = read_input("백업 파일 경로 (.zip): ").strip().strip('"')
                if destination:
                    print(f"백업 완료: {vault.create_backup(destination)}개 파일")
            elif choice == "13":
                archive = read_input("백업 ZIP 경로: ").strip().strip('"')
                destination = read_input("새 복원 폴더 경로: ").strip().strip('"')
                if archive and destination:
                    print("복원 완료:", Vault.restore_backup(archive, destination))
            elif choice == "14":
                vault.integrity_check()
            elif choice == "15":
                vault.show_vault_info()
            else:
                print("메뉴 번호를 다시 선택하세요.")
                continue

            while True:
                answer = read_input(
                    "\n작업을 계속하시겠습니까? (y/n): "
                ).strip().lower()
                if answer == "y":
                    break
                if answer == "n":
                    vault.lock()
                    return
                print("y 또는 n을 입력하세요.")

    except TimeoutError as error:
        print(f"\n{error}")
        vault.lock()
    except (KeyboardInterrupt, EOFError):
        print("\n프로그램을 종료합니다.")
    except Exception as error:
        print(f"\n작업 중 오류가 발생했습니다: {error}")
    finally:
        if vault.key is not None:
            vault.lock()


if __name__ == "__main__":
    main()
