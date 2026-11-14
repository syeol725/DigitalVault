#!/usr/bin/env python3
"""DigitalVault Portable - Windows 10/11 USB document vault."""

import base64
import csv
import getpass
import hashlib
import hmac
import json
import os
import secrets
import shutil
import sys
import tempfile
import time
import zipfile
import unicodedata
from io import BytesIO, StringIO
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
WRAP_AAD = b"DigitalVault:master-key:v2"
INDEX_AAD = b"DigitalVault:index:v2"



AUDIT_AAD_V1 = b"DigitalVault:audit:v1"
AUDIT_AAD_V2 = b"DigitalVault:audit:v2"
AUDIT_GENESIS = "0" * 64


def _audit_digest(key, sequence, previous, timestamp, event):
    payload = json.dumps(
        [int(sequence), str(previous), str(timestamp), str(event)],
        ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


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


def read_input(prompt):
    """시간 제한 없이 일반 입력을 받습니다."""
    return input(prompt)


def clear_console():
    """이전 작업 출력을 지우고 다음 메뉴를 표시합니다."""
    os.system("cls" if os.name == "nt" else "clear")


def display_width(value):
    return sum(
        2 if unicodedata.east_asian_width(char) in ("F", "W", "A") else 1
        for char in str(value)
    )


def truncate_display(value, width):
    """한글·영문 표시 폭을 고려해 표 셀 안에서 파일명을 줄입니다."""
    value = str(value)
    if display_width(value) <= width:
        return value

    shortened = ""
    for char in value:
        if display_width(shortened + char + "…") > width:
            break
        shortened += char
    return shortened + "…"


def center_display(value, width):
    value = str(value)
    padding = max(0, width - display_width(value))
    left = padding // 2
    return " " * left + value + " " * (padding - left)


def pad_display(value, width, align="left"):
    value = str(value)
    padding = max(0, width - display_width(value))
    if align == "right":
        return " " * padding + value
    return value + " " * padding


def show_main_menu(document_count=0):
    print()
    print(f"DigitalVault  |  문서 {document_count}개")
    print("-" * 48)
    print("문서 관리")
    print(" A 추가   B 목록   C 열기   D 내보내기")
    print(" E 삭제   F 이름 변경")
    print("보안 관리")
    print(" G 비밀번호 변경   H 마스터 키 재발급")
    print(" I 복구 키 발급    J 보안 기록")
    print("금고 관리")
    print(" K 백업   L 백업 불러오기")
    print(" M 무결성 검사   N 금고 정보")
    print("-" * 48)
    print(" 0 잠금 및 종료")


def normalize_menu_choice(value):
    return value.strip().upper()


def continue_decision(value):
    answer = value.strip().casefold()
    if answer in {"y", "yes", "예", "ㅇ"}:
        return "continue"
    if answer in {"n", "no", "아니오", "아니요", "ㄴ"}:
        return "exit"
    return "invalid"


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


def masked_password(prompt):
    """비밀번호 입력 문자를 화면에 표시하지 않습니다."""
    if os.name == "nt":
        import msvcrt

        print(prompt, end="", flush=True)
        chars = []
        while True:
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
        import termios
        import tty

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        chars = []
        decoder = codecs.getincrementaldecoder("utf-8")()
        print(prompt, end="", flush=True)
        try:
            tty.setcbreak(fd)
            input_settings = termios.tcgetattr(fd)
            input_settings[3] &= ~termios.ECHO
            termios.tcsetattr(fd, termios.TCSADRAIN, input_settings)
            while True:
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

    return getpass.getpass(prompt)


def prompt_new_password():
    while True:
        password = masked_password("새 비밀번호: ")
        if len(password) < 8:
            print("비밀번호는 8자 이상이어야 합니다. 다시 입력하세요.")
            continue

        confirm = masked_password("비밀번호 확인: ")
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
        self.recover_interrupted_merge()
        self.cleanup_stale_temp_files()

    def recover_interrupted_merge(self):
        """비정상 종료로 중단된 병합을 시작 전 상태로 되돌립니다."""
        journal_path = self.folder / ".merge-recovery.json"
        if not journal_path.exists():
            return
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        stage_name = journal.get("stage")
        if (not isinstance(stage_name, str) or not stage_name.startswith(".vault-merge-")
                or Path(stage_name).name != stage_name):
            raise RuntimeError("중단된 병합 복구 정보가 올바르지 않습니다.")
        stage = self.folder / stage_name
        state = journal.get("state")
        if state == "applying":
            for file_id in journal.get("replace_ids", []):
                if not isinstance(file_id, str) or len(file_id) != 24:
                    raise RuntimeError("중단된 병합의 문서 식별자가 올바르지 않습니다.")
                backup = stage / (file_id + ".old")
                if not backup.is_file():
                    raise RuntimeError("중단된 병합의 원본 문서를 찾을 수 없습니다: " + file_id)
                atomic_write(self.docs / (file_id + ".bin"), backup.read_bytes())
            for file_id in journal.get("new_ids", []):
                if not isinstance(file_id, str) or len(file_id) != 24:
                    raise RuntimeError("중단된 병합의 신규 문서 식별자가 올바르지 않습니다.")
                (self.docs / (file_id + ".bin")).unlink(missing_ok=True)
            old_index = stage / "index.old"
            if not old_index.is_file():
                raise RuntimeError("중단된 병합의 이전 인덱스 백업을 찾을 수 없습니다.")
            atomic_write(self.index_file, old_index.read_bytes())
        elif state != "committed":
            raise RuntimeError("중단된 병합의 복구 상태를 확인할 수 없습니다.")
        shutil.rmtree(stage, ignore_errors=True)
        journal_path.unlink(missing_ok=True)

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

    def rotate_master_key(self, password):
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
        new_recovery_key = None
        if meta.get("recovery_salt") and meta.get("recovery_wrapped_key"):
            new_recovery_key = secrets.token_urlsafe(32)
            recovery_salt = secrets.token_bytes(16)
            new_meta["recovery_salt"] = base64.b64encode(
                recovery_salt
            ).decode("ascii")
            new_meta["recovery_wrapped_key"] = base64.b64encode(
                encrypt(derive_key(new_recovery_key, recovery_salt), new_key,
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
                audit_records, audit_errors, _legacy = self._decode_audit_log(self.key)
                if audit_errors:
                    raise ValueError("보안 기록 무결성 검사에 실패해 마스터 키를 재발급할 수 없습니다.")
                atomic_write(staged_audit, self._encode_audit_records(new_key, audit_records))
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
            self.log_event("master_key_rotated")
            print("마스터 키를 재발급하고 문서·인덱스·키 메타데이터를 갱신했습니다.")
        finally:
            shutil.rmtree(stage, ignore_errors=True)

        return new_recovery_key

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
        items = sorted(
            self.index.items(),
            key=lambda item: item[1]["name"].casefold()
        )
        print("\n저장된 문서")
        if not items:
            print("저장된 문서가 없습니다.")
            print("총 0개  |  0 B")
            return

        number_width = max(
            display_width("번호"),
            len(str(len(items)))
        )
        name_width = min(
            36,
            max(
                display_width("파일명"),
                max(display_width(info["name"]) for _, info in items)
            )
        )
        extension_width = max(
            display_width("형식"),
            max(
                display_width(info["extension"].lstrip(".").upper())
                for _, info in items
            )
        )
        sizes = []
        total_size = 0
        for file_id, _ in items:
            path = self.docs / (file_id + ".bin")
            size = path.stat().st_size if path.exists() else 0
            sizes.append(size)
            total_size += size
        size_width = max(
            display_width("암호화 크기"),
            max(display_width(f"{size:,} B") for size in sizes)
        )
        table_width = (
            number_width + 2 + name_width + 2
            + extension_width + 2 + size_width
        )

        print(
            f"{pad_display('번호', number_width, 'right')}  "
            f"{pad_display('파일명', name_width)}  "
            f"{pad_display('형식', extension_width)}  "
            f"{pad_display('암호화 크기', size_width, 'right')}"
        )
        print("-" * table_width)

        for number, ((file_id, info), size) in enumerate(zip(items, sizes), 1):
            name = truncate_display(info["name"], name_width)
            extension = info["extension"].lstrip(".").upper()
            size_text = f"{size:,} B"
            print(
                f"{pad_display(number, number_width, 'right')}  "
                f"{pad_display(name, name_width)}  "
                f"{pad_display(extension, extension_width)}  "
                f"{pad_display(size_text, size_width, 'right')}"
            )

        print("-" * table_width)
        print(f"총 {len(items)}개  |  {total_size:,} B")
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

    def verify_password(self, password):
        """현재 금고의 비밀번호가 맞는지 확인합니다."""
        try:
            meta = json.loads(self.meta_file.read_text(encoding="utf-8"))
            if meta.get("format_version") != FORMAT_VERSION:
                return False
            salt = base64.b64decode(meta["salt"], validate=True)
            wrapped = base64.b64decode(meta["wrapped_key"], validate=True)
            master = decrypt(
                derive_key(password, salt, meta.get("kdf")), wrapped, WRAP_AAD
            )
            return len(master) == 32 and secrets.compare_digest(master, self.key)
        except Exception:
            return False

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

    def _decode_audit_log(self, key=None):
        key = self.key if key is None else key
        path = self.folder / "security.log"
        if not path.exists():
            return [], [], False
        records, errors = [], []
        legacy = False
        expected_sequence, previous_hash = 0, AUDIT_GENESIS
        for number, line in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
            try:
                sealed = base64.b64decode(line, validate=True)
                try:
                    record = json.loads(decrypt(key, sealed, AUDIT_AAD_V2).decode("utf-8"))
                    sequence = int(record["sequence"])
                    previous = str(record["previous_hash"])
                    timestamp, event = str(record["time"]), str(record["event"])
                    expected = _audit_digest(key, sequence, previous, timestamp, event)
                    if (sequence != expected_sequence + 1 or previous != previous_hash
                            or not secrets.compare_digest(expected, str(record["chain_hash"]))):
                        raise ValueError("보안 기록 연결 검증에 실패했습니다.")
                    expected_sequence, previous_hash = sequence, expected
                except Exception as v2_error:
                    try:
                        record = json.loads(decrypt(key, sealed, AUDIT_AAD_V1).decode("utf-8"))
                        if not isinstance(record, dict) or "time" not in record or "event" not in record:
                            raise ValueError("기록 형식이 올바르지 않습니다.")
                        legacy = True
                    except Exception:
                        raise v2_error
                records.append({"time": str(record["time"]), "event": str(record["event"])})
            except Exception as error:
                errors.append((number, str(error)))
        return records, errors, legacy

    def _encode_audit_records(self, key, records):
        lines, previous_hash = [], AUDIT_GENESIS
        for sequence, source in enumerate(records, 1):
            timestamp, event = str(source["time"]), str(source["event"])[:64]
            digest = _audit_digest(key, sequence, previous_hash, timestamp, event)
            record = {
                "version": 2, "sequence": sequence, "previous_hash": previous_hash,
                "time": timestamp, "event": event, "chain_hash": digest,
            }
            sealed = encrypt(
                key, json.dumps(record, ensure_ascii=False).encode("utf-8"),
                AUDIT_AAD_V2
            )
            lines.append(base64.b64encode(sealed).decode("ascii"))
            previous_hash = digest
        return ("\n".join(lines) + ("\n" if lines else "")).encode("ascii")

    def verify_security_log(self):
        if self.key is None:
            raise RuntimeError("잠금 해제된 금고에서만 보안 기록을 검사할 수 있습니다.")
        records, errors, legacy = self._decode_audit_log()
        if errors:
            print(f"[확인 필요] 보안 기록 {len(errors)}건에서 복호화 또는 연결 오류가 발견되었습니다.")
            for number, _error in errors:
                print(f"[오류] {number}번째 기록")
            return False
        if legacy:
            print(f"[부분 검증] {len(records)}건의 구형 기록은 암호 인증만 확인했습니다. 신규 기록부터 연결 검증이 적용됩니다.")
        else:
            print(f"[정상] 보안 기록 {len(records)}건의 암호 인증 및 연결 무결성이 확인되었습니다.")
        return True

    def log_event(self, event):
        if self.key is None:
            return
        records, errors, _legacy = self._decode_audit_log()
        if errors:
            print("주의: 보안 기록 검증에 실패해 새 기록을 추가하지 않았습니다.")
            return
        records.append({
            "time": datetime.now(timezone.utc).isoformat(),
            "event": str(event)[:64],
        })
        atomic_write(self.folder / "security.log", self._encode_audit_records(self.key, records))

    def show_security_log(self):
        records, errors, legacy = self._decode_audit_log()
        if not records and not errors:
            print("보안 기록이 없습니다.")
            return
        for number, record in enumerate(records, 1):
            print("{}  {}  {}".format(number, record["time"], record["event"]))
        for number, _error in errors:
            print("{}  [읽을 수 없거나 연결 검증에 실패한 기록]".format(number))
        if errors:
            print("※ 보안 기록 무결성에 문제가 있습니다.")
        elif legacy:
            print("※ 구형 기록은 암호 인증만 확인했으며, 신규 기록부터 연결 검증을 적용합니다.")
        else:
            print("※ 보안 기록 연결 무결성 검증 완료")
    def export_security_log(self, destination):
        """복호화한 보안 기록을 Excel 호환 UTF-8 CSV로 내보냅니다."""
        if self.key is None:
            raise RuntimeError("잠금 해제된 금고에서만 보안 기록을 내보낼 수 있습니다.")

        destination = Path(destination).expanduser()
        source = self.folder / "security.log"
        if source.exists() and destination.resolve() == source.resolve():
            raise ValueError("보안 기록 원본 파일에는 내보낼 수 없습니다.")

        output = StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(["번호", "발생 시각(UTC)", "이벤트", "상태"])

        lines = source.read_text(encoding="ascii").splitlines() if source.exists() else []
        for number, line in enumerate(lines, 1):
            try:
                sealed = base64.b64decode(line, validate=True)
                try:
                    record = json.loads(decrypt(self.key, sealed, AUDIT_AAD_V2))
                except Exception:
                    record = json.loads(decrypt(self.key, sealed, AUDIT_AAD_V1))
                timestamp = str(record.get("time", ""))
                event = str(record.get("event", ""))
                # 스프레드시트에서 수식으로 해석될 수 있는 셀 접두 문자를 무력화합니다.
                if event.startswith(("=", "+", "-", "@", "\t", "\r")):
                    event = "'" + event
                writer.writerow([number, timestamp, event, "정상"])
            except Exception:
                writer.writerow([number, "", "", "읽을 수 없는 기록"])

        atomic_write(destination, output.getvalue().encode("utf-8-sig"))
        return len(lines)

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

    def create_backup(self, destination, overwrite=False):
        destination = Path(destination).expanduser()
        if destination.exists() and not overwrite:
            raise FileExistsError("같은 이름의 백업본이 이미 있습니다.")
        # 백업에는 복원에 필요한 금고 메타데이터, 암호화 인덱스,
        # 암호화된 문서만 포함합니다. 보안 이벤트 로그는 별도 운영 기록이므로 제외합니다.
        files = [self.meta_file, self.index_file] + sorted(self.docs.glob("*.bin"))
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

    def inspect_backup(self, archive_path, backup_password):
        """백업 전체를 검증·복호화하고 현재 금고와의 문서명 충돌을 미리 계산합니다."""
        if self.key is None:
            raise RuntimeError("잠금 해제된 금고에서만 백업을 확인할 수 있습니다.")
        archive_path = Path(archive_path)
        with zipfile.ZipFile(archive_path, "r") as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise ValueError("백업에 중복 경로가 있습니다.")
            if any(name.startswith(("/", "\\")) or ".." in Path(name).parts
                   or "\\" in name for name in names):
                raise ValueError("안전하지 않은 백업 경로입니다.")
            if "backup_manifest.json" not in names:
                raise ValueError("백업 무결성 정보가 없습니다.")
            manifest = json.loads(archive.read("backup_manifest.json"))
            expected = manifest.get("files")
            if manifest.get("format") != 1 or not isinstance(expected, dict):
                raise ValueError("지원하지 않는 백업 형식입니다.")
            if not {"vault.json", "index.bin"}.issubset(expected):
                raise ValueError("필수 금고 파일이 없습니다.")
            if set(expected) - set(names) or set(names) != set(expected) | {"backup_manifest.json"}:
                raise ValueError("백업 파일 구성이 올바르지 않습니다.")
            payloads = {}
            for name, digest in expected.items():
                if name not in {"vault.json", "index.bin"} and (
                    not name.startswith("documents/") or not name.endswith(".bin")
                    or len(Path(name).parts) != 2
                ):
                    raise ValueError("허용되지 않은 백업 파일 경로입니다.")
                data = archive.read(name)
                if not secrets.compare_digest(hashlib.sha256(data).hexdigest(), str(digest)):
                    raise ValueError("백업 파일 해시가 일치하지 않습니다: " + name)
                payloads[name] = data

        source_meta = json.loads(payloads["vault.json"].decode("utf-8"))
        if source_meta.get("format_version") != FORMAT_VERSION:
            raise ValueError("지원하지 않는 백업 금고 버전입니다.")
        source_salt = base64.b64decode(source_meta["salt"], validate=True)
        source_wrapped = base64.b64decode(source_meta["wrapped_key"], validate=True)
        source_key = decrypt(
            derive_key(backup_password, source_salt, source_meta.get("kdf")),
            source_wrapped, WRAP_AAD
        )
        if len(source_key) != 32:
            raise ValueError("백업 금고 키가 올바르지 않습니다.")
        source_index = json.loads(
            decrypt(source_key, payloads["index.bin"], INDEX_AAD).decode("utf-8")
        )
        if not isinstance(source_index, dict):
            raise ValueError("백업 문서 목록 형식이 올바르지 않습니다.")

        existing = {}
        for file_id, info in self.index.items():
            existing.setdefault(info.get("name", "").casefold(), (file_id, info))
        seen_names, documents = set(), []
        for old_id, info in source_index.items():
            if (not isinstance(old_id, str) or len(old_id) != 24
                    or any(ch not in "0123456789abcdef" for ch in old_id)
                    or not isinstance(info, dict)):
                raise ValueError("백업 문서 식별자 또는 정보가 올바르지 않습니다.")
            name, extension = info.get("name"), info.get("extension")
            if (not isinstance(name, str) or not name or Path(name).name != name
                    or not isinstance(extension, str) or extension.lower() not in EXTENSIONS
                    or Path(name).suffix.lower() != extension.lower()
                    or name.casefold() in seen_names):
                raise ValueError("백업에 유효하지 않거나 중복된 문서명이 있습니다.")
            seen_names.add(name.casefold())
            source_path = f"documents/{old_id}.bin"
            if source_path not in payloads:
                raise ValueError(f"백업 문서 파일이 없습니다: {name}")
            aad = ("DigitalVault:document:v2:" + old_id).encode()
            plain = decrypt(source_key, payloads[source_path], aad)
            collision = existing.get(name.casefold())
            documents.append({
                "id": old_id, "name": name, "extension": extension.lower(),
                "size": len(plain),
                "collision_id": collision[0] if collision else None,
                "collision_name": collision[1].get("name") if collision else None,
            })
        extra_docs = {name for name in payloads if name.startswith("documents/")}
        expected_docs = {f"documents/{doc['id']}.bin" for doc in documents}
        if extra_docs != expected_docs:
            raise ValueError("백업 문서 목록과 실제 문서 파일이 일치하지 않습니다.")
        collisions = sum(1 for doc in documents if doc["collision_id"])
        return {
            "created_utc": manifest.get("created_utc", ""),
            "document_count": len(documents),
            "new_count": len(documents) - collisions,
            "collision_count": collisions,
            "documents": documents,
        }

    def merge_backup(self, archive_path, backup_password, conflict_choices=None):
        """검증된 백업을 현재 금고에 병합하고 선택된 충돌 문서만 교체합니다."""
        if self.key is None:
            raise RuntimeError("잠금 해제된 금고에서만 백업을 병합할 수 있습니다.")
        conflict_choices = conflict_choices or {}
        preview = self.inspect_backup(archive_path, backup_password)
        staged_dir = Path(tempfile.mkdtemp(prefix=".vault-merge-", dir=self.folder))
        previous_index = self.index.copy()
        staged_new, staged_replace = {}, {}
        applied_new, applied_replace = [], []
        added = replaced = skipped = 0
        try:
            with zipfile.ZipFile(archive_path, "r") as archive:
                manifest = json.loads(archive.read("backup_manifest.json"))
                payloads = {
                    name: archive.read(name)
                    for name in manifest["files"]
                }
            source_meta = json.loads(payloads["vault.json"].decode("utf-8"))
            source_key = decrypt(
                derive_key(
                    backup_password,
                    base64.b64decode(source_meta["salt"], validate=True),
                    source_meta.get("kdf")
                ),
                base64.b64decode(source_meta["wrapped_key"], validate=True),
                WRAP_AAD
            )
            source_index = json.loads(
                decrypt(source_key, payloads["index.bin"], INDEX_AAD).decode("utf-8")
            )
            existing_by_name = {
                info.get("name", "").casefold(): (file_id, info)
                for file_id, info in self.index.items()
            }
            used_names = set(existing_by_name)
            staged_index = previous_index.copy()

            for old_id, info in source_index.items():
                name = info["name"]
                collision = existing_by_name.get(name.casefold())
                source_aad = ("DigitalVault:document:v2:" + old_id).encode()
                plain = decrypt(source_key, payloads[f"documents/{old_id}.bin"], source_aad)
                if collision:
                    choice = conflict_choices.get(old_id, "keep")
                    if choice not in {"keep", "replace"}:
                        raise ValueError("알 수 없는 문서 충돌 처리 방식입니다.")
                    if choice == "keep":
                        skipped += 1
                        continue
                    target_id, target_info = collision
                    target_aad = ("DigitalVault:document:v2:" + target_id).encode()
                    staged_replace[target_id] = encrypt(self.key, plain, target_aad)
                    staged_index[target_id] = {
                        "name": target_info["name"],
                        "extension": target_info["extension"],
                    }
                    replaced += 1
                    continue

                new_name = name
                if new_name.casefold() in used_names:
                    stem, suffix = Path(name).stem, Path(name).suffix
                    number = 1
                    while f"{stem} (복원 {number}){suffix}".casefold() in used_names:
                        number += 1
                    new_name = f"{stem} (복원 {number}){suffix}"
                used_names.add(new_name.casefold())
                new_id = secrets.token_hex(12)
                while new_id in staged_index:
                    new_id = secrets.token_hex(12)
                new_aad = ("DigitalVault:document:v2:" + new_id).encode()
                staged_new[new_id] = encrypt(self.key, plain, new_aad)
                staged_index[new_id] = {
                    "name": new_name, "extension": info["extension"].lower()
                }
                added += 1

            for file_id, data in staged_new.items():
                (staged_dir / (file_id + ".new")).write_bytes(data)
            for file_id, data in staged_replace.items():
                (staged_dir / (file_id + ".new")).write_bytes(data)
                original = (self.docs / (file_id + ".bin")).read_bytes()
                (staged_dir / (file_id + ".old")).write_bytes(original)
            (staged_dir / "index.old").write_bytes(self.index_file.read_bytes())
            journal_path = self.folder / ".merge-recovery.json"
            write_json(journal_path, {
                "state": "applying", "stage": staged_dir.name,
                "new_ids": list(staged_new), "replace_ids": list(staged_replace),
            })

            # 원본 파일과 인덱스 백업을 먼저 기록한 뒤 실제 문서를 교체합니다.
            for file_id in staged_replace:
                os.replace(staged_dir / (file_id + ".new"), self.docs / (file_id + ".bin"))
                applied_replace.append(file_id)
            for file_id in staged_new:
                target = self.docs / (file_id + ".bin")
                if target.exists():
                    raise FileExistsError("문서 ID 충돌이 발생했습니다.")
                os.replace(staged_dir / (file_id + ".new"), target)
                applied_new.append(file_id)

            self.index = staged_index
            self.save_index()
            write_json(journal_path, {
                "state": "committed", "stage": staged_dir.name,
                "new_ids": list(staged_new), "replace_ids": list(staged_replace),
            })
            self.last_merge_summary = {
                "added": added, "replaced": replaced, "skipped": skipped,
            }
            try:
                self.log_event("backup_merged")
            except Exception:
                print("주의: 병합은 완료됐지만 보안 기록을 추가하지 못했습니다.")
            return added + replaced
        except Exception:
            self.index = previous_index
            for file_id in applied_new:
                (self.docs / (file_id + ".bin")).unlink(missing_ok=True)
            for file_id in applied_replace:
                backup = staged_dir / (file_id + ".old")
                if backup.exists():
                    os.replace(backup, self.docs / (file_id + ".bin"))
            try:
                self.save_index()
                if "journal_path" in locals():
                    journal_path.unlink(missing_ok=True)
            except Exception:
                # 복구 정보는 남겨 두어 다음 실행 때 원본 상태로 복구할 수 있게 합니다.
                pass
            raise
        finally:
            preserve_stage = False
            if "journal_path" in locals() and journal_path.exists():
                try:
                    journal = json.loads(journal_path.read_text(encoding="utf-8"))
                    if journal.get("state") == "committed":
                        journal_path.unlink(missing_ok=True)
                    else:
                        preserve_stage = True
                except Exception:
                    preserve_stage = True
            if not preserve_stage:
                shutil.rmtree(staged_dir, ignore_errors=True)

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
                if manifest.get("format") != 1 or not isinstance(expected, dict):
                    raise ValueError("지원하지 않는 백업 형식입니다.")
                if "vault.json" not in expected or "index.bin" not in expected:
                    raise ValueError("필수 금고 파일이 없습니다.")
                if set(expected) - set(names) or set(names) != set(expected) | {"backup_manifest.json"}:
                    raise ValueError("백업 파일 구성이 올바르지 않습니다.")
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
    from digital_vault_gui import main as gui_main
    gui_main()


if __name__ == "__main__":
    main()
