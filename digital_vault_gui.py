"""DigitalVault desktop GUI (Tkinter)."""
import contextlib
import io
import json
import os
import sys
import shutil
import tempfile
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from digital_vault import (
    EXTENSIONS, Vault, app_directory, default_vault_directory, decrypt,
    atomic_write, prompt_new_password,
)


class DigitalVaultApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("DigitalVault")
        self.root.geometry("1080x720")
        self.root.minsize(900, 600)
        self.root.configure(bg="#F4F6FA")
        self.vault = None
        self._style()
        self._login_screen()
        self.root.protocol("WM_DELETE_WINDOW", self._close)

    def _style(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", rowheight=38, font=("Malgun Gothic", 10),
                        background="#FFFFFF", fieldbackground="#FFFFFF",
                        foreground="#202938", borderwidth=0)
        style.configure("Treeview.Heading", font=("Malgun Gothic", 9, "bold"),
                        background="#EEF1F6", foreground="#526078", relief="flat")
        style.map("Treeview", background=[("selected", "#E4ECFF")],
                  foreground=[("selected", "#173B83")])
        style.configure("TButton", font=("Malgun Gothic", 9), padding=(12, 8))
        style.configure("Accent.TButton", font=("Malgun Gothic", 9, "bold"),
                        padding=(14, 9), background="#315ECA", foreground="#FFFFFF")
        style.map("Accent.TButton", background=[("active", "#244DAA")])
        style.configure("TLabel", font=("Malgun Gothic", 10), background="#FFFFFF",
                        foreground="#202938")
        style.configure("Muted.TLabel", foreground="#738096", background="#FFFFFF")
        style.configure("Title.TLabel", font=("Malgun Gothic", 20, "bold"))
        style.configure("Card.TFrame", background="#FFFFFF")
        style.configure("Sidebar.TFrame", background="#202B3C")
        style.configure("Sidebar.TButton", background="#202B3C", foreground="#E8EDF5",
                        borderwidth=0, anchor="w", padding=(18, 12))
        style.map("Sidebar.TButton", background=[("active", "#33445D")])

    def _center(self, window, width=460, height=360):
        window.update_idletasks()
        x = (window.winfo_screenwidth() - width) // 2
        y = (window.winfo_screenheight() - height) // 2
        window.geometry(f"{width}x{height}+{x}+{y}")

    def _login_screen(self):
        self.login_frame = tk.Frame(self.root, bg="#F4F6FA")
        self.login_frame.pack(fill="both", expand=True)
        card = tk.Frame(self.login_frame, bg="#FFFFFF", padx=38, pady=34,
                        highlightthickness=1, highlightbackground="#E2E7EF")
        card.place(relx=.5, rely=.5, anchor="center", width=460)
        tk.Label(card, text="DigitalVault", bg="#FFFFFF", fg="#1D2A3B",
                 font=("Malgun Gothic", 23, "bold")).pack(anchor="w")
        tk.Label(card, text="암호화 문서 금고", bg="#FFFFFF", fg="#7B8798",
                 font=("Malgun Gothic", 10)).pack(anchor="w", pady=(4, 24))

        default_path = default_vault_directory()
        self.folder_var = tk.StringVar(value=str(default_path))
        tk.Label(card, text="금고 저장 위치", bg="#FFFFFF", fg="#48566B",
                 font=("Malgun Gothic", 9, "bold")).pack(anchor="w")
        folder_row = tk.Frame(card, bg="#FFFFFF")
        folder_row.pack(fill="x", pady=(7, 18))
        tk.Entry(folder_row, textvariable=self.folder_var, relief="solid",
                 bd=1, font=("Malgun Gothic", 9)).pack(side="left", fill="x", expand=True, ipady=8)
        ttk.Button(folder_row, text="찾기", command=self._choose_folder).pack(side="left", padx=(8, 0))

        self.password_var = tk.StringVar()
        tk.Label(card, text="비밀번호", bg="#FFFFFF", fg="#48566B",
                 font=("Malgun Gothic", 9, "bold")).pack(anchor="w")
        entry = tk.Entry(card, textvariable=self.password_var, show="●", relief="solid",
                         bd=1, font=("Malgun Gothic", 11))
        entry.pack(fill="x", pady=(7, 16), ipady=9)
        entry.bind("<Return>", lambda _e: self._authenticate())
        ttk.Button(card, text="금고 열기", style="Accent.TButton",
                   command=self._authenticate).pack(fill="x")
        ttk.Button(card, text="복구 키로 비밀번호 재설정",
                   command=self._recover_password).pack(fill="x", pady=(8, 0))
        tk.Label(card, text="처음 사용하는 폴더라면 새 금고가 생성됩니다.",
                 bg="#FFFFFF", fg="#8993A3", font=("Malgun Gothic", 8)).pack(anchor="w", pady=(15, 0))
        entry.focus_set()

    def _choose_folder(self):
        folder = filedialog.askdirectory(title="금고 폴더 선택",
                                         initialdir=self.folder_var.get() or str(app_directory()))
        if folder:
            self.folder_var.set(folder)

    def _capture(self, callback):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = callback()
        return result, output.getvalue().strip()

    def _authenticate(self):
        folder_text = self.folder_var.get().strip()
        password = self.password_var.get()
        if not folder_text or not password:
            messagebox.showwarning("입력 확인", "금고 위치와 비밀번호를 입력하세요.", parent=self.root)
            return
        try:
            vault = Vault(Path(folder_text).expanduser())
            if not vault.exists:
                if len(password) < 8:
                    messagebox.showwarning("비밀번호 확인", "새 금고 비밀번호는 8자 이상이어야 합니다.", parent=self.root)
                    return
                confirm = simpledialog.askstring("비밀번호 확인", "새 비밀번호를 한 번 더 입력하세요.",
                                                 show="●", parent=self.root)
                if confirm is None:
                    return
                if password != confirm:
                    messagebox.showerror("확인 실패", "비밀번호가 일치하지 않습니다.", parent=self.root)
                    return
                vault.create(password)
                recovery = getattr(vault, "recovery_key_display", None)
                if recovery:
                    messagebox.showinfo("복구 키 보관", "복구 키를 안전한 별도 장소에 보관하세요.\n\n"
                                       + recovery, parent=self.root)
            else:
                _result, output = self._capture(lambda: vault.login(password))
                if vault.key is None:
                    message = output or "비밀번호가 올바르지 않습니다."
                    if vault.lock_status():
                        message += f"\n로그인 제한: {vault.lock_status()}초"
                    messagebox.showerror("로그인 실패", message, parent=self.root)
                    return
            self.vault = vault
            self._dashboard()
        except Exception as error:
            messagebox.showerror("금고 열기 실패", str(error), parent=self.root)

    def _recover_password(self):
        folder_text = self.folder_var.get().strip()
        if not folder_text:
            messagebox.showwarning("금고 위치", "먼저 금고 폴더를 선택하세요.", parent=self.root)
            return
        try:
            vault = Vault(Path(folder_text).expanduser())
            if not vault.exists:
                messagebox.showerror("복구 실패", "선택한 위치에 금고가 없습니다.", parent=self.root)
                return
            recovery = simpledialog.askstring("복구 키", "보관한 복구 키를 입력하세요:",
                                              show="●", parent=self.root)
            if recovery is None:
                return
            new_password = simpledialog.askstring("새 비밀번호", "새 비밀번호 (8자 이상):",
                                                  show="●", parent=self.root)
            if new_password is None:
                return
            if len(new_password) < 8:
                messagebox.showerror("비밀번호 확인", "비밀번호는 8자 이상이어야 합니다.", parent=self.root)
                return
            confirm = simpledialog.askstring("새 비밀번호 확인", "새 비밀번호를 다시 입력하세요:",
                                             show="●", parent=self.root)
            if confirm != new_password:
                messagebox.showerror("비밀번호 확인", "비밀번호가 일치하지 않습니다.", parent=self.root)
                return
            vault.recover_with_key(recovery, new_password)
            self.vault = vault
            self._dashboard()
            messagebox.showinfo("복구 완료", "새 비밀번호로 금고를 복구했습니다.", parent=self.root)
        except Exception as error:
            messagebox.showerror("복구 실패", str(error), parent=self.root)

    def _clear(self):
        for child in self.root.winfo_children():
            child.destroy()

    def _dashboard(self):
        self._clear()
        shell = tk.Frame(self.root, bg="#F4F6FA")
        shell.pack(fill="both", expand=True)
        sidebar = ttk.Frame(shell, style="Sidebar.TFrame", width=220)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        tk.Label(sidebar, text="DigitalVault", bg="#202B3C", fg="#FFFFFF",
                 font=("Malgun Gothic", 17, "bold")).pack(anchor="w", padx=20, pady=(26, 3))
        tk.Label(sidebar, text="SECURE DOCUMENT STORAGE", bg="#202B3C", fg="#9EABC0",
                 font=("Segoe UI", 7, "bold")).pack(anchor="w", padx=21, pady=(0, 30))
        for label, command in [
            ("▦   문서 보관함", self._refresh_documents),
            ("＋   문서 추가", self._add_document),
            ("⇩   문서 내보내기", self._export_document),
            ("◈   보안 관리", self._security_menu),
            ("▤   백업 및 복구", self._backup_menu),
            ("✓   무결성 검사", self._integrity_check),
            ("ⓘ   금고 정보", self._vault_info),
        ]:
            ttk.Button(sidebar, text=label, style="Sidebar.TButton",
                       command=command).pack(fill="x", padx=8, pady=2)
        ttk.Button(sidebar, text="잠금 및 종료", style="Sidebar.TButton",
                   command=self._lock).pack(side="bottom", fill="x", padx=8, pady=18)

        main = tk.Frame(shell, bg="#F4F6FA")
        main.pack(side="left", fill="both", expand=True)
        header = tk.Frame(main, bg="#FFFFFF", padx=30, pady=22)
        header.pack(fill="x")
        tk.Label(header, text="문서 보관함", bg="#FFFFFF", fg="#202938",
                 font=("Malgun Gothic", 20, "bold")).pack(side="left")
        tk.Label(header, text="잠금 해제됨", bg="#E7F6EE", fg="#21834D",
                 font=("Malgun Gothic", 9, "bold"), padx=10, pady=5).pack(side="right")
        content = tk.Frame(main, bg="#F4F6FA", padx=28, pady=24)
        content.pack(fill="both", expand=True)

        stats = tk.Frame(content, bg="#F4F6FA")
        stats.pack(fill="x", pady=(0, 20))
        self.count_label = self._stat_card(stats, "저장된 문서", "0개")
        self.size_label = self._stat_card(stats, "암호화 용량", "0 B")
        self._refresh_documents()

        toolbar = tk.Frame(content, bg="#F4F6FA")
        toolbar.pack(fill="x", pady=(0, 12))
        tk.Label(toolbar, text="저장된 파일", bg="#F4F6FA", fg="#202938",
                 font=("Malgun Gothic", 12, "bold")).pack(side="left")
        ttk.Button(toolbar, text="이름 변경", command=self._rename_document).pack(side="right", padx=(6, 0))
        ttk.Button(toolbar, text="삭제", command=self._delete_document).pack(side="right", padx=(6, 0))
        ttk.Button(toolbar, text="열기", style="Accent.TButton",
                   command=self._open_document).pack(side="right")

        table_card = tk.Frame(content, bg="#FFFFFF", padx=14, pady=14,
                              highlightthickness=1, highlightbackground="#E6EAF0")
        table_card.pack(fill="both", expand=True)
        columns = ("name", "type", "size")
        self.tree = ttk.Treeview(table_card, columns=columns, show="headings", selectmode="extended")
        self.tree.heading("name", text="파일명", anchor="w")
        self.tree.heading("type", text="형식", anchor="center")
        self.tree.heading("size", text="암호화 크기", anchor="e")
        self.tree.column("name", width=520, anchor="w")
        self.tree.column("type", width=100, anchor="center", stretch=False)
        self.tree.column("size", width=150, anchor="e", stretch=False)
        scrollbar = ttk.Scrollbar(table_card, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", lambda _e: self._open_document())
        self._refresh_documents()

    def _stat_card(self, parent, title, value):
        card = tk.Frame(parent, bg="#FFFFFF", padx=20, pady=15,
                        highlightthickness=1, highlightbackground="#E6EAF0")
        card.pack(side="left", fill="x", expand=True, padx=(0, 12))
        tk.Label(card, text=title, bg="#FFFFFF", fg="#7B8798",
                 font=("Malgun Gothic", 9)).pack(anchor="w")
        label = tk.Label(card, text=value, bg="#FFFFFF", fg="#202938",
                         font=("Malgun Gothic", 19, "bold"))
        label.pack(anchor="w", pady=(6, 0))
        return label

    def _documents(self):
        return sorted(self.vault.index.items(), key=lambda item: item[1]["name"].casefold())

    def _refresh_documents(self):
        if not self.vault or not hasattr(self, "tree"):
            return
        for item in self.tree.get_children():
            self.tree.delete(item)
        total = 0
        for file_id, info in self._documents():
            path = self.vault.docs / (file_id + ".bin")
            size = path.stat().st_size if path.exists() else 0
            total += size
            self.tree.insert("", "end", iid=file_id,
                             values=(info["name"], info["extension"].lstrip(".").upper(),
                                     self._format_size(size)))
        self.count_label.configure(text=f"{len(self.vault.index)}개")
        self.size_label.configure(text=self._format_size(total))

    @staticmethod
    def _format_size(size):
        if size < 1024:
            return f"{size:,} B"
        if size < 1024 ** 2:
            return f"{size / 1024:.1f} KB"
        return f"{size / (1024 ** 2):.2f} MB"

    def _selected_ids(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("문서 선택", "먼저 문서를 선택하세요.", parent=self.root)
            return []
        return list(selected)

    def _add_document(self):
        paths = filedialog.askopenfilenames(
            title="금고에 추가할 문서 선택",
            filetypes=[("지원 문서", "*.pdf *.docx *.txt *.pptx *.xlsx *.jpg *.jpeg *.png"),
                       ("모든 파일", "*.*")], parent=self.root)
        if not paths:
            return
        added, failed = [], []
        for path in paths:
            source = Path(path)
            if source.suffix.lower() not in EXTENSIONS:
                failed.append(f"{source.name}: 지원하지 않는 형식")
                continue
            before = len(self.vault.index)
            _result, output = self._capture(lambda p=source: self.vault.add_document(p))
            if len(self.vault.index) > before:
                added.append(source.name)
            else:
                failed.append(f"{source.name}: {output or '저장 실패'}")
        self._refresh_documents()
        message = f"문서 {len(added)}개를 추가했습니다."
        if failed:
            message += "\n\n실패:\n" + "\n".join(failed)
        messagebox.showinfo("문서 추가", message, parent=self.root)

    def _export_document(self):
        ids = self._selected_ids()
        if not ids:
            return
        file_id = ids[0]
        info = self.vault.index[file_id]
        ext = info["extension"]
        destination = filedialog.asksaveasfilename(
            title="문서를 저장할 위치 선택", initialfile=info["name"],
            defaultextension=ext,
            filetypes=[(f"원본 형식 (*{ext})", f"*{ext}"), ("모든 파일", "*.*")],
            parent=self.root)
        if not destination:
            return
        target = Path(destination)
        if target.exists() and not messagebox.askyesno("덮어쓰기 확인",
                "같은 이름의 파일이 있습니다. 덮어쓸까요?", parent=self.root):
            return
        try:
            data = decrypt(self.vault.key,
                (self.vault.docs / (file_id + ".bin")).read_bytes(),
                ("DigitalVault:document:v2:" + file_id).encode())
            atomic_write(target, data)
            messagebox.showinfo("내보내기 완료",
                "문서를 내보냈습니다.\n내보낸 파일은 금고 외부에 암호화되지 않은 상태로 저장됩니다.",
                parent=self.root)
        except Exception as error:
            messagebox.showerror("내보내기 실패", str(error), parent=self.root)

    def _open_document(self):
        ids = self._selected_ids()
        if not ids:
            return
        file_id = ids[0]
        temp_dir = None
        try:
            info = self.vault.index[file_id]
            data = decrypt(self.vault.key,
                (self.vault.docs / (file_id + ".bin")).read_bytes(),
                ("DigitalVault:document:v2:" + file_id).encode())
            temp_dir = Path(tempfile.mkdtemp(prefix=self.vault.temp_prefix))
            try:
                os.chmod(temp_dir, 0o700)
            except OSError:
                pass
            temp_file = temp_dir / Path(info["name"]).name
            temp_file.write_bytes(data)
            try:
                os.chmod(temp_file, 0o600)
            except OSError:
                pass
            if os.name == "nt":
                os.startfile(str(temp_file))
            else:
                import subprocess
                if sys.platform == "darwin":
                    subprocess.Popen(["open", str(temp_file)])
                else:
                    subprocess.Popen(["xdg-open", str(temp_file)])
            messagebox.showinfo("문서 열기",
                "문서를 외부 프로그램에서 열었습니다.\n확인을 누르면 임시 복호화 파일을 정리합니다.\n"
                "문서를 사용 중이라면 먼저 닫아 주세요.", parent=self.root)
        except Exception as error:
            messagebox.showerror("문서 열기 실패", str(error), parent=self.root)
        finally:
            if temp_dir is not None:
                shutil.rmtree(temp_dir, ignore_errors=True)

    def _delete_document(self):
        ids = self._selected_ids()
        if not ids:
            return
        names = [self.vault.index[file_id]["name"] for file_id in ids]
        if not messagebox.askyesno("문서 삭제", f"선택한 문서 {len(ids)}개를 삭제할까요?\n\n"
                + "\n".join(names), parent=self.root):
            return
        for file_id in ids:
            (self.vault.docs / (file_id + ".bin")).unlink(missing_ok=True)
            self.vault.index.pop(file_id, None)
        self.vault.save_index()
        self.vault.log_event("document_deleted")
        self._refresh_documents()

    def _rename_document(self):
        ids = self._selected_ids()
        if not ids:
            return
        file_id = ids[0]
        old = self.vault.index[file_id]["name"]
        new = simpledialog.askstring("이름 변경", "새 파일명을 입력하세요.",
                                     initialvalue=old, parent=self.root)
        if not new:
            return
        if Path(new).name != new:
            messagebox.showerror("이름 확인", "파일명만 입력할 수 있습니다.", parent=self.root)
            return
        ext = self.vault.index[file_id]["extension"]
        if Path(new).suffix.lower() != ext:
            new = Path(new).stem + ext
        if any(key != file_id and value["name"].casefold() == new.casefold()
               for key, value in self.vault.index.items()):
            messagebox.showerror("이름 중복", "같은 이름의 문서가 이미 있습니다.", parent=self.root)
            return
        self.vault.index[file_id]["name"] = new
        self.vault.save_index()
        self.vault.log_event("document_renamed")
        self._refresh_documents()

    def _security_menu(self):
        choice = tk.Menu(self.root, tearoff=False)
        choice.add_command(label="비밀번호 변경", command=self._change_password)
        choice.add_command(label="마스터 키 재발급", command=self._rotate_key)
        choice.add_command(label="복구 키 발급", command=self._issue_recovery)
        choice.add_command(label="보안 기록", command=self._show_log)
        choice.tk_popup(self.root.winfo_pointerx(), self.root.winfo_pointery())

    def _change_password(self):
        old = simpledialog.askstring("비밀번호 변경", "현재 비밀번호:", show="●", parent=self.root)
        if old is None:
            return
        new = simpledialog.askstring("비밀번호 변경", "새 비밀번호 (8자 이상):", show="●", parent=self.root)
        if new is None:
            return
        if len(new) < 8:
            messagebox.showerror("비밀번호 확인", "비밀번호는 8자 이상이어야 합니다.", parent=self.root)
            return
        confirm = simpledialog.askstring("비밀번호 변경", "새 비밀번호 확인:", show="●", parent=self.root)
        if confirm != new:
            messagebox.showerror("비밀번호 확인", "비밀번호가 일치하지 않습니다.", parent=self.root)
            return
        output = self._capture(lambda: self.vault.change_password(old, new))[1]
        if "실패" in output:
            messagebox.showerror("변경 실패", output, parent=self.root)
        else:
            messagebox.showinfo("완료", "비밀번호를 변경했습니다.", parent=self.root)

    def _rotate_key(self):
        if not messagebox.askyesno("마스터 키 재발급",
                "마스터 키를 새로 발급하고 모든 문서를 다시 암호화할까요?", parent=self.root):
            return
        password = simpledialog.askstring("재인증", "현재 비밀번호:", show="●", parent=self.root)
        if password is None:
            return
        meta = json.loads(self.vault.meta_file.read_text(encoding="utf-8"))
        recovery = None
        if meta.get("recovery_wrapped_key"):
            recovery = simpledialog.askstring("복구 키 확인",
                "복구 기능을 유지하려면 기존 복구 키를 입력하세요:", show="●", parent=self.root)
            if recovery is None:
                return
        try:
            self.vault.rotate_master_key(password, recovery)
            messagebox.showinfo("완료", "마스터 키를 재발급했습니다.", parent=self.root)
        except Exception as error:
            messagebox.showerror("재발급 실패", str(error), parent=self.root)

    def _issue_recovery(self):
        password = simpledialog.askstring("복구 키 발급", "현재 비밀번호를 입력하세요:",
                                          show="●", parent=self.root)
        if password is None:
            return
        try:
            key = self.vault.setup_recovery_key(password)
            messagebox.showinfo("복구 키 발급", "아래 키를 안전한 별도 장소에 보관하세요.\n"
                "이 창을 닫으면 다시 표시되지 않습니다.\n\n" + key, parent=self.root)
        except Exception as error:
            messagebox.showerror("발급 실패", str(error), parent=self.root)

    def _show_log(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.vault.show_security_log()
        self._text_window("보안 기록", output.getvalue())

    def _backup_menu(self):
        menu = tk.Menu(self.root, tearoff=False)
        menu.add_command(label="금고 백업 만들기", command=self._create_backup)
        menu.add_command(label="백업을 현재 금고에 병합", command=self._merge_backup)
        menu.tk_popup(self.root.winfo_pointerx(), self.root.winfo_pointery())

    def _create_backup(self):
        destination = filedialog.asksaveasfilename(
            title="금고 백업 저장", defaultextension=".zip",
            filetypes=[("DigitalVault 백업", "*.zip"), ("모든 파일", "*.*")],
            parent=self.root)
        if not destination:
            return
        target = Path(destination)
        overwrite = target.exists()
        if overwrite and not messagebox.askyesno("덮어쓰기 확인",
                "같은 이름의 백업본이 있습니다. 덮어쓸까요?", parent=self.root):
            return
        try:
            count = self.vault.create_backup(target, overwrite=overwrite)
            messagebox.showinfo("백업 완료", f"백업을 만들었습니다.\n포함 파일: {count}개", parent=self.root)
        except Exception as error:
            messagebox.showerror("백업 실패", str(error), parent=self.root)

    def _merge_backup(self):
        archive = filedialog.askopenfilename(title="불러올 백업 선택",
            filetypes=[("DigitalVault 백업", "*.zip"), ("모든 파일", "*.*")], parent=self.root)
        if not archive:
            return
        password = simpledialog.askstring("백업 인증", "백업 당시 금고 비밀번호:",
                                           show="●", parent=self.root)
        if password is None:
            return
        try:
            count = self.vault.merge_backup(archive, password)
            self._refresh_documents()
            messagebox.showinfo("백업 불러오기 완료",
                f"문서 {count}개를 현재 금고에 병합했습니다.\n기존 문서는 유지됩니다.", parent=self.root)
        except Exception as error:
            messagebox.showerror("백업 불러오기 실패", str(error), parent=self.root)

    def _integrity_check(self):
        result, output = self._capture(self.vault.integrity_check)
        self._text_window("무결성 검사 결과", output)
        if result:
            messagebox.showinfo("검사 완료", "모든 문서의 무결성 검사가 정상적으로 완료되었습니다.",
                                parent=self.root)
        else:
            messagebox.showwarning("확인 필요", "일부 항목에서 문제가 발견되었습니다. 결과를 확인하세요.",
                                   parent=self.root)

    def _vault_info(self):
        total = sum((self.vault.docs / (key + ".bin")).stat().st_size
                    for key in self.vault.index
                    if (self.vault.docs / (key + ".bin")).exists())
        meta = json.loads(self.vault.meta_file.read_text(encoding="utf-8"))
        text = (
            "암호화 방식: AES-256-GCM\n"
            "키 파생 방식: scrypt\n"
            f"포맷 버전: {meta.get('format_version')}\n"
            f"저장 문서: {len(self.vault.index)}개\n"
            f"암호화 용량: {total:,} bytes\n"
            f"복구 키: {'설정됨' if meta.get('recovery_wrapped_key') else '미설정'}\n\n"
            f"저장 위치:\n{self.vault.folder}"
        )
        messagebox.showinfo("금고 정보", text, parent=self.root)

    def _text_window(self, title, text):
        window = tk.Toplevel(self.root)
        window.title(title)
        window.geometry("760x520")
        frame = tk.Frame(window, padx=14, pady=14)
        frame.pack(fill="both", expand=True)
        widget = tk.Text(frame, wrap="word", font=("Consolas", 10), relief="solid", bd=1)
        widget.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(frame, command=widget.yview)
        scroll.pack(side="right", fill="y")
        widget.configure(yscrollcommand=scroll.set)
        widget.insert("1.0", text or "표시할 내용이 없습니다.")
        widget.configure(state="disabled")

    def _lock(self):
        if self.vault and self.vault.key is not None:
            self.vault.lock()
        self.vault = None
        self._clear()
        self._login_screen()

    def _close(self):
        if self.vault and self.vault.key is not None:
            self.vault.lock()
        self.root.destroy()

    def run(self):
        self.root.mainloop()


def main():
    DigitalVaultApp().run()


if __name__ == "__main__":
    main()
