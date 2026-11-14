"""DigitalVault desktop GUI (Tkinter)."""
import contextlib
import io
import json
import os
import sys
import shutil
import tempfile
import tkinter as tk
import tkinter.font as tkfont
from pathlib import Path
from tkinter import filedialog, ttk

from digital_vault import (
    EXTENSIONS, Vault, app_directory, default_vault_directory, decrypt,
    atomic_write, prompt_new_password,
)


class DigitalVaultApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("DigitalVault")
        self.root.geometry("1180x780")
        self.root.minsize(980, 660)
        self.root.configure(bg="#F5F7FB")
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
        style.configure("Treeview", rowheight=42, font=("Malgun Gothic", 10),
                        background="#FFFFFF", fieldbackground="#FFFFFF",
                        foreground="#202938", borderwidth=0, relief="flat")
        style.configure("Treeview.Heading", font=("Malgun Gothic", 9, "bold"),
                        background="#F2F5FA", foreground="#526078", relief="flat", padding=(12, 12))
        style.map("Treeview", background=[("selected", "#E4ECFF")],
                  foreground=[("selected", "#173B83")])
        style.configure("TButton", font=("Malgun Gothic", 9), padding=(14, 10),
                        background="#FFFFFF", foreground="#344054", borderwidth=0, relief="flat")
        style.map("TButton", background=[("active", "#EDF2FA"), ("pressed", "#E4EAF4")])
        style.configure("Accent.TButton", font=("Malgun Gothic", 9, "bold"),
                        padding=(16, 11), background="#315ECA", foreground="#FFFFFF", borderwidth=0)
        style.map("Accent.TButton", background=[("active", "#244DAA")])
        style.configure("TLabel", font=("Malgun Gothic", 10), background="#FFFFFF",
                        foreground="#202938")
        style.configure("Muted.TLabel", foreground="#738096", background="#FFFFFF")
        style.configure("Title.TLabel", font=("Malgun Gothic", 20, "bold"))
        style.configure("Card.TFrame", background="#FFFFFF")
        style.configure("Sidebar.TFrame", background="#182436")
        style.configure("Sidebar.TButton", background="#182436", foreground="#D8E1EF",
                        borderwidth=0, anchor="w", padding=(18, 13), font=("Malgun Gothic", 9))
        style.map("Sidebar.TButton", background=[("active", "#2B3B52")], foreground=[("active", "#FFFFFF")])

    def _center(self, window, width=460, height=360):
        window.update_idletasks()
        x = (window.winfo_screenwidth() - width) // 2
        y = (window.winfo_screenheight() - height) // 2
        window.geometry(f"{width}x{height}+{x}+{y}")

    def _login_screen(self):
        self.login_frame = tk.Frame(self.root, bg="#F5F7FB")
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
            self._show_message("warning", "입력 확인", "금고 위치와 비밀번호를 입력하세요.", parent=self.root)
            return
        try:
            vault = Vault(Path(folder_text).expanduser())
            if not vault.exists:
                if len(password) < 8:
                    self._show_message("warning", "비밀번호 확인", "새 금고 비밀번호는 8자 이상이어야 합니다.", parent=self.root)
                    return
                confirm = self._ask_string("비밀번호 확인", "새 비밀번호를 한 번 더 입력하세요.",
                                                 show="●", parent=self.root)
                if confirm is None:
                    return
                if password != confirm:
                    self._show_message("error", "확인 실패", "비밀번호가 일치하지 않습니다.", parent=self.root)
                    return
                vault.create(password)
                recovery = getattr(vault, "recovery_key_display", None)
                if recovery:
                    self._show_message("info", "복구 키 보관", "복구 키를 안전한 별도 장소에 보관하세요.\n\n"
                                       + recovery, parent=self.root)
            else:
                _result, output = self._capture(lambda: vault.login(password))
                if vault.key is None:
                    message = output or "비밀번호가 올바르지 않습니다."
                    if vault.lock_status():
                        message += f"\n로그인 제한: {vault.lock_status()}초"
                    self._show_message("error", "로그인 실패", message, parent=self.root)
                    return
            self.vault = vault
            self._dashboard()
        except Exception as error:
            self._show_message("error", "금고 열기 실패", str(error), parent=self.root)

    def _recover_password(self):
        folder_text = self.folder_var.get().strip()
        if not folder_text:
            self._show_message("warning", "금고 위치", "먼저 금고 폴더를 선택하세요.", parent=self.root)
            return
        try:
            vault = Vault(Path(folder_text).expanduser())
            if not vault.exists:
                self._show_message("error", "복구 실패", "선택한 위치에 금고가 없습니다.", parent=self.root)
                return
            recovery = self._ask_string("복구 키", "보관한 복구 키를 입력하세요:",
                                              show="●", parent=self.root)
            if recovery is None:
                return
            new_password = self._ask_string("새 비밀번호", "새 비밀번호 (8자 이상):",
                                                  show="●", parent=self.root)
            if new_password is None:
                return
            if len(new_password) < 8:
                self._show_message("error", "비밀번호 확인", "비밀번호는 8자 이상이어야 합니다.", parent=self.root)
                return
            confirm = self._ask_string("새 비밀번호 확인", "새 비밀번호를 다시 입력하세요:",
                                             show="●", parent=self.root)
            if confirm != new_password:
                self._show_message("error", "비밀번호 확인", "비밀번호가 일치하지 않습니다.", parent=self.root)
                return
            vault.recover_with_key(recovery, new_password)
            self.vault = vault
            self._dashboard()
            self._show_message("info", "복구 완료", "새 비밀번호로 금고를 복구했습니다.", parent=self.root)
        except Exception as error:
            self._show_message("error", "복구 실패", str(error), parent=self.root)

    def _clear(self):
        # 이전 화면의 Treeview 위젯 참조가 남으면 재로그인 시 TclError가 발생한다.
        self.tree = None
        for child in self.root.winfo_children():
            child.destroy()

    def _dashboard(self):
        self._clear()
        shell = tk.Frame(self.root, bg="#F5F7FB")
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

        main = tk.Frame(shell, bg="#F5F7FB")
        main.pack(side="left", fill="both", expand=True)
        header = tk.Frame(main, bg="#FFFFFF", padx=30, pady=22)
        header.pack(fill="x")
        tk.Label(header, text="문서 보관함", bg="#FFFFFF", fg="#202938",
                 font=("Malgun Gothic", 20, "bold")).pack(side="left")
        tk.Label(header, text="잠금 해제됨", bg="#E7F6EE", fg="#21834D",
                 font=("Malgun Gothic", 9, "bold"), padx=10, pady=5).pack(side="right")
        content = tk.Frame(main, bg="#F5F7FB", padx=28, pady=24)
        content.pack(fill="both", expand=True)

        stats = tk.Frame(content, bg="#F5F7FB")
        stats.pack(fill="x", pady=(0, 20))
        self.count_label = self._stat_card(stats, "저장된 문서", "0개")
        self.size_label = self._stat_card(stats, "암호화 용량", "0 B")

        toolbar = tk.Frame(content, bg="#F5F7FB")
        toolbar.pack(fill="x", pady=(0, 12))
        tk.Label(toolbar, text="저장된 파일", bg="#F5F7FB", fg="#202938",
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
        self.tree.bind("<Button-1>", self._toggle_tree_selection)
        self._refresh_documents()

    def _dialog_window(self, title, width=560, height=260):
        window = tk.Toplevel(self.root)
        window.title(title)
        window.configure(bg="#F5F7FB")
        window.transient(self.root)
        window.resizable(False, False)

        screen_w = window.winfo_screenwidth()
        screen_h = window.winfo_screenheight()
        width = min(width, max(360, screen_w - 48))
        max_height = max(220, screen_h - 72)
        height = min(height, max_height)
        x = max(12, (screen_w - width) // 2)
        y = max(12, (screen_h - height) // 2)
        window.geometry(f"{width}x{height}+{x}+{y}")
        window.grab_set()
        return window

    def _dialog_text(self, parent, message, max_lines=14, width_chars=64):
        """긴 안내는 텍스트 영역만 스크롤하고, 하단 버튼은 별도 영역에 고정합니다."""
        value = str(message)
        font = tkfont.Font(family="Malgun Gothic", size=9)
        max_pixel_width = font.measure("가" * width_chars)
        line_height = max(18, font.metrics("linespace") + 3)

        def wrapped_line_count(line):
            if not line:
                return 1
            count = 1
            current_width = 0
            for char in line:
                char_width = font.measure(char)
                if current_width and current_width + char_width > max_pixel_width:
                    count += 1
                    current_width = char_width
                else:
                    current_width += char_width
            return count

        estimated_lines = sum(wrapped_line_count(line) for line in value.split("\n"))
        estimated_lines = max(1, estimated_lines)
        visible_lines = min(estimated_lines, max_lines)

        frame = tk.Frame(parent, bg="#FFFFFF")
        text = tk.Text(
            frame, width=width_chars, height=visible_lines, wrap="word",
            font=("Malgun Gothic", 9), bg="#FFFFFF", fg="#536176",
            relief="flat", borderwidth=0, padx=0, pady=0,
            cursor="arrow", takefocus=False,
            spacing1=2, spacing3=2
        )
        text.insert("1.0", value)
        text.configure(state="disabled")
        text.pack(side="left", fill="both", expand=True)

        if estimated_lines > max_lines:
            scrollbar = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
            scrollbar.pack(side="right", fill="y")
            text.configure(yscrollcommand=scrollbar.set)

        return frame, visible_lines, line_height

    def _dialog_height(self, visible_lines, line_height, fixed_height):
        screen_h = self.root.winfo_screenheight()
        desired = fixed_height + visible_lines * line_height
        return min(desired, max(220, screen_h - 72))

    def _show_message(self, kind, title, message, parent=None):
        colors = {"info": "#315ECA", "warning": "#B7791F", "error": "#C43D4B"}
        symbols = {"info": "i", "warning": "!", "error": "×"}
        text_value = str(message)
        # 버튼/제목/여백 높이를 먼저 확보하고, 본문만 남은 공간을 사용합니다.
        font = tkfont.Font(family="Malgun Gothic", size=9)
        line_height = max(18, font.metrics("linespace") + 3)
        provisional_lines = min(max(1, sum(max(1, len(line) // 58 + 1) for line in text_value.split("\n"))), 14)
        height = self._dialog_height(provisional_lines, line_height, 184)
        window = self._dialog_window(title, 560, height)

        card = tk.Frame(window, bg="#FFFFFF", padx=28, pady=22)
        card.pack(fill="both", expand=True, padx=12, pady=12)
        top = tk.Frame(card, bg="#FFFFFF")
        top.pack(side="top", fill="x")
        tk.Label(top, text=symbols[kind], bg=colors[kind], fg="#FFFFFF",
                 font=("Segoe UI", 13, "bold"), width=2, height=1).pack(side="left", padx=(0, 12))
        tk.Label(top, text=title, bg="#FFFFFF", fg="#202938",
                 font=("Malgun Gothic", 13, "bold")).pack(side="left")

        button = ttk.Button(card, text="확인", style="Accent.TButton",
                            command=window.destroy)
        button.pack(side="bottom", anchor="e", pady=(12, 0))

        available_lines = max(2, min(14, (height - 184) // line_height))
        body, _lines, _lh = self._dialog_text(
            card, text_value, max_lines=available_lines, width_chars=64
        )
        body.pack(side="top", fill="both", expand=True, pady=(16, 0))

        window.bind("<Return>", lambda _e: window.destroy())
        window.bind("<Escape>", lambda _e: window.destroy())
        window.wait_window()

    def _ask_yes_no(self, title, message, parent=None):
        result = {"value": False}
        text_value = str(message)
        font = tkfont.Font(family="Malgun Gothic", size=9)
        line_height = max(18, font.metrics("linespace") + 3)
        provisional_lines = min(max(1, sum(max(1, len(line) // 58 + 1) for line in text_value.split("\n"))), 14)
        height = self._dialog_height(provisional_lines, line_height, 178)
        window = self._dialog_window(title, 560, height)

        card = tk.Frame(window, bg="#FFFFFF", padx=28, pady=22)
        card.pack(fill="both", expand=True, padx=12, pady=12)
        tk.Label(card, text=title, bg="#FFFFFF", fg="#202938",
                 font=("Malgun Gothic", 13, "bold")).pack(side="top", anchor="w")

        # 버튼을 먼저 하단에 배치해 본문 길이와 관계없이 항상 보이도록 합니다.
        actions = tk.Frame(card, bg="#FFFFFF")
        actions.pack(side="bottom", fill="x", pady=(14, 0))
        ttk.Button(actions, text="취소", command=window.destroy).pack(side="right", padx=(8, 0))
        ttk.Button(actions, text="확인", style="Accent.TButton",
                   command=lambda: (result.update(value=True), window.destroy())).pack(side="right")

        available_lines = max(2, min(14, (height - 178) // line_height))
        body, _lines, _lh = self._dialog_text(
            card, text_value, max_lines=available_lines, width_chars=64
        )
        body.pack(side="top", fill="both", expand=True, pady=(16, 0))

        window.bind("<Return>", lambda _e: (result.update(value=True), window.destroy()))
        window.bind("<Escape>", lambda _e: window.destroy())
        window.wait_window()
        return result["value"]

    def _ask_string(self, title, prompt, **kwargs):
        result = {"value": None}
        show = kwargs.get("show")
        initial = kwargs.get("initialvalue", "")
        prompt_text = str(prompt)
        font = tkfont.Font(family="Malgun Gothic", size=9)
        line_height = max(18, font.metrics("linespace") + 3)
        provisional_lines = min(max(1, sum(max(1, len(line) // 58 + 1) for line in prompt_text.split("\n"))), 8)
        height = self._dialog_height(provisional_lines, line_height, 222)
        window = self._dialog_window(title, 560, height)

        card = tk.Frame(window, bg="#FFFFFF", padx=28, pady=22)
        card.pack(fill="both", expand=True, padx=12, pady=12)
        tk.Label(card, text=title, bg="#FFFFFF", fg="#202938",
                 font=("Malgun Gothic", 13, "bold")).pack(side="top", anchor="w")

        actions = tk.Frame(card, bg="#FFFFFF")
        actions.pack(side="bottom", fill="x", pady=(14, 0))
        ttk.Button(actions, text="취소", command=window.destroy).pack(side="right", padx=(8, 0))

        def submit():
            result["value"] = value.get()
            window.destroy()

        ttk.Button(actions, text="확인", style="Accent.TButton", command=submit).pack(side="right")

        value = tk.StringVar(value=initial or "")
        entry = tk.Entry(card, textvariable=value, show=show or "",
                         relief="solid", bd=1, font=("Malgun Gothic", 10))
        entry.pack(side="bottom", fill="x", ipady=9, pady=(10, 0))

        available_lines = max(2, min(8, (height - 222) // line_height))
        body, _lines, _lh = self._dialog_text(
            card, prompt_text, max_lines=available_lines, width_chars=64
        )
        body.pack(side="top", fill="both", expand=True, pady=(16, 0))

        window.bind("<Return>", lambda _e: submit())
        window.bind("<Escape>", lambda _e: window.destroy())
        entry.focus_set()
        window.wait_window()
        return result["value"]

    def _tool_dialog(self, title, actions):
        """도구 메뉴의 제목과 버튼 문구에 맞춰 창 크기를 조절합니다."""
        window = tk.Toplevel(self.root)
        window.title(title)
        window.configure(bg="#F5F7FB")
        window.transient(self.root)
        window.resizable(False, False)

        title_font = tkfont.Font(family="Malgun Gothic", size=16, weight="bold")
        button_font = tkfont.Font(family="Malgun Gothic", size=10)
        longest_label = max(
            [title_font.measure(str(title))]
            + [button_font.measure(str(label)) for label, _command in actions]
            + [button_font.measure("닫기")]
        )
        screen_w = window.winfo_screenwidth()
        screen_h = window.winfo_screenheight()
        width = min(max(380, longest_label + 88), max(320, screen_w - 48))
        desired_height = 154 + len(actions) * 52
        height = min(desired_height, max(220, screen_h - 72))

        body = tk.Frame(window, bg="#FFFFFF", padx=24, pady=22,
                        highlightthickness=1, highlightbackground="#E5EAF2")
        body.pack(fill="both", expand=True, padx=14, pady=14)
        tk.Label(body, text=title, bg="#FFFFFF", fg="#202938",
                 font=title_font).pack(anchor="w", pady=(0, 16))
        for label, command in actions:
            ttk.Button(
                body, text=label,
                command=lambda fn=command, w=window: (w.destroy(), fn()),
                style="Accent.TButton"
            ).pack(fill="x", pady=4)
        ttk.Button(body, text="닫기", command=window.destroy).pack(
            fill="x", pady=(12, 0)
        )

        # 고정 추정치가 아닌 실제 위젯 요청 크기로 창 높이를 산정해
        # 마지막 '닫기' 버튼이 창 아래로 밀려나지 않도록 합니다.
        window.update_idletasks()
        required_width = window.winfo_reqwidth() + 8
        required_height = window.winfo_reqheight() + 8
        width = min(max(width, required_width), max(320, screen_w - 48))
        height = min(max(240, required_height), max(220, screen_h - 48))
        x = max(12, (screen_w - width) // 2)
        y = max(12, (screen_h - height) // 2)
        window.geometry(f"{width}x{height}+{x}+{y}")
        window.grab_set()

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
        if not self.vault or self.tree is None:
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

    def _toggle_tree_selection(self, event):
        """Ctrl/Shift 없이 클릭할 때마다 해당 문서의 선택 상태를 전환합니다."""
        file_id = self.tree.identify_row(event.y)
        if not file_id:
            return "break"
        selected = set(self.tree.selection())
        if file_id in selected:
            self.tree.selection_remove(file_id)
        else:
            self.tree.selection_add(file_id)
        self.tree.focus(file_id)
        return "break"

    def _selected_ids(self):
        selected = self.tree.selection()
        if not selected:
            self._show_message("info", "문서 선택", "먼저 문서를 선택하세요.", parent=self.root)
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
        self._show_message("info", "문서 추가", message, parent=self.root)

    def _export_document(self):
        ids = self._selected_ids()
        if ids:
            self._export_document_sequence(ids, 0)

    def _export_document_sequence(self, ids, index):
        if index >= len(ids):
            return
        file_id = ids[index]
        info = self.vault.index.get(file_id)
        if info is None:
            self._show_message("warning", "내보내기 건너뜀",
                "선택한 문서를 찾을 수 없습니다.", parent=self.root)
            return
        ext = info["extension"]
        destination = filedialog.asksaveasfilename(
            title=f"문서 내보내기 ({index + 1}/{len(ids)})",
            initialfile=info["name"], defaultextension=ext,
            confirmoverwrite=True,
            filetypes=[(f"원본 형식 (*{ext})", f"*{ext}"), ("모든 파일", "*.*")],
            parent=self.root)
        if not destination:
            return
        try:
            data = decrypt(self.vault.key,
                (self.vault.docs / (file_id + ".bin")).read_bytes(),
                ("DigitalVault:document:v2:" + file_id).encode())
            atomic_write(Path(destination), data)
            message = (
                f"선택한 문서 {len(ids)}개 중 {index + 1}번째 문서를 내보냈습니다.\n"
                "내보낸 파일은 금고 외부에 암호화되지 않은 상태로 저장됩니다."
            )
            if index + 1 < len(ids):
                message += "\n\n확인을 누르면 다음 문서의 저장 위치를 선택합니다."
            else:
                message += "\n\n선택한 문서의 내보내기가 모두 완료되었습니다."
            self._show_message("info", "내보내기 진행", message, parent=self.root)
        except Exception as error:
            self._show_message("error", "내보내기 실패",
                f"{info['name']}\n\n{error}", parent=self.root)
        if index + 1 < len(ids):
            self._export_document_sequence(ids, index + 1)

    def _open_document(self):
        ids = self._selected_ids()
        if ids:
            self._open_document_sequence(ids, 0)

    def _open_document_sequence(self, ids, index):
        if index >= len(ids):
            return
        file_id = ids[index]
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
            message = (
                f"선택한 문서 {len(ids)}개 중 {index + 1}번째 문서를 열었습니다.\n"
                "문서를 외부 프로그램에서 사용한 뒤 확인을 눌러 주세요."
            )
            if index + 1 < len(ids):
                message += "\n\n확인을 누르면 다음 문서를 엽니다."
            else:
                message += "\n\n선택한 문서를 모두 열었습니다."
            self._show_message("info", "문서 열기 진행", message, parent=self.root)
        except Exception as error:
            self._show_message("error", "문서 열기 실패",
                f"{self.vault.index.get(file_id, {}).get('name', file_id)}\n\n{error}",
                parent=self.root)
        finally:
            if temp_dir is not None:
                shutil.rmtree(temp_dir, ignore_errors=True)
        if index + 1 < len(ids):
            self._open_document_sequence(ids, index + 1)

    def _delete_document(self):
        ids = self._selected_ids()
        if not ids:
            return
        names = [self.vault.index[file_id]["name"] for file_id in ids]
        if not self._ask_yes_no("문서 삭제", f"선택한 문서 {len(ids)}개를 삭제할까요?\n\n"
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
        if len(ids) > 1:
            self._show_message("warning", "이름 변경",
                "이름 변경은 한 번에 한 문서만 가능합니다.\n문서 하나만 선택한 뒤 다시 시도하세요.",
                parent=self.root)
            return
        file_id = ids[0]
        old = self.vault.index[file_id]["name"]
        new = self._ask_string("이름 변경", "새 파일명을 입력하세요.",
                                     initialvalue=old, parent=self.root)
        if not new:
            return
        if Path(new).name != new:
            self._show_message("error", "이름 확인", "파일명만 입력할 수 있습니다.", parent=self.root)
            return
        ext = self.vault.index[file_id]["extension"]
        if Path(new).suffix.lower() != ext:
            new = Path(new).stem + ext
        if any(key != file_id and value["name"].casefold() == new.casefold()
               for key, value in self.vault.index.items()):
            self._show_message("error", "이름 중복", "같은 이름의 문서가 이미 있습니다.", parent=self.root)
            return
        self.vault.index[file_id]["name"] = new
        self.vault.save_index()
        self.vault.log_event("document_renamed")
        self._refresh_documents()

    def _security_menu(self):
        self._tool_dialog("보안 관리", [
            ("비밀번호 변경", self._change_password),
            ("마스터 키 재발급", self._rotate_key),
            ("복구 키 발급", self._issue_recovery),
            ("보안 기록", self._show_log),
        ])

    def _change_password(self):
        old = self._ask_string("비밀번호 변경", "현재 비밀번호:", show="●", parent=self.root)
        if old is None:
            return
        new = self._ask_string("비밀번호 변경", "새 비밀번호 (8자 이상):", show="●", parent=self.root)
        if new is None:
            return
        if len(new) < 8:
            self._show_message("error", "비밀번호 확인", "비밀번호는 8자 이상이어야 합니다.", parent=self.root)
            return
        confirm = self._ask_string("비밀번호 변경", "새 비밀번호 확인:", show="●", parent=self.root)
        if confirm != new:
            self._show_message("error", "비밀번호 확인", "비밀번호가 일치하지 않습니다.", parent=self.root)
            return
        output = self._capture(lambda: self.vault.change_password(old, new))[1]
        if "실패" in output:
            self._show_message("error", "변경 실패", output, parent=self.root)
        else:
            self._show_message("info", "완료", "비밀번호를 변경했습니다.", parent=self.root)

    def _rotate_key(self):
        if not self._ask_yes_no("마스터 키 재발급",
                "마스터 키를 새로 발급하고 모든 문서를 다시 암호화할까요?", parent=self.root):
            return
        password = self._ask_string("재인증", "현재 비밀번호:", show="●", parent=self.root)
        if password is None:
            return
        meta = json.loads(self.vault.meta_file.read_text(encoding="utf-8"))
        recovery = None
        if meta.get("recovery_wrapped_key"):
            recovery = self._ask_string("복구 키 확인",
                "복구 기능을 유지하려면 기존 복구 키를 입력하세요:", show="●", parent=self.root)
            if recovery is None:
                return
        try:
            self.vault.rotate_master_key(password, recovery)
            self._show_message("info", "완료", "마스터 키를 재발급했습니다.", parent=self.root)
        except Exception as error:
            self._show_message("error", "재발급 실패", str(error), parent=self.root)

    def _issue_recovery(self):
        password = self._ask_string("복구 키 발급", "현재 비밀번호를 입력하세요:",
                                          show="●", parent=self.root)
        if password is None:
            return
        try:
            key = self.vault.setup_recovery_key(password)
            self._show_message("info", "복구 키 발급", "아래 키를 안전한 별도 장소에 보관하세요.\n"
                "이 창을 닫으면 다시 표시되지 않습니다.\n\n" + key, parent=self.root)
        except Exception as error:
            self._show_message("error", "발급 실패", str(error), parent=self.root)

    def _show_log(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.vault.show_security_log()
        self._text_window("보안 기록", output.getvalue())

    def _backup_menu(self):
        self._tool_dialog("백업 및 복구", [
            ("금고 백업 만들기", self._create_backup),
            ("이 금고에 백업 불러오기", self._merge_backup),
        ])

    def _create_backup(self):
        destination = filedialog.asksaveasfilename(
            title="금고 백업 저장", defaultextension=".zip", confirmoverwrite=True,
            filetypes=[("DigitalVault 백업", "*.zip"), ("모든 파일", "*.*")],
            parent=self.root)
        if not destination:
            return
        target = Path(destination)
        # asksaveasfilename의 기본 덮어쓰기 확인을 사용한다.
        # 확인 후 선택 창이 반환되므로 앱에서 같은 질문을 반복하지 않는다.
        try:
            count = self.vault.create_backup(target, overwrite=True)
            self._show_message("info", "백업 완료", f"백업을 만들었습니다.\n포함 파일: {count}개", parent=self.root)
        except Exception as error:
            self._show_message("error", "백업 실패", str(error), parent=self.root)

    def _merge_backup(self):
        archive = filedialog.askopenfilename(title="불러올 백업 선택",
            filetypes=[("DigitalVault 백업", "*.zip"), ("모든 파일", "*.*")], parent=self.root)
        if not archive:
            return
        password = self._ask_string("백업 인증", "백업 당시 금고 비밀번호:",
                                           show="●", parent=self.root)
        if password is None:
            return
        try:
            count = self.vault.merge_backup(archive, password)
            self._refresh_documents()
            self._show_message("info", "백업 불러오기 완료",
                f"문서 {count}개를 현재 금고에 병합했습니다.\n기존 문서는 유지됩니다.", parent=self.root)
        except Exception as error:
            self._show_message("error", "백업 불러오기 실패", str(error), parent=self.root)

    def _integrity_check(self):
        try:
            result, output = self._capture(self.vault.integrity_check)
            if result:
                summary = "[검사 완료] 모든 문서의 무결성 검사가 정상적으로 완료되었습니다."
            else:
                summary = "[확인 필요] 일부 항목에서 문제가 발견되었습니다."
            report = f"{summary}\n\n{output or '검사 결과가 없습니다.'}"
        except Exception as error:
            report = f"[검사 실패] 무결성 검사를 완료하지 못했습니다.\n\n{error}"

        # 결과 창 하나에 상태와 상세 내역을 함께 표시해 별도 안내창이 중복으로 뜨지 않게 합니다.
        self._text_window("무결성 검사 결과", report)

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
        self._show_message("info", "금고 정보", text, parent=self.root)

    def _text_window(self, title, text):
        window = tk.Toplevel(self.root)
        window.title(title)
        window.configure(bg="#F5F7FB")
        window.transient(self.root)
        window.geometry("800x560")
        window.minsize(620, 400)
        header = tk.Frame(window, bg="#FFFFFF", padx=22, pady=16)
        header.pack(fill="x")
        tk.Label(header, text=title, bg="#FFFFFF", fg="#202938",
                 font=("Malgun Gothic", 15, "bold")).pack(anchor="w")
        frame = tk.Frame(window, bg="#F5F7FB", padx=16, pady=16)
        frame.pack(fill="both", expand=True)
        widget = tk.Text(frame, wrap="word", font=("Consolas", 10),
                         bg="#FFFFFF", fg="#344054", insertbackground="#344054",
                         relief="flat", padx=14, pady=14, spacing1=3)
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
