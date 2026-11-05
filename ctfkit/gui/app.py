"""Tkinter 화면. 항목은 schema 가 만들어 주므로 여기에는 표시와 실행 흐름만 둔다."""

import re
import subprocess
import sys
import time
import tkinter as tk
from tkinter import filedialog, font as tkfont, ttk

from ctfkit.flags import DEFAULT_FLAG_PATTERN
from ctfkit.gui.runner import ERROR_PREFIXES, Job, classify
from ctfkit.gui.schema import InputProblem, build_argv, build_schema

BG, SIDE, CARD, FIELD_BG = "#14171c", "#1b1f26", "#1f242c", "#12151a"
LINE, TEXT, MUTED, ON_ACCENT = "#2d333d", "#e7eaf0", "#8f98a8", "#08131f"
ACCENT, GREEN, RED, YELLOW = "#4ea1ff", "#5fd38d", "#ff6b6b", "#f2c14e"

_POLL_MS = 40
_MAX_OUTPUT_LINES = 20000   # Text 위젯이 느려지지 않도록 화면에 쌓는 줄 수를 제한한다
_SHORT_KINDS = ("number", "combo", "check")   # 한 줄에 나란히 놓는 짧은 항목
_SHORT_PER_ROW = 4
_DEFAULT_FLAG_RE = re.compile(DEFAULT_FLAG_PATTERN, re.IGNORECASE)


def _pick_font(root, *names: str) -> str:
    available = set(tkfont.families(root))
    return next((n for n in names if n in available), "TkDefaultFont")


class App:
    def __init__(self, root: tk.Misc, schema: list | None = None):
        self.root = root
        self.schema = build_schema() if schema is None else schema
        self.job = None
        self.widgets = {}
        self.saved = {}          # (명령, 하위 명령, 항목) -> 입력값. 화면을 옮겨 다녀도 유지한다
        self.command = None
        self.action = None
        self.started = 0.0
        self.line_count = 0
        self.dropped = 0
        self.flag_re = _DEFAULT_FLAG_RE
        self.on_finish = None
        self.scale = root.winfo_fpixels("1i") / 96
        self.ui_font = _pick_font(root, "Malgun Gothic", "Apple SD Gothic Neo", "Noto Sans CJK KR", "NanumGothic")
        self.mono_font = _pick_font(root, "Consolas", "D2Coding", "Menlo", "DejaVu Sans Mono")

        root.title("ctfkit")
        root.geometry(f"{self._px(1120)}x{self._px(780)}")
        root.minsize(self._px(900), self._px(640))
        root.configure(bg=BG)
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.bind("<Control-Return>", self._run_shortcut)
        self._style()
        self._layout()
        self.show_command(self.schema[0].name)
        self._after_id = root.after(_POLL_MS, self._pump)

    def _px(self, n: int) -> int:
        return int(n * self.scale)

    def _style(self) -> None:
        s = ttk.Style(self.root)
        s.theme_use("clam")
        s.configure("TCombobox", fieldbackground=FIELD_BG, background=CARD, foreground=TEXT, arrowcolor=MUTED,
                    bordercolor=LINE, lightcolor=LINE, darkcolor=LINE, insertcolor=TEXT, padding=4)
        s.map("TCombobox", fieldbackground=[("readonly", FIELD_BG)], foreground=[("readonly", TEXT)],
              selectbackground=[("readonly", FIELD_BG)], selectforeground=[("readonly", TEXT)])
        s.configure("Vertical.TScrollbar", background=LINE, troughcolor=FIELD_BG, bordercolor=FIELD_BG,
                    lightcolor=LINE, darkcolor=LINE, arrowcolor=MUTED, gripcount=0, relief="flat")
        s.map("Vertical.TScrollbar", background=[("active", MUTED)])
        self.root.option_add("*TCombobox*Listbox.background", FIELD_BG)
        self.root.option_add("*TCombobox*Listbox.foreground", TEXT)
        self.root.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
        self.root.option_add("*TCombobox*Listbox.font", (self.ui_font, 10))

    def _layout(self) -> None:
        pad = self._px(20)
        side = tk.Frame(self.root, bg=SIDE, width=self._px(180))
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        tk.Label(side, text="ctfkit", bg=SIDE, fg=TEXT, font=(self.mono_font, 19, "bold"), anchor="w").pack(
            fill="x", padx=self._px(18), pady=(self._px(18), 0))
        tk.Label(side, text="CTF 워게임 보조 도구", bg=SIDE, fg=MUTED, font=(self.ui_font, 9), anchor="w").pack(
            fill="x", padx=self._px(18), pady=(0, self._px(16)))
        self.nav = {}
        for command in self.schema:
            label = tk.Label(side, text=command.label, bg=SIDE, fg=MUTED, font=(self.ui_font, 10), anchor="w",
                             padx=self._px(18), pady=self._px(8), cursor="hand2")
            label.pack(fill="x")
            label.bind("<Button-1>", lambda e, n=command.name: self.show_command(n))
            self.nav[command.name] = label

        main = tk.Frame(self.root, bg=BG)
        main.pack(side="left", fill="both", expand=True)

        self.status = tk.Label(main, text="● 대기 중", bg=SIDE, fg=MUTED, font=(self.ui_font, 9), anchor="w",
                               padx=pad, pady=self._px(5))
        self.status.pack(side="bottom", fill="x")

        head = tk.Frame(main, bg=BG)
        head.pack(fill="x", padx=pad, pady=(self._px(16), 0))
        self.title = tk.Label(head, bg=BG, fg=TEXT, font=(self.ui_font, 15, "bold"), anchor="w")
        self.title.pack(fill="x")
        self.desc = tk.Label(head, bg=BG, fg=MUTED, font=(self.ui_font, 9), anchor="w")
        self.desc.pack(fill="x")

        self.tabs = tk.Frame(main, bg=BG)
        self.tabs.pack(fill="x", padx=pad, pady=(self._px(10), 0))
        self.form = tk.Frame(main, bg=BG)
        self.form.pack(fill="x", padx=pad, pady=(self._px(10), 0))
        self.form.columnconfigure(1, weight=1)

        bar = tk.Frame(main, bg=BG)
        bar.pack(fill="x", padx=pad, pady=self._px(10))
        self.run_btn = self._button(bar, "▶ 실행  (Ctrl+Enter)", self.run, ACCENT, ON_ACCENT)
        self.stop_btn = self._button(bar, "■ 중지", self.stop)
        self.stop_btn.config(state="disabled")
        self._button(bar, "지우기", self.clear)
        self._button(bar, "결과 복사", self.copy)

        # 긴 경로도 끝까지 스크롤하고 복사할 수 있도록 Label 대신 읽기 전용 Entry 를 쓴다
        self.cmd_var = tk.StringVar()
        tk.Entry(main, textvariable=self.cmd_var, state="readonly", readonlybackground=BG, fg=MUTED, bd=0,
                 highlightthickness=0, font=(self.mono_font, 9)).pack(fill="x", padx=pad)

        wrap = tk.Frame(main, bg=FIELD_BG, highlightthickness=1, highlightbackground=LINE)
        wrap.pack(fill="both", expand=True, padx=pad, pady=(self._px(5), self._px(12)))
        scrollbar = ttk.Scrollbar(wrap, orient="vertical")
        self.out = tk.Text(wrap, bg=FIELD_BG, fg=TEXT, font=(self.mono_font, 10), bd=0, wrap="word",
                           state="disabled", padx=self._px(10), pady=self._px(8), spacing1=2, height=4,
                           yscrollcommand=lambda a, b: self._autohide(scrollbar, a, b))
        self.out.pack(side="left", fill="both", expand=True)
        self.out.bind("<Button-1>", lambda e: self.out.focus_set())   # 비활성 상태에서도 선택·복사 가능하게
        scrollbar.config(command=self.out.yview)
        self.out.tag_config("ok", foreground=GREEN)
        self.out.tag_config("bad", foreground=RED)
        self.out.tag_config("warn", foreground=YELLOW)
        self.out.tag_config("flag", background=GREEN, foreground=ON_ACCENT, font=(self.mono_font, 10, "bold"))

    @staticmethod
    def _autohide(scrollbar, first, last) -> None:
        if float(first) <= 0 and float(last) >= 1:
            scrollbar.pack_forget()
        else:
            scrollbar.pack(side="right", fill="y")
        scrollbar.set(first, last)

    def _button(self, parent, text, command, bg=CARD, fg=TEXT) -> tk.Button:
        button = tk.Button(parent, text=text, command=command, bg=bg, fg=fg, activebackground=LINE,
                           activeforeground=TEXT, disabledforeground=MUTED, relief="flat", bd=0,
                           font=(self.ui_font, 9), padx=self._px(12), pady=self._px(4), cursor="hand2")
        button.pack(side="left", padx=(0, self._px(6)))
        return button

    # ---------- 화면 전환 ----------

    def show_command(self, name: str) -> None:
        self._save_values()
        self.command = next(c for c in self.schema if c.name == name)
        self.action = None
        for key, label in self.nav.items():
            active = key == name
            label.config(bg=CARD if active else SIDE, fg=TEXT if active else MUTED)
        self.title.config(text=self.command.label)
        self.desc.config(text=self.command.desc)
        for widget in self.tabs.winfo_children():
            widget.destroy()
        self.tab_labels = {}
        if len(self.command.actions) > 1:
            for action in self.command.actions:
                tab = tk.Label(self.tabs, text=action.label, font=(self.ui_font, 9), padx=self._px(11),
                               pady=self._px(4), cursor="hand2")
                tab.pack(side="left", padx=(0, self._px(4)))
                tab.bind("<Button-1>", lambda e, n=action.name: self.show_action(n))
                self.tab_labels[action.name] = tab
        self.show_action(self.command.actions[0].name)

    def show_action(self, name) -> None:
        self._save_values()
        self.action = next(a for a in self.command.actions if a.name == name)
        for key, tab in self.tab_labels.items():
            active = key == name
            tab.config(bg=ACCENT if active else CARD, fg=ON_ACCENT if active else MUTED)
        self._build_form()

    def _visible_fields(self) -> list:
        return [*self.command.shared, *self.action.fields]

    def _build_form(self) -> None:
        for widget in self.form.winfo_children():
            widget.destroy()
        self.widgets = {}
        fields = self._visible_fields()
        row = 0
        for f in fields:
            if f.kind not in _SHORT_KINDS:
                self._long_field(row, f)
                row += 1
        short = [f for f in fields if f.kind in _SHORT_KINDS]
        for start in range(0, len(short), _SHORT_PER_ROW):
            holder = tk.Frame(self.form, bg=BG)
            holder.grid(row=row, column=0, columnspan=2, sticky="w", pady=self._px(3))
            for f in short[start:start + _SHORT_PER_ROW]:
                self._short_field(holder, f)
            row += 1

    def _saved_value(self, f):
        return self.saved.get((self.command.name, self.action.name, f.dest), f.default)

    def _save_values(self) -> None:
        if self.command is None or self.action is None:
            return
        for dest, value in self.values().items():
            self.saved[(self.command.name, self.action.name, dest)] = value

    def _entry_style(self) -> dict:
        return dict(bg=FIELD_BG, fg=TEXT, insertbackground=TEXT, relief="flat", font=(self.mono_font, 10),
                    highlightthickness=1, highlightbackground=LINE, highlightcolor=ACCENT)

    def _long_field(self, row: int, f) -> None:
        tk.Label(self.form, text=f.label, bg=BG, fg=MUTED, font=(self.ui_font, 9), anchor="nw").grid(
            row=row, column=0, sticky="nw", pady=self._px(3), padx=(0, self._px(12)))
        value = self._saved_value(f)
        if f.kind in ("text", "lines"):
            text = tk.Text(self.form, height=3 if f.kind == "text" else 2, wrap="word", padx=self._px(6),
                           pady=self._px(4), **self._entry_style())
            text.bind("<Tab>", lambda e: (e.widget.tk_focusNext().focus(), "break")[1])
            # Text 의 기본 동작이 먼저 실행되면 입력에 줄바꿈이 끼어든다
            text.bind("<Control-Return>", lambda e: (self.run(), "break")[1])
            text.insert("1.0", str(value))
            text.grid(row=row, column=1, sticky="ew", pady=self._px(3))
            self.widgets[f.dest] = ("text", text)
            return

        var = tk.StringVar(value=str(value))
        holder = tk.Frame(self.form, bg=BG)
        holder.grid(row=row, column=1, sticky="ew", pady=self._px(3))
        entry = tk.Entry(holder, textvariable=var, **self._entry_style())
        entry.pack(side="left", fill="x", expand=True, ipady=self._px(3))
        entry.xview_moveto(1)
        if f.kind in ("file", "save", "dir"):
            pick = {"file": filedialog.askopenfilename, "save": filedialog.asksaveasfilename,
                    "dir": filedialog.askdirectory}[f.kind]

            def browse():
                chosen = pick()
                if chosen:
                    var.set(chosen)
                    entry.xview_moveto(1)   # 긴 경로는 파일 이름이 보이도록 끝으로 스크롤

            tk.Button(holder, text="찾아보기", bg=CARD, fg=TEXT, relief="flat", bd=0, font=(self.ui_font, 9),
                      padx=self._px(10), cursor="hand2", command=browse).pack(
                side="left", padx=(self._px(6), 0), fill="y")
        self.widgets[f.dest] = ("var", var)

    def _short_field(self, holder, f) -> None:
        value = self._saved_value(f)
        cell = tk.Frame(holder, bg=BG)
        cell.pack(side="left", padx=(0, self._px(22)))
        if f.kind == "check":
            var = tk.BooleanVar(value=bool(value))
            tk.Checkbutton(cell, text=f.label, variable=var, bg=BG, fg=MUTED, activebackground=BG,
                           activeforeground=TEXT, selectcolor=FIELD_BG, bd=0, highlightthickness=0,
                           font=(self.ui_font, 9)).pack(side="left")
            self.widgets[f.dest] = ("var", var)
            return

        tk.Label(cell, text=f.label, bg=BG, fg=MUTED, font=(self.ui_font, 9)).pack(
            side="left", padx=(0, self._px(8)))
        var = tk.StringVar(value=str(value))
        if f.kind == "combo":
            ttk.Combobox(cell, textvariable=var, values=f.choices or [], width=12, font=(self.ui_font, 10),
                         state="normal" if f.editable else "readonly").pack(side="left")
        else:
            tk.Entry(cell, textvariable=var, width=7, **self._entry_style()).pack(side="left", ipady=self._px(3))
        self.widgets[f.dest] = ("var", var)

    def values(self) -> dict:
        return {dest: w.get("1.0", "end-1c") if kind == "text" else w.get()
                for dest, (kind, w) in self.widgets.items()}

    def set_values(self, values: dict) -> None:
        for dest, value in values.items():
            kind, widget = self.widgets[dest]
            if kind == "text":
                widget.delete("1.0", "end")
                widget.insert("1.0", value)
            else:
                widget.set(value)

    # ---------- 실행 ----------

    def _run_shortcut(self, _event) -> None:
        self.run()

    def run(self) -> None:
        if self.job:
            return
        values = self.values()
        try:
            argv, stdin = build_argv(self.command, self.action, values)
        except InputProblem as e:
            self._set_status(f"✖ {e}", YELLOW)
            return
        self.flag_re = self._flag_pattern(values.get("flag"))
        self.clear()
        shown = ["ctfkit", *argv]
        self.cmd_var.set("$ " + subprocess.list2cmdline(shown) + ("   < 입력" if stdin else ""))
        try:
            self.job = Job(argv, stdin)
        except (OSError, ValueError) as e:
            self._set_status(f"✖ 실행 실패: {e}", RED)
            return
        self.started = time.time()
        self.line_count = self.dropped = 0
        self.run_btn.config(state="disabled")
        self.stop_btn.config(state="normal")

    @staticmethod
    def _flag_pattern(custom: str | None):
        if custom:
            try:
                return re.compile(custom)
            except re.error:
                pass   # 잘못된 정규식은 ctfkit 이 오류로 알려 준다
        return _DEFAULT_FLAG_RE

    def _pump(self) -> None:
        if self.job:
            for line in self.job.poll():
                self._write(line)
            if self.job.done:
                self._finish()
            else:
                self._set_status(f"● 실행 중  {time.time() - self.started:.1f}초", ACCENT)
        self._after_id = self.root.after(_POLL_MS, self._pump)

    @staticmethod
    def _line_tag(line: str) -> str:
        if line.startswith(ERROR_PREFIXES) or line.startswith("[-]"):
            return "bad"
        if line.startswith("[+]"):
            return "ok"
        if line.startswith("[!]"):
            return "warn"
        return ""

    def _write(self, line: str) -> None:
        if self.line_count >= _MAX_OUTPUT_LINES:
            self.dropped += 1
            return
        self.line_count += 1
        tag = self._line_tag(line)
        self.out.config(state="normal")
        pos = 0
        for match in self.flag_re.finditer(line):
            if match.end() == match.start():
                continue
            self.out.insert("end", line[pos:match.start()], tag)
            self.out.insert("end", match.group(0), "flag")
            pos = match.end()
        self.out.insert("end", line[pos:] + "\n", tag)
        self.out.config(state="disabled")
        self.out.see("end")

    def _finish(self) -> None:
        job, self.job = self.job, None
        took = time.time() - self.started
        self.run_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        if self.dropped:
            self.out.config(state="normal")
            self.out.insert("end", f"[!] 출력이 많아 {self.dropped}줄을 생략했습니다. "
                                   f"전체 결과는 CLI에서 파일로 저장하세요.\n", "warn")
            self.out.config(state="disabled")
            self.out.see("end")
        state = classify(job.exit_code, job.saw_error_line, job.stopped)
        text, color = {
            "ok": (f"✔ 완료  {took:.2f}초", GREEN),
            "no_result": (f"● 완료 (종료 코드 1: 결과 없음 또는 실패 응답)  {took:.2f}초", YELLOW),
            "error": (f"✖ 오류  {took:.2f}초", RED),
            "stopped": (f"■ 중지됨  {took:.1f}초", YELLOW),
        }[state]
        self._set_status(text, color)
        if self.on_finish:
            callback, self.on_finish = self.on_finish, None
            callback()

    def _set_status(self, text: str, color: str) -> None:
        self.status.config(text=text, fg=color)

    def stop(self) -> None:
        if self.job:
            self.job.stop()

    def clear(self) -> None:
        self.out.config(state="normal")
        self.out.delete("1.0", "end")
        self.out.config(state="disabled")

    def copy(self) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(self.out.get("1.0", "end-1c"))
        self._set_status("✔ 결과를 복사했습니다", GREEN)

    def close(self) -> None:
        self.stop()
        self.root.after_cancel(self._after_id)
        self.root.destroy()


def launch() -> int:
    if sys.platform == "win32":
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)   # 고해상도 화면에서 글자가 흐려지지 않게
        except (AttributeError, OSError):
            pass
    root = tk.Tk()
    App(root)
    root.mainloop()
    return 0
