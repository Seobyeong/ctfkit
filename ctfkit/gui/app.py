"""Tkinter 화면. 항목은 schema 가 만들어 주므로 여기에는 표시와 실행 흐름만 둔다.

화면 구성 (위에서 아래로):
  사이드바 : 명령을 분야별로 묶어 보여 준다 (GUI_HINTS 의 group)
  머리글   : 명령 이름·설명, 하위 명령 탭
  입력 카드: 필수 항목은 항상 보이고, 선택 옵션이 많으면 "옵션 더 보기" 로 접는다
  실행 줄  : 실행 / 중지
  플래그 줄: 결과에서 플래그를 찾으면 따로 크게 보여 주고 한 번에 복사한다
  결과 카드: 실행한 명령줄과 출력
  상태 줄  : 진행 상태와 단축키
"""

import re
import subprocess
import sys
import time
import tkinter as tk
from tkinter import filedialog, font as tkfont, ttk

from ctfkit import __version__
from ctfkit.flags import DEFAULT_FLAG_PATTERN
from ctfkit.gui.runner import ERROR_PREFIXES, Job, classify
from ctfkit.gui.schema import InputProblem, build_argv, build_schema

# 색: 배경은 세 단계(BG < SIDE < CARD), 글자는 두 단계(TEXT, MUTED), 강조색 하나(ACCENT)
BG, SIDE, CARD, FIELD_BG = "#101318", "#161a21", "#1a1f27", "#0d1014"
RAISED, LINE = "#252c37", "#2a313c"
TEXT, MUTED, FAINT, ON_ACCENT = "#e6e9ef", "#929bab", "#5d6675", "#07121e"
ACCENT, ACCENT_HOVER = "#4ea1ff", "#74b6ff"
GREEN, RED, YELLOW, FLAG_BG = "#5fd38d", "#ff6b6b", "#f2c14e", "#12281c"

_POLL_MS = 40
_MAX_OUTPUT_LINES = 20000   # Text 위젯이 느려지지 않도록 화면에 쌓는 줄 수를 제한한다
_SHORT_KINDS = ("number", "combo", "check")   # 한 줄에 나란히 놓는 짧은 항목
_SHORT_PER_ROW = 4
_FOLD_OVER = 3              # 선택 옵션이 이보다 많으면 "옵션 더 보기" 로 접는다
_DEFAULT_FLAG_RE = re.compile(DEFAULT_FLAG_PATTERN, re.IGNORECASE)
_EMPTY_HINT = "실행 결과가 여기에 표시됩니다\nCtrl+Enter 로 실행"


def _pick_font(root, *names: str) -> str:
    available = set(tkfont.families(root))
    return next((n for n in names if n in available), "TkDefaultFont")


def split_fields(fields: list) -> tuple:
    """항목을 (항상 보이는 것, 접어 두는 것) 으로 나눈다.

    접는 대상은 필수가 아닌 옵션이다. 입력 파일(file)은 입력 칸의 대안이라 항상 보인다.
    선택 옵션이 _FOLD_OVER 개 이하면 접지 않는다 (접어서 얻는 것이 없다).
    """
    optional = [f for f in fields if f.option and not f.required and f.dest != "file"]
    if len(optional) <= _FOLD_OVER:
        return list(fields), []
    return [f for f in fields if f not in optional], optional


class App:
    def __init__(self, root: tk.Misc, schema: list | None = None):
        self.root = root
        self.schema = build_schema() if schema is None else schema
        self.job = None
        self.widgets = {}
        self.saved = {}          # (명령, 하위 명령, 항목) -> 입력값. 화면을 옮겨 다녀도 유지한다
        self.expanded = {}       # (명령, 하위 명령) -> 옵션을 펼쳤는가
        self.folded_widgets = []
        self.command = None
        self.action = None
        self.started = 0.0
        self.line_count = 0
        self.dropped = 0
        self.flags = []          # 이번 실행에서 찾은 플래그 (중복 없이, 나온 순서)
        self.flag_re = _DEFAULT_FLAG_RE
        self.on_finish = None
        self.scale = root.winfo_fpixels("1i") / 96
        self.ui_font = _pick_font(root, "Malgun Gothic", "Apple SD Gothic Neo", "Noto Sans CJK KR", "NanumGothic")
        self.mono_font = _pick_font(root, "Consolas", "D2Coding", "Menlo", "DejaVu Sans Mono")

        root.title("ctfkit")
        root.geometry(f"{self._px(1160)}x{self._px(800)}")
        root.minsize(self._px(940), self._px(700))
        root.configure(bg=BG)
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.bind("<Control-Return>", self._run_shortcut)
        root.bind("<Control-l>", lambda e: self.clear())
        root.bind("<Escape>", lambda e: self.stop())
        self._style()
        self._layout()
        self.show_command(self.schema[0].name)
        self._after_id = root.after(_POLL_MS, self._pump)

    def _px(self, n: int) -> int:
        return int(n * self.scale)

    def _style(self) -> None:
        s = ttk.Style(self.root)
        s.theme_use("clam")
        s.configure("TCombobox", fieldbackground=FIELD_BG, background=RAISED, foreground=TEXT, arrowcolor=MUTED,
                    bordercolor=LINE, lightcolor=LINE, darkcolor=LINE, insertcolor=TEXT, padding=4)
        s.map("TCombobox", fieldbackground=[("readonly", FIELD_BG)], foreground=[("readonly", TEXT)],
              selectbackground=[("readonly", FIELD_BG)], selectforeground=[("readonly", TEXT)],
              bordercolor=[("focus", ACCENT)])
        s.configure("Vertical.TScrollbar", background=LINE, troughcolor=FIELD_BG, bordercolor=FIELD_BG,
                    lightcolor=LINE, darkcolor=LINE, arrowcolor=MUTED, gripcount=0, relief="flat")
        s.map("Vertical.TScrollbar", background=[("active", MUTED)])
        self.root.option_add("*TCombobox*Listbox.background", FIELD_BG)
        self.root.option_add("*TCombobox*Listbox.foreground", TEXT)
        self.root.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
        self.root.option_add("*TCombobox*Listbox.font", (self.ui_font, 10))

    # ---------- 화면 뼈대 ----------

    def _layout(self) -> None:
        self._sidebar()
        main = tk.Frame(self.root, bg=BG)
        main.pack(side="left", fill="both", expand=True)
        pad = self._px(24)

        # 상태 줄: 왼쪽은 진행 상태, 오른쪽은 단축키
        foot = tk.Frame(main, bg=SIDE)
        foot.pack(side="bottom", fill="x")
        self.status = tk.Label(foot, text="● 대기 중", bg=SIDE, fg=MUTED, font=(self.ui_font, 9), anchor="w",
                               padx=pad, pady=self._px(6))
        self.status.pack(side="left")
        tk.Label(foot, text="Ctrl+Enter 실행   Esc 중지   Ctrl+L 지우기", bg=SIDE, fg=FAINT,
                 font=(self.ui_font, 9), padx=pad).pack(side="right")

        head = tk.Frame(main, bg=BG)
        head.pack(fill="x", padx=pad, pady=(self._px(20), 0))
        self.title = tk.Label(head, bg=BG, fg=TEXT, font=(self.ui_font, 16, "bold"), anchor="w")
        self.title.pack(fill="x")
        self.desc = tk.Label(head, bg=BG, fg=MUTED, font=(self.ui_font, 9), anchor="w", justify="left")
        self.desc.pack(fill="x", pady=(self._px(2), 0))

        # 하위 명령 탭: 아래쪽 선 위에 놓이고, 고른 탭만 강조색 밑줄이 생긴다
        self.tabs = tk.Frame(main, bg=BG)
        self.tabs.pack(fill="x", padx=pad, pady=(self._px(12), 0))
        self.tab_rule = tk.Frame(main, bg=LINE, height=1)
        self.tab_rule.pack(fill="x", padx=pad)

        card = self._card(main)
        card.pack(fill="x", padx=pad, pady=(self._px(14), 0))
        self.form = tk.Frame(card, bg=CARD)
        self.form.pack(fill="x", padx=self._px(16), pady=self._px(12))
        self.form.columnconfigure(1, weight=1)

        bar = tk.Frame(main, bg=BG)
        bar.pack(fill="x", padx=pad, pady=(self._px(12), 0))
        self.run_btn = self._button(bar, "▶  실행", self.run, primary=True)
        self.stop_btn = self._button(bar, "■  중지", self.stop)
        self.stop_btn.config(state="disabled")

        # 플래그 줄: 플래그를 찾았을 때만 나타난다
        self.flag_bar = tk.Frame(main, bg=FLAG_BG, highlightthickness=1, highlightbackground=GREEN)
        tk.Label(self.flag_bar, text="FLAG", bg=GREEN, fg=ON_ACCENT, font=(self.ui_font, 8, "bold"),
                 padx=self._px(8), pady=self._px(2)).pack(side="left", padx=self._px(10), pady=self._px(8))
        self.flag_var = tk.StringVar()
        tk.Entry(self.flag_bar, textvariable=self.flag_var, state="readonly", readonlybackground=FLAG_BG,
                 fg=GREEN, bd=0, highlightthickness=0, font=(self.mono_font, 11, "bold")).pack(
            side="left", fill="x", expand=True)
        self.flag_more = tk.Label(self.flag_bar, bg=FLAG_BG, fg=MUTED, font=(self.ui_font, 9))
        self.flag_more.pack(side="left", padx=(0, self._px(8)))
        self._link(self.flag_bar, "복사", self.copy_flag, bg=FLAG_BG, fg=GREEN).pack(
            side="right", padx=self._px(12))

        # 결과 카드: 머리글(실행한 명령줄 + 복사·지우기) 아래에 출력
        self.out_card = self._card(main)
        self.out_card.pack(fill="both", expand=True, padx=pad, pady=(self._px(12), self._px(16)))
        out_head = tk.Frame(self.out_card, bg=CARD)
        out_head.pack(fill="x", padx=self._px(14), pady=(self._px(8), self._px(6)))
        tk.Label(out_head, text="결과", bg=CARD, fg=TEXT, font=(self.ui_font, 10, "bold")).pack(side="left")
        self._link(out_head, "지우기", self.clear).pack(side="right")
        self._link(out_head, "결과 복사", self.copy).pack(side="right", padx=(0, self._px(14)))
        self._link(out_head, "명령 복사", self.copy_command).pack(side="right", padx=(0, self._px(14)))
        # 긴 경로도 끝까지 스크롤하고 복사할 수 있도록 Label 대신 읽기 전용 Entry 를 쓴다
        self.cmd_var = tk.StringVar()
        tk.Entry(out_head, textvariable=self.cmd_var, state="readonly", readonlybackground=CARD, fg=MUTED, bd=0,
                 highlightthickness=0, font=(self.mono_font, 9)).pack(
            side="left", fill="x", expand=True, padx=self._px(14))

        tk.Frame(self.out_card, bg=LINE, height=1).pack(fill="x")
        wrap = tk.Frame(self.out_card, bg=FIELD_BG)
        wrap.pack(fill="both", expand=True)
        scrollbar = ttk.Scrollbar(wrap, orient="vertical")
        self.out = tk.Text(wrap, bg=FIELD_BG, fg=TEXT, font=(self.mono_font, 10), bd=0, wrap="word",
                           state="disabled", padx=self._px(14), pady=self._px(10), spacing1=2, height=4,
                           highlightthickness=0, selectbackground=RAISED,
                           yscrollcommand=lambda a, b: self._autohide(scrollbar, a, b))
        self.out.pack(side="left", fill="both", expand=True)
        self.out.bind("<Button-1>", lambda e: self.out.focus_set())   # 비활성 상태에서도 선택·복사 가능하게
        scrollbar.config(command=self.out.yview)
        self.out.tag_config("ok", foreground=GREEN)
        self.out.tag_config("bad", foreground=RED)
        self.out.tag_config("warn", foreground=YELLOW)
        self.out.tag_config("flag", background=GREEN, foreground=ON_ACCENT, font=(self.mono_font, 10, "bold"))
        # 출력이 비어 있을 때 가운데에 띄우는 안내. 출력 내용이 아니므로 복사되지 않는다
        self.hint = tk.Label(wrap, text=_EMPTY_HINT, bg=FIELD_BG, fg=FAINT, font=(self.ui_font, 10),
                             justify="center")
        self._show_hint(_EMPTY_HINT)

    def _sidebar(self) -> None:
        side = tk.Frame(self.root, bg=SIDE, width=self._px(196))
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        tk.Frame(self.root, bg=LINE, width=1).pack(side="left", fill="y")
        left = self._px(20)
        tk.Label(side, text="ctfkit", bg=SIDE, fg=TEXT, font=(self.mono_font, 18, "bold"), anchor="w").pack(
            fill="x", padx=left, pady=(self._px(18), 0))
        tk.Label(side, text="CTF 워게임 보조 도구", bg=SIDE, fg=MUTED, font=(self.ui_font, 9), anchor="w").pack(
            fill="x", padx=left, pady=(0, self._px(6)))
        tk.Label(side, text=f"v{__version__}", bg=SIDE, fg=FAINT, font=(self.mono_font, 8), anchor="w").pack(
            side="bottom", fill="x", padx=left, pady=self._px(10))

        self.nav = {}
        group = None
        for command in self.schema:
            if command.group != group:
                group = command.group
                tk.Label(side, text=group, bg=SIDE, fg=FAINT, font=(self.ui_font, 8, "bold"), anchor="w").pack(
                    fill="x", padx=left, pady=(self._px(12), self._px(3)))
            row = tk.Frame(side, bg=SIDE, cursor="hand2")
            row.pack(fill="x")
            marker = tk.Frame(row, bg=SIDE, width=self._px(3))
            marker.pack(side="left", fill="y")
            label = tk.Label(row, text=command.label, bg=SIDE, fg=MUTED, font=(self.ui_font, 10), anchor="w",
                             padx=self._px(17), pady=self._px(5), cursor="hand2")
            label.pack(side="left", fill="x", expand=True)
            for widget in (row, label):
                widget.bind("<Button-1>", lambda e, n=command.name: self.show_command(n))
                widget.bind("<Enter>", lambda e, n=command.name: self._nav_hover(n, True))
                widget.bind("<Leave>", lambda e, n=command.name: self._nav_hover(n, False))
            self.nav[command.name] = (row, marker, label)

    def _nav_paint(self, name: str, hover: bool = False) -> None:
        row, marker, label = self.nav[name]
        active = self.command is not None and self.command.name == name
        bg = CARD if active else (RAISED if hover else SIDE)
        row.config(bg=bg)
        label.config(bg=bg, fg=TEXT if active or hover else MUTED)
        marker.config(bg=ACCENT if active else bg)

    def _nav_hover(self, name: str, entering: bool) -> None:
        self._nav_paint(name, hover=entering)

    def _card(self, parent) -> tk.Frame:
        return tk.Frame(parent, bg=CARD, highlightthickness=1, highlightbackground=LINE)

    @staticmethod
    def _autohide(scrollbar, first, last) -> None:
        if float(first) <= 0 and float(last) >= 1:
            scrollbar.pack_forget()
        else:
            scrollbar.pack(side="right", fill="y")
        scrollbar.set(first, last)

    def _button(self, parent, text, command, primary=False) -> tk.Button:
        normal, hover = (ACCENT, ACCENT_HOVER) if primary else (RAISED, LINE)
        button = tk.Button(parent, text=text, command=command, bg=normal, fg=ON_ACCENT if primary else TEXT,
                           activebackground=hover, activeforeground=ON_ACCENT if primary else TEXT,
                           disabledforeground=FAINT, relief="flat", bd=0,
                           font=(self.ui_font, 10, "bold" if primary else "normal"),
                           padx=self._px(18 if primary else 14), pady=self._px(5), cursor="hand2")
        button.pack(side="left", fill="y", padx=(0, self._px(8)))   # fill=y: 글꼴이 달라도 높이를 맞춘다
        button.bind("<Enter>", lambda e: str(button["state"]) != "disabled" and button.config(bg=hover))
        button.bind("<Leave>", lambda e: str(button["state"]) != "disabled" and button.config(bg=normal))
        return button

    def _link(self, parent, text, command, bg=CARD, fg=MUTED) -> tk.Label:
        """글자만 있는 가벼운 버튼 (복사·지우기 같은 보조 동작용)."""
        link = tk.Label(parent, text=text, bg=bg, fg=fg, font=(self.ui_font, 9), cursor="hand2")
        link.bind("<Button-1>", lambda e: command())
        link.bind("<Enter>", lambda e: link.config(fg=TEXT))
        link.bind("<Leave>", lambda e: link.config(fg=fg))
        return link

    # ---------- 화면 전환 ----------

    def show_command(self, name: str) -> None:
        self._save_values()
        self.command = next(c for c in self.schema if c.name == name)
        self.action = None
        for key in self.nav:
            self._nav_paint(key)
        self.title.config(text=self.command.label)
        self.desc.config(text=self.command.desc)
        for widget in self.tabs.winfo_children():
            widget.destroy()
        self.tab_labels = {}
        has_tabs = len(self.command.actions) > 1
        if has_tabs:
            for action in self.command.actions:
                tab = tk.Frame(self.tabs, bg=BG, cursor="hand2")
                tab.pack(side="left", padx=(0, self._px(18)))
                label = tk.Label(tab, text=action.label, bg=BG, font=(self.ui_font, 10), pady=self._px(6),
                                 cursor="hand2")
                label.pack()
                underline = tk.Frame(tab, bg=BG, height=self._px(2))
                underline.pack(fill="x")
                for widget in (tab, label):
                    widget.bind("<Button-1>", lambda e, n=action.name: self.show_action(n))
                self.tab_labels[action.name] = (label, underline)
        # 탭이 없으면 탭 아래 선도 숨겨 머리글과 입력 카드 사이가 비어 보이지 않게 한다
        self.tab_rule.config(bg=LINE if has_tabs else BG)
        self.tabs.pack_configure(pady=(self._px(12) if has_tabs else 0, 0))
        self.show_action(self.command.actions[0].name)

    def show_action(self, name) -> None:
        self._save_values()
        self.action = next(a for a in self.command.actions if a.name == name)
        for key, (label, underline) in self.tab_labels.items():
            active = key == name
            label.config(fg=TEXT if active else MUTED)
            underline.config(bg=ACCENT if active else BG)
        self._build_form()

    def _visible_fields(self) -> list:
        return [*self.command.shared, *self.action.fields]

    def _build_form(self) -> None:
        for widget in self.form.winfo_children():
            widget.destroy()
        self.widgets = {}
        self.folded_widgets = []
        shown, folded = split_fields(self._visible_fields())

        row = self._place_fields(shown, 0)
        if not shown and not folded:
            tk.Label(self.form, text="입력할 항목이 없습니다. 실행을 누르세요.", bg=CARD, fg=MUTED,
                     font=(self.ui_font, 9)).grid(row=0, column=0, columnspan=2, sticky="w")
        if folded:
            before = set(self.form.winfo_children())
            self.fold_link = self._link(self.form, "", self._toggle_folded, fg=ACCENT)
            self.fold_link.grid(row=row, column=0, columnspan=2, sticky="w", pady=(self._px(6), self._px(2)))
            before.add(self.fold_link)
            self._place_fields(folded, row + 1)
            self.folded_widgets = [w for w in self.form.winfo_children() if w not in before]
            key = (self.command.name, self.action.name)
            # 접힌 항목에 이미 값을 넣어 두었다면 펼쳐서 보여 준다 (숨은 값이 실행에 쓰이면 헷갈린다)
            changed = any(str(self._saved_value(f)) != str(f.default) for f in folded)
            self._set_folded(not (self.expanded.get(key) or changed), len(folded))

    def _place_fields(self, fields: list, row: int) -> int:
        """긴 항목은 한 줄에 하나씩, 짧은 항목은 한 줄에 여러 개 놓는다. 다음에 쓸 줄 번호를 돌려준다."""
        for f in fields:
            if f.kind not in _SHORT_KINDS:
                self._long_field(row, f)
                row += 1
        short = [f for f in fields if f.kind in _SHORT_KINDS]
        for start in range(0, len(short), _SHORT_PER_ROW):
            holder = tk.Frame(self.form, bg=CARD)
            holder.grid(row=row, column=0, columnspan=2, sticky="w", pady=self._px(4))
            for f in short[start:start + _SHORT_PER_ROW]:
                self._short_field(holder, f)
            row += 1
        return row

    def _set_folded(self, folded: bool, count: int) -> None:
        self.expanded[(self.command.name, self.action.name)] = not folded
        self.fold_link.config(text=f"▸  옵션 더 보기 ({count})" if folded else "▾  옵션 접기")
        for widget in self.folded_widgets:
            if folded:
                widget.grid_remove()
            else:
                widget.grid()

    def _toggle_folded(self) -> None:
        key = (self.command.name, self.action.name)
        _, folded = split_fields(self._visible_fields())
        self._set_folded(self.expanded.get(key, False), len(folded))

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

    def _field_label(self, parent, f) -> tk.Label:
        # 필수 항목은 밝은 글자에 * 를 붙여 선택 항목과 구분한다
        return tk.Label(parent, text=f.label + (" *" if f.required else ""), bg=CARD,
                        fg=TEXT if f.required else MUTED, font=(self.ui_font, 9), anchor="nw")

    def _long_field(self, row: int, f) -> None:
        self._field_label(self.form, f).grid(
            row=row, column=0, sticky="nw", pady=(self._px(7), self._px(4)), padx=(0, self._px(16)))
        value = self._saved_value(f)
        if f.kind in ("text", "lines"):
            text = tk.Text(self.form, height=3 if f.kind == "text" else 2, wrap="word", padx=self._px(8),
                           pady=self._px(5), **self._entry_style())
            text.bind("<Tab>", lambda e: (e.widget.tk_focusNext().focus(), "break")[1])
            # Text 의 기본 동작이 먼저 실행되면 입력에 줄바꿈이 끼어든다
            text.bind("<Control-Return>", lambda e: (self.run(), "break")[1])
            text.insert("1.0", str(value))
            text.grid(row=row, column=1, sticky="ew", pady=self._px(4))
            self.widgets[f.dest] = ("text", text)
            return

        var = tk.StringVar(value=str(value))
        holder = tk.Frame(self.form, bg=CARD)
        holder.grid(row=row, column=1, sticky="ew", pady=self._px(4))
        entry = tk.Entry(holder, textvariable=var, **self._entry_style())
        entry.pack(side="left", fill="x", expand=True, ipady=self._px(4))
        entry.xview_moveto(1)
        if f.kind in ("file", "save", "dir"):
            pick = {"file": filedialog.askopenfilename, "save": filedialog.asksaveasfilename,
                    "dir": filedialog.askdirectory}[f.kind]

            def browse():
                chosen = pick()
                if chosen:
                    var.set(chosen)
                    entry.xview_moveto(1)   # 긴 경로는 파일 이름이 보이도록 끝으로 스크롤

            button = tk.Button(holder, text="찾아보기", bg=RAISED, fg=TEXT, activebackground=LINE,
                               activeforeground=TEXT, relief="flat", bd=0, font=(self.ui_font, 9),
                               padx=self._px(12), cursor="hand2", command=browse)
            button.pack(side="left", padx=(self._px(8), 0), fill="y")
            button.bind("<Enter>", lambda e: button.config(bg=LINE))
            button.bind("<Leave>", lambda e: button.config(bg=RAISED))
        self.widgets[f.dest] = ("var", var)

    def _short_field(self, holder, f) -> None:
        value = self._saved_value(f)
        cell = tk.Frame(holder, bg=CARD)
        cell.pack(side="left", padx=(0, self._px(24)))
        if f.kind == "check":
            var = tk.BooleanVar(value=bool(value))
            tk.Checkbutton(cell, text=f.label, variable=var, bg=CARD, fg=MUTED, activebackground=CARD,
                           activeforeground=TEXT, selectcolor=FIELD_BG, bd=0, highlightthickness=0,
                           font=(self.ui_font, 9)).pack(side="left")
            self.widgets[f.dest] = ("var", var)
            return

        self._field_label(cell, f).pack(side="left", padx=(0, self._px(8)))
        var = tk.StringVar(value=str(value))
        if f.kind == "combo":
            ttk.Combobox(cell, textvariable=var, values=f.choices or [], width=12, font=(self.ui_font, 10),
                         state="normal" if f.editable else "readonly").pack(side="left")
        else:
            tk.Entry(cell, textvariable=var, width=7, **self._entry_style()).pack(side="left", ipady=self._px(4))
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
        self._reset_output()
        shown = ["ctfkit", *argv]
        self.cmd_var.set("$ " + subprocess.list2cmdline(shown) + ("   < 입력" if stdin else ""))
        try:
            self.job = Job(argv, stdin)
        except (OSError, ValueError) as e:
            self._set_status(f"✖ 실행 실패: {e}", RED)
            return
        self.started = time.time()
        self.line_count = self.dropped = 0
        self.run_btn.config(state="disabled", bg=RAISED, text="실행 중…")
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
        if self.line_count == 0:
            self.hint.place_forget()
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
            self._found_flag(match.group(0))
        self.out.insert("end", line[pos:] + "\n", tag)
        self.out.config(state="disabled")
        self.out.see("end")

    def _found_flag(self, flag: str) -> None:
        if flag in self.flags:
            return
        self.flags.append(flag)
        self.flag_var.set(self.flags[0])
        self.flag_more.config(text=f"외 {len(self.flags) - 1}개" if len(self.flags) > 1 else "")
        if not self.flag_bar.winfo_manager():
            self.flag_bar.pack(fill="x", padx=self._px(24), pady=(self._px(12), 0), before=self.out_card)

    def _finish(self) -> None:
        job, self.job = self.job, None
        took = time.time() - self.started
        self.run_btn.config(state="normal", bg=ACCENT, text="▶  실행")
        self.stop_btn.config(state="disabled")
        if self.dropped:
            self.out.config(state="normal")
            self.out.insert("end", f"[!] 출력이 많아 {self.dropped}줄을 생략했습니다. "
                                   f"전체 결과는 CLI에서 파일로 저장하세요.\n", "warn")
            self.out.config(state="disabled")
            self.out.see("end")
        if self.line_count == 0:
            self._show_hint("출력이 없습니다")
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

    # ---------- 결과 영역 ----------

    def _show_hint(self, text: str) -> None:
        self.hint.config(text=text)
        self.hint.place(relx=0.5, rely=0.45, anchor="center")

    def _reset_output(self) -> None:
        """출력과 플래그 줄을 비운다. 안내 문구는 띄우지 않는다 (곧 출력이 채워진다)."""
        self.out.config(state="normal")
        self.out.delete("1.0", "end")
        self.out.config(state="disabled")
        self.hint.place_forget()
        self.flags = []
        self.flag_var.set("")
        self.flag_bar.pack_forget()

    def clear(self) -> None:
        if self.job:
            return   # 실행 중에 지우면 줄 수 집계와 화면이 어긋난다
        self._reset_output()
        self.cmd_var.set("")
        self.line_count = 0
        self._show_hint(_EMPTY_HINT)

    def _copy(self, text: str, what: str) -> None:
        if not text:
            self._set_status(f"● 복사할 내용이 없습니다 ({what})", MUTED)
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self._set_status(f"✔ 복사했습니다 ({what})", GREEN)

    def copy(self) -> None:
        self._copy(self.out.get("1.0", "end-1c"), "결과")

    def copy_command(self) -> None:
        # "$ ctfkit auto   < 입력" 에서 붙여 넣어 실행할 수 있는 부분만
        self._copy(self.cmd_var.get().removeprefix("$ ").split("   < ")[0], "명령")

    def copy_flag(self) -> None:
        self._copy("\n".join(self.flags), "플래그")

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
