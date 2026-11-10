"""Tkinter 화면. 항목은 schema 가 만들어 주므로 여기에는 표시와 실행 흐름만 둔다.

화면 구성 (위에서 아래로):
  사이드바 : 명령을 분야별로 묶어 보여 준다 (GUI_HINTS 의 group)
  머리글   : 명령 이름·설명, 하위 명령 탭
  입력 카드: 필수 항목은 항상 보이고, 선택 옵션이 많으면 "옵션 더 보기" 로 접는다
  실행 줄  : 실행 / 중지(실행 중에만) / 입력 문제 안내 / 예시 채우기
  플래그 줄: 결과에서 플래그를 찾으면 따로 크게 보여 주고 한 번에 복사한다
  결과 카드: 실행한 명령줄과 출력. 결과를 다른 도구의 입력으로 보낼 수 있다
  상태 줄  : 진행 상태와 단축키

결과는 화면(명령 + 하위 명령)마다 따로 보관한다. 다른 화면으로 옮기면 그 화면의 마지막 결과가 보이고,
돌아오면 원래 결과가 그대로 있다. 한 화면의 플래그가 다른 화면에 남아 헷갈리는 일이 없다.
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
_TIP_DELAY_MS = 450
_DEFAULT_FLAG_RE = re.compile(DEFAULT_FLAG_PATTERN, re.IGNORECASE)
_EMPTY_HINT = "실행 결과가 여기에 표시됩니다\nCtrl+Enter 로 실행"
_EMPTY_HINT_EXAMPLE = "‘예시 채우기’ 를 누르면 바로 실행해 볼 수 있습니다\nCtrl+Enter 로 실행"
_IDLE = "● 대기 중"


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


class Output:
    """화면 하나(명령 + 하위 명령)의 마지막 실행 결과."""

    def __init__(self):
        self.reset()

    def reset(self) -> None:
        self.command_line = ""   # "$ ctfkit ..." 로 보여 줄 명령줄
        self.segments = []       # [(글자, 태그)] 화면에 넣은 순서 그대로
        self.flags = []          # 찾은 플래그 (중복 없이, 나온 순서)
        self.lines = 0
        self.dropped = 0         # 줄 수 상한을 넘어 버린 줄 수
        self.status = None       # 끝난 뒤의 (상태 글자, 색). 아직 실행한 적 없으면 None

    def text(self) -> str:
        return "".join(text for text, _ in self.segments)


class Tooltip:
    """위젯에 마우스를 잠시 올리면 뜨는 작은 설명."""

    def __init__(self, widget, text: str, font):
        self.widget, self.text, self.font = widget, text, font
        self.tip = None
        self.after_id = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self.hide, add="+")
        widget.bind("<ButtonPress>", self.hide, add="+")
        widget.bind("<Destroy>", self.hide, add="+")

    def _schedule(self, _event=None) -> None:
        self.hide()
        self.after_id = self.widget.after(_TIP_DELAY_MS, self.show)

    def show(self) -> None:
        self.after_id = None
        if self.tip or not self.widget.winfo_exists():
            return
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_attributes("-topmost", True)   # 창 뒤로 숨지 않게
        x = self.widget.winfo_rootx()
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self.tip.wm_geometry(f"+{x}+{y}")
        tk.Label(self.tip, text=self.text, bg=RAISED, fg=TEXT, font=self.font, justify="left", wraplength=420,
                 padx=10, pady=6, highlightthickness=1, highlightbackground=LINE).pack()

    def hide(self, _event=None) -> None:
        if self.after_id:
            try:
                self.widget.after_cancel(self.after_id)
            except tk.TclError:
                pass
            self.after_id = None
        if self.tip:
            try:
                self.tip.destroy()
            except tk.TclError:
                pass
            self.tip = None


class App:
    def __init__(self, root: tk.Misc, schema: list | None = None):
        self.root = root
        self.schema = build_schema() if schema is None else schema
        self.job = None
        self.job_output = None   # 실행 중인 작업의 결과가 쌓이는 곳 (화면을 옮겨도 그 화면의 것으로 남는다)
        self.job_label = ""
        self.widgets = {}        # 항목 이름 -> ("text" | "var", 값을 읽을 대상)
        self.inputs = {}         # 항목 이름 -> 실제 입력 위젯 (문제가 있는 칸을 강조하고 커서를 옮길 때 쓴다)
        self.saved = {}          # (명령, 하위 명령, 항목) -> 입력값. 화면을 옮겨 다녀도 유지한다
        self.expanded = {}       # (명령, 하위 명령) -> 옵션을 펼쳤는가
        self.outputs = {}        # (명령, 하위 명령) -> Output
        self.folded_widgets = []
        self.tips = []
        self.marked = None       # 입력 문제로 강조해 둔 위젯
        self.command = None
        self.action = None
        self.started = 0.0
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

    # 지금 보고 있는 화면의 결과. 테스트와 복사 기능이 이 이름들을 쓴다
    @property
    def output(self) -> Output:
        key = (self.command.name, self.action.name if self.action else None)
        return self.outputs.setdefault(key, Output())

    @property
    def flags(self) -> list:
        return self.output.flags

    @property
    def line_count(self) -> int:
        return self.output.lines

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
        self.status = tk.Label(foot, text=_IDLE, bg=SIDE, fg=MUTED, font=(self.ui_font, 9), anchor="w",
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

        # 실행 줄: 실행 · (실행 중에만) 중지 · 입력 문제 안내 ··· 예시 채우기
        bar = tk.Frame(main, bg=BG)
        bar.pack(fill="x", padx=pad, pady=(self._px(12), 0))
        self.run_btn = self._button(bar, "▶  실행", self.run, primary=True)
        self.stop_btn = self._button(bar, "■  중지", self.stop)
        self.stop_btn.pack_forget()
        self.example_link = self._link(bar, "예시 채우기", self.fill_example, bg=BG, fg=ACCENT)
        self.problem = tk.Label(bar, bg=BG, fg=YELLOW, font=(self.ui_font, 9), anchor="w")
        self.problem.pack(side="left", padx=(self._px(4), 0))

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

        # 결과 카드: 머리글(실행한 명령줄 + 보내기·복사·지우기) 아래에 출력
        self.out_card = self._card(main)
        self.out_card.pack(fill="both", expand=True, padx=pad, pady=(self._px(12), self._px(16)))
        out_head = tk.Frame(self.out_card, bg=CARD)
        out_head.pack(fill="x", padx=self._px(14), pady=(self._px(8), self._px(6)))
        tk.Label(out_head, text="결과", bg=CARD, fg=TEXT, font=(self.ui_font, 10, "bold")).pack(side="left")
        self._link(out_head, "지우기", self.clear).pack(side="right")
        self._link(out_head, "결과 복사", self.copy).pack(side="right", padx=(0, self._px(14)))
        self._link(out_head, "명령 복사", self.copy_command).pack(side="right", padx=(0, self._px(14)))
        self.send_link = self._link(out_head, "다른 도구로 보내기 ▾", self.open_send_menu)
        self.send_link.pack(side="right", padx=(0, self._px(14)))
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
        else:
            # 자식이 없는 Frame 은 직전 크기를 그대로 유지한다. 높이를 직접 줄여야 빈 자리가 남지 않는다
            self.tabs.config(height=1)
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
        self._clear_problem()
        self._build_form()
        if self.action.example:
            self.example_link.pack(side="left", padx=(self._px(6), self._px(10)), before=self.problem)
        else:
            self.example_link.pack_forget()
        self._render_output()

    def _visible_fields(self) -> list:
        return [*self.command.shared, *self.action.fields]

    def _build_form(self) -> None:
        for tip in self.tips:
            tip.hide()
        self.tips = []
        for widget in self.form.winfo_children():
            widget.destroy()
        self.widgets = {}
        self.inputs = {}
        self.folded_widgets = []
        self.marked = None
        shown, folded = split_fields(self._visible_fields())
        # 긴 항목이 있으면 라벨 칸의 폭을 일정하게 잡아, 화면을 옮겨도 입력 칸의 왼쪽 끝이 같은 자리에 오게 한다
        has_long = any(f.kind not in _SHORT_KINDS for f in self._visible_fields())
        self.form.columnconfigure(0, minsize=self._px(104) if has_long else 0)

        row = self._place_fields(shown, 0, has_long)
        if not shown and not folded:
            tk.Label(self.form, text="입력할 항목이 없습니다. 실행을 누르세요.", bg=CARD, fg=MUTED,
                     font=(self.ui_font, 9)).grid(row=0, column=0, columnspan=2, sticky="w")
        if folded:
            before = set(self.form.winfo_children())
            self.fold_link = self._link(self.form, "", self._toggle_folded, fg=ACCENT)
            self.fold_link.grid(row=row, column=0, columnspan=2, sticky="w", pady=(self._px(6), self._px(2)))
            before.add(self.fold_link)
            self._place_fields(folded, row + 1, has_long)
            self.folded_widgets = [w for w in self.form.winfo_children() if w not in before]
            key = (self.command.name, self.action.name)
            # 접힌 항목에 이미 값을 넣어 두었다면 펼쳐서 보여 준다 (숨은 값이 실행에 쓰이면 헷갈린다)
            changed = any(str(self._saved_value(f)) != str(f.default) for f in folded)
            self._set_folded(not (self.expanded.get(key) or changed), len(folded))

    def _place_fields(self, fields: list, row: int, has_long: bool = True) -> int:
        """긴 항목은 한 줄에 하나씩, 짧은 항목은 한 줄에 여러 개 놓는다. 다음에 쓸 줄 번호를 돌려준다."""
        for f in fields:
            if f.kind not in _SHORT_KINDS:
                self._long_field(row, f)
                row += 1
        short = [f for f in fields if f.kind in _SHORT_KINDS]
        for start in range(0, len(short), _SHORT_PER_ROW):
            holder = tk.Frame(self.form, bg=CARD)
            # 긴 항목이 있는 화면에서는 짧은 항목 줄도 입력 칸과 같은 자리에서 시작한다
            holder.grid(row=row, column=1 if has_long else 0, columnspan=1 if has_long else 2, sticky="w",
                        pady=self._px(4))
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
        label = tk.Label(parent, text=f.label + (" *" if f.required else ""), bg=CARD,
                         fg=TEXT if f.required else MUTED, font=(self.ui_font, 9), anchor="nw")
        self._add_tip(label, f)
        return label

    def _add_tip(self, widget, f) -> None:
        """라벨만으로 알 수 없는 설명(기본값, 형식 예시)이 있으면 마우스를 올렸을 때 보여 준다."""
        if f.help and f.help.strip() != f.label:
            self.tips.append(Tooltip(widget, f.help.strip(), (self.ui_font, 9)))

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
            self.inputs[f.dest] = text
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
        self.inputs[f.dest] = entry

    def _short_field(self, holder, f) -> None:
        value = self._saved_value(f)
        cell = tk.Frame(holder, bg=CARD)
        cell.pack(side="left", padx=(0, self._px(24)))
        if f.kind == "check":
            var = tk.BooleanVar(value=bool(value))
            check = tk.Checkbutton(cell, text=f.label, variable=var, bg=CARD, fg=MUTED, activebackground=CARD,
                                   activeforeground=TEXT, selectcolor=FIELD_BG, bd=0, highlightthickness=0,
                                   font=(self.ui_font, 9))
            check.pack(side="left")
            self._add_tip(check, f)
            self.widgets[f.dest] = ("var", var)
            self.inputs[f.dest] = check
            return

        self._field_label(cell, f).pack(side="left", padx=(0, self._px(8)))
        var = tk.StringVar(value=str(value))
        if f.kind == "combo":
            widget = ttk.Combobox(cell, textvariable=var, values=f.choices or [], width=12, font=(self.ui_font, 10),
                                  state="normal" if f.editable else "readonly")
            widget.pack(side="left")
        else:
            widget = tk.Entry(cell, textvariable=var, width=7, **self._entry_style())
            widget.pack(side="left", ipady=self._px(4))
        self.widgets[f.dest] = ("var", var)
        self.inputs[f.dest] = widget

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

    def fill_example(self) -> None:
        """이 화면의 예시 값을 입력 칸에 채운다. 다른 칸에 넣어 둔 값은 건드리지 않는다."""
        if not self.action.example:
            return
        self._save_values()
        for dest, value in self.action.example.items():
            self.saved[(self.command.name, self.action.name, dest)] = value
        self._clear_problem()
        self._build_form()   # 접힌 옵션에 예시 값이 들어가면 펼쳐서 보여 주도록 다시 그린다
        self._set_status("● 예시를 채웠습니다. 실행을 누르세요", MUTED)

    # ---------- 입력 문제 안내 ----------

    def _show_problem(self, problem: InputProblem) -> None:
        """무엇이 빠졌는지 실행 버튼 옆에 적고, 문제가 된 입력 칸을 강조해 커서를 옮긴다."""
        self._set_status(f"✖ {problem}", YELLOW)
        self.problem.config(text=f"⚠  {problem}")
        dest = getattr(problem, "dest", None)
        widget = self.inputs.get(dest)
        if widget is None:
            return
        _, folded = split_fields(self._visible_fields())
        if any(f.dest == dest for f in folded) and not self.expanded.get((self.command.name, self.action.name)):
            self._set_folded(False, len(folded))   # 접힌 옵션 안의 문제면 펼쳐서 보여 준다
        try:
            widget.config(highlightbackground=RED, highlightcolor=RED)
            self.marked = widget
        except tk.TclError:
            pass   # ttk 위젯(목록)은 테두리 색을 바꿀 수 없다. 커서만 옮긴다
        widget.focus_set()

    def _clear_problem(self) -> None:
        self.problem.config(text="")
        if self.marked is not None:
            try:
                self.marked.config(highlightbackground=LINE, highlightcolor=ACCENT)
            except tk.TclError:
                pass   # 화면을 옮겨 이미 사라진 위젯
            self.marked = None

    # ---------- 실행 ----------

    def _run_shortcut(self, _event) -> None:
        self.run()

    def run(self) -> None:
        if self.job:
            return
        self._clear_problem()
        values = self.values()
        try:
            argv, stdin = build_argv(self.command, self.action, values)
        except InputProblem as e:
            self._show_problem(e)
            return
        self.flag_re = self._flag_pattern(values.get("flag"))
        output = self.output
        output.reset()
        shown = ["ctfkit", *argv]
        output.command_line = "$ " + subprocess.list2cmdline(shown) + ("   < 입력" if stdin else "")
        self._render_output()
        try:
            self.job = Job(argv, stdin)
        except (OSError, ValueError) as e:
            self._set_status(f"✖ 실행 실패: {e}", RED)
            return
        self.job_output = output
        self.job_label = self.title.cget("text")
        self.started = time.time()
        self.hint.place_forget()   # 곧 출력이 채워진다
        self.run_btn.config(state="disabled", bg=RAISED, text="실행 중…")
        self.stop_btn.pack(side="left", fill="y", padx=(0, self._px(8)), after=self.run_btn)

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
                elsewhere = "" if self.job_output is self.output else f"  ·  {self.job_label}"
                self._set_status(f"● 실행 중  {time.time() - self.started:.1f}초{elsewhere}", ACCENT)
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
        """실행 중인 작업의 출력 한 줄을 그 작업의 결과에 쌓고, 그 화면을 보고 있으면 화면에도 넣는다."""
        output = self.job_output
        if output.lines >= _MAX_OUTPUT_LINES:
            output.dropped += 1
            return
        output.lines += 1
        tag = self._line_tag(line)
        segments, pos, new_flag = [], 0, False
        for match in self.flag_re.finditer(line):
            if match.end() == match.start():
                continue
            segments.append((line[pos:match.start()], tag))
            segments.append((match.group(0), "flag"))
            pos = match.end()
            if match.group(0) not in output.flags:
                output.flags.append(match.group(0))
                new_flag = True
        segments.append((line[pos:] + "\n", tag))
        segments = [s for s in segments if s[0]]
        output.segments.extend(segments)
        if output is self.output:
            self._insert(segments)
            if new_flag:
                self._paint_flag_bar()

    def _insert(self, segments: list) -> None:
        self.hint.place_forget()
        self.out.config(state="normal")
        for text, tag in segments:
            self.out.insert("end", text, tag)
        self.out.config(state="disabled")
        self.out.see("end")

    def _finish(self) -> None:
        job, self.job = self.job, None
        output = self.job_output
        took = time.time() - self.started
        self.run_btn.config(state="normal", bg=ACCENT, text="▶  실행")
        self.stop_btn.pack_forget()
        if output.dropped:
            note = [(f"[!] 출력이 많아 {output.dropped}줄을 생략했습니다. "
                     f"전체 결과는 CLI에서 파일로 저장하세요.\n", "warn")]
            output.segments.extend(note)
            if output is self.output:
                self._insert(note)
        state = classify(job.exit_code, job.saw_error_line, job.stopped)
        text, color = {
            "ok": (f"✔ 완료  {took:.2f}초", GREEN),
            "no_result": (f"● 완료 (종료 코드 1: 결과 없음 또는 실패 응답)  {took:.2f}초", YELLOW),
            "error": (f"✖ 오류  {took:.2f}초", RED),
            "stopped": (f"■ 중지됨  {took:.1f}초", YELLOW),
        }[state]
        output.status = (text, color)
        if output is self.output:
            self._set_status(text, color)
            self._refresh_hint()
        else:
            # 다른 화면에서 끝난 작업: 어느 화면의 결과인지 알려 준다
            self._set_status(f"{text}  ·  {self.job_label}", color)
        if self.on_finish:
            callback, self.on_finish = self.on_finish, None
            callback()

    def _set_status(self, text: str, color: str) -> None:
        self.status.config(text=text, fg=color)

    def stop(self) -> None:
        if self.job:
            self.job.stop()

    # ---------- 결과 영역 ----------

    def _render_output(self) -> None:
        """지금 화면의 결과를 결과 카드·플래그 줄·상태 줄에 다시 그린다."""
        output = self.output
        self.out.config(state="normal")
        self.out.delete("1.0", "end")
        for text, tag in output.segments:
            self.out.insert("end", text, tag)
        self.out.config(state="disabled")
        self.out.see("end")
        self.cmd_var.set(output.command_line)
        self._paint_flag_bar()
        self._refresh_hint()
        if not self.job:
            text, color = output.status or (_IDLE, MUTED)
            self._set_status(text, color)

    def _paint_flag_bar(self) -> None:
        flags = self.output.flags
        if not flags:
            self.flag_var.set("")
            self.flag_bar.pack_forget()
            return
        self.flag_var.set(flags[0])
        self.flag_more.config(text=f"외 {len(flags) - 1}개" if len(flags) > 1 else "")
        if not self.flag_bar.winfo_manager():
            self.flag_bar.pack(fill="x", padx=self._px(24), pady=(self._px(12), 0), before=self.out_card)

    def _refresh_hint(self) -> None:
        """결과가 비어 있을 때 가운데에 띄우는 안내를 상황에 맞게 고른다."""
        output = self.output
        if output.lines or (self.job and self.job_output is output):
            self.hint.place_forget()
            return
        if output.status:
            text = "출력이 없습니다"
        else:
            text = _EMPTY_HINT_EXAMPLE if self.action and self.action.example else _EMPTY_HINT
        self.hint.config(text=text)
        self.hint.place(relx=0.5, rely=0.45, anchor="center")

    def clear(self) -> None:
        if self.job and self.job_output is self.output:
            return   # 실행 중인 결과를 지우면 줄 수 집계와 화면이 어긋난다
        self.output.reset()
        self._render_output()

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

    # ---------- 결과를 다른 도구로 보내기 ----------

    def send_targets(self) -> list:
        """결과를 받을 수 있는 화면 목록 [(메뉴 이름, 명령, 하위 명령, 항목)]. 글자 입력 칸이 있는 화면이다."""
        targets = []
        for command in self.schema:
            for action in command.actions:
                field = next((f for f in action.fields if f.stdin), None)
                if field is None:
                    continue
                many = len(command.actions) > 1
                targets.append((f"{command.label} · {action.label}" if many else command.label,
                                command.name, action.name, field.dest))
        return targets

    def open_send_menu(self) -> None:
        menu = tk.Menu(self.root, tearoff=0, bg=CARD, fg=TEXT, activebackground=RAISED, activeforeground=TEXT,
                       bd=0, font=(self.ui_font, 9))
        for label, command, action, dest in self.send_targets():
            menu.add_command(label=label, command=lambda c=command, a=action, d=dest: self.send_to(c, a, d))
        x = self.send_link.winfo_rootx()
        y = self.send_link.winfo_rooty() + self.send_link.winfo_height()
        menu.tk_popup(x, y)

    def send_to(self, command: str, action, dest: str) -> None:
        """지금 화면의 결과를 다른 화면의 입력 칸에 넣고 그 화면으로 옮긴다 (여러 단계를 손으로 풀 때)."""
        text = self.output.text().strip()
        if not text:
            self._set_status("● 보낼 결과가 없습니다. 먼저 실행하세요", MUTED)
            return
        self.show_command(command)
        self.show_action(action)
        self.set_values({dest: text})
        if not (self.job and self.job_output is self.output):
            self.output.reset()   # 새 입력과 맞지 않는 예전 결과는 치운다
            self._render_output()
        self._set_status(f"● 결과를 입력에 넣었습니다  ·  {self.title.cget('text')}", MUTED)

    def close(self) -> None:
        self.stop()
        for tip in self.tips:
            tip.hide()
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
