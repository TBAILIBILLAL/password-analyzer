"""The window: type a password and see its strength as you type."""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox, ttk

from .analyzer import Analysis, analyze
from .generator import suggestions
from .history import PasswordHistory

COLORS = ("#c62828", "#ef6c00", "#f9a825", "#7cb342", "#2e7d32")  # very weak ... very strong
EMPTY = "#d7dce2"
REUSE_DELAY_MS = 500  # the history check is slow on purpose, so it waits until typing pauses


class App(ttk.Frame):
    def __init__(self, root: tk.Tk, history: PasswordHistory | None = None):
        super().__init__(root, padding=18)
        self.root = root
        self.history = history or PasswordHistory()
        self.reuse_result: tuple[str, str, str] | None = None  # (account, password, result)
        self.reuse_timer: str | None = None
        self.score = -1  # nothing typed yet

        self.password = tk.StringVar()
        self.account = tk.StringVar()
        self.show = tk.BooleanVar(value=False)

        root.title("Password Strength Analyzer")
        self.pack(fill="both", expand=True)
        self._build()
        self.password.trace_add("write", lambda *_: self.refresh())
        self.account.trace_add("write", lambda *_: self.refresh())
        self.new_alternatives()
        self._fix_window_size()
        self.refresh()
        self.password_entry.focus_set()

    def _fix_window_size(self) -> None:
        """Size the window for a full report once, so it does not jump around while typing."""
        self.display(analyze("Summer2024", "name", "new"))  # a report with every row filled in
        self.root.update_idletasks()
        width, height = self.root.winfo_reqwidth(), self.root.winfo_reqheight()
        line = self.advice.winfo_reqheight() // 3  # room for one more line of advice
        height += line
        # centred, and never lower than the screen can show (the title bar and taskbar need room too)
        left = max(0, (self.root.winfo_screenwidth() - width) // 2)
        top = max(0, (self.root.winfo_screenheight() - height) // 2 - 40)
        self.root.geometry(f"{width}x{height}+{left}+{top}")
        self.root.minsize(width, height - line)

    # ------------------------------------------------------------------ layout

    def _build(self) -> None:
        style = ttk.Style()
        style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("Verdict.TLabel", font=("Segoe UI", 13, "bold"))
        style.configure("Section.TLabel", font=("Segoe UI", 10, "bold"))
        style.configure("Muted.TLabel", foreground="#5f6b7a")

        ttk.Label(self, text="Password Strength Analyzer", style="Title.TLabel").pack(anchor="w")
        ttk.Label(self, text="Nothing you type leaves this computer or is saved as text.",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 12))

        form = ttk.Frame(self)
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)
        ttk.Label(form, text="Password").grid(row=0, column=0, sticky="w", padx=(0, 10), pady=4)
        self.password_entry = ttk.Entry(form, textvariable=self.password, show="•", font=("Consolas", 12))
        self.password_entry.grid(row=0, column=1, sticky="ew", pady=4)
        ttk.Checkbutton(form, text="Show", variable=self.show, command=self._toggle_show).grid(row=0, column=2, padx=(10, 0))
        ttk.Label(form, text="Your name or email").grid(row=1, column=0, sticky="w", padx=(0, 10), pady=4)
        ttk.Entry(form, textvariable=self.account).grid(row=1, column=1, sticky="ew", pady=4)
        ttk.Label(form, text="optional", style="Muted.TLabel").grid(row=1, column=2, padx=(10, 0))

        self.meter = tk.Canvas(self, height=14, highlightthickness=0, bg=self.root.cget("bg"))
        self.meter.pack(fill="x", pady=(14, 4))
        self.meter.bind("<Configure>", lambda _: self._draw_meter())
        self.verdict = ttk.Label(self, style="Verdict.TLabel")
        self.verdict.pack(anchor="w")
        self.times = ttk.Label(self, style="Muted.TLabel", wraplength=720, justify="left")
        self.times.pack(anchor="w", pady=(0, 10))

        ttk.Label(self, text="Checks", style="Section.TLabel").pack(anchor="w")
        self.checks = ttk.Frame(self)
        self.checks.pack(fill="x", pady=(2, 10))

        ttk.Label(self, text="How to improve", style="Section.TLabel").pack(anchor="w")
        self.advice = ttk.Label(self, wraplength=720, justify="left")
        self.advice.pack(anchor="w", fill="x", pady=(2, 10))

        header = ttk.Frame(self)
        header.pack(fill="x")
        ttk.Label(header, text="Stronger alternatives", style="Section.TLabel").pack(side="left")
        ttk.Button(header, text="Generate new", command=self.new_alternatives).pack(side="right")
        self.alternatives = ttk.Frame(self)
        self.alternatives.pack(fill="x", pady=(4, 12))
        self.alternatives.columnconfigure(1, weight=1)

        actions = ttk.Frame(self)
        actions.pack(fill="x", side="bottom")
        ttk.Button(actions, text="Remember this password as used", command=self.remember).pack(side="left")
        ttk.Button(actions, text="Clear my history", command=self.clear_history).pack(side="left", padx=8)
        self.status = ttk.Label(actions, style="Muted.TLabel")
        self.status.pack(side="right")

    def _toggle_show(self) -> None:
        self.password_entry.configure(show="" if self.show.get() else "•")

    def _draw_meter(self) -> None:
        self.meter.delete("all")
        width = self.meter.winfo_width()
        gap = 6
        segment = (width - 4 * gap) / 5
        for i in range(5):
            x = i * (segment + gap)
            color = COLORS[self.score] if 0 <= self.score and i <= self.score else EMPTY
            self.meter.create_rectangle(x, 2, x + segment, 12, fill=color, outline="")

    # ------------------------------------------------------------------ analysis

    def refresh(self) -> None:
        """Analyze what is typed now. The slower history check follows once typing pauses."""
        password, account = self.password.get(), self.account.get()
        reuse = None
        if self.reuse_result and self.reuse_result[:2] == (account, password):
            reuse = self.reuse_result[2]
        self.display(analyze(password, account, reuse))

        if self.reuse_timer:
            self.root.after_cancel(self.reuse_timer)
            self.reuse_timer = None
        if password and reuse is None:
            self.reuse_timer = self.root.after(REUSE_DELAY_MS, lambda: self._start_reuse_check(account, password))

    def _start_reuse_check(self, account: str, password: str) -> None:
        self.reuse_timer = None

        def work() -> None:
            try:
                result = self.history.check(account, password)
            except Exception:
                return  # the history is optional; the rest of the analysis still stands
            self.root.after(0, lambda: self._finish_reuse_check(account, password, result))

        threading.Thread(target=work, daemon=True).start()

    def _finish_reuse_check(self, account: str, password: str, result: str) -> None:
        self.reuse_result = (account, password, result)
        if (self.account.get(), self.password.get()) == (account, password):
            self.display(analyze(password, account, result))

    def display(self, analysis: Analysis) -> None:
        typed = analysis.length > 0
        self.score = analysis.score if typed else -1
        self._draw_meter()
        if typed:
            self.verdict.configure(text=f"{analysis.label}  ·  about {analysis.bits:.0f} bits",
                                   foreground=COLORS[analysis.score])
            self.times.configure(text=f"Time to crack: {analysis.offline_time} if the password database is stolen, "
                                      f"{analysis.online_time} by guessing online")
        else:
            self.verdict.configure(text="Type a password", foreground="#5f6b7a")
            self.times.configure(text="")

        for child in self.checks.winfo_children():
            child.destroy()
        for row, check in enumerate(analysis.checks):
            mark, color = ("✓", "#2e7d32") if check.passed else ("✗", "#c62828")
            ttk.Label(self.checks, text=mark, foreground=color, font=("Segoe UI", 11, "bold")).grid(row=row, column=0, padx=(0, 8))
            ttk.Label(self.checks, text=check.name, width=20).grid(row=row, column=1, sticky="w")
            ttk.Label(self.checks, text=check.message, wraplength=500, justify="left").grid(row=row, column=2, sticky="w")

        if not typed:
            self.advice.configure(text="")
        elif analysis.suggestions:
            self.advice.configure(text="\n".join("• " + suggestion for suggestion in analysis.suggestions))
        else:
            self.advice.configure(text="Nothing to improve. Use this password for one account only.")

    # ------------------------------------------------------------------ alternatives and history

    def new_alternatives(self) -> None:
        for child in self.alternatives.winfo_children():
            child.destroy()
        for row, suggestion in enumerate(suggestions()):
            ttk.Label(self.alternatives, text=suggestion.kind, width=14).grid(row=row, column=0, sticky="w", pady=2)
            field = ttk.Entry(self.alternatives, font=("Consolas", 10), width=52)
            field.insert(0, suggestion.password)
            field.configure(state="readonly")
            field.grid(row=row, column=1, sticky="ew", pady=2)
            ttk.Label(self.alternatives, text=f"{suggestion.bits:.0f} bits", style="Muted.TLabel", width=8).grid(row=row, column=2, padx=8)
            ttk.Button(self.alternatives, text="Copy", width=6,
                       command=lambda text=suggestion.password: self.copy(text)).grid(row=row, column=3)

    def copy(self, text: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status.configure(text="Copied to the clipboard")

    def remember(self) -> None:
        password, account = self.password.get(), self.account.get()
        if not password:
            self.status.configure(text="Type a password first")
            return
        self.history.add(account, password)
        self.reuse_result = (account, password, "exact")
        self.status.configure(text="Remembered. It will be flagged if you enter it again.")
        self.refresh()

    def clear_history(self) -> None:
        account = self.account.get()
        if not messagebox.askyesno("Clear history", "Forget all remembered passwords for this name?"):
            return
        removed = self.history.clear(account)
        self.reuse_result = None
        self.status.configure(text=f"Removed {removed} remembered password(s)")
        self.refresh()


def run() -> None:
    try:  # sharp text on high-resolution screens (Windows only)
        from ctypes import windll

        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    root = tk.Tk()
    App(root)
    root.mainloop()
