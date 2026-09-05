"""Tkinter dialogs for SafeBase.

Two kinds of dialogs live here:

1. Password dialogs (create / enter / change) — return a DialogResult with
   the raw password. The AI never sees this; the dialog is shown directly on
   the human's desktop by the server process.

2. Editor dialog (`_default_editor_dialog`) — opens a Toplevel window showing
   the decrypted JSON in an editable ScrolledText widget. The human edits the
   content directly and clicks Save; the AI never receives the value. Returns
   the edited dict on Save, or None on cancel.

The dialog *functions* are injected via module-level references on the
`server` facade (`server._prompt_*_fn`, `server._editor_dialog_fn`) so tests
can monkeypatch them without a GUI. See `safebase/access.py` and
`safebase/core.py` for the call sites (they read these references lazily via
`import server` so monkeypatching the facade propagates).
"""

from typing import Any, Optional

from safebase.config import _DEFAULT_DURATION, _DURATION_OPTIONS


class DialogResult:
    """Result of a password dialog. password is None if the human cancelled.

    Note: kept as a plain class (not a dataclass) for backward compatibility
    with existing test code that constructs it positionally.
    """

    def __init__(self, password: Optional[str], duration_minutes: int) -> None:
        self.password = password
        self.duration_minutes = duration_minutes


# ---------------------------------------------------------------------------
# Password dialogs
# ---------------------------------------------------------------------------

def _default_create_password_dialog(database: str, bucket: str) -> Optional[DialogResult]:
    """Show a tkinter dialog to create a new bucket password."""
    return _tkinter_dialog(
        title=f"SafeBase — Create Password",
        prompt=f"Create a password for bucket:\n{database}/{bucket}",
        confirm=True,
    )


def _default_enter_password_dialog(database: str, bucket: str) -> Optional[DialogResult]:
    """Show a tkinter dialog to enter an existing bucket password."""
    return _tkinter_dialog(
        title=f"SafeBase — Enter Password",
        prompt=f"Enter password for bucket:\n{database}/{bucket}",
        confirm=False,
    )


def _default_change_password_dialog(database: str, bucket: str) -> Optional[DialogResult]:
    """Show a tkinter dialog to enter a new bucket password (for change)."""
    return _tkinter_dialog(
        title=f"SafeBase — New Password",
        prompt=f"Enter NEW password for bucket:\n{database}/{bucket}",
        confirm=True,
    )


def _tkinter_dialog(title: str, prompt: str, confirm: bool) -> Optional[DialogResult]:
    """Build and run a tkinter password dialog. Returns None on cancel."""
    try:
        import tkinter as tk
        from tkinter import ttk
    except ImportError:
        raise RuntimeError(
            "tkinter is not available. SafeBase requires a display and tkinter "
            "to prompt the human for the password. This cannot run headless."
        )

    result: dict[str, Any] = {"password": None, "duration": _DEFAULT_DURATION, "ok": False}

    def on_ok():
        if confirm and entry.get() != confirm_entry.get():
            error_label.config(text="Passwords do not match")
            return
        if not entry.get():
            error_label.config(text="Password cannot be empty")
            return
        result["password"] = entry.get()
        result["duration"] = int(duration_var.get())
        result["ok"] = True
        root.destroy()

    def on_cancel():
        root.destroy()

    root = tk.Tk()
    root.title(title)
    root.resizable(False, False)

    # Force the dialog to the front so it is not hidden behind other windows.
    # topmost is released after 500ms so the dialog behaves normally afterwards.
    root.attributes('-topmost', True)
    root.lift()
    root.focus_force()
    root.after(500, lambda: root.attributes('-topmost', False))

    frame = ttk.Frame(root, padding=16)
    frame.grid(row=0, column=0, sticky="nsew")

    ttk.Label(frame, text=prompt).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))

    ttk.Label(frame, text="Password:").grid(row=1, column=0, sticky="w", pady=2)
    entry = ttk.Entry(frame, show="*", width=32)
    entry.grid(row=1, column=1, pady=2)
    entry.focus_set()

    confirm_entry = None
    if confirm:
        ttk.Label(frame, text="Confirm:").grid(row=2, column=0, sticky="w", pady=2)
        confirm_entry = ttk.Entry(frame, show="*", width=32)
        confirm_entry.grid(row=2, column=1, pady=2)

    # Show/hide password toggle — lets the human verify long passwords.
    show_var = tk.BooleanVar(value=False)

    def toggle_show():
        char = "" if show_var.get() else "*"
        entry.config(show=char)
        if confirm_entry is not None:
            confirm_entry.config(show=char)

    show_cb = ttk.Checkbutton(frame, text="Show password", variable=show_var, command=toggle_show)
    show_cb.grid(row=3, column=1, sticky="w", pady=(4, 0))

    ttk.Label(frame, text="Keep unlocked for:").grid(row=4, column=0, sticky="w", pady=(12, 2))
    duration_var = tk.IntVar(value=_DEFAULT_DURATION)
    dur_frame = ttk.Frame(frame)
    dur_frame.grid(row=4, column=1, sticky="w", pady=(12, 2))
    for i, mins in enumerate(_DURATION_OPTIONS):
        label = f"{mins} min" if mins > 0 else "Process lifetime"
        rb = ttk.Radiobutton(dur_frame, text=label, variable=duration_var, value=mins)
        rb.grid(row=0, column=i, padx=2)

    error_label = ttk.Label(frame, text="", foreground="red")
    error_label.grid(row=5, column=0, columnspan=2, sticky="w", pady=(8, 0))

    btn_frame = ttk.Frame(frame)
    btn_frame.grid(row=6, column=0, columnspan=2, pady=(16, 0))
    ttk.Button(btn_frame, text="Cancel", command=on_cancel).grid(row=0, column=0, padx=4)
    ttk.Button(btn_frame, text="Unlock" if not confirm else "Create", command=on_ok).grid(row=0, column=1, padx=4)

    root.bind("<Return>", lambda e: on_ok())
    root.bind("<Escape>", lambda e: on_cancel())

    root.mainloop()

    if not result["ok"]:
        return None
    return DialogResult(password=result["password"], duration_minutes=result["duration"])


# ---------------------------------------------------------------------------
# Editor dialog (for edit_file — human edits decrypted JSON directly)
# ---------------------------------------------------------------------------

def _default_editor_dialog(
    database: str,
    bucket: str,
    filename: str,
    content: dict[str, Any],
) -> Optional[dict[str, Any]]:
    """Open a Toplevel editor showing decrypted JSON for the human to edit.

    Returns the edited dict on Save, or None on Cancel. The AI never sees the
    content — only this server process renders it on the human's screen.

    Uses a hidden Tk root + a visible Toplevel (rather than a second Tk root)
    so it composes safely if another Tk root was recently used.
    """
    import json

    try:
        import tkinter as tk
        from tkinter import ttk, scrolledtext
    except ImportError:
        raise RuntimeError(
            "tkinter is not available. SafeBase requires a display and tkinter "
            "to show the editor. This cannot run headless."
        )

    prefill = json.dumps(content, indent=2, sort_keys=True, ensure_ascii=False)
    outcome: dict[str, Any] = {"content": None, "ok": False}

    def on_save():
        raw = text.get("1.0", "end-1c")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as e:
            error_label.config(text=f"Invalid JSON: {e.msg} (line {e.lineno}, col {e.colno})")
            return
        if not isinstance(parsed, dict):
            error_label.config(text="Top-level JSON must be an object ({...})")
            return
        outcome["content"] = parsed
        outcome["ok"] = True
        root.destroy()

    def on_cancel():
        root.destroy()

    root = tk.Tk()
    root.withdraw()  # hide the root; only the Toplevel is visible
    top = tk.Toplevel(root)
    top.title(f"SafeBase — Edit {database}/{bucket}/{filename}")
    top.resizable(True, True)

    # Force to front on open, then release so it behaves normally afterwards.
    top.attributes('-topmost', True)
    top.lift()
    top.focus_force()
    top.after(500, lambda: top.attributes('-topmost', False))

    top.grid_rowconfigure(0, weight=1)
    top.grid_columnconfigure(0, weight=1)

    text = scrolledtext.ScrolledText(top, width=72, height=28, font=("Consolas", 10))
    text.grid(row=0, column=0, sticky="nsew", padx=8, pady=(8, 4))
    text.insert("1.0", prefill)
    text.focus_set()

    error_label = ttk.Label(top, text="", foreground="red")
    error_label.grid(row=1, column=0, sticky="w", padx=8)

    btn_frame = ttk.Frame(top)
    btn_frame.grid(row=2, column=0, sticky="ew", padx=8, pady=8)
    ttk.Button(btn_frame, text="Cancel", command=on_cancel).pack(side="right", padx=4)
    ttk.Button(btn_frame, text="Save", command=on_save).pack(side="right", padx=4)

    top.bind("<Control-Return>", lambda e: on_save())
    top.bind("<Escape>", lambda e: on_cancel())
    top.protocol("WM_DELETE_WINDOW", on_cancel)

    root.mainloop()

    if not outcome["ok"]:
        return None
    return outcome["content"]
