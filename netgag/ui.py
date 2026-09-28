"""NetGag main window (tkinter)."""

import hashlib
import logging
import ntpath
import os
import queue
import subprocess
import threading
import time
import tkinter as tk
from dataclasses import dataclass, field
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from . import auditlog, config, firewall, folderwatch, handlers, hooklog, ifeo, pathutil, procs, selftest

log = logging.getLogger(__name__)

POLL_MS = 100
FOLDER_EVENT_DEBOUNCE_S = 0.4
LARGE_FOLDER_WARNING = 300

STATE_LABEL = {
    "blocked": "Blocked", "partial": "Partial", "allowed": "Allowed",
    "isolated": "Isolated launch", "unknown": "Checking...",
}
STATE_ORDER = {"blocked": 0, "partial": 1, "isolated": 2, "allowed": 3, "unknown": 4}
HEADINGS = {
    "name": "File",
    "type": "Type",
    "status": "Network State",
    "process": "Process State",
    "size": "File Size",
    "path": "Full Path",
}


@dataclass
class Entry:
    path: str
    plan: Optional[handlers.Plan] = None
    size: Optional[int] = None
    state: str = "unknown"          # blocked | partial | allowed | isolated | unknown
    running: bool = False
    missing: bool = False
    name: str = field(init=False)
    key: str = field(init=False)

    def __post_init__(self):
        self.path = pathutil.norm_path(self.path)
        self.name = ntpath.basename(self.path)
        self.key = pathutil.norm_key(self.path)
        if self.plan is None:
            self.plan = handlers.classify(self.path)
        if self.plan.kind == "html":
            self.state = "isolated"

    @property
    def kind(self):
        return self.plan.kind

    @property
    def target(self):
        """The program a firewall rule must match for this entry ('' if none)."""
        if self.kind == "exe":
            return self.path
        if self.kind == "script":
            return self.plan.runner
        return ""


def collect_state(snapshot):
    """Worker-thread safe: firewall + process + file info.

    *snapshot* is {key: (path, target, kind)}.
    Returns {key: (state, running, size, missing)}.
    """
    rules = firewall.query_state()
    running = procs.running_keys()
    out = {}
    for key, (path, target, kind) in snapshot.items():
        try:
            size, missing = os.path.getsize(path), False
        except OSError:
            size, missing = None, not os.path.exists(path)
        if kind == "html":
            out[key] = ("isolated", False, size, missing)
            continue
        tkey = pathutil.norm_key(target) if target else ""
        dirs = rules.get(tkey, set())
        if {"Outbound", "Inbound"} <= dirs:
            state = "blocked"
        elif dirs:
            state = "partial"
        else:
            state = "allowed"
        out[key] = (state, bool(tkey) and tkey in running, size, missing)
    return out


class NetGagApp(tk.Tk):
    def __init__(self, cfg=None):
        super().__init__()
        self.cfg = cfg if cfg is not None else config.load()
        self.title("NetGag - Network Isolator")
        try:
            self.geometry(self.cfg["size"])
        except tk.TclError:
            self.geometry("1000x560")
        self.minsize(820, 420)

        self.entries = {}       # key -> Entry
        self.key_of = {}        # tree iid -> key
        self.sort_col, self.sort_rev = "name", False
        self.is_busy = False
        self.msg_queue = queue.Queue()
        self.opt_recursive = tk.BooleanVar(value=self.cfg["recursive"])
        self.opt_kill_proc = tk.BooleanVar(value=self.cfg["kill_process"])
        self.hooked_pids = {}    # entry key -> set of pids we've injected (for Activity Log)
        self._folder_event_pending = False
        self._folder_event_last = 0.0
        self.folder_watcher = folderwatch.FolderWatcher(self._on_folder_event)

        self.apply_theme()
        self.build_menu()
        self.build_ui()

        for path in self.cfg["files"]:
            entry = self._make_entry(path)
            self.entries[entry.key] = entry
        self.render_table()

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.after(POLL_MS, self._poll_queue)
        self.after(300, lambda: self._import_existing(quiet=True))
        self.folder_watcher.start()
        self._sync_folder_watcher()

    # ------------------------------------------------------------------ setup
    def apply_theme(self):
        self.style = ttk.Style(self)
        available = self.style.theme_names()
        if "vista" in available:
            self.style.theme_use("vista")
        elif "winnative" in available:
            self.style.theme_use("winnative")
        else:
            self.style.theme_use("clam")
        self.style.configure(".", font=("Segoe UI", 9))
        self.style.configure("Treeview", font=("Segoe UI", 9), rowheight=23)
        self.style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        self.style.configure("Primary.TButton", font=("Segoe UI", 9, "bold"))

    def build_menu(self):
        menubar = tk.Menu(self)

        m_file = tk.Menu(menubar, tearoff=0)
        m_file.add_command(label="Add File(s)...", accelerator="Ctrl+O", command=self.on_add_files)
        m_file.add_command(label="Add Folder...", accelerator="Ctrl+Shift+O", command=self.on_add_folder)
        m_file.add_separator()
        m_file.add_command(label="Remove Selected from List", accelerator="Del", command=self.on_remove_selected)
        m_file.add_command(label="Clear List", command=self.on_clear_list)
        m_file.add_separator()
        m_file.add_command(label="Exit", accelerator="Alt+F4", command=self.on_close)
        menubar.add_cascade(label="File", menu=m_file)

        m_ops = tk.Menu(menubar, tearoff=0)
        m_ops.add_command(label="Block Selected", accelerator="Ctrl+B", command=self.on_block_selected)
        m_ops.add_command(label="Unblock Selected", accelerator="Ctrl+U", command=self.on_unblock_selected)
        m_ops.add_command(label="Run Selected (network-blocked)", accelerator="Ctrl+R",
                          command=self.on_run_selected)
        m_ops.add_command(label="Run Selected Offline (fake disconnect, experimental)",
                          command=self.on_run_offline_selected)
        m_ops.add_command(label="Fake Offline Now (inject into running copy)",
                          command=self.on_inject_running)
        m_ops.add_separator()
        m_ops.add_command(label="Block All in List", command=self.on_block_all)
        m_ops.add_command(label="Unblock All in List", command=self.on_unblock_all)
        m_ops.add_separator()
        m_ops.add_command(label="Refresh Status", accelerator="F5", command=self.refresh_tracked_files)
        m_ops.add_command(label="Import Existing NetGag Rules", command=lambda: self._import_existing(quiet=False))
        m_ops.add_command(label="Purge All NetGag Rules System-Wide...", command=self.on_purge_all_rules)
        menubar.add_cascade(label="Operations", menu=m_ops)

        m_tools = tk.Menu(menubar, tearoff=0)
        m_tools.add_command(label="Watched Folders...", command=self.on_manage_watched)
        m_tools.add_command(label="Custom Interpreters...", command=self.on_manage_interpreters)
        m_tools.add_separator()
        m_tools.add_command(label="View Hook Activity Log...", command=self.on_view_activity_log)
        m_tools.add_command(label="Blocked-Connection Log (Security Audit)...", command=self.on_manage_auditlog)
        m_tools.add_command(label="Auto-Hook on Every Launch (Advanced)...", command=self.on_manage_autohook)
        m_tools.add_command(label="Test NetGag's Blocking Mechanism...", command=self.on_run_selftest)
        m_tools.add_separator()
        m_tools.add_command(label="Open Windows Defender Firewall with Advanced Security",
                            command=lambda: subprocess.Popen(["mmc.exe", "wf.msc"]))
        m_tools.add_command(label="Open Settings Folder", command=self.on_open_settings_folder)
        menubar.add_cascade(label="Tools", menu=m_tools)
        self.config(menu=menubar)

        self.bind("<Control-o>", lambda e: self.on_add_files())
        self.bind("<Control-O>", lambda e: self.on_add_folder())
        self.bind("<Control-b>", lambda e: self.on_block_selected())
        self.bind("<Control-u>", lambda e: self.on_unblock_selected())
        self.bind("<Control-r>", lambda e: self.on_run_selected())
        self.bind("<Delete>", lambda e: self.on_remove_selected())
        self.bind("<F5>", lambda e: self.refresh_tracked_files())
        self.bind("<Control-a>", self.on_select_all)

    def build_ui(self):
        toolbar = ttk.Frame(self, padding=(10, 8, 10, 4))
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="Add File(s)...", width=13, command=self.on_add_files).pack(side="left", padx=(0, 4))
        ttk.Button(toolbar, text="Add Folder...", width=13, command=self.on_add_folder).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Remove", width=9, command=self.on_remove_selected).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Clear List", width=10, command=self.on_clear_list).pack(side="left", padx=4)
        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=8)
        self.btn_block = ttk.Button(toolbar, text="Block Selected", style="Primary.TButton", width=15,
                                    command=self.on_block_selected)
        self.btn_block.pack(side="left", padx=4)
        self.btn_unblock = ttk.Button(toolbar, text="Unblock Selected", width=16, command=self.on_unblock_selected)
        self.btn_unblock.pack(side="left", padx=4)
        self.btn_run = ttk.Button(toolbar, text="Run Blocked", width=12, command=self.on_run_selected)
        self.btn_run.pack(side="left", padx=4)
        self.btn_refresh = ttk.Button(toolbar, text="Refresh", width=9, command=self.refresh_tracked_files)
        self.btn_refresh.pack(side="left", padx=4)

        opt_bar = ttk.Frame(self, padding=(10, 0, 10, 6))
        opt_bar.pack(fill="x")
        ttk.Checkbutton(opt_bar, text="Scan subfolders when adding directory",
                        variable=self.opt_recursive).pack(side="left", padx=(0, 14))
        ttk.Checkbutton(opt_bar, text="Close running instances when blocking (asks first)",
                        variable=self.opt_kill_proc).pack(side="left")

        table_frame = ttk.Frame(self, padding=(10, 0, 10, 6))
        table_frame.pack(fill="both", expand=True)
        cols = tuple(HEADINGS)
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="extended")
        widths = {"name": 170, "type": 120, "status": 110, "process": 95, "size": 80, "path": 380}
        anchors = {"name": "w", "type": "w", "status": "center", "process": "center", "size": "e", "path": "w"}
        for col in cols:
            self.tree.heading(col, text=HEADINGS[col], command=lambda c=col: self.sort_by(c))
            self.tree.column(col, width=widths[col], anchor=anchors[col])
        self.tree.tag_configure("blocked", foreground="#9a1515")
        self.tree.tag_configure("partial", foreground="#b25e00")
        self.tree.tag_configure("allowed", foreground="#176329")
        self.tree.tag_configure("isolated", foreground="#1a4f9c")
        self.tree.tag_configure("unknown", foreground="#666666")

        scroll_y = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        scroll_x = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Block", command=self.on_block_selected)
        self.context_menu.add_command(label="Unblock", command=self.on_unblock_selected)
        self.context_menu.add_command(label="Run (network-blocked)", command=self.on_run_selected)
        self.context_menu.add_command(label="Run Offline (fake disconnect)", command=self.on_run_offline_selected)
        self.context_menu.add_command(label="Fake Offline Now (running copy)", command=self.on_inject_running)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Open File Location", command=self.on_open_file_location)
        self.context_menu.add_command(label="Copy Path", command=self.on_copy_path)
        self.context_menu.add_command(label="Remove from List", command=self.on_remove_selected)
        self.tree.bind("<Button-3>", self.on_right_click)

        status_bar = ttk.Frame(self, relief="sunken", padding=(6, 3))
        status_bar.pack(fill="x", side="bottom")
        self.status_msg = ttk.Label(status_bar, text="Ready.")
        self.status_msg.pack(side="left", fill="x", expand=True)
        ttk.Separator(status_bar, orient="vertical").pack(side="left", fill="y", padx=8)
        self.status_items = ttk.Label(status_bar, text="Items: 0", width=12, anchor="center")
        self.status_items.pack(side="left")
        ttk.Separator(status_bar, orient="vertical").pack(side="left", fill="y", padx=8)
        self.status_blocked = ttk.Label(status_bar, text="Blocked: 0", width=12, anchor="center")
        self.status_blocked.pack(side="left")

    # ------------------------------------------------------- background tasks
    def set_busy_state(self, busy):
        self.is_busy = busy
        state = "disabled" if busy else "normal"
        for btn in (self.btn_block, self.btn_unblock, self.btn_run, self.btn_refresh):
            btn.config(state=state)

    def _busy_guard(self):
        """True (and a status hint) if an operation is already running."""
        if self.is_busy:
            self.status_msg.config(text="Busy - please wait for the current operation to finish.")
            return True
        return False

    def run_task(self, work, on_done=None, status=None, quiet=False):
        """Run work(post_status) on a thread; on_done(result) runs on the UI thread.

        Only one task runs at a time.  All Tk access happens on the main thread:
        workers talk to the UI exclusively through msg_queue.  A *quiet* task
        (periodic background work) logs failures instead of showing a dialog.
        """
        if self._busy_guard():
            return False
        self.set_busy_state(True)
        if status:
            self.status_msg.config(text=status)

        def runner():
            try:
                self.msg_queue.put(("done", on_done, work(self._post_status), None, quiet))
            except Exception as exc:  # noqa: BLE001 - reported to the user
                log.exception("Background task failed")
                self.msg_queue.put(("done", on_done, None, exc, quiet))

        threading.Thread(target=runner, daemon=True).start()
        return True

    def _post_status(self, text):
        self.msg_queue.put(("status", text))

    def _poll_queue(self):
        self.after(POLL_MS, self._poll_queue)
        try:
            while True:
                msg = self.msg_queue.get_nowait()
                if msg[0] == "status":
                    self.status_msg.config(text=msg[1])
                elif msg[0] == "folder_changed":
                    self._folder_event_pending = True
                    self._folder_event_last = time.monotonic()
                else:
                    self._finish_task(*msg[1:])
        except queue.Empty:
            pass
        if (self._folder_event_pending and not self.is_busy
                and time.monotonic() - self._folder_event_last >= FOLDER_EVENT_DEBOUNCE_S):
            self._folder_event_pending = False
            self._scan_watched_folders()

    def _finish_task(self, on_done, result, error, quiet=False):
        self.set_busy_state(False)
        if error is not None:
            self.status_msg.config(text="Operation failed (see log for details).")
            if not quiet:
                messagebox.showerror("NetGag", f"The operation failed:\n\n{error}")
            return
        if not quiet:
            self.status_msg.config(text="Ready.")
        if on_done:
            on_done(result)

    def _snapshot(self):
        return {k: (e.path, e.target, e.kind) for k, e in self.entries.items()}

    # ---------------------------------------------------------------- helpers
    def _make_entry(self, path):
        return Entry(path, handlers.classify(path, self.cfg))

    def get_selected_entries(self):
        out = []
        for iid in self.tree.selection():
            entry = self.entries.get(self.key_of.get(iid))
            if entry:
                out.append(entry)
        return out

    def save_config(self):
        self.cfg["files"] = [e.path for e in self.entries.values()]
        self.cfg["recursive"] = bool(self.opt_recursive.get())
        self.cfg["kill_process"] = bool(self.opt_kill_proc.get())
        try:
            config.save(self.cfg)
        except OSError:
            log.exception("Could not save settings")

    def _show_failures(self, title, failed):
        lines = [f"{ntpath.basename(p)}: {(err or 'unknown error')[:160]}" for p, err in failed[:10]]
        if len(failed) > 10:
            lines.append(f"... and {len(failed) - 10} more")
        messagebox.showerror("NetGag", f"{title}:\n\n" + "\n".join(lines))

    def _sort_key(self, col):
        return {
            "name": lambda e: e.name.lower(),
            "type": lambda e: (e.plan.label.lower(), e.name.lower()),
            "status": lambda e: (STATE_ORDER.get(e.state, 9), e.name.lower()),
            "process": lambda e: (not e.running, e.name.lower()),
            "size": lambda e: (e.size is None, e.size or 0),
            "path": lambda e: e.path.lower(),
        }[col]

    def sort_by(self, col):
        if col == self.sort_col:
            self.sort_rev = not self.sort_rev
        else:
            self.sort_col, self.sort_rev = col, False
        self.render_table()

    def render_table(self):
        selected = {self.key_of.get(i) for i in self.tree.selection()}
        top = self.tree.yview()[0]
        self.tree.delete(*self.tree.get_children())
        self.key_of.clear()

        for col, text in HEADINGS.items():
            arrow = ""
            if col == self.sort_col:
                arrow = " \u25bc" if self.sort_rev else " \u25b2"
            self.tree.heading(col, text=text + arrow)

        blocked, reselect = 0, []
        for e in sorted(self.entries.values(), key=self._sort_key(self.sort_col), reverse=self.sort_rev):
            iid = "r" + hashlib.sha256(e.key.encode("utf-8")).hexdigest()[:12]
            self.key_of[iid] = e.key
            if e.state == "blocked":
                blocked += 1
            if e.missing:
                proc = "File missing"
            elif e.state in ("unknown", "isolated"):
                proc = "-"
            else:
                proc = "Running" if e.running else "Stopped"
            size = pathutil.format_size(e.size) if e.size is not None else "-"
            self.tree.insert("", "end", iid=iid, tags=(e.state,),
                             values=(e.name, e.plan.label, STATE_LABEL.get(e.state, e.state),
                                     proc, size, e.path))
            if e.key in selected:
                reselect.append(iid)
        if reselect:
            self.tree.selection_set(reselect)
        self.tree.yview_moveto(top)
        self.status_items.config(text=f"Items: {len(self.entries)}")
        self.status_blocked.config(text=f"Blocked: {blocked}")

    def _apply_state(self, result):
        for key, (state, running, size, missing) in result.items():
            entry = self.entries.get(key)
            if entry is None:          # removed while the refresh was running
                continue
            entry.state, entry.running, entry.size, entry.missing = state, running, size, missing
        self.render_table()

    # ------------------------------------------------------- list management
    def _ask_interpreter(self, ext, reason, asked):
        """Offer to pick the program that runs *ext* files (once per extension per batch)."""
        if ext in asked:
            return asked[ext]
        chosen = False
        if ext and messagebox.askyesno(
            "Unknown file type",
            f"{reason}\n\nDo you want to choose the program that runs {ext} files?\n\n"
            "(Experimental: NetGag copies that program for each blocked file. This is tested "
            "with Python, Node.js, batch and VBScript; interpreters that need many files "
            "next to them may not work.)",
        ):
            exe = filedialog.askopenfilename(
                title=f"Select the program that runs {ext} files",
                filetypes=[("Programs (*.exe)", "*.exe")])
            if exe:
                self.cfg.setdefault("interpreters", {})[ext] = pathutil.norm_path(exe)
                chosen = True
        asked[ext] = chosen
        return chosen

    def _add_paths(self, paths):
        """Add files to the list. Returns the number of newly added items."""
        added, skipped = 0, []
        ignored = set(self.cfg.get("ignored", []))
        asked = {}

        def add_entry(entry):
            nonlocal added
            ignored.discard(entry.key)
            if entry.key not in self.entries:
                self.entries[entry.key] = entry
                added += 1

        for raw in paths:
            path = pathutil.norm_path(raw)
            name, ext = ntpath.basename(path), ntpath.splitext(path)[1].lower()
            plan = handlers.classify(path, self.cfg)

            if plan.kind == "unsupported" and plan.needs_interpreter and self._ask_interpreter(ext, plan.problem, asked):
                plan = handlers.classify(path, self.cfg)

            if plan.kind == "source":
                outputs = handlers.find_build_outputs(path)
                if not outputs:
                    skipped.append(f"{name}: source code never uses the network itself - build it, then add "
                                   "the compiled .exe (or add the build folder)")
                    continue
                for out in outputs:
                    if pathutil.is_protected(out):
                        continue
                    add_entry(self._make_entry(out))
                continue
            if plan.kind == "unsupported":
                skipped.append(f"{name}: {plan.problem}")
                continue
            if plan.kind == "exe" and pathutil.is_protected(path):
                skipped.append(f"{name}: protected Windows component")
                continue
            add_entry(Entry(path, plan))

        self.cfg["ignored"] = sorted(ignored)
        if skipped:
            shown = "\n".join(skipped[:10]) + (f"\n... and {len(skipped) - 10} more" if len(skipped) > 10 else "")
            messagebox.showwarning("NetGag", "Some files were not added:\n\n" + shown)
        self.save_config()
        self.render_table()
        return added

    def on_add_files(self):
        if self._busy_guard():
            return
        patterns = tuple("*" + e for e in handlers.SUPPORTED_EXTS)
        files = filedialog.askopenfilenames(
            title="Select File(s) to Add to NetGag",
            filetypes=[("Supported files", patterns), ("Programs (*.exe)", "*.exe"), ("All files", "*.*")],
        )
        if files and self._add_paths(files):
            self.refresh_tracked_files()

    def _ask_folder_options(self, folder):
        """Modal dialog. Returns (set_of_extensions, mode) or None if cancelled."""
        dlg = tk.Toplevel(self)
        dlg.title("Add Folder")
        dlg.transient(self)
        dlg.resizable(False, False)
        ttk.Label(dlg, text=folder, wraplength=460, padding=(12, 10, 12, 2)).pack(anchor="w")
        ttk.Label(dlg, text="Include these file types:", padding=(12, 6, 12, 2)).pack(anchor="w")

        preselected = set(self.cfg.get("folder_types", [".exe"]))
        group_vars = []
        box = ttk.Frame(dlg, padding=(24, 0, 12, 0))
        box.pack(anchor="w")
        for label, exts in handlers.FOLDER_GROUPS:
            var = tk.BooleanVar(value=bool(preselected & set(exts)))
            ttk.Checkbutton(box, text=label, variable=var).pack(anchor="w")
            group_vars.append((var, exts))

        ttk.Label(dlg, text="What should NetGag do?", padding=(12, 10, 12, 2)).pack(anchor="w")
        mode = tk.StringVar(value="watch")
        radios = ttk.Frame(dlg, padding=(24, 0, 12, 0))
        radios.pack(anchor="w")
        for value, text in (
            ("watch", "Block everything now and keep watching for new files"),
            ("block", "Block everything now (don't watch)"),
            ("add", "Only add to the list (don't block yet)"),
        ):
            ttk.Radiobutton(radios, text=text, value=value, variable=mode).pack(anchor="w")

        result = {}

        def ok():
            exts = {e for var, group in group_vars if var.get() for e in group}
            if not exts:
                messagebox.showinfo("NetGag", "Select at least one file type.", parent=dlg)
                return
            result["value"] = (exts, mode.get())
            dlg.destroy()

        buttons = ttk.Frame(dlg, padding=12)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Cancel", command=dlg.destroy).pack(side="right", padx=(6, 0))
        ttk.Button(buttons, text="OK", style="Primary.TButton", command=ok).pack(side="right")
        dlg.wait_visibility()
        dlg.grab_set()
        self.wait_window(dlg)
        return result.get("value")

    def on_add_folder(self):
        if self._busy_guard():
            return
        folder = filedialog.askdirectory(title="Select Folder to Add to NetGag")
        if not folder:
            return
        folder = pathutil.norm_path(folder)
        options = self._ask_folder_options(folder)
        if options is None:
            return
        exts, mode = options
        self.cfg["folder_types"] = sorted(exts)
        recursive = self.opt_recursive.get()

        def work(post):
            post("Scanning folder...")
            return pathutil.find_files(folder, recursive, sorted(exts))

        def done(found):
            if mode == "watch":
                self._register_watch(folder, recursive, sorted(exts))
            if not found:
                messagebox.showinfo("NetGag", "No matching files found in the selected folder."
                                    + ("\nThe folder is still being watched." if mode == "watch" else ""))
                return
            if len(found) > LARGE_FOLDER_WARNING and not messagebox.askyesno(
                    "Large folder", f"Found {len(found)} matching files. Add them all?"):
                return
            self._add_paths(found)
            targets = [self.entries[k] for k in (pathutil.norm_key(p) for p in found) if k in self.entries]
            if mode in ("watch", "block") and targets:
                self._block(targets)
            else:
                self.refresh_tracked_files()

        self.run_task(work, done, "Scanning folder...")

    def _register_watch(self, folder, recursive, exts):
        key = pathutil.norm_key(folder)
        watched = self.cfg["watched_folders"]
        for w in watched:
            if pathutil.norm_key(w["path"]) == key:
                w["recursive"], w["exts"] = recursive, list(exts)
                break
        else:
            watched.append({"path": folder, "recursive": recursive, "exts": list(exts)})
        self.save_config()
        self._sync_folder_watcher()

    def on_remove_selected(self):
        self._remove_entries(self.get_selected_entries())

    def on_clear_list(self):
        if self.entries and messagebox.askyesno("Clear List", "Remove every item from the list?"):
            self._remove_entries(list(self.entries.values()))

    def _remove_entries(self, entries):
        if self._busy_guard() or not entries:
            return
        blocked = [e for e in entries if e.state in ("blocked", "partial")]
        if blocked and not messagebox.askyesno(
            "Remove from List",
            f"{len(blocked)} of these item(s) are currently blocked.\n\n"
            "Removing them from the list will also unblock them. Continue?",
            icon="warning",
        ):
            return
        keys = [e.key for e in entries]

        def finish(_result=None):
            ignored = set(self.cfg.get("ignored", []))
            for key in keys:
                self.entries.pop(key, None)
                ignored.add(key)     # stops folder watching from re-adding it
            self.cfg["ignored"] = sorted(ignored)
            self.save_config()
            self.render_table()

        if blocked:
            self.run_task(lambda post: self._unblock_work(blocked), finish, "Removing firewall rules...")
        else:
            finish()

    @staticmethod
    def _unblock_work(entries):
        """Remove firewall rules, then delete the private runner copies of scripts."""
        firewall.unblock_many([e.target for e in entries if e.target])
        for e in entries:
            if e.kind == "script":
                handlers.remove_runner(e.path)

    # ------------------------------------------------------- firewall actions
    def refresh_tracked_files(self):
        if not self.entries:
            self.render_table()
            return
        snapshot = self._snapshot()
        self.run_task(lambda post: collect_state(snapshot), self._apply_state,
                      "Querying Windows Firewall and process status...")

    def _import_existing(self, quiet=True):
        """Load programs/scripts that already have NetGag rules (e.g. after a restart)."""
        def done(programs):
            added = 0
            for program in programs:
                owner = handlers.owner_of_program(program)      # runner copy -> its script
                path = owner or program
                if pathutil.is_protected(path):
                    continue
                entry = self._make_entry(path)
                if entry.key not in self.entries:
                    self.entries[entry.key] = entry
                    added += 1
            if added:
                self.save_config()
            self.render_table()
            self.refresh_tracked_files()
            if not quiet:
                messagebox.showinfo("NetGag", f"Added {added} item(s) that already had NetGag rules."
                                    if added else "No additional NetGag rules were found.")

        self.run_task(lambda post: firewall.list_managed_programs(), done,
                      "Checking existing NetGag firewall rules...")

    def on_block_selected(self):
        entries = self.get_selected_entries()
        if not entries:
            messagebox.showinfo("NetGag", "Select one or more items first.")
            return
        self._block(entries)

    def on_block_all(self):
        entries = list(self.entries.values())
        if not entries:
            messagebox.showinfo("NetGag", "The list is empty.")
            return
        if len(entries) > 1 and not messagebox.askyesno(
                "Block All", f"Block all {len(entries)} items in the list?"):
            return
        self._block(entries)

    def _block(self, entries, kill=None, confirm=True, after=None):
        """Block entries. *after()* runs when everything succeeded."""
        if self._busy_guard():
            return
        blockable = [e for e in entries if e.kind in ("exe", "script")
                     and not (e.kind == "exe" and pathutil.is_protected(e.path))]
        if not blockable:
            if any(e.kind == "html" for e in entries):
                messagebox.showinfo(
                    "NetGag", "HTML pages run inside the browser, so a firewall cannot single them out.\n\n"
                              "Use 'Run Blocked' to open them in an isolated browser window with the network switched off.")
            elif entries:
                messagebox.showinfo("NetGag", "None of the selected items can be blocked "
                                              "(unsupported type or protected Windows component).")
            return
        kill = self.opt_kill_proc.get() if kill is None else kill
        scripts = [e for e in blockable if e.kind == "script"]

        if kill and confirm and scripts:
            # Finding running script instances needs a (slow) process query: keep it off the UI thread.
            def scan(post):
                post("Looking for running instances of the scripts...")
                return {e.key: procs.find_script_instances(e.path, e.plan.interpreter, e.target)
                        for e in scripts}

            self.run_task(scan, lambda found: self._confirm_and_block(blockable, kill, confirm, after, found),
                          "Looking for running instances...")
            return
        self._confirm_and_block(blockable, kill, confirm, after, {})

    def _confirm_and_block(self, entries, kill, confirm, after, script_pids):
        if kill and confirm:
            live = procs.running_keys()
            running = [e for e in entries if e.kind == "exe" and e.key in live and not procs.is_self(e.path)]
            running += [e for e in entries if script_pids.get(e.key)]
            if running:
                names = "\n".join(f"  - {e.name}" for e in running[:10])
                if len(running) > 10:
                    names += "\n  ..."
                answer = messagebox.askyesnocancel(
                    "Close running programs?",
                    f"{len(running)} of the selected item(s) are running:\n\n{names}\n\n"
                    "Yes - force-close them, then block (unsaved data will be lost)\n"
                    "No - block without closing them (running copies keep their connection)\n"
                    "Cancel - do nothing",
                    icon="warning",
                )
                if answer is None:
                    return
                kill = answer
            else:
                kill = False

        snapshot = self._snapshot()

        def work(post):
            killed = 0
            if kill:
                for i, e in enumerate(entries, 1):
                    post(f"Closing ({i}/{len(entries)}): {e.name}")
                    if e.kind == "exe":
                        killed += procs.terminate_by_path(e.path)
                    else:
                        killed += sum(procs.terminate_pid(pid) for pid in script_pids.get(e.key, []))
            failures, ready = [], []
            for e in entries:
                if e.kind == "script":
                    post(f"Preparing isolated runner for {e.name}...")
                    try:
                        handlers.ensure_runner(e.plan, e.path)
                    except handlers.RunnerError as exc:
                        failures.append((e.path, str(exc)))
                        continue
                ready.append(e)
            by_target = {e.target: e.path for e in ready}
            results = firewall.block_many(
                list(by_target), lambda done, total: post(f"Blocking ({done}/{total})..."))
            blocked_ok = 0
            for target, ok, err in results:
                if ok:
                    blocked_ok += 1
                else:
                    failures.append((by_target[target], err))
            post("Refreshing status...")
            return blocked_ok, failures, collect_state(snapshot), killed

        def done(res):
            blocked_ok, failures, state, killed = res
            self._apply_state(state)
            text = f"Blocked {blocked_ok} item(s)"
            if killed:
                text += f", closed {killed} process(es)"
            self.status_msg.config(text=text + ".")
            if failures:
                self._show_failures("Some items could not be blocked", failures)
            elif after:
                after()

        self.run_task(work, done, "Blocking...")

    def on_unblock_selected(self):
        entries = self.get_selected_entries()
        if not entries:
            messagebox.showinfo("NetGag", "Select one or more items first.")
            return
        self._unblock(entries)

    def on_unblock_all(self):
        entries = list(self.entries.values())
        if not entries:
            messagebox.showinfo("NetGag", "The list is empty.")
            return
        self._unblock(entries)

    def _unblock(self, entries):
        if self._busy_guard():
            return
        entries = [e for e in entries if e.target]
        if not entries:
            self.status_msg.config(text="Nothing to unblock (HTML pages are only isolated at launch).")
            return
        snapshot = self._snapshot()

        def work(post):
            self._unblock_work(entries)
            post("Refreshing status...")
            return collect_state(snapshot)

        def done(state):
            self._apply_state(state)
            self.status_msg.config(text=f"Unblocked {len(entries)} item(s).")

        self.run_task(work, done, "Unblocking...")

    def on_purge_all_rules(self):
        if self._busy_guard():
            return
        if not messagebox.askyesno(
            "Confirm Global Reset",
            "This deletes ALL 'NetGag_*' firewall rules on this computer, including "
            "rules for programs that are not in the list, and the private script runners.\n\nProceed?",
            icon="warning",
        ):
            return
        snapshot = self._snapshot()

        def work(post):
            removed = firewall.purge_all()
            handlers.remove_all_runners()
            return removed, (collect_state(snapshot) if snapshot else {})

        def done(res):
            removed, state = res
            self._apply_state(state)
            self.status_msg.config(text=f"Removed {removed} firewall rule(s).")

        self.run_task(work, done, "Purging NetGag firewall rules...")

    # ------------------------------------------------------------- running
    def on_run_selected(self):
        entries = self.get_selected_entries()
        if not entries:
            messagebox.showinfo("NetGag", "Select one or more items first.")
            return
        if len(entries) > 5 and not messagebox.askyesno("Run", f"Start all {len(entries)} selected items?"):
            return
        self._run_entries(entries, ask=True)

    def _run_entries(self, entries, ask=True):
        if self._busy_guard():
            return
        unblocked = [e for e in entries if e.kind == "script" and e.state != "blocked"]
        if unblocked and ask:
            if not messagebox.askyesno(
                "Not blocked yet",
                f"{len(unblocked)} script(s) are not blocked yet - running them now would NOT be "
                "network-blocked.\n\nBlock them first, then run?",
            ):
                return
            self._block(unblocked, after=lambda: self._run_entries(entries, ask=False))
            return

        problems, started = [], 0
        for e in entries:
            if e.kind in ("source", "unsupported"):
                problems.append((e.path, "This file type cannot be launched."))
                continue
            if e.kind == "script" and e.state != "blocked":
                problems.append((e.path, "Not blocked, so it was not started."))
                continue
            try:
                handlers.launch_unelevated(handlers.write_launcher(e.path, e.plan))
                started += 1
            except handlers.RunnerError as exc:
                problems.append((e.path, str(exc)))
        self.status_msg.config(text=f"Started {started} item(s) with the network blocked."
                               if started else "Nothing was started.")
        if problems:
            self._show_failures("Some items could not be started", problems)

    # ------------------------------------------------------- fake-offline hook
    def on_run_offline_selected(self):
        entries = [e for e in self.get_selected_entries() if handlers.hook_supported(e.plan)]
        if not entries:
            messagebox.showinfo("NetGag", "Select a program or script first "
                                          "(HTML pages don't support this launch mode).")
            return
        if not messagebox.askyesno(
            "Run Offline (fake disconnect)",
            "This starts the selected item so it BELIEVES it has no network at all, rather than "
            "just having its connections blocked.\n\n"
            "It runs with NetGag's own Administrator rights (unlike 'Run Blocked', this mode "
            "can't hand it reduced privileges) and only works for 64-bit programs.\n\nContinue?",
        ):
            return
        self._run_entries_hooked(entries)

    def _run_entries_hooked(self, entries):
        if self._busy_guard():
            return
        unblocked = [e for e in entries if e.kind == "script" and e.state != "blocked"]
        if unblocked:
            if not messagebox.askyesno(
                "Not blocked yet",
                f"{len(unblocked)} script(s) don't have an isolated runner yet - block them first, then run offline?",
            ):
                return
            self._block(unblocked, after=lambda: self._run_entries_hooked(entries))
            return

        def work(post):
            started, problems = [], []
            for e in entries:
                post(f"Starting {e.name} in fake-offline mode...")
                try:
                    pid = handlers.launch_hooked(e.path, e.plan)
                    self.hooked_pids.setdefault(e.key, set()).add(pid)
                    started.append((e.name, pid))
                except handlers.RunnerError as exc:
                    problems.append((e.path, str(exc)))
            if started:
                post("Confirming the hook actually attached...")
                time.sleep(1.5)   # let the DLL's fast scan pass finish
            return started, problems

        def done(res):
            started, problems = res
            verified = 0
            for _name, pid in started:
                if hooklog.patched_functions_for_pid(pid):
                    verified += 1
            text = (f"Started {len(started)} item(s) believing they have no network"
                    if started else "Nothing was started")
            if started:
                text += f" ({verified}/{len(started)} confirmed via the hook's own log)"
            self.status_msg.config(text=text + ".")
            if problems:
                self._show_failures("Some items could not be started offline", problems)
            elif started and verified < len(started):
                messagebox.showwarning(
                    "NetGag", f"{len(started) - verified} of the started item(s) did not show any "
                              "confirmed patches in the hook's activity log within 1.5 seconds - "
                              "it may be a 32-bit process, or just needs a moment longer. Check "
                              "Tools -> View Hook Activity Log.")

        self.run_task(work, done, "Starting in fake-offline mode...")

    def on_inject_running(self):
        entries = [e for e in self.get_selected_entries() if handlers.hook_supported(e.plan)]
        if not entries:
            messagebox.showinfo("NetGag", "Select a running program or script first "
                                          "(HTML pages don't support this).")
            return
        if not messagebox.askyesno(
            "Fake Offline Now",
            "This injects the network hook into the ALREADY RUNNING copy of the selected item(s), "
            "so it starts believing it has no network from this point on.\n\n"
            "Only works for 64-bit processes; any connections it already has open stay open.\n\nContinue?",
        ):
            return

        def work(post):
            started, problems = [], []
            for e in entries:
                post(f"Finding running instance of {e.name}...")
                pids = (procs.find_pids_by_path(e.path) if e.kind == "exe"
                       else procs.find_script_instances(e.path, e.plan.interpreter, e.target))
                if not pids:
                    problems.append((e.path, "It is not currently running."))
                    continue
                for pid in pids:
                    try:
                        handlers.inject_running(pid)
                        self.hooked_pids.setdefault(e.key, set()).add(pid)
                        started.append((e.name, pid))
                    except handlers.RunnerError as exc:
                        problems.append((e.path, str(exc)))
            if started:
                post("Confirming the hook actually attached...")
                time.sleep(1.5)
            return started, problems

        def done(res):
            started, problems = res
            verified = sum(1 for _name, pid in started if hooklog.patched_functions_for_pid(pid))
            text = (f"Injected the network hook into {len(started)} running process(es)"
                    if started else "Nothing was injected")
            if started:
                text += f" ({verified}/{len(started)} confirmed via the hook's own log)"
            self.status_msg.config(text=text + ".")
            if problems:
                self._show_failures("Some items could not be hooked", problems)
            elif started and verified < len(started):
                messagebox.showwarning(
                    "NetGag", f"{len(started) - verified} did not show confirmed patches within 1.5 "
                              "seconds - it may be a 32-bit process, or just needs a moment longer.")

        self.run_task(work, done, "Injecting network hook...")

    # -------------------------------------------------------- folder watching
    def _sync_folder_watcher(self):
        """Call whenever cfg['watched_folders'] changes so the reactive
        watcher (FindFirstChangeNotificationW) matches the current set."""
        self.folder_watcher.set_folders(
            (w["path"], w.get("recursive", True)) for w in self.cfg["watched_folders"])

    def _on_folder_event(self, _changed_path):
        """Called from FolderWatcher's OWN background thread - must only ever
        touch thread-safe things (the queue), never Tk widgets directly."""
        self.msg_queue.put(("folder_changed",))

    def _scan_watched_folders(self):
        folders = [dict(w) for w in self.cfg["watched_folders"]]
        if not folders or self.is_busy:
            return
        known = set(self.entries) | set(self.cfg.get("ignored", []))

        def work(post):
            found, seen = [], set(known)
            for w in folders:
                if not os.path.isdir(w["path"]):
                    continue
                for path in pathutil.find_files(w["path"], w.get("recursive", True), w.get("exts", [".exe"])):
                    key = pathutil.norm_key(path)
                    if key in seen or pathutil.is_protected(path):
                        continue
                    seen.add(key)
                    found.append(path)
            return found

        def done(found):
            if not found:
                return
            new_entries = []
            for path in found:
                entry = self._make_entry(path)
                if entry.key not in self.entries:
                    self.entries[entry.key] = entry
                    new_entries.append(entry)
            self.save_config()
            self.render_table()
            if new_entries:
                self._block(new_entries, kill=False, confirm=False)

        self.run_task(work, done, quiet=True)

    def on_manage_watched(self):
        dlg = tk.Toplevel(self)
        dlg.title("Watched Folders")
        dlg.transient(self)
        ttk.Label(dlg, padding=8,
                  text="New files of the chosen types that appear in these folders are blocked automatically.").pack(anchor="w")
        frame = ttk.Frame(dlg, padding=(8, 0, 8, 8))
        frame.pack(fill="both", expand=True)
        listbox = tk.Listbox(frame, width=90, height=10, selectmode="extended", exportselection=False)
        scroll = ttk.Scrollbar(frame, command=listbox.yview)
        listbox.config(yscrollcommand=scroll.set)
        listbox.pack(side="left", fill="both", expand=True)
        scroll.pack(side="left", fill="y")

        def fill():
            listbox.delete(0, "end")
            for w in self.cfg["watched_folders"]:
                extra = "  [" + " ".join(w.get("exts", [".exe"])) + "]"
                extra += "  (subfolders)" if w.get("recursive", True) else ""
                listbox.insert("end", w["path"] + extra)

        def remove():
            for idx in sorted(listbox.curselection(), reverse=True):
                del self.cfg["watched_folders"][idx]
            self.save_config()
            self._sync_folder_watcher()
            fill()

        buttons = ttk.Frame(dlg, padding=(8, 0, 8, 8))
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Stop Watching Selected", command=remove).pack(side="left")
        ttk.Button(buttons, text="Close", command=dlg.destroy).pack(side="right")
        fill()
        dlg.wait_visibility()
        dlg.grab_set()

    def on_manage_interpreters(self):
        dlg = tk.Toplevel(self)
        dlg.title("Custom Interpreters")
        dlg.transient(self)
        ttk.Label(dlg, padding=8, wraplength=560,
                  text="Programs used to run file types NetGag does not know (experimental). "
                       "They also override the automatic choice for known types, e.g. to pick a "
                       "specific Python or Node.js.").pack(anchor="w")
        frame = ttk.Frame(dlg, padding=(8, 0, 8, 8))
        frame.pack(fill="both", expand=True)
        listbox = tk.Listbox(frame, width=90, height=8, exportselection=False)
        listbox.pack(side="left", fill="both", expand=True)

        def fill():
            listbox.delete(0, "end")
            for ext, exe in sorted(self.cfg.get("interpreters", {}).items()):
                listbox.insert("end", f"{ext}  ->  {exe}")

        def add():
            ext = _ask_string(dlg, "File extension", "Extension (for example .rb):")
            if not ext:
                return
            ext = ext.strip().lower()
            ext = ext if ext.startswith(".") else "." + ext
            exe = filedialog.askopenfilename(parent=dlg, title=f"Program that runs {ext} files",
                                             filetypes=[("Programs (*.exe)", "*.exe")])
            if exe:
                self.cfg.setdefault("interpreters", {})[ext] = pathutil.norm_path(exe)
                self.save_config()
                fill()

        def remove():
            sel = listbox.curselection()
            if sel:
                ext = listbox.get(sel[0]).split()[0]
                self.cfg.get("interpreters", {}).pop(ext, None)
                self.save_config()
                fill()

        buttons = ttk.Frame(dlg, padding=(8, 0, 8, 8))
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Add...", command=add).pack(side="left")
        ttk.Button(buttons, text="Remove Selected", command=remove).pack(side="left", padx=6)
        ttk.Button(buttons, text="Close", command=dlg.destroy).pack(side="right")
        fill()
        dlg.wait_visibility()
        dlg.grab_set()

    # -------------------------------------------------------- diagnostics
    def on_view_activity_log(self):
        """Shows, per currently-hooked entry, which functions were confirmed
        patched and how many times the target actually tried to reach the
        network - straight from the hook DLL's own log, not a guess."""
        dlg = tk.Toplevel(self)
        dlg.title("Hook Activity Log")
        dlg.transient(self)
        ttk.Label(dlg, padding=8, wraplength=620,
                  text="What the network hook has actually seen, per item you've started with "
                       "'Run Offline' or 'Fake Offline Now' this session.").pack(anchor="w")
        text = tk.Text(dlg, width=100, height=24, wrap="none", font=("Consolas", 9))
        text.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        def refresh():
            text.delete("1.0", "end")
            lines = hooklog.read_lines()
            if not self.hooked_pids:
                text.insert("end", "Nothing has been started with the network hook yet this session.\n")
                return
            for entry in self.entries.values():
                pids = self.hooked_pids.get(entry.key)
                if not pids:
                    continue
                text.insert("end", f"=== {entry.name} ===\n")
                for pid in sorted(pids):
                    patched = hooklog.patched_functions_for_pid(pid, lines)
                    counts = hooklog.activity_counts_for_pid(pid, lines)
                    text.insert("end", f"  pid {pid}: {len(patched)} function(s) patched"
                                       f"{' - ' + ', '.join(sorted(patched)) if patched else ''}\n")
                    if counts:
                        summary = ", ".join(f"{k}={v}" for k, v in counts.items() if v)
                        text.insert("end", f"           calls seen so far: {summary or '(none yet)'}\n")
                    else:
                        text.insert("end", "           calls seen so far: (none yet)\n")
                text.insert("end", "\n")

        buttons = ttk.Frame(dlg, padding=(8, 0, 8, 8))
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Refresh", command=refresh).pack(side="left")
        ttk.Button(buttons, text="Close", command=dlg.destroy).pack(side="right")
        refresh()
        dlg.wait_visibility()
        dlg.grab_set()

    def on_manage_auditlog(self):
        """Opt-in view of real Windows Firewall blocked-connection events
        (Event 5157) for currently tracked items. Enabling the underlying
        audit policy is a genuine system-wide change, so this always asks
        first and explains why."""
        dlg = tk.Toplevel(self)
        dlg.title("Blocked-Connection Log")
        dlg.transient(self)
        status_var = tk.StringVar(value="Checking...")
        ttk.Label(dlg, padding=8, wraplength=620,
                  text="Shows real blocked-connection attempts (Windows Event ID 5157) for your "
                       "tracked, firewall-blocked items - not just that a rule exists, but that "
                       "Windows actually caught something. Requires a Windows audit policy that is "
                       "off by default; turning it on logs blocked connections for the WHOLE "
                       "system, not just NetGag's items.").pack(anchor="w")
        ttk.Label(dlg, textvariable=status_var, padding=(8, 0)).pack(anchor="w")

        listbox = tk.Listbox(dlg, width=110, height=14, exportselection=False)
        listbox.pack(fill="both", expand=True, padx=8, pady=8)

        def set_status():
            def work(post):
                return auditlog.is_enabled()

            def done(enabled):
                status_var.set("Audit policy: ON" if enabled else "Audit policy: OFF (nothing will be logged)")
                btn_toggle.config(text="Disable" if enabled else "Enable")

            self.run_task(work, done, "Checking audit policy state...")

        def toggle():
            def work(post):
                if "Enable" in btn_toggle.cget("text"):
                    if not messagebox.askyesno(
                        "Enable Blocked-Connection Logging",
                        "This turns on Windows' 'Filtering Platform Connection' failure auditing "
                        "SYSTEM-WIDE - every blocked connection on this machine will be logged to "
                        "the Security event log from now on, not just NetGag's tracked items.\n\n"
                        "Continue?", icon="warning",
                    ):
                        return "cancelled"
                    auditlog.enable()
                else:
                    auditlog.disable()
                return "ok"

            def done(result):
                if result != "cancelled":
                    set_status()

            self.run_task(work, done, "Updating audit policy...")

        def refresh_events():
            paths = [e.target for e in self.entries.values() if e.target]

            def work(post):
                return auditlog.recent_blocks(paths)

            def done(rows):
                listbox.delete(0, "end")
                if not rows:
                    listbox.insert("end", "No matching blocked-connection events found.")
                    return
                for row in rows:
                    listbox.insert("end", f"{row.get('time', '')}  {row.get('program', '')}  -> "
                                          f"{row.get('destAddress', '')}:{row.get('destPort', '')} "
                                          f"({row.get('protocol', '')})")

            self.run_task(work, done, "Querying the Security event log...")

        buttons = ttk.Frame(dlg, padding=(8, 0, 8, 8))
        buttons.pack(fill="x")
        btn_toggle = ttk.Button(buttons, text="...", command=toggle)
        btn_toggle.pack(side="left")
        ttk.Button(buttons, text="Refresh Events", command=refresh_events).pack(side="left", padx=6)
        ttk.Button(buttons, text="Close", command=dlg.destroy).pack(side="right")
        set_status()
        dlg.wait_visibility()
        dlg.grab_set()

    def on_manage_autohook(self):
        """IFEO auto-hook management - deliberately separate from the main
        list, since this is a system-wide-by-filename change (see
        netgag/ifeo.py). Generic/shared names are refused, not just warned."""
        dlg = tk.Toplevel(self)
        dlg.title("Auto-Hook on Every Launch (Advanced)")
        dlg.transient(self)
        ttk.Label(dlg, padding=8, wraplength=640,
                  text="Makes a specific program believe it has no network EVERY time it starts, "
                       "by ANY means (double-click, a shortcut, another program) - not only when "
                       "launched through NetGag.\n\n"
                       "This works by file NAME, not by folder: it affects every process anywhere "
                       "on this machine with that exact file name. NetGag refuses names shared by "
                       "many unrelated programs (interpreters, shells, browsers, core Windows "
                       "components) since that would hijack far more than intended.").pack(anchor="w")

        listbox = tk.Listbox(dlg, width=90, height=8, exportselection=False)
        listbox.pack(fill="both", expand=True, padx=8, pady=8)

        def fill():
            listbox.delete(0, "end")

            def work(post):
                return ifeo.list_enabled()

            def done(names):
                listbox.delete(0, "end")
                if not names:
                    listbox.insert("end", "(none enabled)")
                else:
                    for name in names:
                        listbox.insert("end", name)

            self.run_task(work, done, "Checking registered auto-hook entries...")

        def add():
            path = filedialog.askopenfilename(parent=dlg, title="Select the program to auto-hook",
                                              filetypes=[("Programs (*.exe)", "*.exe")])
            if not path:
                return
            name = ntpath.basename(path)
            if ifeo.is_generic_name(path):
                messagebox.showerror(
                    "NetGag", f"{name} is a name shared by many unrelated programs (or a core "
                             "Windows component) - NetGag refuses to auto-hook it.", parent=dlg)
                return
            if not messagebox.askyesno(
                "Confirm Auto-Hook",
                f"Every process anywhere on this machine literally named {name} will believe it "
                "has no network, starting now, until you remove this.\n\nContinue?",
                icon="warning", parent=dlg,
            ):
                return

            def work(post):
                ifeo.enable(path)
                return None

            def done(_res):
                fill()

            self.run_task(work, done, f"Registering auto-hook for {name}...")

        def remove():
            sel = listbox.curselection()
            if not sel:
                return
            name = listbox.get(sel[0])
            if name == "(none enabled)":
                return

            def work(post):
                ifeo.disable(name)
                return None

            def done(_res):
                fill()

            self.run_task(work, done, f"Removing auto-hook for {name}...")

        buttons = ttk.Frame(dlg, padding=(8, 0, 8, 8))
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Enable for a Program...", command=add).pack(side="left")
        ttk.Button(buttons, text="Remove Selected", command=remove).pack(side="left", padx=6)
        ttk.Button(buttons, text="Close", command=dlg.destroy).pack(side="right")
        fill()
        dlg.wait_visibility()
        dlg.grab_set()

    def on_run_selftest(self):
        """Runs the same proof tests/smoke_multitype.py and smoke_nethook.py
        do, but from inside the shipped app, against the bundled test target -
        never touches anything the user has added."""
        if not messagebox.askyesno(
            "Test NetGag's Blocking Mechanism",
            "This briefly runs NetGag's own bundled test program through both isolation "
            "mechanisms to confirm they work on this machine. It does not touch anything "
            "you've added.\n\nContinue?",
        ):
            return

        def work(post):
            return selftest.run_all(post)

        def done(results):
            lines = []
            all_ok = True
            for name, ok, detail in results:
                lines.append(f"{'PASS' if ok else 'FAIL'} - {name}\n{detail}")
                all_ok = all_ok and ok
            text = "\n\n".join(lines)
            if all_ok:
                messagebox.showinfo("Self-Test Results", text)
            else:
                messagebox.showwarning("Self-Test Results", text)

        self.run_task(work, done, "Running self-test...")

    # ------------------------------------------------------------- misc UI
    def on_select_all(self, _event=None):
        self.tree.selection_set(self.tree.get_children())
        return "break"

    def on_right_click(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            if row not in self.tree.selection():
                self.tree.selection_set(row)
            self.context_menu.post(event.x_root, event.y_root)

    def on_open_file_location(self):
        selected = self.get_selected_entries()
        if not selected:
            return
        path = selected[0].path
        if os.path.exists(path):
            subprocess.Popen(f'explorer /select,"{path}"')
        elif os.path.isdir(os.path.dirname(path)):
            os.startfile(os.path.dirname(path))
        else:
            messagebox.showinfo("NetGag", "That file (and its folder) no longer exist.")

    def on_copy_path(self):
        selected = self.get_selected_entries()
        if selected:
            self.clipboard_clear()
            self.clipboard_append("\n".join(e.path for e in selected))

    def on_open_settings_folder(self):
        folder = config.config_dir()
        os.makedirs(folder, exist_ok=True)
        os.startfile(folder)

    def on_close(self):
        self.cfg["size"] = f"{self.winfo_width()}x{self.winfo_height()}"
        self.save_config()
        self.folder_watcher.stop()
        self.destroy()


def _ask_string(parent, title, prompt):
    """Tiny modal text prompt."""
    dlg = tk.Toplevel(parent)
    dlg.title(title)
    dlg.transient(parent)
    dlg.resizable(False, False)
    ttk.Label(dlg, text=prompt, padding=(12, 10, 12, 4)).pack(anchor="w")
    var = tk.StringVar()
    entry = ttk.Entry(dlg, textvariable=var, width=30)
    entry.pack(padx=12)
    result = {}

    def ok(_event=None):
        result["value"] = var.get()
        dlg.destroy()

    buttons = ttk.Frame(dlg, padding=12)
    buttons.pack(fill="x")
    ttk.Button(buttons, text="Cancel", command=dlg.destroy).pack(side="right", padx=(6, 0))
    ttk.Button(buttons, text="OK", command=ok).pack(side="right")
    entry.bind("<Return>", ok)
    dlg.wait_visibility()
    dlg.grab_set()
    entry.focus_set()
    parent.wait_window(dlg)
    return result.get("value")
