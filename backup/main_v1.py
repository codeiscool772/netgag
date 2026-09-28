import os
import sys
import ctypes
import hashlib
import pathlib
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

RULE_PREFIX = "NetGag_"

def set_high_dpi():
    """Ensure crisp typography on modern high-DPI monitors."""
    if sys.platform == "win32":
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass

def is_admin():
    """Check if the current process holds Administrator rights."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def elevate_if_needed():
    """Relaunch as administrator when run directly as a python script."""
    if sys.platform != "win32" or is_admin():
        return
    
    if getattr(sys, "frozen", False):
        target = sys.executable
        params = " ".join([f'"{a}"' for a in sys.argv[1:]])
    else:
        target = sys.executable
        script = os.path.abspath(sys.argv[0])
        params = f'"{script}" ' + " ".join([f'"{a}"' for a in sys.argv[1:]])
        
    ctypes.windll.shell32.ShellExecuteW(None, "runas", target, params, None, 1)
    sys.exit(0)

def generate_rule_name(exe_path, direction):
    """Compute deterministic, collision-resistant rule names for Windows Firewall."""
    pure = pathlib.PureWindowsPath(exe_path)
    clean_stem = pure.stem.replace(" ", "_")[:16]
    normalized_path = str(pure).lower().encode("utf-8")
    path_hash = hashlib.sha256(normalized_path).hexdigest()[:10]
    return f"{RULE_PREFIX}{direction}_{clean_stem}_{path_hash}"

def execute_cmd(cmd_list):
    """Run system commands silently with no console flash."""
    flags = 0x08000000 if sys.platform == "win32" else 0  # CREATE_NO_WINDOW
    return subprocess.run(
        cmd_list,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=flags,
        text=True
    )

def check_file_blocked(exe_path):
    """Query Windows Firewall to test if outbound block is active."""
    rule_out = generate_rule_name(exe_path, "OUT")
    res = execute_cmd(["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_out}"])
    return res.returncode == 0 and "Rule Name:" in res.stdout

def block_file(exe_path):
    """Apply kernel-level block rules for outbound and inbound traffic on all profiles."""
    rule_out = generate_rule_name(exe_path, "OUT")
    rule_in = generate_rule_name(exe_path, "IN")

    # Clean previous instances
    execute_cmd(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_out}"])
    execute_cmd(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_in}"])

    cmd_out = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_out}",
        "dir=out",
        "action=block",
        f"program={exe_path}",
        "enable=yes",
        "profile=any",
        "protocol=any"
    ]
    cmd_in = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_in}",
        "dir=in",
        "action=block",
        f"program={exe_path}",
        "enable=yes",
        "profile=any",
        "protocol=any"
    ]
    r1 = execute_cmd(cmd_out)
    r2 = execute_cmd(cmd_in)
    return r1.returncode == 0 and r2.returncode == 0

def unblock_file(exe_path):
    """Delete isolation rules from Windows Firewall."""
    rule_out = generate_rule_name(exe_path, "OUT")
    rule_in = generate_rule_name(exe_path, "IN")
    execute_cmd(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_out}"])
    execute_cmd(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_in}"])

def terminate_process_by_path(exe_path):
    """Terminate running process instances strictly matching the exact executable path."""
    norm = os.path.normpath(exe_path).replace("'", "''")
    ps = (
        f"$target = '{norm}'; "
        "Get-Process | Where-Object { "
        "  try { $_.Path -and ($_.Path -eq $target) } catch { $false } "
        "} | Stop-Process -Force -ErrorAction SilentlyContinue"
    )
    flags = 0x08000000 if sys.platform == "win32" else 0
    subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=flags
    )

def get_running_process_paths():
    """Retrieve normalized paths of all currently running processes."""
    ps = "Get-Process | Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue"
    flags = 0x08000000 if sys.platform == "win32" else 0
    res = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=flags,
        text=True
    )
    if res.returncode == 0:
        return {os.path.normpath(line.strip()).lower() for line in res.stdout.splitlines() if line.strip()}
    return set()

def clear_all_tool_rules():
    """Emergency reset: purge all NetGag_* rules system-wide."""
    ps_cmd = f'Get-NetFirewallRule -DisplayName "{RULE_PREFIX}*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue'
    flags = 0x08000000 if sys.platform == "win32" else 0
    subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=flags
    )


class NetGagApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NetGag - Network Isolator")
        self.geometry("920x560")
        self.minsize(740, 420)

        # File store: key = normalized full path, value = dict(name, size, blocked, running)
        self.tracked_files = {}
        self.opt_recursive_folder = tk.BooleanVar(value=True)
        self.opt_kill_proc = tk.BooleanVar(value=True)
        self.is_busy = False

        self.apply_theme()
        self.build_menu()
        self.build_ui()

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

        # File Menu
        m_file = tk.Menu(menubar, tearoff=0)
        m_file.add_command(label="Add File(s)...", accelerator="Ctrl+O", command=self.on_add_files)
        m_file.add_command(label="Add Folder...", accelerator="Ctrl+Shift+O", command=self.on_add_folder)
        m_file.add_separator()
        m_file.add_command(label="Remove Selected from List", accelerator="Del", command=self.on_remove_selected)
        m_file.add_command(label="Clear List", command=self.on_clear_list)
        m_file.add_separator()
        m_file.add_command(label="Exit", accelerator="Alt+F4", command=self.destroy)
        menubar.add_cascade(label="File", menu=m_file)

        # Operations Menu
        m_ops = tk.Menu(menubar, tearoff=0)
        m_ops.add_command(label="Block Selected", accelerator="Ctrl+B", command=self.on_block_selected)
        m_ops.add_command(label="Unblock Selected", accelerator="Ctrl+U", command=self.on_unblock_selected)
        m_ops.add_separator()
        m_ops.add_command(label="Block All in List", command=self.on_block_all)
        m_ops.add_command(label="Unblock All in List", command=self.on_unblock_all)
        m_ops.add_separator()
        m_ops.add_command(label="Refresh Status", accelerator="F5", command=self.refresh_tracked_files)
        m_ops.add_command(label="Purge All NetGag Rules System-Wide...", command=self.on_purge_all_rules)
        menubar.add_cascade(label="Operations", menu=m_ops)

        # Tools Menu
        m_tools = tk.Menu(menubar, tearoff=0)
        m_tools.add_command(label="Open Windows Advanced Firewall...", command=lambda: subprocess.Popen(["wf.msc"], shell=True))
        menubar.add_cascade(label="Tools", menu=m_tools)

        self.config(menu=menubar)

        # Keyboard shortcuts
        self.bind("<Control-o>", lambda e: self.on_add_files())
        self.bind("<Control-O>", lambda e: self.on_add_folder())
        self.bind("<Control-b>", lambda e: self.on_block_selected())
        self.bind("<Control-u>", lambda e: self.on_unblock_selected())
        self.bind("<Delete>", lambda e: self.on_remove_selected())
        self.bind("<F5>", lambda e: self.refresh_tracked_files())
        self.bind("<Control-a>", self.on_select_all)

    def build_ui(self):
        # 1. Top Toolbar
        toolbar = ttk.Frame(self, padding=(10, 8, 10, 4))
        toolbar.pack(fill="x")

        # Left controls: Import buttons
        btn_add_files = ttk.Button(toolbar, text="Add File(s)...", width=13, command=self.on_add_files)
        btn_add_files.pack(side="left", padx=(0, 4))

        btn_add_dir = ttk.Button(toolbar, text="Add Folder...", width=13, command=self.on_add_folder)
        btn_add_dir.pack(side="left", padx=4)

        btn_remove = ttk.Button(toolbar, text="Remove", width=9, command=self.on_remove_selected)
        btn_remove.pack(side="left", padx=4)

        btn_clear = ttk.Button(toolbar, text="Clear List", width=10, command=self.on_clear_list)
        btn_clear.pack(side="left", padx=4)

        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=8)

        # Middle controls: Block/Unblock actions
        self.btn_block = ttk.Button(toolbar, text="Block Selected", style="Primary.TButton", width=15, command=self.on_block_selected)
        self.btn_block.pack(side="left", padx=4)

        self.btn_unblock = ttk.Button(toolbar, text="Unblock Selected", width=16, command=self.on_unblock_selected)
        self.btn_unblock.pack(side="left", padx=4)

        self.btn_refresh = ttk.Button(toolbar, text="Refresh", width=9, command=self.refresh_tracked_files)
        self.btn_refresh.pack(side="left", padx=4)

        # 2. Options Bar
        opt_bar = ttk.Frame(self, padding=(10, 0, 10, 6))
        opt_bar.pack(fill="x")

        chk_recurse = ttk.Checkbutton(opt_bar, text="Scan subfolders when adding directory", variable=self.opt_recursive_folder)
        chk_recurse.pack(side="left", padx=(0, 14))

        chk_kill = ttk.Checkbutton(opt_bar, text="Terminate active process before blocking (ensures offline start)", variable=self.opt_kill_proc)
        chk_kill.pack(side="left")

        # 3. Main Data Table
        table_frame = ttk.Frame(self, padding=(10, 0, 10, 6))
        table_frame.pack(fill="both", expand=True)

        cols = ("name", "status", "process", "size", "path")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="extended")

        self.tree.heading("name", text="Executable", command=lambda: self.sort_column("name", False))
        self.tree.heading("status", text="Network State", command=lambda: self.sort_column("status", False))
        self.tree.heading("process", text="Process State", command=lambda: self.sort_column("process", False))
        self.tree.heading("size", text="File Size", command=lambda: self.sort_column("size", False))
        self.tree.heading("path", text="Full Path", command=lambda: self.sort_column("path", False))

        self.tree.column("name", width=180, anchor="w")
        self.tree.column("status", width=110, anchor="center")
        self.tree.column("process", width=100, anchor="center")
        self.tree.column("size", width=90, anchor="e")
        self.tree.column("path", width=420, anchor="w")

        # Visual state tagging (dark red for blocked, dark green for allowed, subtle blue for running)
        self.tree.tag_configure("blocked", foreground="#9a1515")
        self.tree.tag_configure("allowed", foreground="#176329")

        scroll_y = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        scroll_x = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        # Context Menu
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Block", command=self.on_block_selected)
        self.context_menu.add_command(label="Unblock", command=self.on_unblock_selected)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Open File Location", command=self.on_open_file_location)
        self.context_menu.add_command(label="Remove from List", command=self.on_remove_selected)
        self.tree.bind("<Button-3>", self.on_right_click)

        # 4. Status Bar
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

    def set_busy_state(self, busy):
        self.is_busy = busy
        st = "disabled" if busy else "normal"
        self.btn_block.config(state=st)
        self.btn_unblock.config(state=st)
        self.btn_refresh.config(state=st)

    def on_select_all(self, event=None):
        self.tree.selection_set(self.tree.get_children())
        return "break"

    def on_right_click(self, event):
        row_id = self.tree.identify_row(event.y)
        if row_id:
            if row_id not in self.tree.selection():
                self.tree.selection_set(row_id)
            self.context_menu.post(event.x_root, event.y_root)

    def on_open_file_location(self):
        selected = self.get_selected_paths()
        if selected:
            first_path = selected[0]
            if os.path.exists(first_path):
                subprocess.Popen(f'explorer /select,"{first_path}"')

    def on_add_files(self):
        files = filedialog.askopenfilenames(
            title="Select Executable(s) to Add to NetGag",
            filetypes=[("Executable Files (*.exe)", "*.exe"), ("All Files (*.*)", "*.*")]
        )
        if files:
            for f in files:
                norm = os.path.normpath(f)
                if norm not in self.tracked_files:
                    self.tracked_files[norm] = {}
            self.refresh_tracked_files()

    def on_add_folder(self):
        folder = filedialog.askdirectory(title="Select Folder to Add to NetGag")
        if folder:
            norm_folder = os.path.normpath(folder)
            recursive = self.opt_recursive_folder.get()
            found = []
            if recursive:
                for root, _, files in os.walk(norm_folder):
                    for f in files:
                        if f.lower().endswith(".exe"):
                            found.append(os.path.normpath(os.path.join(root, f)))
            else:
                try:
                    for item in os.listdir(norm_folder):
                        full = os.path.normpath(os.path.join(norm_folder, item))
                        if os.path.isfile(full) and item.lower().endswith(".exe"):
                            found.append(full)
                except Exception:
                    pass

            if not found:
                messagebox.showinfo("NetGag", "No .exe files found in selected directory.")
                return

            for f in found:
                if f not in self.tracked_files:
                    self.tracked_files[f] = {}
            self.refresh_tracked_files()

    def on_remove_selected(self):
        selected = self.get_selected_paths()
        for path in selected:
            if path in self.tracked_files:
                del self.tracked_files[path]
        self.render_table()

    def on_clear_list(self):
        self.tracked_files.clear()
        self.render_table()

    def get_selected_paths(self):
        selected_iids = self.tree.selection()
        paths = []
        for iid in selected_iids:
            item = self.tree.item(iid)
            if item and item.get("values"):
                full_path = item["values"][4]
                paths.append(full_path)
        return paths

    def refresh_tracked_files(self):
        if not self.tracked_files:
            self.render_table()
            return
        if self.is_busy:
            return

        self.set_busy_state(True)
        self.status_msg.config(text="Querying Windows Firewall and process status...")
        paths = list(self.tracked_files.keys())
        threading.Thread(target=self._worker_refresh, args=(paths,), daemon=True).start()

    def _worker_refresh(self, paths):
        running_set = get_running_process_paths()
        updated_data = {}

        for p in paths:
            if not os.path.exists(p):
                continue
            is_blocked = check_file_blocked(p)
            is_running = os.path.normpath(p).lower() in running_set
            
            try:
                raw_size = os.path.getsize(p)
                size_mb = raw_size / (1024 * 1024)
                size_str = f"{size_mb:.2f} MB" if size_mb >= 1.0 else f"{raw_size / 1024:.1f} KB"
            except OSError:
                size_str = "N/A"

            updated_data[p] = {
                "name": os.path.basename(p),
                "blocked": is_blocked,
                "running": is_running,
                "size": size_str,
                "path": p
            }

        self.after(0, self._apply_refresh_results, updated_data)

    def _apply_refresh_results(self, updated_data):
        self.tracked_files = updated_data
        self.render_table()
        self.set_busy_state(False)
        self.status_msg.config(text="Ready.")

    def render_table(self):
        self.tree.delete(*self.tree.get_children())
        blocked_count = 0

        for path, info in self.tracked_files.items():
            is_blocked = info.get("blocked", False)
            is_running = info.get("running", False)

            if is_blocked:
                blocked_count += 1

            status_str = "Blocked" if is_blocked else "Allowed"
            proc_str = "Running" if is_running else "Stopped"
            tag = "blocked" if is_blocked else "allowed"

            self.tree.insert(
                "",
                "end",
                values=(
                    info.get("name", os.path.basename(path)),
                    status_str,
                    proc_str,
                    info.get("size", "-"),
                    path
                ),
                tags=(tag,)
            )

        total = len(self.tracked_files)
        self.status_items.config(text=f"Items: {total}")
        self.status_blocked.config(text=f"Blocked: {blocked_count}")

    def on_block_selected(self):
        targets = self.get_selected_paths()
        if not targets:
            # Fallback to all if nothing specifically highlighted
            targets = list(self.tracked_files.keys())
        if not targets:
            messagebox.showinfo("NetGag", "No executables available to block.")
            return

        self.set_busy_state(True)
        threading.Thread(target=self._worker_block, args=(targets, self.opt_kill_proc.get()), daemon=True).start()

    def on_block_all(self):
        targets = list(self.tracked_files.keys())
        if not targets:
            messagebox.showinfo("NetGag", "No executables in list to block.")
            return

        self.set_busy_state(True)
        threading.Thread(target=self._worker_block, args=(targets, self.opt_kill_proc.get()), daemon=True).start()

    def _worker_block(self, targets, kill_proc):
        total = len(targets)
        for i, path in enumerate(targets, 1):
            fn = os.path.basename(path)
            if kill_proc:
                self.after(0, lambda name=fn: self.status_msg.config(text=f"Terminating active process: {name}..."))
                terminate_process_by_path(path)

            self.after(0, lambda idx=i, count=total, name=fn: self.status_msg.config(text=f"Blocking ({idx}/{count}): {name}"))
            block_file(path)

        self.after(0, self.refresh_tracked_files)

    def on_unblock_selected(self):
        targets = self.get_selected_paths()
        if not targets:
            targets = list(self.tracked_files.keys())
        if not targets:
            messagebox.showinfo("NetGag", "No executables available to unblock.")
            return

        self.set_busy_state(True)
        threading.Thread(target=self._worker_unblock, args=(targets,), daemon=True).start()

    def on_unblock_all(self):
        targets = list(self.tracked_files.keys())
        if not targets:
            messagebox.showinfo("NetGag", "No executables in list to unblock.")
            return

        self.set_busy_state(True)
        threading.Thread(target=self._worker_unblock, args=(targets,), daemon=True).start()

    def _worker_unblock(self, targets):
        total = len(targets)
        for i, path in enumerate(targets, 1):
            fn = os.path.basename(path)
            self.after(0, lambda idx=i, count=total, name=fn: self.status_msg.config(text=f"Unblocking ({idx}/{count}): {name}"))
            unblock_file(path)

        self.after(0, self.refresh_tracked_files)

    def on_purge_all_rules(self):
        confirm = messagebox.askyesno(
            "Confirm Global Reset",
            "This will delete ALL 'NetGag_*' firewall rules across the entire operating system.\n\nProceed?",
            icon="warning"
        )
        if confirm:
            self.set_busy_state(True)
            self.status_msg.config(text="Purging NetGag firewall rules...")
            threading.Thread(target=self._worker_purge, daemon=True).start()

    def _worker_purge(self):
        clear_all_tool_rules()
        self.after(0, self.refresh_tracked_files)

    def sort_column(self, col, reverse):
        items = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        try:
            # Try numeric sort for size
            items.sort(key=lambda t: float(t[0].split()[0]), reverse=reverse)
        except Exception:
            items.sort(reverse=reverse)

        for index, (_, k) in enumerate(items):
            self.tree.move(k, "", index)

        self.tree.heading(col, command=lambda: self.sort_column(col, not reverse))


if __name__ == "__main__":
    elevate_if_needed()
    set_high_dpi()
    app = NetGagApp()
    app.mainloop()