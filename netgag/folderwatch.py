"""Reacts to new files in watched folders using FindFirstChangeNotificationW
instead of polling on a timer - a new file gets picked up within milliseconds
instead of up to 60 seconds, and nothing runs at all while nothing changes.
"""

import ctypes
import logging
import threading
from ctypes import wintypes

log = logging.getLogger(__name__)

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.FindFirstChangeNotificationW.argtypes = [wintypes.LPCWSTR, wintypes.BOOL, wintypes.DWORD]
kernel32.FindFirstChangeNotificationW.restype = wintypes.HANDLE
kernel32.FindNextChangeNotification.argtypes = [wintypes.HANDLE]
kernel32.FindNextChangeNotification.restype = wintypes.BOOL
kernel32.FindCloseChangeNotification.argtypes = [wintypes.HANDLE]
kernel32.FindCloseChangeNotification.restype = wintypes.BOOL
kernel32.WaitForMultipleObjects.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
                                            wintypes.BOOL, wintypes.DWORD]
kernel32.WaitForMultipleObjects.restype = wintypes.DWORD
kernel32.CreateEventW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.CreateEventW.restype = wintypes.HANDLE
kernel32.SetEvent.argtypes = [wintypes.HANDLE]
kernel32.SetEvent.restype = wintypes.BOOL
kernel32.ResetEvent.argtypes = [wintypes.HANDLE]
kernel32.ResetEvent.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102
WAIT_FAILED = 0xFFFFFFFF
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
# WaitForMultipleObjects caps at 64 handles; we reserve 2 (stop + rebuild), so
# this many folders can be watched reactively at once. Fewer than that is the
# overwhelmingly common case for a personal utility like this.
MAX_FOLDERS = 62


class FolderWatcher:
    """Watches a set of (path, recursive) folders; calls on_change(path) from
    a background thread the instant something changes in one of them. Also
    fires a periodic safety-net call (every SAFETY_POLL_MS) in case a real
    change notification is ever missed (rare, but FindFirstChangeNotification
    gives no absolute guarantee under very high churn)."""

    SAFETY_POLL_MS = 5 * 60 * 1000

    def __init__(self, on_change):
        self._on_change = on_change
        self._lock = threading.Lock()
        self._folders = {}   # path -> (handle, recursive)
        self._stop_event = kernel32.CreateEventW(None, True, False, None)
        self._rebuild_event = kernel32.CreateEventW(None, True, False, None)
        self._thread = None

    def start(self):
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()

    def stop(self):
        kernel32.SetEvent(self._stop_event)
        if self._thread:
            self._thread.join(timeout=2)
        with self._lock:
            for handle, _recursive in self._folders.values():
                kernel32.FindCloseChangeNotification(handle)
            self._folders.clear()

    def set_folders(self, entries):
        """entries: iterable of (path, recursive). Replaces the watched set."""
        entries = list(entries)[:MAX_FOLDERS]
        with self._lock:
            wanted = {path for path, _r in entries}
            for path, (handle, _recursive) in list(self._folders.items()):
                if path not in wanted:
                    kernel32.FindCloseChangeNotification(handle)
                    del self._folders[path]
            for path, recursive in entries:
                if path in self._folders:
                    continue
                handle = kernel32.FindFirstChangeNotificationW(
                    path, bool(recursive), FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME)
                if handle and handle != INVALID_HANDLE_VALUE:
                    self._folders[path] = (handle, recursive)
                else:
                    log.warning("Could not watch folder for changes: %s", path)
        kernel32.SetEvent(self._rebuild_event)

    def _run(self):
        while True:
            with self._lock:
                items = list(self._folders.items())
            n = len(items) + 2
            handles = (wintypes.HANDLE * n)()
            handles[0] = self._stop_event
            handles[1] = self._rebuild_event
            for i, (_path, (handle, _recursive)) in enumerate(items):
                handles[2 + i] = handle

            result = kernel32.WaitForMultipleObjects(n, handles, False, self.SAFETY_POLL_MS)
            if result == WAIT_OBJECT_0:                      # stop requested
                return
            if result == WAIT_OBJECT_0 + 1:                  # folder set changed - just re-arm
                kernel32.ResetEvent(self._rebuild_event)
                continue
            if result == WAIT_TIMEOUT:                        # safety-net tick
                for path, _r in items:
                    self._safe_notify(path)
                continue
            if result == WAIT_FAILED or not (WAIT_OBJECT_0 + 2 <= result < WAIT_OBJECT_0 + n):
                continue                                      # transient error: just loop

            idx = result - (WAIT_OBJECT_0 + 2)
            path, (handle, _recursive) = items[idx]
            kernel32.FindNextChangeNotification(handle)        # re-arm this one
            self._safe_notify(path)

    def _safe_notify(self, path):
        try:
            self._on_change(path)
        except Exception:  # noqa: BLE001 - never let a callback kill the watcher thread
            log.exception("Folder-watch callback failed for %s", path)
