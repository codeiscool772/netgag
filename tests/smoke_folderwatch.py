"""Non-elevated check that FolderWatcher actually reacts to a new file within
a second or two, instead of trusting the ctypes plumbing blindly.

Run: python -m tests.smoke_folderwatch
"""
import os
import queue
import tempfile
import time

from netgag.folderwatch import FolderWatcher


def main():
    events = queue.Queue()
    watcher = FolderWatcher(lambda path: events.put(path))
    watcher.start()

    with tempfile.TemporaryDirectory() as root:
        watcher.set_folders([(root, True)])
        time.sleep(0.3)   # let the watch thread arm the handle

        new_file = os.path.join(root, "new.exe")
        with open(new_file, "wb"):
            pass

        try:
            seen = events.get(timeout=3)
        except queue.Empty:
            print("FAIL: no change notification arrived within 3 seconds")
            watcher.stop()
            return 1
        assert os.path.normcase(seen) == os.path.normcase(root), (seen, root)
        print(f"[ok] change notification fired within 3s for: {seen}")

        # Also confirm it stops noticing after being told to watch nothing.
        # Windows can fire more than one notification for a single file
        # operation, so drain and settle before checking for silence -
        # otherwise a late duplicate about new.exe could be mistaken for
        # evidence the unwatch didn't work.
        watcher.set_folders([])
        time.sleep(1.0)
        while not events.empty():
            events.get_nowait()

        with open(os.path.join(root, "another.exe"), "wb"):
            pass
        try:
            leftover = events.get(timeout=2)
            print(f"FAIL: still got a notification after unwatching the folder: {leftover}")
            watcher.stop()
            return 1
        except queue.Empty:
            print("[ok] no notification after the folder was unwatched")

    watcher.stop()
    print("ALL FOLDER-WATCH CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
