"""Persistent settings stored in %APPDATA%\\NetGag\\config.json."""

import json
import logging
import os

log = logging.getLogger(__name__)

DEFAULTS = {
    "files": [],
    "watched_folders": [],   # [{"path": str, "recursive": bool, "exts": [".exe", ...]}]
    "ignored": [],           # norm_key()s the user removed; folder watching skips them
    "interpreters": {},      # {".rb": r"C:\Ruby\bin\ruby.exe"} user-chosen interpreters
    "folder_types": [".exe"],  # file types pre-selected in the Add Folder dialog
    "recursive": True,
    "kill_process": True,
    "size": "920x560",
}


def config_dir():
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    return os.path.join(base, "NetGag")


def config_path():
    return os.path.join(config_dir(), "config.json")


def _str_list(value):
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def load(path=None):
    """Load settings, falling back to defaults for anything missing or malformed."""
    cfg = json.loads(json.dumps(DEFAULTS))  # deep copy
    try:
        with open(path or config_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return cfg
    if not isinstance(data, dict):
        return cfg

    if isinstance(data.get("files"), list):
        cfg["files"] = [f for f in data["files"] if isinstance(f, str)]
    if isinstance(data.get("watched_folders"), list):
        cfg["watched_folders"] = [
            {
                "path": w["path"],
                "recursive": bool(w.get("recursive", True)),
                "exts": _str_list(w.get("exts")) or [".exe"],
            }
            for w in data["watched_folders"]
            if isinstance(w, dict) and isinstance(w.get("path"), str)
        ]
    if isinstance(data.get("interpreters"), dict):
        cfg["interpreters"] = {k.lower(): v for k, v in data["interpreters"].items()
                               if isinstance(k, str) and isinstance(v, str)}
    if _str_list(data.get("folder_types")):
        cfg["folder_types"] = _str_list(data["folder_types"])
    if isinstance(data.get("ignored"), list):
        cfg["ignored"] = [k for k in data["ignored"] if isinstance(k, str)]
    for key in ("recursive", "kill_process"):
        if isinstance(data.get(key), bool):
            cfg[key] = data[key]
    if isinstance(data.get("size"), str):
        cfg["size"] = data["size"]
    return cfg


def save(cfg, path=None):
    """Atomically write settings (write to a temp file, then replace)."""
    target = path or config_path()
    os.makedirs(os.path.dirname(target), exist_ok=True)
    tmp = target + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
    os.replace(tmp, target)
