"""Small persistent key/value cache (SQLite, standard library).

Everything fetched from the network (OWASP data, CVE records, exploited-vuln
lists...) is cached so repeat runs are fast and the tool degrades gracefully
offline.  If the cache directory is not writable the cache silently becomes
in-memory only; it never makes a scan fail.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


def default_cache_dir() -> Path:
    override = os.environ.get("VULNSCAN_CACHE_DIR")
    if override:
        return Path(override)
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "vulnscan"
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "vulnscan"


class Cache:
    def __init__(self, root: Optional[os.PathLike] = None) -> None:
        self.root = Path(root) if root else default_cache_dir()
        self._lock = threading.Lock()
        self._mem: Dict[str, Tuple[float, str]] = {}
        self._db: Optional[sqlite3.Connection] = None
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            db = sqlite3.connect(str(self.root / "cache.sqlite3"), check_same_thread=False)
            db.execute("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, ts REAL NOT NULL, value TEXT NOT NULL)")
            db.commit()
            self._db = db
        except (OSError, sqlite3.Error):
            self._db = None

    @property
    def persistent(self) -> bool:
        return self._db is not None

    def _get_raw(self, key: str) -> Optional[Tuple[float, str]]:
        with self._lock:
            if self._db is not None:
                try:
                    row = self._db.execute("SELECT ts, value FROM kv WHERE key=?", (key,)).fetchone()
                    return (row[0], row[1]) if row else None
                except sqlite3.Error:
                    return None
            return self._mem.get(key)

    def get(self, key: str, max_age: Optional[float] = None) -> Optional[Any]:
        """Return the cached object, or None if missing / older than max_age seconds."""
        raw = self._get_raw(key)
        if raw is None:
            return None
        ts, value = raw
        if max_age is not None and time.time() - ts > max_age:
            return None
        try:
            return json.loads(value)
        except ValueError:
            return None

    def age(self, key: str) -> Optional[float]:
        raw = self._get_raw(key)
        return None if raw is None else max(0.0, time.time() - raw[0])

    def set(self, key: str, obj: Any) -> None:
        value = json.dumps(obj, separators=(",", ":"))
        now = time.time()
        with self._lock:
            if self._db is not None:
                try:
                    self._db.execute("INSERT OR REPLACE INTO kv (key, ts, value) VALUES (?,?,?)",
                                     (key, now, value))
                    self._db.commit()
                    return
                except sqlite3.Error:
                    pass
            self._mem[key] = (now, value)

    def clear(self) -> None:
        with self._lock:
            self._mem.clear()
            if self._db is not None:
                try:
                    self._db.execute("DELETE FROM kv")
                    self._db.commit()
                except sqlite3.Error:
                    pass
