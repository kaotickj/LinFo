"""Constrained, bounded local probes. No shell=True or network requests."""
from __future__ import annotations
from dataclasses import dataclass
import os
import shutil
import subprocess


@dataclass(frozen=True)
class Result:
    ok: bool
    out: str = ""
    error: str = ""
    returncode: int | None = None


class Probe:
    def __init__(self):
        self.cache: dict[tuple[str, ...], Result] = {}

    def which(self, name: str) -> str | None:
        return shutil.which(name)

    def run(self, *args: str, timeout: float = 6.0, cache: bool = True) -> Result:
        key = tuple(args)
        if cache and key in self.cache:
            return self.cache[key]
        if not args or not self.which(args[0]) and not os.path.isabs(args[0]):
            return Result(False, error=f"Command not found: {args[0] if args else '(none)'}")
        try:
            cp = subprocess.run(args, capture_output=True, text=True, errors="replace",
                                timeout=timeout, check=False, stdin=subprocess.DEVNULL)
            result = Result(cp.returncode == 0, cp.stdout[:18000], cp.stderr[:1500], cp.returncode)
        except (FileNotFoundError, PermissionError, OSError, subprocess.TimeoutExpired) as exc:
            result = Result(False, error=str(exc)[:400])
        if cache:
            self.cache[key] = result
        return result

    @staticmethod
    def read(path: str, max_size: int = 120_000) -> str | None:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read(max_size)
        except (OSError, UnicodeError):
            return None

    @staticmethod
    def sysctl(key: str) -> str | None:
        # Only called with constant paths from LinFo's check definitions.
        if not key or any(x not in "abcdefghijklmnopqrstuvwxyz0123456789_." for x in key):
            return None
        path = "/proc/sys/" + key.replace(".", "/")
        raw = Probe.read(path, 200)
        return raw.strip() if raw is not None else None
