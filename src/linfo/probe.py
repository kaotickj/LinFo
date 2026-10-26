"""Bounded, cancellable local probes. No shell interpolation or network probes."""
from __future__ import annotations
from dataclasses import dataclass
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import threading
import time

SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
OUTPUT_LIMIT = 262144
_ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def clean_text(value: str) -> str:
    return _CONTROL.sub("", _ANSI.sub("", value))


class ProbeCancelled(Exception):
    """The user cancelled, or the cooperative scan deadline elapsed."""


@dataclass(frozen=True)
class Result:
    ok: bool
    out: str = ""
    error: str = ""
    returncode: int | None = None
    timed_out: bool = False
    truncated: bool = False
    missing: bool = False
    cancelled: bool = False


class Probe:
    def __init__(self, cancel_event: threading.Event | None = None, timeout: float = 180.0):
        self.cache: dict[tuple[str, ...], Result] = {}
        self.cancel_event = cancel_event if cancel_event is not None else threading.Event()
        self.deadline = time.monotonic() + timeout
        self.cancel_reason = ""
        self.errors: list[str] = []
        self.read_issues: dict[str, str] = {}

    def check_cancelled(self) -> None:
        if self.cancel_event.is_set():
            self.cancel_reason = "Cancelled by the user"
        elif time.monotonic() >= self.deadline:
            self.cancel_reason = "Total assessment time limit reached"
        if self.cancel_reason:
            raise ProbeCancelled(self.cancel_reason)

    def which(self, name: str) -> str | None:
        return shutil.which(name, path=SYSTEM_PATH)

    @staticmethod
    def _stop(process: subprocess.Popen) -> None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            process.wait(timeout=0.2)
        except subprocess.TimeoutExpired:
            pass
        # Grandchildren can retain pipes even when their parent has exited.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            pass

    def run(self, *args: str, timeout: float = 6.0, cache: bool = True) -> Result:
        self.check_cancelled()
        if not args or any(not isinstance(arg, str) for arg in args):
            return Result(False, error="Commands require a nonempty sequence of string arguments.")
        key = tuple(args)
        if cache and key in self.cache:
            return self.cache[key]
        executable = self.which(args[0])
        if not executable:
            return Result(False, error=f"Command not found: {args[0]}", missing=True)
        end = min(self.deadline, time.monotonic() + max(0.05, timeout))
        env = dict(os.environ)
        for name in list(env):
            if name.startswith("LD_") or name in {"PYTHONPATH", "PYTHONHOME", "BASH_ENV", "ENV", "PERL5LIB", "PERL5OPT", "RUBYLIB", "RUBYOPT", "NODE_OPTIONS"}:
                env.pop(name, None)
        env.update(LC_ALL="C", LANG="C", PATH=SYSTEM_PATH, PAGER="cat", SYSTEMD_PAGER="cat", SYSTEMD_COLORS="0")
        stdout, stderr = bytearray(), bytearray()
        process = None
        selector = selectors.DefaultSelector()
        timed_out = truncated = False
        failure = ""
        code = None
        try:
            process = subprocess.Popen((executable, *args[1:]), stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       env=env, start_new_session=True, close_fds=True)
            for stream, target in ((process.stdout, stdout), (process.stderr, stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, target)
            while selector.get_map() or process.poll() is None:
                self.check_cancelled()
                if time.monotonic() >= end:
                    timed_out = True
                    self._stop(process)
                    break
                if not selector.get_map():
                    try:
                        process.wait(timeout=0.05)
                    except subprocess.TimeoutExpired:
                        pass
                    continue
                for item, _ in selector.select(timeout=min(0.1, max(0, end - time.monotonic()))):
                    try:
                        block = os.read(item.fd, 65536)
                    except BlockingIOError:
                        continue
                    if not block:
                        selector.unregister(item.fileobj)
                        continue
                    available = OUTPUT_LIMIT - len(item.data)
                    item.data.extend(block[:max(0, available)])
                    truncated |= len(block) > available
            code = process.poll()
        except ProbeCancelled:
            if process:
                self._stop(process)
            raise
        except OSError as exc:
            failure = f"{type(exc).__name__}: {exc.strerror or str(exc)}"
            if process:
                self._stop(process)
        finally:
            selector.close()
            if process:
                if process.poll() is None:
                    self._stop(process)
                for stream in (process.stdout, process.stderr):
                    if stream:
                        stream.close()
        diagnostics = []
        if failure:
            diagnostics.append(failure)
        if timed_out:
            diagnostics.append("Command time limit reached; output may be incomplete.")
        if truncated:
            diagnostics.append("Output limit reached; result is incomplete.")
        err = clean_text(stderr.decode("utf-8", errors="replace"))[:1500]
        if err:
            diagnostics.append(err)
        if timed_out or truncated or failure:
            # Keep cross-report collection metadata free of command stderr, which
            # can include repository URLs or other sensitive configuration values.
            limits = [failure] if failure else []
            if timed_out:
                limits.append("command time limit reached")
            if truncated:
                limits.append("output limit reached")
            self.errors.append(f"{args[0]}: " + "; ".join(limits))
        result = Result(code == 0 and not (failure or timed_out or truncated),
                        clean_text(stdout.decode("utf-8", errors="replace")),
                        " ".join(diagnostics), code, timed_out, truncated)
        if cache:
            self.cache[key] = result
        self.check_cancelled()
        return result

    def read(self, path: str, max_size: int = 120_000) -> str | None:
        self.check_cancelled()
        path = str(path)
        if not 1 <= max_size <= 8388608:
            raise ValueError("Text size limit must be between 1 byte and 8 MiB.")
        fd = None
        try:
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                self.read_issues[path] = "Not a regular file; devices, sockets and pipes are not read"
                return None
            data = bytearray()
            while len(data) <= max_size:
                self.check_cancelled()
                block = os.read(fd, min(65536, max_size + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            if len(data) > max_size:
                self.read_issues[path] = "Text size limit exceeded; partial content was not evaluated"
                self.errors.append(f"{path}: {self.read_issues[path]}")
                return None
            return clean_text(data.decode("utf-8", errors="replace"))
        except OSError as exc:
            self.read_issues[path] = f"{type(exc).__name__}: {exc.strerror or str(exc)}"
            if not isinstance(exc, FileNotFoundError):
                self.errors.append(f"{path}: {self.read_issues[path]}")
            return None
        finally:
            if fd is not None:
                os.close(fd)

    def sysctl(self, key: str) -> str | None:
        if not key or any(x not in "abcdefghijklmnopqrstuvwxyz0123456789_." for x in key):
            return None
        raw = self.read("/proc/sys/" + key.replace(".", "/"), 200)
        return raw.strip() if raw is not None else None
