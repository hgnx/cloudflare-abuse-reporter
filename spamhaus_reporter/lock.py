from __future__ import annotations

import os
from pathlib import Path


class AlreadyRunningError(RuntimeError):
    pass


class ProcessLock:
    """Non-blocking single-process lock for scheduled/manual overlap protection."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.fd: int | None = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if os.name == "nt":
                import msvcrt
                try:
                    msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
                except OSError as exc:
                    raise AlreadyRunningError(f"Another reporter process holds {self.path}") from exc
            else:
                import fcntl
                try:
                    fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as exc:
                    raise AlreadyRunningError(f"Another reporter process holds {self.path}") from exc
            os.ftruncate(self.fd, 0)
            os.write(self.fd, f"{os.getpid()}\n".encode())
            os.fsync(self.fd)
            return self
        except Exception:
            os.close(self.fd)
            self.fd = None
            raise

    def __exit__(self, exc_type, exc, tb):
        if self.fd is None:
            return
        try:
            if os.name == "nt":
                import msvcrt
                os.lseek(self.fd, 0, os.SEEK_SET)
                msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fd, fcntl.LOCK_UN)
        finally:
            os.close(self.fd)
            self.fd = None
