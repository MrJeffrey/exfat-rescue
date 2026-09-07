"""Strictly read-only image file access."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .errors import OutputError, SourceError

ProgressCallback = Callable[[str, int, int, str], None]
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_POSIX_FADVISE = getattr(os, "posix_fadvise", None)
_POSIX_FADV_DONTNEED = getattr(os, "POSIX_FADV_DONTNEED", None)
_PROOF_STATE_FIELDS = (
    "device",
    "inode",
    "mode",
    "link_count",
    "owner",
    "size_bytes",
    "modified_ns",
    "changed_ns",
)


def _proof_state(state: os.stat_result) -> dict[str, int]:
    return {
        "device": state.st_dev,
        "inode": state.st_ino,
        "mode": state.st_mode,
        "link_count": state.st_nlink,
        "owner": state.st_uid,
        "size_bytes": state.st_size,
        "modified_ns": state.st_mtime_ns,
        "changed_ns": state.st_ctime_ns,
    }


def _release_file_cache(
    fd: int, offset: int, length: int, *, through_eof: bool = False
) -> bool:
    """Best-effort release of clean pages consumed by a one-pass file read."""
    if offset < 0 or length < 0:
        raise ValueError("cache-release extent is invalid")
    if length == 0:
        return True
    if _POSIX_FADVISE is None or _POSIX_FADV_DONTNEED is None:
        return False
    try:
        _POSIX_FADVISE(
            fd,
            offset,
            0 if through_eof else length,
            _POSIX_FADV_DONTNEED,
        )
    except OSError:
        return False
    return True


@dataclass(frozen=True)
class ImageSource:
    path: Path
    fd: int
    size: int
    device: int
    inode: int
    modified_ns: int
    changed_ns: int
    _selected_volume_digests: dict[tuple[int, int], str] = field(
        default_factory=dict, repr=False, compare=False
    )
    _progress: ProgressCallback | None = field(default=None, repr=False, compare=False)

    @classmethod
    def open(
        cls,
        value: str | Path,
        *,
        progress: ProgressCallback | None = None,
    ) -> ImageSource:
        path = Path(value)
        try:
            before = os.lstat(path)
        except OSError as exc:
            raise SourceError(f"Cannot read image '{path}': {exc.strerror}.") from exc
        if stat.S_ISLNK(before.st_mode):
            raise SourceError(
                "The image must be a regular file, not a symlink or block device."
            )
        if not stat.S_ISREG(before.st_mode):
            raise SourceError(
                "This release accepts a regular disk-image file only; block devices are not supported."
            )
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        fd: int | None = None
        try:
            fd = os.open(path, flags)
            after = os.fstat(fd)
        except OSError as exc:
            if fd is not None:
                os.close(fd)
            raise SourceError(
                f"Cannot safely open image '{path}': {exc.strerror}."
            ) from exc
        if not stat.S_ISREG(after.st_mode) or (before.st_dev, before.st_ino) != (
            after.st_dev,
            after.st_ino,
        ):
            os.close(fd)
            raise SourceError(
                "The image changed while opening; please retry with a stable regular file."
            )
        return cls(
            path=path,
            fd=fd,
            size=after.st_size,
            device=after.st_dev,
            inode=after.st_ino,
            modified_ns=after.st_mtime_ns,
            changed_ns=after.st_ctime_ns,
            _progress=progress,
        )

    def close(self) -> None:
        os.close(self.fd)

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            return b""
        try:
            return os.pread(self.fd, length, offset)
        except OSError as exc:
            raise SourceError(
                f"Could not read the image at byte offset {offset}: {exc.strerror}."
            ) from exc

    def read_exact(self, offset: int, length: int) -> bytes:
        """Read precisely *length* bytes or reject a truncated/mutable source.

        Recovery must never silently turn a short pread into a shorter output file.
        """
        if offset < 0 or length < 0 or offset + length > self.size:
            raise SourceError("The requested source extent is outside the image.")
        value = self.read_at(offset, length)
        if len(value) != length:
            raise SourceError(
                "The image was truncated or could not supply a complete requested extent."
            )
        return value

    def release_cache(self, offset: int, length: int) -> bool:
        """Release clean pages after a completed one-pass sequential read.

        Linux accounts source-image page cache to a constrained service. Without
        this hint, a multi-terabyte scan can reach ``memory.high`` and spend most
        of its time in direct reclaim even though the process has bounded RSS.
        Cache release is strictly a best-effort performance hint: unsupported
        platforms and filesystems continue with identical read semantics.
        """
        if offset < 0 or length < 0 or offset + length > self.size:
            raise ValueError("cache-release extent is outside the image")
        return _release_file_cache(self.fd, offset, length)

    def sha256_region(
        self, offset: int, length: int, *, chunk_size: int = 1024 * 1024
    ) -> str:
        """Return a bounded-memory SHA-256 of an exact region of the source image."""
        if offset < 0 or length < 0 or offset + length > self.size:
            raise SourceError("The selected exFAT volume is outside the image.")
        if chunk_size < 1:
            raise ValueError("chunk_size must be positive")
        digest = hashlib.sha256()
        remaining, position = length, offset
        reported = 0
        if self._progress is not None:
            self._progress("hash-volume", 0, length, "bytes")
        while remaining:
            count = min(remaining, chunk_size)
            digest.update(self.read_exact(position, count))
            self.release_cache(position, count)
            position += count
            remaining -= count
            completed = length - remaining
            if self._progress is not None and (
                completed == length or completed - reported >= 1024**3
            ):
                reported = completed
                self._progress("hash-volume", completed, length, "bytes")
        return digest.hexdigest()

    def selected_volume_sha256(self, offset: int, length: int) -> str:
        """Hash the selected volume once per unchanged open source descriptor.

        Planning, recovery, and verification deliberately ask for the same full
        content proof at several safety boundaries.  Re-reading a multi-terabyte
        image at each boundary adds no information while the exact same descriptor
        remains open and its security-relevant file state is unchanged.  Retain the
        first digest in memory and revalidate descriptor state before every reuse.
        A new process or newly opened source still performs a complete hash.
        """
        key = (offset, length)
        self.assert_unchanged()
        cached = self._selected_volume_digests.get(key)
        if cached is not None:
            return cached
        digest = self.sha256_region(offset, length)
        self.assert_unchanged()
        self._selected_volume_digests[key] = digest
        return digest

    def remember_selected_volume_digest(
        self, offset: int, length: int, digest: str
    ) -> None:
        """Retain a digest computed while another complete source pass was in flight.

        The scanner reads the cluster heap once in physical order.  It can therefore
        hash those same bytes without a second I/O pass, provided it also hashes the
        bounded regions before and after the heap.  Only accept that result after the
        opened descriptor has been revalidated.  A conflicting proof already seeded
        by resume metadata is a hard source mismatch, not a cache replacement.
        """
        self.assert_unchanged()
        if (
            offset < 0
            or length < 0
            or offset + length > self.size
            or not isinstance(digest, str)
            or not _SHA256.fullmatch(digest)
        ):
            raise SourceError("The scanned selected-volume digest is malformed.")
        key = (offset, length)
        cached = self._selected_volume_digests.get(key)
        if cached is not None and cached != digest:
            raise SourceError(
                "The selected exFAT volume does not match its recorded content proof."
            )
        self._selected_volume_digests[key] = digest

    def proof_state(self) -> dict[str, int]:
        """Return exact local file state suitable for conservative digest reuse."""
        self.assert_unchanged()
        try:
            current = os.fstat(self.fd)
        except OSError as exc:
            raise SourceError(
                f"Could not inspect the opened image: {exc.strerror}."
            ) from exc
        return _proof_state(current)

    def reuse_selected_volume_digest(
        self,
        offset: int,
        length: int,
        digest: str,
        proof: object,
    ) -> bool:
        """Seed an earlier digest only for the exact same unchanged local file state.

        This deliberately returns ``False`` for malformed, stale, copied, or replaced
        state so callers can transparently fall back to a complete hash.
        """
        self.assert_unchanged()
        if (
            offset < 0
            or length < 0
            or offset + length > self.size
            or not isinstance(digest, str)
            or not _SHA256.fullmatch(digest)
            or not isinstance(proof, dict)
            or set(proof) != set(_PROOF_STATE_FIELDS)
            or any(type(proof[field]) is not int for field in _PROOF_STATE_FIELDS)
        ):
            return False
        try:
            current = os.fstat(self.fd)
        except OSError as exc:
            raise SourceError(
                f"Could not inspect the opened image: {exc.strerror}."
            ) from exc
        if proof != _proof_state(current):
            return False
        self._selected_volume_digests[(offset, length)] = digest
        return True

    def fingerprint(self) -> dict[str, object]:
        digest = hashlib.sha256()
        digest.update(str(self.size).encode("ascii"))
        for offset in (0, max(0, self.size - 65536)):
            digest.update(self.read_at(offset, min(65536, self.size - offset)))
        return {
            "algorithm": "sha256-size-head-tail-v1",
            "value": digest.hexdigest(),
            "size_bytes": self.size,
        }

    def assert_unchanged(self, fingerprint: dict[str, object] | None = None) -> None:
        """Refuse mixed-source results if the image changes during a scan."""
        try:
            current = os.fstat(self.fd)
        except OSError as exc:
            raise SourceError(
                f"Could not verify the image after reading it: {exc.strerror}."
            ) from exc
        identity = (
            current.st_dev,
            current.st_ino,
            current.st_size,
            current.st_mtime_ns,
            current.st_ctime_ns,
        )
        opened = (
            self.device,
            self.inode,
            self.size,
            self.modified_ns,
            self.changed_ns,
        )
        if identity != opened or (
            fingerprint is not None and self.fingerprint() != fingerprint
        ):
            raise SourceError(
                "The image changed while it was being scanned. Stop any writer or imaging process and scan a stable snapshot again."
            )

    def is_same_file(self, path: Path) -> bool:
        try:
            item = os.stat(path)
        except FileNotFoundError:
            return path.absolute() == self.path.absolute()
        return (item.st_dev, item.st_ino) == (self.device, self.inode)


def refuse_output_path(source: ImageSource, value: str | Path) -> Path:
    path = Path(value)
    if source.is_same_file(path):
        raise OutputError("Refusing to use the image itself as the manifest output.")
    if path.exists():
        raise OutputError(
            f"Manifest already exists: '{path}'. Choose a new path; existing files are never overwritten."
        )
    if not path.parent.exists() or not path.parent.is_dir():
        raise OutputError(f"Manifest directory does not exist: '{path.parent}'.")
    return path


def preflight_output_path(source: ImageSource, value: str | Path) -> Path:
    """Reject obvious output failures before an expensive full-image scan."""
    path = refuse_output_path(source, value)
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".preflight", dir=path.parent
        )
        os.close(fd)
    except OSError as exc:
        raise OutputError(
            f"Cannot create a manifest in '{path.parent}': {exc.strerror}."
        ) from exc
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
    return path
