"""Descriptor-relative, bounded extraction of already validated recovery plans.

This module deliberately knows nothing about exFAT FAT interpretation.  The planner is
the sole authority for extents; this layer only copies those extents after validating
the immutable run state.
"""

from __future__ import annotations

import ctypes
import errno

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised by platform import tests
    fcntl = None
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, is_dataclass
from pathlib import Path
from typing import Any

from .errors import (
    ManifestError,
    OutputError,
    ResourceLimitError,
    SourceError,
    UsageError,
)
from .manifest import DEFAULT_MAX_MANIFEST_BYTES
from .scanner import HARD_MAX_CANDIDATES
from .source import ImageSource, ProgressCallback, _release_file_cache

LEGACY_RUN_VERSION = 1
RUN_VERSION = 2
DEFAULT_MAX_OUTPUT_BYTES = 100 * 1024**3
HARD_MAX_RECOVERY_CANDIDATES = HARD_MAX_CANDIDATES
_ID = re.compile(r"^[0-9a-f]{64}$")
_CHECKPOINT_NAME = re.compile(r"^[0-9a-f]{64}\.json$")
_CHUNK = 1024 * 1024
CHECKPOINT_SYNC_INTERVAL = 256
MAX_STATE_BYTES = 1024 * 1024
# A run descriptor can contain the explicit 500,000-candidate ceiling (about 34 MiB).
MAX_RUN_BYTES = 40 * 1024 * 1024
MAX_REPORT_BYTES = 512 * 1024 * 1024
MAX_INTERNAL_MANIFEST_BYTES = DEFAULT_MAX_MANIFEST_BYTES
DEFAULT_RUN_LIMITS = {
    "max_output_bytes": DEFAULT_MAX_OUTPUT_BYTES,
    "max_candidates": 100_000,
    "max_scan_clusters": 50_000_000,
    "max_fat_steps": 10_000_000,
}
LOCKING_AVAILABLE = fcntl is not None
SOURCE_FILE_STATE_FIELDS = {
    "device",
    "inode",
    "mode",
    "link_count",
    "owner",
    "size_bytes",
    "modified_ns",
    "changed_ns",
}


def _valid_source_file_state(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == SOURCE_FILE_STATE_FIELDS
        and all(type(item) is int and item >= 0 for item in value.values())
    )


def _private_file_state(state: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISREG(state.st_mode)
        or state.st_nlink != 1
        or state.st_uid != os.geteuid()
        or stat.S_IMODE(state.st_mode) != 0o600
    ):
        raise OutputError(f"{label} is not a private, singly-linked regular file.")


def _private_dir_state(state: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISDIR(state.st_mode)
        or state.st_uid != os.geteuid()
        or stat.S_IMODE(state.st_mode) != 0o700
    ):
        raise OutputError(f"{label} is not a private tool-owned directory.")


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _same_file_state(left: os.stat_result, right: os.stat_result) -> bool:
    """Compare security-relevant state while ignoring read-induced access times."""
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_nlink,
        left.st_uid,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_nlink,
        right.st_uid,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _assert_unchanged_named_file(
    directory_fd: int,
    name: str,
    opened_fd: int,
    initial: os.stat_result,
    label: str,
) -> None:
    """Refuse an in-place change or pathname replacement during a file read."""
    try:
        current_fd = os.fstat(opened_fd)
        current_name = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        _raise_output_io(f"Could not revalidate {label}", exc)
    _private_file_state(current_fd, label)
    _private_file_state(current_name, label)
    if not _same_file_state(initial, current_fd) or not _same_identity(
        initial, current_name
    ):
        raise OutputError(f"{label} changed or was replaced while being read.")


def _assert_published_file(
    directory_fd: int,
    name: str,
    opened_fd: int,
    staged: os.stat_result,
    label: str,
) -> None:
    """Validate a no-replace publication without treating rename ctime as a write."""
    try:
        current_fd = os.fstat(opened_fd)
        current_name = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        _raise_output_io(f"Could not revalidate {label}", exc)
    _private_file_state(current_fd, label)
    _private_file_state(current_name, label)
    comparable = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_uid",
        "st_size",
        "st_mtime_ns",
    )
    if any(
        getattr(current_fd, field) != getattr(staged, field) for field in comparable
    ) or not _same_identity(staged, current_name):
        raise OutputError(f"{label} changed or was replaced while publishing.")


def _raise_output_io(label: str, exc: OSError) -> None:
    if exc.errno == errno.ENOSPC:
        raise ResourceLimitError("Recovery destination is full.") from exc
    raise OutputError(f"{label}: {exc.strerror}.") from exc


def _fsync(fd: int, label: str) -> None:
    try:
        os.fsync(fd)
    except OSError as exc:
        _raise_output_io(f"Could not make {label} durable", exc)


def _rename_noreplace(
    source_fd: int, source_name: str, destination_fd: int, destination_name: str
) -> None:
    """Atomically publish one descriptor-relative name without replacement."""
    libc = ctypes.CDLL(None, use_errno=True)
    source = os.fsencode(source_name)
    destination = os.fsencode(destination_name)
    if sys.platform.startswith("linux"):
        try:
            rename = libc.renameat2
        except AttributeError as exc:  # pragma: no cover - obsolete libc/kernel
            raise OutputError(
                "This Linux system lacks atomic no-replace publication support."
            ) from exc
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        result = rename(source_fd, source, destination_fd, destination, 1)
    elif sys.platform == "darwin":
        try:
            rename = libc.renameatx_np
        except AttributeError as exc:  # pragma: no cover - unsupported macOS
            raise OutputError(
                "This macOS system lacks atomic no-replace publication support."
            ) from exc
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        result = rename(source_fd, source, destination_fd, destination, 0x00000004)
    else:  # pragma: no cover - package metadata supports Linux and macOS only
        raise OutputError(
            "Atomic no-replace publication is supported only on Linux and macOS."
        )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error in {errno.EEXIST, errno.ENOTEMPTY}:
        raise OutputError(
            f"Refusing to overwrite existing recovery state '{destination_name}'."
        )
    _raise_output_io(
        f"Could not atomically publish recovery state '{destination_name}'",
        OSError(error, os.strerror(error)),
    )


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _json_object(data: bytes, label: str) -> dict[str, Any]:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(data, object_pairs_hook=no_duplicates)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
    ) as exc:
        raise ManifestError(f"{label} is not strict JSON.") from exc
    if not isinstance(value, dict):
        raise ManifestError(f"{label} is not a JSON object.")
    return value


def _plan_dict(plan: Any) -> dict[str, Any]:
    if is_dataclass(plan):
        result = asdict(plan)
    elif isinstance(plan, dict):
        result = dict(plan)
    else:
        raise ManifestError("The planner returned an unsupported recovery plan.")
    result["extents"] = [
        dict(item) if isinstance(item, dict) else asdict(item)
        for item in result.get("extents", ())
    ]
    return result


def _validate_plan(plan: Any) -> dict[str, Any]:
    value = _plan_dict(plan)
    expected_fields = {
        "candidate_id",
        "entry_offset",
        "entry_set_sha256",
        "name",
        "logical_size_bytes",
        "valid_data_bytes",
        "extents",
        "allocation_mode",
        "metadata_location",
        "disposition",
        "recovery_basis",
        "reasons",
    }
    if set(value) != expected_fields:
        raise ManifestError("A recovery plan has missing or undeclared fields.")
    candidate_id = value.get("candidate_id")
    if not isinstance(candidate_id, str) or not _ID.fullmatch(candidate_id):
        raise ManifestError("Recovery plans must use full SHA-256 candidate IDs.")
    size, valid = value.get("logical_size_bytes"), value.get("valid_data_bytes")
    if (
        isinstance(size, bool)
        or isinstance(valid, bool)
        or not isinstance(size, int)
        or not isinstance(valid, int)
        or not 0 <= valid <= size
    ):
        raise ManifestError(
            f"Plan '{candidate_id}' has invalid logical or valid-data sizes."
        )
    if not isinstance(value.get("disposition"), str) or value["disposition"] not in {
        "recoverable",
        "conflicted",
        "unrecoverable",
    }:
        raise ManifestError(f"Plan '{candidate_id}' has an invalid disposition.")
    if value.get("recovery_basis") is not None and not isinstance(
        value.get("recovery_basis"), str
    ):
        raise ManifestError(f"Plan '{candidate_id}' contains invalid metadata.")
    if (
        not isinstance(value.get("entry_offset"), int)
        or isinstance(value.get("entry_offset"), bool)
        or value["entry_offset"] < 0
        or not isinstance(value.get("entry_set_sha256"), str)
        or not _ID.fullmatch(value["entry_set_sha256"])
        or not isinstance(value.get("name"), str)
        or not isinstance(value.get("allocation_mode"), str)
        or value["allocation_mode"] not in {"empty", "contiguous", "fat_chain"}
        or not isinstance(value.get("metadata_location"), str)
        or value["metadata_location"]
        not in {"active_directory", "deleted_directory", "orphan"}
        or not isinstance(value.get("reasons"), (list, tuple))
        or not all(isinstance(reason, str) and reason for reason in value["reasons"])
        or list(value["reasons"]) != sorted(set(value["reasons"]))
    ):
        raise ManifestError(f"Plan '{candidate_id}' contains invalid metadata.")
    value["reasons"] = list(value["reasons"])
    bases = {
        "active_contiguous_allocated",
        "active_fat_chain_allocated",
        "active_empty",
        "deleted_contiguous_unallocated",
        "deleted_fat_chain_unallocated",
        "deleted_empty",
        "orphan_contiguous_unallocated",
        "orphan_fat_chain_unallocated",
        "orphan_empty",
    }
    if (
        value["disposition"] == "recoverable"
        and (value["recovery_basis"] not in bases or value["reasons"])
    ) or (
        value["disposition"] != "recoverable"
        and (value["recovery_basis"] is not None or not value["reasons"])
    ):
        raise ManifestError(
            f"Plan '{candidate_id}' has inconsistent disposition evidence."
        )
    extents = value["extents"]
    if len(extents) > 4096:
        raise ResourceLimitError(
            "A recovery plan exceeds the 4,096-extent safety limit."
        )
    for extent in extents:
        if (
            isinstance(extent.get("first_cluster"), bool)
            or isinstance(extent.get("cluster_count"), bool)
            or not isinstance(extent.get("first_cluster"), int)
            or not isinstance(extent.get("cluster_count"), int)
            or extent["first_cluster"] < 2
            or extent["cluster_count"] < 1
        ):
            raise ManifestError(f"Plan '{candidate_id}' contains an invalid extent.")
    return value


def _recovery_result_counts(plans: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    """Return successful-run counts from the selected validated plan set."""
    recovered = sum(plan["disposition"] == "recoverable" for plan in plans)
    conflicted = sum(plan["disposition"] == "conflicted" for plan in plans)
    unrecoverable = sum(plan["disposition"] == "unrecoverable" for plan in plans)
    return {
        "recovered_count": recovered,
        "conflicted_count": conflicted,
        "unrecoverable_count": unrecoverable,
        "refused_count": conflicted + unrecoverable,
        "failed_count": 0,
    }


def _validate_plan_geometry(
    plan: dict[str, Any], binding: Mapping[str, object]
) -> None:
    if plan["disposition"] != "recoverable":
        return
    cluster_size = binding.get("cluster_size_bytes")
    heap = binding.get("cluster_heap_offset_bytes")
    volume_offset = binding.get("volume_offset_bytes")
    volume_length = binding.get("volume_length_bytes")
    if (
        not all(
            isinstance(value, int) and not isinstance(value, bool)
            for value in (cluster_size, heap, volume_offset, volume_length)
        )
        or cluster_size <= 0
        or volume_length <= 0
    ):
        raise ManifestError("The source binding has invalid extraction geometry.")
    expected_clusters = (plan["logical_size_bytes"] + cluster_size - 1) // cluster_size
    actual_clusters = sum(extent["cluster_count"] for extent in plan["extents"])
    if actual_clusters != expected_clusters:
        raise ManifestError(
            f"Plan '{plan['candidate_id']}' extents do not exactly cover DataLength."
        )
    volume_end = volume_offset + volume_length
    for extent in plan["extents"]:
        start = heap + (extent["first_cluster"] - 2) * cluster_size
        end = start + extent["cluster_count"] * cluster_size
        if start < volume_offset or end > volume_end:
            raise ManifestError(
                f"Plan '{plan['candidate_id']}' extends outside the selected volume."
            )


def _mkdir_at(fd: int, name: str) -> int:
    try:
        os.mkdir(name, 0o700, dir_fd=fd)
    except FileExistsError as exc:
        raise OutputError(
            f"Recovery output contains an existing '{name}' object."
        ) from exc
    except OSError as exc:
        raise OutputError(
            f"Could not create recovery output directory '{name}': {exc.strerror}."
        ) from exc
    try:
        created = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except OSError as exc:
        _raise_output_io(f"Could not inspect recovery directory '{name}'", exc)
    _private_dir_state(created, f"Recovery directory '{name}'")
    try:
        opened = os.open(
            name,
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=fd,
        )
    except OSError as exc:
        _raise_output_io(f"Could not open recovery directory '{name}'", exc)
    try:
        state = os.fstat(opened)
        _private_dir_state(state, f"Recovery directory '{name}'")
        if not _same_identity(created, state):
            raise OutputError(
                f"Recovery directory '{name}' was replaced while opening."
            )
        _fsync(fd, f"parent of recovery directory '{name}'")
    except OSError as exc:
        os.close(opened)
        _raise_output_io(f"Could not inspect recovery directory '{name}'", exc)
    except Exception:
        os.close(opened)
        raise
    return opened


def _open_dir_at(fd: int, name: str) -> int:
    try:
        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        raise
    except OSError as exc:
        _raise_output_io(f"Could not inspect recovery directory '{name}'", exc)
    _private_dir_state(before, f"Recovery directory '{name}'")
    try:
        opened = os.open(
            name,
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=fd,
        )
    except FileNotFoundError:
        raise
    except OSError as exc:
        _raise_output_io(f"Could not open recovery directory '{name}'", exc)
    try:
        state = os.fstat(opened)
        _private_dir_state(state, f"Recovery directory '{name}'")
        if not _same_identity(before, state):
            raise OutputError(
                f"Recovery directory '{name}' was replaced while opening."
            )
    except OSError as exc:
        os.close(opened)
        _raise_output_io(f"Could not inspect recovery directory '{name}'", exc)
    except Exception:
        os.close(opened)
        raise
    return opened


def _open_dir_with_parent(path: Path) -> tuple[int, int, str]:
    """Open a private directory and retain its parent/name identity boundary."""
    path = path.absolute()
    parent_fd: int | None = None
    fd: int | None = None
    try:
        parent_fd = os.open(
            path.parent,
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        fd = os.open(
            path.name,
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        state = os.fstat(fd)
    except OSError as exc:
        if fd is not None:
            os.close(fd)
        if parent_fd is not None:
            os.close(parent_fd)
        raise OutputError(
            f"Could not open recovery output '{path}': {exc.strerror}."
        ) from exc
    if not _same_identity(before, state):
        os.close(fd)
        os.close(parent_fd)
        raise OutputError("Recovery output directory was replaced while opening.")
    try:
        _private_dir_state(state, "Recovery output directory")
    except OutputError:
        os.close(fd)
        os.close(parent_fd)
        raise
    return fd, parent_fd, path.name


def _assert_root_path(
    parent_fd: int, name: str, root_fd: int, label: str = "Recovery output"
) -> None:
    """Prove the held root descriptor still has its expected published pathname."""
    try:
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        opened = os.fstat(root_fd)
    except OSError as exc:
        _raise_output_io(f"Could not revalidate {label}", exc)
    _private_dir_state(named, label)
    _private_dir_state(opened, label)
    if not _same_identity(named, opened):
        raise OutputError(f"{label} was replaced while the operation was running.")


@dataclass(frozen=True)
class _RequestedParentProof:
    """Lexical requested parent path and held identity retained through completion."""

    lexical_path: Path
    device: int
    inode: int


def _requested_parent_proof(parent: Path, parent_fd: int) -> _RequestedParentProof:
    """Bind a held parent descriptor to the lexical path supplied by the caller."""
    try:
        lexical = parent.absolute()
        named = os.stat(lexical, follow_symlinks=False)
        held = os.fstat(parent_fd)
    except OSError as exc:
        _raise_output_io("Could not inspect requested recovery output parent", exc)
    if not stat.S_ISDIR(named.st_mode) or not stat.S_ISDIR(held.st_mode):
        raise OutputError("Requested recovery output parent is not a directory.")
    if not _same_identity(named, held):
        raise OutputError("Recovery output parent changed while opening.")
    return _RequestedParentProof(lexical, held.st_dev, held.st_ino)


def _assert_requested_parent(proof: _RequestedParentProof, parent_fd: int) -> None:
    """Refuse success if the original requested parent path was renamed or replaced."""
    try:
        # Deliberately reopen the caller's lexical path.  Checking only its
        # resolved destination would miss an ancestor symlink retarget.
        named = os.stat(proof.lexical_path, follow_symlinks=False)
        held = os.fstat(parent_fd)
    except OSError as exc:
        _raise_output_io("Could not revalidate requested recovery output parent", exc)
    if (
        not stat.S_ISDIR(named.st_mode)
        or not stat.S_ISDIR(held.st_mode)
        or named.st_dev != proof.device
        or named.st_ino != proof.inode
        or held.st_dev != proof.device
        or held.st_ino != proof.inode
    ):
        raise OutputError("Requested recovery output parent changed before success.")


def _open_dir(path: Path) -> int:
    fd, parent_fd, _name = _open_dir_with_parent(path)
    os.close(parent_fd)
    return fd


def _lock_directory(fd: int, label: str) -> None:
    """Take the one writer lock that is held until this descriptor closes."""
    if fcntl is None:
        raise OutputError(
            "Recovery directory locking is unavailable; exfat-rescue requires Linux or macOS."
        )
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EAGAIN}:
            raise OutputError(
                f"{label} is already being recovered by another process."
            ) from exc
        _raise_output_io(f"Could not lock {label}", exc)


def _bootstrap_name(target_name: str) -> str:
    """Return a short deterministic sibling name even for a 255-byte target name."""
    digest = hashlib.sha256(os.fsencode(target_name)).hexdigest()
    return f".exfat-rescue-bootstrap-{digest}"


def _new_output_target(output: str | Path) -> Path:
    """Normalize a new output target without accepting a directory itself."""
    target = Path(os.path.abspath(os.fspath(output)))
    if target == Path.cwd() or target == target.parent:
        raise OutputError(
            "Recovery output must name a new directory, not the current directory "
            "or filesystem root."
        )
    return target


def _stat_at_or_none(fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        _raise_output_io(f"Could not inspect recovery output '{name}'", exc)


def _ensure_empty_dir_at(fd: int, name: str) -> int:
    try:
        opened = _open_dir_at(fd, name)
    except FileNotFoundError:
        opened = _mkdir_at(fd, name)
    try:
        entries = _listdir_at(
            opened, f"bootstrap recovery directory '{name}'", max_entries=0
        )
    except Exception:
        os.close(opened)
        raise
    if entries:
        os.close(opened)
        raise OutputError(f"Bootstrap recovery directory '{name}' is not empty.")
    return opened


def _ensure_exact_state_at(
    fd: int, name: str, data: bytes, *, max_bytes: int = MAX_STATE_BYTES
) -> None:
    """Keep an exact descriptor or safely finish only its matching staged prefix."""
    temporary_name = _state_temporary_name(name)
    final_state = _stat_at_or_none(fd, name)
    temporary_state = _stat_at_or_none(fd, temporary_name)
    if final_state is not None and temporary_state is not None:
        raise OutputError(f"Bootstrap recovery state '{name}' is ambiguous.")
    if final_state is not None:
        if not _regular_at_equals(fd, name, data, max_bytes=max_bytes):
            raise OutputError(
                f"Bootstrap recovery state '{name}' does not match this run."
            )
        return
    _write_new_at(fd, name, data)


def _stage_bootstrap(root_fd: int, *, manifest_bytes: bytes, run_bytes: bytes) -> None:
    """Finish the bounded, idempotent pre-publication state without cleanup."""
    allowed = {
        "records",
        "files",
        "work",
        "manifest.jsonl",
        "run.json",
        _state_temporary_name("manifest.jsonl"),
        _state_temporary_name("run.json"),
    }
    entries = set(
        _listdir_at(root_fd, "bootstrap recovery output", max_entries=len(allowed))
    )
    if not entries.issubset(allowed):
        raise OutputError("Bootstrap recovery output contains unknown objects.")
    child_fds: list[int] = []
    try:
        for name in ("records", "files", "work"):
            child_fds.append(_ensure_empty_dir_at(root_fd, name))
        _ensure_exact_state_at(
            root_fd,
            "manifest.jsonl",
            manifest_bytes,
            max_bytes=MAX_INTERNAL_MANIFEST_BYTES,
        )
        # A published run descriptor proves the manifest and empty initial directories
        # were durable first.
        _ensure_exact_state_at(root_fd, "run.json", run_bytes, max_bytes=MAX_RUN_BYTES)
        _fsync(root_fd, "bootstrap recovery output directory")
    finally:
        for child_fd in reversed(child_fds):
            os.close(child_fd)


def _validate_published_bootstrap(
    root_fd: int, *, manifest_bytes: bytes, run_bytes: bytes
) -> None:
    """Require the just-published bootstrap to remain in its exact initial state."""
    expected = {"records", "files", "work", "manifest.jsonl", "run.json"}
    if (
        set(
            _listdir_at(
                root_fd,
                "published bootstrap recovery output",
                max_entries=len(expected),
            )
        )
        != expected
    ):
        raise OutputError(
            "Published bootstrap recovery output contains unknown objects."
        )
    if not _regular_at_equals(
        root_fd,
        "manifest.jsonl",
        manifest_bytes,
        max_bytes=MAX_INTERNAL_MANIFEST_BYTES,
    ) or not _regular_at_equals(
        root_fd, "run.json", run_bytes, max_bytes=MAX_RUN_BYTES
    ):
        raise OutputError(
            "Published bootstrap recovery state changed during publication."
        )
    child_fds: list[int] = []
    try:
        for name in ("records", "files", "work"):
            child_fd = _open_dir_at(root_fd, name)
            child_fds.append(child_fd)
            if _listdir_at(
                child_fd, f"published bootstrap directory '{name}'", max_entries=0
            ):
                raise OutputError(
                    f"Published bootstrap directory '{name}' is not empty."
                )
    finally:
        for child_fd in reversed(child_fds):
            os.close(child_fd)


def _prepare_new_run_root(
    target: Path, *, manifest_bytes: bytes, run_bytes: bytes
) -> tuple[int, int, str]:
    """Stage a retryable bootstrap then atomically publish the output directory."""
    target = _new_output_target(target)
    try:
        parent_fd = os.open(
            target.parent,
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise OutputError(
            f"Could not safely open recovery output parent: {exc.strerror}."
        ) from exc
    bootstrap = _bootstrap_name(target.name)
    root_fd: int | None = None
    try:
        target_state = _stat_at_or_none(parent_fd, target.name)
        bootstrap_state = _stat_at_or_none(parent_fd, bootstrap)
        if target_state is not None and bootstrap_state is not None:
            raise OutputError("Recovery output and its bootstrap state both exist.")
        if target_state is not None:
            raise OutputError(
                "Recovery output must be a new directory and must not be the image."
            )
        if bootstrap_state is None:
            root_fd = _mkdir_at(parent_fd, bootstrap)
        else:
            root_fd = _open_dir_at(parent_fd, bootstrap)
        _lock_directory(root_fd, "Recovery bootstrap")
        _stage_bootstrap(root_fd, manifest_bytes=manifest_bytes, run_bytes=run_bytes)
        if _stat_at_or_none(parent_fd, target.name) is not None:
            raise OutputError(
                "Recovery output appeared while its bootstrap was being staged."
            )
        _fsync(root_fd, "bootstrap recovery output directory")
        _fsync(parent_fd, "recovery output parent directory")
        _rename_noreplace(parent_fd, bootstrap, parent_fd, target.name)
        _fsync(parent_fd, "recovery output parent directory")
        published = _open_dir_at(parent_fd, target.name)
        try:
            if not _same_identity(os.fstat(root_fd), os.fstat(published)):
                raise OutputError("Recovery output was replaced while being published.")
        finally:
            os.close(published)
        _assert_root_path(parent_fd, target.name, root_fd)
        _validate_published_bootstrap(
            root_fd, manifest_bytes=manifest_bytes, run_bytes=run_bytes
        )
        _assert_root_path(parent_fd, target.name, root_fd)
        return root_fd, parent_fd, target.name
    except Exception:
        if root_fd is not None:
            os.close(root_fd)
            root_fd = None
        raise
    finally:
        if root_fd is None:
            os.close(parent_fd)


def _state_temporary_name(name: str) -> str:
    return f".{name}.partial"


def _descriptor_prefix_equals(target: int, expected: bytes, length: int) -> bool:
    """Compare a descriptor prefix in bounded chunks without copying ``expected``."""
    if length < 0 or length > len(expected):
        return False
    os.lseek(target, 0, os.SEEK_SET)
    view = memoryview(expected)
    offset = 0
    while offset < length:
        part = os.read(target, min(_CHUNK, length - offset))
        if not part or part != view[offset : offset + len(part)]:
            return False
        offset += len(part)
    return True


def _write_new_at(fd: int, name: str, data: bytes) -> None:
    """Durably publish exact state, resuming only a matching private prefix."""
    temporary_name = _state_temporary_name(name)
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    except OSError as exc:
        _raise_output_io(f"Could not inspect recovery state '{name}'", exc)
    else:
        raise OutputError(f"Refusing to overwrite existing recovery state '{name}'.")
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        target = os.open(temporary_name, flags, 0o600, dir_fd=fd)
    except FileExistsError:
        try:
            target = os.open(
                temporary_name,
                os.O_RDWR
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=fd,
            )
        except OSError as exc:
            _raise_output_io(f"Could not resume recovery state '{name}' temporary", exc)
    except OSError as exc:
        _raise_output_io(f"Could not stage recovery state '{name}'", exc)
    try:
        opened = os.fstat(target)
        _private_file_state(opened, f"Recovery state '{name}' temporary")
        if opened.st_size > len(data):
            raise OutputError(
                f"Recovery state '{name}' temporary exceeds the expected size."
            )
        try:
            prefix_matches = _descriptor_prefix_equals(target, data, opened.st_size)
        except OSError as exc:
            _raise_output_io(
                f"Could not inspect recovery state '{name}' temporary", exc
            )
        if not prefix_matches:
            raise OutputError(
                f"Recovery state '{name}' temporary does not match the expected data."
            )
        try:
            os.lseek(target, opened.st_size, os.SEEK_SET)
        except OSError as exc:
            _raise_output_io(f"Could not resume recovery state '{name}' temporary", exc)
        _write_all(
            target,
            memoryview(data)[opened.st_size :],
            f"recovery state '{name}'",
        )
        _fsync(target, f"recovery state '{name}' temporary")
        try:
            staged = os.stat(temporary_name, dir_fd=fd, follow_symlinks=False)
        except OSError as exc:
            _raise_output_io(
                f"Could not inspect recovery state '{name}' temporary", exc
            )
        if not _same_identity(opened, staged):
            raise OutputError(
                f"Recovery state '{name}' temporary was replaced and was left untouched."
            )
        _private_file_state(staged, f"Recovery state '{name}' temporary")
        staged = os.fstat(target)
        _private_file_state(staged, f"Recovery state '{name}' temporary")
        _rename_noreplace(fd, temporary_name, fd, name)
        _assert_published_file(fd, name, target, staged, f"Recovery state '{name}'")
        published = os.fstat(target)
        try:
            if published.st_size != len(data) or not _descriptor_prefix_equals(
                target, data, len(data)
            ):
                raise OutputError(f"Recovery state '{name}' changed while publishing.")
        except OSError as exc:
            _raise_output_io(f"Could not revalidate recovery state '{name}'", exc)
        _assert_unchanged_named_file(
            fd, name, target, published, f"Recovery state '{name}'"
        )
    except OSError as exc:
        _raise_output_io(f"Could not inspect recovery state '{name}'", exc)
    finally:
        os.close(target)
    # Candidate data has already been published durably. Checkpoints can therefore
    # batch the expensive directory flush: a crash may lose only the last batch of
    # record names, which resume safely reconstructs from exact published data.
    if not _CHECKPOINT_NAME.fullmatch(name):
        _fsync(fd, "recovery state directory")


def _write_all(fd: int, data: bytes | memoryview, label: str) -> None:
    view = memoryview(data)
    while view:
        try:
            written = os.write(fd, view)
        except OSError as exc:
            if exc.errno == errno.ENOSPC:
                raise ResourceLimitError("Recovery destination is full.") from exc
            raise OutputError(f"Could not write {label}: {exc.strerror}.") from exc
        if written <= 0:
            raise OutputError(f"Short write while writing {label}.")
        view = view[written:]


def _read_regular_at(fd: int, name: str, *, max_bytes: int = MAX_STATE_BYTES) -> bytes:
    try:
        target = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=fd,
        )
    except OSError as exc:
        raise OutputError(
            f"Could not safely read recovery state '{name}': {exc.strerror}."
        ) from exc
    try:
        state = os.fstat(target)
        _private_file_state(state, f"Recovery state '{name}'")
        if state.st_size > max_bytes:
            raise ManifestError(f"Recovery state '{name}' exceeds its size limit.")
        try:
            data = os.pread(target, state.st_size, 0)
        except OSError as exc:
            _raise_output_io(f"Could not read recovery state '{name}'", exc)
        if len(data) != state.st_size:
            raise OutputError(
                f"Recovery state '{name}' changed or could not be read completely."
            )
        _assert_unchanged_named_file(
            fd, name, target, state, f"Recovery state '{name}'"
        )
        return data
    except OSError as exc:
        _raise_output_io(f"Could not inspect recovery state '{name}'", exc)
    finally:
        os.close(target)


def _regular_at_equals(
    fd: int,
    name: str,
    expected: bytes,
    *,
    max_bytes: int = MAX_STATE_BYTES,
    return_proof: bool = False,
) -> bool | tuple[int, ...] | None:
    """Compare private state through a held descriptor without copying it wholesale."""
    try:
        target = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=fd,
        )
    except OSError as exc:
        raise OutputError(
            f"Could not safely read recovery state '{name}': {exc.strerror}."
        ) from exc
    try:
        state = os.fstat(target)
        _private_file_state(state, f"Recovery state '{name}'")
        if state.st_size > max_bytes:
            raise ManifestError(f"Recovery state '{name}' exceeds its size limit.")
        matches = state.st_size == len(expected)
        offset = 0
        view = memoryview(expected)
        while matches and offset < len(expected):
            try:
                part = os.read(target, min(_CHUNK, len(expected) - offset))
            except OSError as exc:
                _raise_output_io(f"Could not read recovery state '{name}'", exc)
            if not part or part != view[offset : offset + len(part)]:
                matches = False
                break
            offset += len(part)
        if matches:
            try:
                matches = not os.read(target, 1)
            except OSError as exc:
                _raise_output_io(f"Could not read recovery state '{name}'", exc)
        _assert_unchanged_named_file(
            fd, name, target, state, f"Recovery state '{name}'"
        )
        proof = _file_state_proof(state)
        if return_proof:
            return proof if matches else None
        return matches
    except OSError as exc:
        _raise_output_io(f"Could not inspect recovery state '{name}'", exc)
    finally:
        os.close(target)


def _listdir_at(fd: int, label: str, *, max_entries: int) -> list[str]:
    names: list[str] = []
    try:
        with os.scandir(fd) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > max_entries:
                    raise OutputError(f"{label.capitalize()} exceeds its entry limit.")
    except OutputError:
        raise
    except OSError as exc:
        _raise_output_io(f"Could not inspect {label}", exc)
    return names


def _source_binding(source: ImageSource, volume: Any) -> dict[str, Any]:
    offset = int(volume.base_offset)
    length = int(volume.boot.volume_bytes)
    return {
        "image_size_bytes": source.size,
        "volume_offset_bytes": offset,
        "volume_length_bytes": length,
        "volume_sha256": source.selected_volume_sha256(offset, length),
        "cluster_size_bytes": int(volume.boot.cluster_size),
        "cluster_heap_offset_bytes": int(
            volume.base_offset + volume.boot.heap_offset * volume.boot.bytes_per_sector
        ),
        "source_kind": str(volume.location.source_kind),
        "boot_region": str(volume.boot_region),
        "volume_dirty": bool(volume.boot.volume_dirty),
        "media_failure": bool(volume.boot.media_failure),
    }


def _assert_binding(source: ImageSource, volume: Any, binding: dict[str, Any]) -> None:
    source.assert_unchanged()
    if _source_binding(source, volume) != binding:
        raise SourceError("The selected exFAT volume changed during recovery.")


def _record_name(candidate_id: str) -> str:
    return f"{candidate_id}.json"


def _file_state_proof(state: os.stat_result) -> tuple[int, ...]:
    return (
        state.st_dev,
        state.st_ino,
        state.st_mode,
        state.st_nlink,
        state.st_uid,
        state.st_size,
        state.st_mtime_ns,
        state.st_ctime_ns,
    )


@dataclass(frozen=True)
class _CompletionProof:
    """Compact, descriptor-relative state captured immediately after validation.

    The content proof is deliberately represented by the already checked data-file
    state proofs plus aggregate metadata proofs.  Rechecking this object must never
    read recovery contents again: it is the bounded half of the source/output A-B-A
    boundary.
    """

    root: tuple[int, ...]
    records: tuple[int, ...]
    files: tuple[int, ...]
    work: tuple[int, ...]
    root_inventory: bytes
    records_inventory: bytes
    files_inventory: bytes
    work_inventory: bytes
    run: tuple[int, ...]
    manifest: tuple[int, ...]
    checkpoints: bytes
    recovered: bytes
    report: tuple[int, ...] | None
    data_proofs: Mapping[str, tuple[int, ...]]

    def unchanged_before_report(self, later: _CompletionProof) -> bool:
        """Compare the objects a newly created report cannot legitimately alter."""
        return (
            self.records == later.records
            and self.files == later.files
            and self.work == later.work
            and self.records_inventory == later.records_inventory
            and self.files_inventory == later.files_inventory
            and self.work_inventory == later.work_inventory
            and self.run == later.run
            and self.manifest == later.manifest
            and self.checkpoints == later.checkpoints
            and self.recovered == later.recovered
        )


def _hash_file_at(
    fd: int, name: str, *, expected_size: int
) -> tuple[int, str, tuple[int, ...]]:
    try:
        target = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=fd,
        )
    except OSError as exc:
        _raise_output_io("Could not safely open recovered data", exc)
    try:
        try:
            state = os.fstat(target)
            _private_file_state(state, "Recovered data")
            if state.st_size != expected_size:
                raise OutputError("Recovered data has an unexpected logical size.")
            digest, count = hashlib.sha256(), 0
            while count < expected_size:
                part = os.read(target, min(_CHUNK, expected_size - count))
                if not part:
                    raise OutputError("Recovered data ended before its logical size.")
                count += len(part)
                digest.update(part)
            if os.read(target, 1):
                raise OutputError("Recovered data exceeds its logical size.")
            _release_file_cache(target, 0, count, through_eof=True)
            _assert_unchanged_named_file(fd, name, target, state, "Recovered data")
            return count, digest.hexdigest(), _file_state_proof(state)
        except OutputError:
            raise
        except OSError as exc:
            _raise_output_io("Could not safely read recovered data", exc)
    finally:
        os.close(target)


def _check_file_proof_at(
    fd: int,
    name: str,
    *,
    expected_size: int,
    expected_proof: tuple[int, ...],
) -> tuple[int, ...]:
    """Revalidate an earlier full content proof through exact file state."""
    try:
        target = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=fd,
        )
    except OSError as exc:
        _raise_output_io("Could not safely reopen recovered data", exc)
    try:
        state = os.fstat(target)
        _private_file_state(state, "Recovered data")
        if state.st_size != expected_size:
            raise OutputError("Recovered data has an unexpected logical size.")
        _assert_unchanged_named_file(fd, name, target, state, "Recovered data")
        proof = _file_state_proof(state)
        if proof != expected_proof:
            raise OutputError("Recovered data changed after its content proof.")
        return proof
    except OSError as exc:
        _raise_output_io("Could not safely inspect recovered data", exc)
    finally:
        os.close(target)


def _revalidate_recovered_outputs(
    files_fd: int,
    records: Mapping[str, Mapping[str, object]],
    *,
    prior_proofs: Mapping[str, tuple[int, ...]] | None = None,
) -> dict[str, tuple[int, ...]]:
    """Prove checkpointed data still matches immediately around completion.

    Candidate publication hashes its data before its checkpoint is written.  A
    final bounded descriptor-relative pass closes that otherwise observable
    interval before a report can make the run appear complete.
    """
    proofs: dict[str, tuple[int, ...]] = {}
    for candidate_id, record in records.items():
        if record.get("disposition") != "recovered":
            continue
        logical_size = record.get("logical_size_bytes")
        expected_digest = record.get("output_sha256")
        if (
            type(logical_size) is not int
            or logical_size < 0
            or not isinstance(expected_digest, str)
            or not _ID.fullmatch(expected_digest)
        ):
            raise OutputError("Recovered candidate checkpoint is malformed.")
        candidate_fd = _open_dir_at(files_fd, candidate_id)
        try:
            if set(_listdir_at(candidate_fd, "recovered candidate", max_entries=1)) != {
                "data"
            }:
                raise OutputError(
                    "Recovered candidate inventory is not in its exact expected state."
                )
            prior = None if prior_proofs is None else prior_proofs.get(candidate_id)
            if prior is None:
                size, digest, proof = _hash_file_at(
                    candidate_fd, "data", expected_size=logical_size
                )
            else:
                proof = _check_file_proof_at(
                    candidate_fd,
                    "data",
                    expected_size=logical_size,
                    expected_proof=prior,
                )
                size, digest = logical_size, expected_digest
        finally:
            os.close(candidate_fd)
        if size != logical_size or digest != expected_digest:
            raise OutputError("Checkpointed recovered data was altered.")
        proofs[candidate_id] = proof
    if prior_proofs is not None and set(prior_proofs) != set(proofs):
        raise OutputError("Recovered data proof inventory changed during completion.")
    return proofs


def _revalidate_recovered_proofs_reverse(
    files_fd: int,
    records: Mapping[str, Mapping[str, object]],
    proofs: Mapping[str, tuple[int, ...]],
) -> None:
    """Finish a completion boundary with exact recovered-file state proofs.

    A reverse traversal makes each prior forward proof reachable after every
    other completion-state check, without rereading recovered contents.
    """
    for candidate_id in reversed(proofs):
        record = records[candidate_id]
        logical_size = record["logical_size_bytes"]
        if type(logical_size) is not int:
            raise OutputError("Recovered candidate checkpoint is malformed.")
        candidate_fd = _open_dir_at(files_fd, candidate_id)
        try:
            if set(_listdir_at(candidate_fd, "recovered candidate", max_entries=1)) != {
                "data"
            }:
                raise OutputError(
                    "Recovered candidate inventory is not in its exact expected state."
                )
            _check_file_proof_at(
                candidate_fd,
                "data",
                expected_size=logical_size,
                expected_proof=proofs[candidate_id],
            )
        finally:
            os.close(candidate_fd)


def _revalidate_checkpoint_bytes(
    records_fd: int,
    candidate_ids: Sequence[str],
    checkpoints: Mapping[str, Mapping[str, object]],
) -> dict[str, tuple[int, ...]]:
    """Require the bounded checkpoint inventory to exactly match its records."""
    if len(checkpoints) != len(candidate_ids) or set(checkpoints) != set(candidate_ids):
        raise OutputError(
            "Recovery checkpoint inventory is not in its exact expected state."
        )
    expected_names = {_record_name(candidate_id) for candidate_id in candidate_ids}
    if (
        set(
            _listdir_at(records_fd, "recovery records", max_entries=len(expected_names))
        )
        != expected_names
    ):
        raise OutputError(
            "Recovery checkpoint inventory is not in its exact expected state."
        )
    proofs: dict[str, tuple[int, ...]] = {}
    for candidate_id in candidate_ids:
        expected = _canonical(checkpoints[candidate_id]) + b"\n"
        proof = _regular_at_equals(
            records_fd,
            _record_name(candidate_id),
            expected,
            return_proof=True,
        )
        if proof is None:
            raise OutputError("Recovery checkpoint changed during completion.")
        proofs[candidate_id] = proof
    return proofs


def _proof_part(
    digest: Any, label: str, proof: tuple[int, ...] | tuple[str, ...]
) -> None:
    """Unambiguously add a bounded state item to a completion aggregate."""
    encoded = label.encode("ascii")
    digest.update(len(encoded).to_bytes(4, "big"))
    digest.update(encoded)
    for value in proof:
        if isinstance(value, str):
            encoded = value.encode("utf-8", "surrogateescape")
            digest.update(len(encoded).to_bytes(4, "big"))
            digest.update(encoded)
        else:
            digest.update(int(value).to_bytes(16, "big", signed=True))


def _aggregate_proof_part(
    total: int, label: str, proof: tuple[int, ...] | tuple[str, ...]
) -> int:
    """Add one domain-bound proof to an order-independent bounded aggregate.

    Closing traversals run in reverse.  Hash each labelled state independently so
    the aggregate can be recomputed in that order without retaining one stat tuple
    per checkpoint, while the name remains cryptographically bound to its state.
    """
    item = hashlib.sha256()
    _proof_part(item, label, proof)
    return (total + int.from_bytes(item.digest(), "big")) % (1 << 256)


def _aggregate_proof_bytes(total: int) -> bytes:
    return total.to_bytes(32, "big")


def _directory_snapshot(
    fd: int, label: str, *, max_entries: int
) -> tuple[tuple[int, ...], tuple[str, ...]]:
    """Capture a directory identity and exact inventory without a read baseline."""
    try:
        before = os.fstat(fd)
        _private_dir_state(before, label)
        names = tuple(sorted(_listdir_at(fd, label.lower(), max_entries=max_entries)))
        after = os.fstat(fd)
        _private_dir_state(after, label)
    except OSError as exc:
        _raise_output_io(f"Could not inspect {label.lower()}", exc)
    if _file_state_proof(before) != _file_state_proof(after):
        raise OutputError(f"{label} changed while its inventory was inspected.")
    return _file_state_proof(after), names


def _named_state_proof(fd: int, name: str, label: str) -> tuple[int, ...]:
    """Read no content: bind a private named regular file to its held directory."""
    try:
        target = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=fd,
        )
    except OSError as exc:
        _raise_output_io(f"Could not safely reopen {label}", exc)
    try:
        state = os.fstat(target)
        _private_file_state(state, label)
        _assert_unchanged_named_file(fd, name, target, state, label)
        return _file_state_proof(state)
    except OSError as exc:
        _raise_output_io(f"Could not inspect {label}", exc)
    finally:
        os.close(target)


def _capture_completion_proof(
    root_fd: int,
    root_parent_fd: int,
    root_name: str,
    records_fd: int,
    files_fd: int,
    work_fd: int,
    *,
    candidate_ids: Sequence[str],
    recoverable_ids: set[str],
    checkpoints: Mapping[str, Mapping[str, object]],
    report_complete: bool,
    recovered_file_proofs: Mapping[str, tuple[int, ...]] | None,
    run_proof: tuple[int, ...],
    manifest_proof: tuple[int, ...],
    checkpoint_proofs: Mapping[str, tuple[int, ...]],
    report_proof: tuple[int, ...] | None,
    state_only: bool = False,
) -> _CompletionProof:
    """Capture only names, identities and inventories after content validation."""
    root, root_names = _directory_snapshot(root_fd, "Recovery output", max_entries=6)
    records, record_names = _directory_snapshot(
        records_fd, "Recovery records", max_entries=len(candidate_ids)
    )
    files, file_names = _directory_snapshot(
        files_fd, "Recovery files", max_entries=len(recoverable_ids)
    )
    work, work_names = _directory_snapshot(
        work_fd, "Recovery work directory", max_entries=0
    )
    expected_root = {"run.json", "manifest.jsonl", "records", "files", "work"}
    if report_complete:
        expected_root.add("report.jsonl")
    if set(root_names) != expected_root or work_names:
        raise OutputError(
            "Recovery output inventory is not in its exact expected state."
        )
    expected_records = {_record_name(candidate_id) for candidate_id in candidate_ids}
    if set(record_names) != expected_records or set(file_names) != recoverable_ids:
        raise OutputError(
            "Recovery output inventory is not in its exact expected state."
        )
    _assert_root_path(root_fd, "records", records_fd, "Recovery records")
    _assert_root_path(root_fd, "files", files_fd, "Recovery files")
    _assert_root_path(root_fd, "work", work_fd, "Recovery work directory")
    _assert_root_path(root_parent_fd, root_name, root_fd)

    records_digest, recovered_digest = 0, 0
    if checkpoint_proofs and set(checkpoint_proofs) != set(candidate_ids):
        raise OutputError(
            "Recovery checkpoint proof inventory changed during completion."
        )
    for candidate_id in candidate_ids:
        proof = (
            checkpoint_proofs[candidate_id]
            if checkpoint_proofs
            else _named_state_proof(
                records_fd, _record_name(candidate_id), "Recovery checkpoint"
            )
        )
        records_digest = _aggregate_proof_part(records_digest, candidate_id, proof)
    for candidate_id in sorted(recoverable_ids):
        candidate_fd = _open_dir_at(files_fd, candidate_id)
        try:
            candidate_state, candidate_names = _directory_snapshot(
                candidate_fd, "Recovered candidate", max_entries=1
            )
            if candidate_names != ("data",):
                raise OutputError(
                    "Recovered candidate inventory is not in its exact expected state."
                )
            record = checkpoints[candidate_id]
            logical_size = record.get("logical_size_bytes")
            if type(logical_size) is not int:
                raise OutputError("Recovered candidate checkpoint is malformed.")
            if recovered_file_proofs is None:
                data_proof = _named_state_proof(candidate_fd, "data", "Recovered data")
                if data_proof[5] != logical_size:
                    raise OutputError("Recovered data has an unexpected logical size.")
            else:
                data_proof = _check_file_proof_at(
                    candidate_fd,
                    "data",
                    expected_size=logical_size,
                    expected_proof=recovered_file_proofs[candidate_id],
                )
            recovered_digest = _aggregate_proof_part(
                recovered_digest, candidate_id, candidate_state
            )
            recovered_digest = _aggregate_proof_part(
                recovered_digest, f"{candidate_id}/data", data_proof
            )
        finally:
            os.close(candidate_fd)
    if (
        recovered_file_proofs is not None
        and set(recovered_file_proofs) != recoverable_ids
    ):
        raise OutputError("Recovered data proof inventory changed during completion.")
    root_digest, records_inventory, files_inventory, work_inventory = (
        hashlib.sha256(),
        hashlib.sha256(),
        hashlib.sha256(),
        hashlib.sha256(),
    )
    _proof_part(root_digest, "root", root)
    _proof_part(root_digest, "names", root_names)
    _proof_part(records_inventory, "records", records)
    _proof_part(records_inventory, "names", record_names)
    _proof_part(files_inventory, "files", files)
    _proof_part(files_inventory, "names", file_names)
    _proof_part(work_inventory, "work", work)
    _proof_part(work_inventory, "names", work_names)
    if state_only:
        run_proof = _named_state_proof(root_fd, "run.json", "Recovery run descriptor")
        manifest_proof = _named_state_proof(
            root_fd, "manifest.jsonl", "Recovery manifest"
        )
        report_proof = (
            _named_state_proof(root_fd, "report.jsonl", "Recovery report")
            if report_complete
            else None
        )
        # Metadata is checked after the forward data traversal.  Close that gap
        # with a reverse descriptor-state pass, never by rereading data bytes.
        _revalidate_recovered_proofs_reverse(
            files_fd, checkpoints, recovered_file_proofs or {}
        )
    proof = _CompletionProof(
        root,
        records,
        files,
        work,
        root_digest.digest(),
        records_inventory.digest(),
        files_inventory.digest(),
        work_inventory.digest(),
        run_proof,
        manifest_proof,
        _aggregate_proof_bytes(records_digest),
        _aggregate_proof_bytes(recovered_digest),
        report_proof,
        dict(recovered_file_proofs or {}),
    )
    # The capture above necessarily walks a finite set of independently mutable
    # objects.  Do not return its forward observations directly: a writer could
    # otherwise change an earlier checkpoint or directory while a later object is
    # being inspected.  Close that interval with descriptor-only state checks.
    return _close_completion_proof(
        root_fd,
        root_parent_fd,
        root_name,
        records_fd,
        files_fd,
        work_fd,
        candidate_ids=candidate_ids,
        recoverable_ids=recoverable_ids,
        checkpoints=checkpoints,
        report_complete=report_complete,
        expected=proof,
    )


def _close_completion_proof(
    root_fd: int,
    root_parent_fd: int,
    root_name: str,
    records_fd: int,
    files_fd: int,
    work_fd: int,
    *,
    candidate_ids: Sequence[str],
    recoverable_ids: set[str],
    checkpoints: Mapping[str, Mapping[str, object]],
    report_complete: bool,
    expected: _CompletionProof,
) -> _CompletionProof:
    """Close a completion capture without rereading any recovery content.

    File contents were bound by the preceding full proof.  This deliberately
    bounded pass binds every persistent name, directory inventory, and namespace
    edge to those captured states before publication may continue.  Checkpoint
    and recovered-file state is folded into aggregates so a large recovery never
    retains a second per-checkpoint stat map.
    """
    # Start with the root files.  Their proofs originate in exact content checks
    # for a full capture; for a state-only capture they must still equal those
    # earlier content-bound states.
    report = (
        _named_state_proof(root_fd, "report.jsonl", "Recovery report")
        if report_complete
        else None
    )
    manifest = _named_state_proof(root_fd, "manifest.jsonl", "Recovery manifest")
    run = _named_state_proof(root_fd, "run.json", "Recovery run descriptor")
    if (
        run != expected.run
        or manifest != expected.manifest
        or report != expected.report
    ):
        raise OutputError("Immutable recovery state changed during completion.")

    expected_records = {_record_name(candidate_id) for candidate_id in candidate_ids}
    recovered_digest = 0
    file_state, file_names = _directory_snapshot(
        files_fd, "Recovery files", max_entries=len(recoverable_ids)
    )
    if file_state != expected.files or set(file_names) != recoverable_ids:
        raise OutputError("Recovery output inventory changed during completion.")
    for candidate_id in sorted(recoverable_ids, reverse=True):
        candidate_fd = _open_dir_at(files_fd, candidate_id)
        try:
            candidate_state, candidate_names = _directory_snapshot(
                candidate_fd, "Recovered candidate", max_entries=1
            )
            if candidate_names != ("data",):
                raise OutputError(
                    "Recovered candidate inventory is not in its exact expected state."
                )
            record = checkpoints[candidate_id]
            logical_size = record.get("logical_size_bytes")
            if type(logical_size) is not int:
                raise OutputError("Recovered candidate checkpoint is malformed.")
            data = _named_state_proof(candidate_fd, "data", "Recovered data")
            if data[5] != logical_size:
                raise OutputError("Recovered data has an unexpected logical size.")
            recovered_digest = _aggregate_proof_part(
                recovered_digest, candidate_id, candidate_state
            )
            recovered_digest = _aggregate_proof_part(
                recovered_digest, f"{candidate_id}/data", data
            )
        finally:
            os.close(candidate_fd)
    if _aggregate_proof_bytes(recovered_digest) != expected.recovered:
        raise OutputError("Recovered data changed after its content proof.")

    records_digest = 0
    record_state, record_names = _directory_snapshot(
        records_fd, "Recovery records", max_entries=len(expected_records)
    )
    if record_state != expected.records or set(record_names) != expected_records:
        raise OutputError("Recovery checkpoint inventory changed during completion.")
    for candidate_id in reversed(candidate_ids):
        records_digest = _aggregate_proof_part(
            records_digest,
            candidate_id,
            _named_state_proof(
                records_fd, _record_name(candidate_id), "Recovery checkpoint"
            ),
        )
    if _aggregate_proof_bytes(records_digest) != expected.checkpoints:
        raise OutputError("Recovery checkpoint changed during completion.")

    # End with the namespaces that make all of those names reachable.  This also
    # catches additions made while the root files were being checked above.
    work, work_names = _directory_snapshot(
        work_fd, "Recovery work directory", max_entries=0
    )
    files, file_names = _directory_snapshot(
        files_fd, "Recovery files", max_entries=len(recoverable_ids)
    )
    records, record_names = _directory_snapshot(
        records_fd, "Recovery records", max_entries=len(expected_records)
    )
    root, root_names = _directory_snapshot(root_fd, "Recovery output", max_entries=6)
    root_digest, records_inventory, files_inventory, work_inventory = (
        hashlib.sha256(),
        hashlib.sha256(),
        hashlib.sha256(),
        hashlib.sha256(),
    )
    _proof_part(root_digest, "root", root)
    _proof_part(root_digest, "names", root_names)
    _proof_part(records_inventory, "records", records)
    _proof_part(records_inventory, "names", record_names)
    _proof_part(files_inventory, "files", files)
    _proof_part(files_inventory, "names", file_names)
    _proof_part(work_inventory, "work", work)
    _proof_part(work_inventory, "names", work_names)
    if (
        root != expected.root
        or records != expected.records
        or files != expected.files
        or work != expected.work
        or root_digest.digest() != expected.root_inventory
        or records_inventory.digest() != expected.records_inventory
        or files_inventory.digest() != expected.files_inventory
        or work_inventory.digest() != expected.work_inventory
    ):
        raise OutputError("Recovery output namespace changed during completion.")
    _assert_root_path(root_fd, "records", records_fd, "Recovery records")
    _assert_root_path(root_fd, "files", files_fd, "Recovery files")
    _assert_root_path(root_fd, "work", work_fd, "Recovery work directory")
    _assert_root_path(root_parent_fd, root_name, root_fd)
    return expected


def _revalidate_completion_state(
    root_fd: int,
    root_parent_fd: int,
    root_name: str,
    records_fd: int,
    files_fd: int,
    work_fd: int,
    *,
    run_bytes: bytes,
    manifest_bytes: bytes,
    candidate_ids: Sequence[str],
    recoverable_ids: set[str],
    checkpoints: Mapping[str, Mapping[str, object]],
    report_complete: bool,
    report_bytes: bytes | None = None,
    recovered_file_proofs: Mapping[str, tuple[int, ...]]
    | _CompletionProof
    | None = None,
) -> _CompletionProof:
    """Bind every completion input to held private descriptors immediately in use."""
    _validate_output_inventory(
        root_fd,
        records_fd,
        files_fd,
        work_fd,
        candidate_ids=set(candidate_ids),
        recoverable_ids=recoverable_ids,
        report_complete=report_complete,
    )
    previous = (
        recovered_file_proofs
        if isinstance(recovered_file_proofs, _CompletionProof)
        else None
    )
    data_proofs = (
        previous.data_proofs if previous is not None else recovered_file_proofs
    )
    if data_proofs is None:
        proofs = _revalidate_recovered_outputs(files_fd, checkpoints)
    else:
        proofs = _revalidate_recovered_outputs(
            files_fd,
            checkpoints,
            prior_proofs=data_proofs
            if not isinstance(data_proofs, _CompletionProof)
            else None,
        )
    run_proof = _regular_at_equals(
        root_fd, "run.json", run_bytes, max_bytes=MAX_RUN_BYTES, return_proof=True
    )
    manifest_proof = _regular_at_equals(
        root_fd,
        "manifest.jsonl",
        manifest_bytes,
        max_bytes=MAX_INTERNAL_MANIFEST_BYTES,
        return_proof=True,
    )
    if run_proof is None or manifest_proof is None:
        raise OutputError("Immutable recovery state changed during completion.")
    checkpoint_proofs = _revalidate_checkpoint_bytes(
        records_fd, candidate_ids, checkpoints
    )
    _assert_root_path(root_fd, "records", records_fd, "Recovery records")
    _assert_root_path(root_fd, "files", files_fd, "Recovery files")
    _assert_root_path(root_fd, "work", work_fd, "Recovery work directory")
    _assert_root_path(root_parent_fd, root_name, root_fd)
    report_proof: tuple[int, ...] | None = None
    if report_complete:
        if report_bytes is None:
            raise OutputError("Recovery report changed during completion.")
        report_proof = _regular_at_equals(
            root_fd,
            "report.jsonl",
            report_bytes,
            max_bytes=MAX_REPORT_BYTES,
            return_proof=True,
        )
        if report_proof is None:
            raise OutputError("Recovery report changed during completion.")
    if data_proofs is not None:
        _revalidate_recovered_proofs_reverse(files_fd, checkpoints, proofs)
    completion = _capture_completion_proof(
        root_fd,
        root_parent_fd,
        root_name,
        records_fd,
        files_fd,
        work_fd,
        candidate_ids=candidate_ids,
        recoverable_ids=recoverable_ids,
        checkpoints=checkpoints,
        report_complete=report_complete,
        recovered_file_proofs=proofs,
        run_proof=run_proof,
        manifest_proof=manifest_proof,
        checkpoint_proofs=checkpoint_proofs,
        report_proof=report_proof,
    )
    # Close the capture traversal itself.  The subsequent A-B-A state-only pass
    # catches any mutation after this reverse boundary without rereading contents.
    if proofs is not None:
        _revalidate_recovered_proofs_reverse(files_fd, checkpoints, proofs)
    if previous is not None and not previous.unchanged_before_report(completion):
        raise OutputError("Recovery output state changed after its content proof.")
    return completion


def _revalidate_completion_state_from_proofs(
    root_fd: int,
    root_parent_fd: int,
    root_name: str,
    records_fd: int,
    files_fd: int,
    work_fd: int,
    *,
    run_bytes: bytes,
    manifest_bytes: bytes,
    candidate_ids: Sequence[str],
    recoverable_ids: set[str],
    checkpoints: Mapping[str, Mapping[str, object]],
    report_complete: bool,
    recovered_file_proofs: _CompletionProof,
    report_bytes: bytes | None = None,
) -> _CompletionProof:
    """Reprove exact output state from held proofs without rereading contents."""
    # This is intentionally state-only.  The preceding full validation has already
    # bound every byte-bearing object to ``recovered_file_proofs``.
    proof = _capture_completion_proof(
        root_fd,
        root_parent_fd,
        root_name,
        records_fd,
        files_fd,
        work_fd,
        candidate_ids=candidate_ids,
        recoverable_ids=recoverable_ids,
        checkpoints=checkpoints,
        report_complete=report_complete,
        recovered_file_proofs=recovered_file_proofs.data_proofs,
        run_proof=recovered_file_proofs.run,
        manifest_proof=recovered_file_proofs.manifest,
        checkpoint_proofs={},
        report_proof=recovered_file_proofs.report,
        state_only=True,
    )
    if proof != recovered_file_proofs:
        raise OutputError("Recovery output state changed after its content proof.")
    return proof


def _validate_output_inventory(
    root_fd: int,
    records_fd: int,
    files_fd: int,
    work_fd: int,
    *,
    candidate_ids: set[str],
    recoverable_ids: set[str],
    report_complete: bool,
) -> None:
    """Revalidate every bounded output name immediately around completion."""
    base_root = {"run.json", "manifest.jsonl", "records", "files", "work"}
    root_entries = set(
        _listdir_at(root_fd, "recovery output", max_entries=len(base_root) + 1)
    )
    if report_complete:
        valid_root_states = (base_root | {"report.jsonl"},)
    else:
        valid_root_states = (
            base_root,
            base_root | {_state_temporary_name("report.jsonl")},
        )
    if root_entries not in valid_root_states:
        raise OutputError(
            "Recovery output inventory is not in its exact expected state."
        )
    expected_records = {_record_name(candidate_id) for candidate_id in candidate_ids}
    if (
        set(
            _listdir_at(
                records_fd, "recovery records", max_entries=len(expected_records)
            )
        )
        != expected_records
    ):
        raise OutputError(
            "Recovery record inventory is not in its exact expected state."
        )
    if (
        set(_listdir_at(files_fd, "recovery files", max_entries=len(recoverable_ids)))
        != recoverable_ids
    ):
        raise OutputError("Recovery file inventory is not in its exact expected state.")
    if _listdir_at(work_fd, "recovery work directory", max_entries=0):
        raise OutputError("Recovery work directory is not empty.")
    for candidate_id in recoverable_ids:
        candidate_fd = _open_dir_at(files_fd, candidate_id)
        try:
            if set(_listdir_at(candidate_fd, "recovered candidate", max_entries=1)) != {
                "data"
            }:
                raise OutputError(
                    "Recovered candidate inventory is not in its exact expected state."
                )
        finally:
            os.close(candidate_fd)


def _write_candidate(
    source: ImageSource,
    files_fd: int,
    work_fd: int,
    plan: dict[str, Any],
    binding: Mapping[str, object],
    *,
    candidate_fd: int | None = None,
    resume_temporary: bool = False,
    published_file_proofs: dict[str, tuple[int, ...]] | None = None,
) -> dict[str, Any]:
    candidate_id = plan["candidate_id"]
    own_candidate_fd = candidate_fd is None
    if candidate_fd is None:
        candidate_fd = _mkdir_at(files_fd, candidate_id)
    try:
        tmp_name = f"{candidate_id}.partial"
        try:
            tmp_fd = os.open(
                tmp_name,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=work_fd,
            )
        except FileExistsError as exc:
            if not resume_temporary:
                raise OutputError(
                    "An unexpected recovery temporary was left untouched."
                ) from exc
            try:
                tmp_fd = os.open(
                    tmp_name,
                    os.O_RDWR
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_NONBLOCK", 0),
                    dir_fd=work_fd,
                )
            except OSError as open_exc:
                _raise_output_io(
                    "Could not safely resume the recovery temporary", open_exc
                )
        except OSError as exc:
            _raise_output_io("Could not create a private recovery temporary", exc)
        try:
            tmp_state = os.fstat(tmp_fd)
            _private_file_state(tmp_state, "Recovery temporary")
            logical_size = plan["logical_size_bytes"]
            if tmp_state.st_size > logical_size:
                raise OutputError(
                    "Recovery temporary exceeds the expected logical size."
                )
            existing_size = tmp_state.st_size
            try:
                os.lseek(tmp_fd, existing_size, os.SEEK_SET)
            except OSError as exc:
                _raise_output_io("Could not resume recovery temporary", exc)
            source_digest, output_digest = hashlib.sha256(), hashlib.sha256()
            output_position = 0

            def consume(data: bytes, *, from_source: bool) -> None:
                nonlocal output_position
                if from_source:
                    source_digest.update(data)
                output_digest.update(data)
                prefix_size = min(len(data), max(0, existing_size - output_position))
                if prefix_size:
                    try:
                        existing = os.pread(tmp_fd, prefix_size, output_position)
                    except OSError as exc:
                        _raise_output_io("Could not inspect recovery temporary", exc)
                    if existing != data[:prefix_size]:
                        raise OutputError(
                            "Recovery temporary does not match the exact source plan."
                        )
                if prefix_size < len(data):
                    _write_all(tmp_fd, data[prefix_size:], "recovered data")
                output_position += len(data)

            heap = binding.get("cluster_heap_offset_bytes")
            cluster_size = binding.get("cluster_size_bytes")
            if (
                not isinstance(heap, int)
                or not isinstance(cluster_size, int)
                or cluster_size < 1
            ):
                raise ManifestError("The run source binding lacks extraction geometry.")
            remaining = plan["valid_data_bytes"]
            for extent in plan["extents"]:
                position = heap + (extent["first_cluster"] - 2) * cluster_size
                extent_bytes = extent["cluster_count"] * cluster_size
                take = min(remaining, extent_bytes)
                while take:
                    count = min(take, _CHUNK)
                    data = source.read_exact(position, count)
                    consume(data, from_source=True)
                    source.release_cache(position, count)
                    position += count
                    take -= count
                    remaining -= count
            if remaining:
                raise ManifestError(
                    f"Plan '{candidate_id}' extents do not cover ValidDataLength."
                )
            zeros = plan["logical_size_bytes"] - plan["valid_data_bytes"]
            zero_block = b"\0" * min(_CHUNK, zeros)
            while zeros:
                part = zero_block[: min(len(zero_block), zeros)]
                consume(part, from_source=False)
                zeros -= len(part)
            if output_position != logical_size:
                raise ManifestError(
                    f"Plan '{candidate_id}' does not produce its exact logical size."
                )
            completed_state = os.fstat(tmp_fd)
            if completed_state.st_size != logical_size:
                raise OutputError(
                    "Recovery temporary does not have the exact logical size."
                )
            _fsync(tmp_fd, "recovery temporary")
            try:
                current_tmp = os.stat(tmp_name, dir_fd=work_fd, follow_symlinks=False)
            except OSError as exc:
                _raise_output_io("Could not inspect recovery temporary", exc)
            if not _same_identity(tmp_state, current_tmp):
                raise OutputError(
                    "Recovery temporary was replaced and was left untouched."
                )
            _private_file_state(current_tmp, "Recovery temporary")
            source.assert_unchanged()
            staged = os.fstat(tmp_fd)
            _private_file_state(staged, "Recovery temporary")
            _rename_noreplace(work_fd, tmp_name, candidate_fd, "data")
            _assert_published_file(
                candidate_fd, "data", tmp_fd, staged, "Recovered data"
            )
            _fsync(candidate_fd, "recovered candidate directory")
            _fsync(work_fd, "recovery work directory")
            _, published_digest, published_proof = _hash_file_at(
                candidate_fd, "data", expected_size=logical_size
            )
            if published_digest != output_digest.hexdigest():
                raise OutputError("Recovered data changed while being published.")
            if published_file_proofs is not None:
                published_file_proofs[candidate_id] = published_proof
            return {
                "record_type": "candidate",
                "candidate_id": candidate_id,
                "disposition": "recovered",
                "output_path": f"files/{candidate_id}/data",
                "logical_size_bytes": logical_size,
                "valid_data_bytes": plan["valid_data_bytes"],
                "source_extents": plan["extents"],
                "source_bytes": plan["valid_data_bytes"],
                "zero_filled_bytes": logical_size - plan["valid_data_bytes"],
                "source_data_sha256": source_digest.hexdigest(),
                "output_sha256": output_digest.hexdigest(),
            }
        except OSError as exc:
            _raise_output_io("Could not inspect or synchronize recovery temporary", exc)
        finally:
            os.close(tmp_fd)
    finally:
        if own_candidate_fd:
            os.close(candidate_fd)


def _terminal_record(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_type": "candidate",
        "candidate_id": plan["candidate_id"],
        "disposition": plan["disposition"],
        "reasons": plan.get("reasons", []),
    }


def _projected_checkpoint_record(plan: dict[str, Any]) -> dict[str, Any]:
    """Return an exact-size checkpoint shape without reading source data."""
    if plan["disposition"] != "recoverable":
        return _terminal_record(plan)
    candidate_id = plan["candidate_id"]
    return {
        "record_type": "candidate",
        "candidate_id": candidate_id,
        "disposition": "recovered",
        "output_path": f"files/{candidate_id}/data",
        "logical_size_bytes": plan["logical_size_bytes"],
        "valid_data_bytes": plan["valid_data_bytes"],
        "source_extents": plan["extents"],
        "source_bytes": plan["valid_data_bytes"],
        "zero_filled_bytes": plan["logical_size_bytes"] - plan["valid_data_bytes"],
        "source_data_sha256": "0" * 64,
        "output_sha256": "0" * 64,
    }


def _projected_report_size(plans: Sequence[dict[str, Any]]) -> int:
    """Return the exact final report size before output-directory creation.

    Both report digests are fixed-width lowercase SHA-256 values, so replacing
    them with zeroes preserves the canonical serialized byte count exactly.
    """
    header = _canonical({"record_type": "report", "run_sha256": "0" * 64}) + b"\n"
    records_size = sum(
        len(_canonical(_projected_checkpoint_record(plan))) + 1 for plan in plans
    )
    completion = (
        _canonical(
            {
                "record_type": "complete",
                "candidate_count": len(plans),
                "content_record_count": len(plans) + 1,
                "content_sha256": "0" * 64,
            }
        )
        + b"\n"
    )
    return len(header) + records_size + len(completion)


def _expected_record(
    source: ImageSource, plan: dict[str, Any], binding: Mapping[str, object]
) -> dict[str, Any]:
    """Derive checkpoint hashes without materializing recovered content."""
    heap, cluster_size = (
        binding.get("cluster_heap_offset_bytes"),
        binding.get("cluster_size_bytes"),
    )
    if not isinstance(heap, int) or not isinstance(cluster_size, int):
        raise ManifestError("The run source binding lacks extraction geometry.")
    source_digest = hashlib.sha256()
    output_digest = hashlib.sha256()
    remaining = plan["valid_data_bytes"]
    for extent in plan["extents"]:
        position = heap + (extent["first_cluster"] - 2) * cluster_size
        take = min(remaining, extent["cluster_count"] * cluster_size)
        while take:
            data = source.read_exact(position, min(take, _CHUNK))
            source_digest.update(data)
            output_digest.update(data)
            source.release_cache(position, len(data))
            position += len(data)
            take -= len(data)
            remaining -= len(data)
    if remaining:
        raise ManifestError("Plan extents do not cover ValidDataLength.")
    zeros = plan["logical_size_bytes"] - plan["valid_data_bytes"]
    block = b"\0" * min(_CHUNK, zeros)
    while zeros:
        part = block[: min(len(block), zeros)]
        output_digest.update(part)
        zeros -= len(part)
    return {
        "record_type": "candidate",
        "candidate_id": plan["candidate_id"],
        "disposition": "recovered",
        "output_path": f"files/{plan['candidate_id']}/data",
        "logical_size_bytes": plan["logical_size_bytes"],
        "valid_data_bytes": plan["valid_data_bytes"],
        "source_extents": plan["extents"],
        "source_bytes": plan["valid_data_bytes"],
        "zero_filled_bytes": plan["logical_size_bytes"] - plan["valid_data_bytes"],
        "source_data_sha256": source_digest.hexdigest(),
        "output_sha256": output_digest.hexdigest(),
    }


def _create_run(
    source: ImageSource,
    plans: Iterable[Any],
    output: str | Path,
    *,
    binding: Mapping[str, object],
    limits: Mapping[str, int] | None = None,
    manifest_bytes: bytes | None = None,
    validated_manifest: Any | None = None,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Create a new private run and extract only prevalidated recoverable plans."""
    target = _new_output_target(output)
    limits = {**DEFAULT_RUN_LIMITS, **(limits or {})}
    if (
        set(limits)
        != {
            "max_output_bytes",
            "max_candidates",
            "max_scan_clusters",
            "max_fat_steps",
        }
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 1
            for value in limits.values()
        )
        or limits["max_candidates"] > HARD_MAX_RECOVERY_CANDIDATES
    ):
        raise ResourceLimitError("Recovery requires complete positive integer limits.")
    normalized: list[dict[str, Any]] = []
    for index, plan in enumerate(plans):
        if index >= limits["max_candidates"]:
            raise ResourceLimitError(
                "Selected recovery plans exceed the configured candidate limit."
            )
        normalized.append(_validate_plan(plan))
    if len({plan["candidate_id"] for plan in normalized}) != len(normalized):
        raise ManifestError("Recovery plans contain duplicate candidate IDs.")
    total = sum(
        plan["logical_size_bytes"]
        for plan in normalized
        if plan["disposition"] == "recoverable"
    )
    if total > limits["max_output_bytes"]:
        raise ResourceLimitError(
            "Selected recoverable output exceeds --max-output-bytes."
        )
    if _projected_report_size(normalized) > MAX_REPORT_BYTES:
        raise ResourceLimitError(
            "Selected recovery plans exceed the bounded final-report size."
        )
    if source.is_same_file(target):
        raise OutputError(
            "Recovery output must be a new directory and must not be the image."
        )
    binding = dict(binding)
    required_binding = {
        "volume_offset_bytes",
        "volume_length_bytes",
        "volume_sha256",
        "cluster_size_bytes",
        "cluster_heap_offset_bytes",
    }
    if not required_binding.issubset(binding):
        raise ManifestError("The run source binding lacks required recovery fields.")
    for plan in normalized:
        _validate_plan_geometry(plan, binding)
    source.assert_unchanged()
    if manifest_bytes is None or len(manifest_bytes) > MAX_INTERNAL_MANIFEST_BYTES:
        raise ManifestError(
            "The immutable internal manifest is absent or exceeds its limit."
        )
    if validated_manifest is None:
        from .manifest import parse_manifest_v2_bytes

        manifest = parse_manifest_v2_bytes(manifest_bytes)
    else:
        manifest = validated_manifest
        if getattr(manifest, "raw_bytes", None) != manifest_bytes:
            raise ManifestError(
                "The validated manifest object and immutable bytes disagree."
            )
    selected_by_id = {plan["candidate_id"]: plan for plan in normalized}
    stored_selected = {
        plan.candidate_id: _validate_plan(plan)
        for plan in manifest.plans
        if plan.candidate_id in selected_by_id
    }
    if (
        manifest.header["source"] != binding
        or set(stored_selected) != set(selected_by_id)
        or any(stored_selected[key] != value for key, value in selected_by_id.items())
    ):
        raise ManifestError(
            "Recovery plans and source binding must match the immutable v2 manifest."
        )
    parent_fd = None
    try:
        parent_fd = os.open(
            target.parent,
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise OutputError(
            f"Could not safely open recovery output parent: {exc.strerror}."
        ) from exc
    try:
        destination_state = os.fstatvfs(parent_fd)
    except OSError as exc:
        os.close(parent_fd)
        _raise_output_io("Could not inspect recovery destination capacity", exc)
    available = destination_state.f_bavail * destination_state.f_frsize
    if total > available:
        os.close(parent_fd)
        raise ResourceLimitError(
            "Recovery destination does not have enough available space."
        )
    os.close(parent_fd)
    run = {
        "format": "exfat-rescue.run",
        "version": RUN_VERSION,
        "source": binding,
        "source_file_state": source.proof_state(),
        "limits": limits,
        "candidate_ids": [plan["candidate_id"] for plan in normalized],
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    }
    run_bytes = _canonical(run) + b"\n"
    if len(run_bytes) > MAX_RUN_BYTES:
        raise ManifestError("The immutable run descriptor exceeds its size limit.")
    recoverable_ids = {
        plan["candidate_id"]
        for plan in normalized
        if plan["disposition"] == "recoverable"
    }
    root_fd, root_parent_fd, root_name = _prepare_new_run_root(
        target,
        manifest_bytes=manifest_bytes,
        run_bytes=run_bytes,
    )
    requested_parent = _requested_parent_proof(target.parent, root_parent_fd)
    try:
        child_fds: list[int] = []
        try:
            for name in ("records", "files", "work"):
                child_fds.append(_open_dir_at(root_fd, name))
            records_fd, files_fd, work_fd = child_fds
            checkpoints: dict[str, dict[str, Any]] = {}
            published_file_proofs: dict[str, tuple[int, ...]] = {}
            for index, plan in enumerate(normalized, 1):
                source.assert_unchanged()
                record = (
                    _write_candidate(
                        source,
                        files_fd,
                        work_fd,
                        plan,
                        binding,
                        published_file_proofs=published_file_proofs,
                    )
                    if plan["disposition"] == "recoverable"
                    else _terminal_record(plan)
                )
                _write_new_at(
                    records_fd,
                    _record_name(plan["candidate_id"]),
                    _canonical(record) + b"\n",
                )
                checkpoints[plan["candidate_id"]] = record
                source.assert_unchanged()
                if progress is not None:
                    progress(
                        "recover-candidates",
                        index,
                        len(normalized),
                        "candidates",
                    )
                if index % CHECKPOINT_SYNC_INTERVAL == 0:
                    _fsync(records_fd, "recovery checkpoint batch")
            if normalized and len(normalized) % CHECKPOINT_SYNC_INTERVAL:
                _fsync(records_fd, "final recovery checkpoint batch")
            if source.selected_volume_sha256(
                int(binding["volume_offset_bytes"]),
                int(binding["volume_length_bytes"]),
            ) != binding.get("volume_sha256"):
                raise SourceError("The selected exFAT volume changed during recovery.")
            recovered_file_proofs = _revalidate_completion_state(
                root_fd,
                root_parent_fd,
                root_name,
                records_fd,
                files_fd,
                work_fd,
                run_bytes=run_bytes,
                manifest_bytes=manifest_bytes,
                candidate_ids=run["candidate_ids"],
                recoverable_ids=recoverable_ids,
                checkpoints=checkpoints,
                report_complete=False,
                recovered_file_proofs=published_file_proofs,
            )
            source.assert_unchanged()
            report = _completion(records_fd, run, checkpoints)
            _write_new_at(root_fd, "report.jsonl", report)
            source.assert_unchanged()
            recovered_file_proofs = _revalidate_completion_state(
                root_fd,
                root_parent_fd,
                root_name,
                records_fd,
                files_fd,
                work_fd,
                run_bytes=run_bytes,
                manifest_bytes=manifest_bytes,
                candidate_ids=run["candidate_ids"],
                recoverable_ids=recoverable_ids,
                checkpoints=checkpoints,
                report_complete=True,
                report_bytes=report,
                recovered_file_proofs=recovered_file_proofs,
            )
            source.assert_unchanged()
            _revalidate_completion_state_from_proofs(
                root_fd,
                root_parent_fd,
                root_name,
                records_fd,
                files_fd,
                work_fd,
                run_bytes=run_bytes,
                manifest_bytes=manifest_bytes,
                candidate_ids=run["candidate_ids"],
                recoverable_ids=recoverable_ids,
                checkpoints=checkpoints,
                report_complete=True,
                report_bytes=report,
                recovered_file_proofs=recovered_file_proofs,
            )
            source.assert_unchanged()
            _assert_requested_parent(requested_parent, root_parent_fd)
            return {
                "output": str(target),
                "candidate_count": len(normalized),
                "output_bytes": total,
                "complete": True,
                **_recovery_result_counts(normalized),
            }
        finally:
            for child_fd in reversed(child_fds):
                os.close(child_fd)
    finally:
        try:
            os.close(root_fd)
        finally:
            os.close(root_parent_fd)


def recover_plans(
    source: ImageSource,
    plans: Sequence[Any],
    output_dir: Path,
    *,
    source_binding: Mapping[str, object],
    manifest_bytes: bytes,
    selected_ids: Sequence[str],
    limits: Mapping[str, int],
    resume: bool = False,
    validated_manifest: Any | None = None,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Extract frozen planner plans to a newly-created output directory.

    ``resume`` exists for the frozen public seam; callers should use
    :func:`resume_recovery` so the immutable descriptor remains authoritative.
    """
    if resume:
        raise ManifestError("Resume requires a freshly validated planner result.")
    requested = list(selected_ids)
    if any(
        not isinstance(value, str) or not _ID.fullmatch(value) for value in requested
    ) or len(requested) != len(set(requested)):
        raise UsageError("Candidate selection contains a malformed or duplicate ID.")
    candidate_limit = limits.get("max_candidates", DEFAULT_RUN_LIMITS["max_candidates"])
    if (
        type(candidate_limit) is not int
        or not 1 <= candidate_limit <= HARD_MAX_RECOVERY_CANDIDATES
    ):
        raise ResourceLimitError(
            "Recovery requires a positive selected-candidate limit no greater "
            f"than {HARD_MAX_RECOVERY_CANDIDATES}."
        )
    if len(plans) > HARD_MAX_CANDIDATES:
        raise ResourceLimitError(
            "The recovery-plan universe exceeds the supported discovery ceiling."
        )
    if len(requested) > candidate_limit:
        raise ResourceLimitError(
            "Selected recovery plans exceed the configured candidate limit."
        )
    binding = dict(source_binding)
    required = {
        "volume_offset_bytes",
        "volume_length_bytes",
        "volume_sha256",
        "cluster_size_bytes",
        "cluster_heap_offset_bytes",
    }
    if not required.issubset(binding):
        raise ManifestError("The v2 source binding lacks recovery extraction fields.")
    if validated_manifest is None:
        from .manifest import parse_manifest_v2_bytes

        manifest = parse_manifest_v2_bytes(manifest_bytes)
    else:
        manifest = validated_manifest
        if getattr(manifest, "raw_bytes", None) != manifest_bytes:
            raise ManifestError(
                "The validated manifest object and immutable bytes disagree."
            )
    if len(plans) != len(manifest.plans):
        raise ManifestError(
            "Recovery plans and source binding must exactly match the immutable v2 manifest."
        )
    requested_set = set(requested)
    selected_by_id: dict[str, dict[str, Any]] = {}
    for supplied, stored in zip(plans, manifest.plans, strict=True):
        supplied_plan = _validate_plan(supplied)
        if supplied_plan != _validate_plan(stored):
            raise ManifestError(
                "Recovery plans and source binding must exactly match the immutable v2 manifest."
            )
        if supplied_plan["candidate_id"] in requested_set:
            selected_by_id[supplied_plan["candidate_id"]] = supplied_plan
    if manifest.header["source"] != binding:
        raise ManifestError(
            "Recovery plans and source binding must exactly match the immutable v2 manifest."
        )
    if set(selected_by_id) != requested_set:
        raise UsageError("Candidate selection contains an unknown or duplicate ID.")
    selected = [selected_by_id[item] for item in requested]
    if (
        source.selected_volume_sha256(
            int(binding["volume_offset_bytes"]), int(binding["volume_length_bytes"])
        )
        != binding["volume_sha256"]
    ):
        raise SourceError(
            "The source image does not match the manifest volume binding."
        )
    result = _create_run(
        source,
        selected,
        output_dir,
        binding=binding,
        limits=limits,
        manifest_bytes=manifest_bytes,
        validated_manifest=manifest,
        progress=progress,
    )
    result["selected_candidate_ids"] = requested
    return result


def create_run(
    source: ImageSource,
    volume: Any,
    plans: Iterable[Any],
    output: str | Path,
    *,
    limits: dict[str, Any] | None = None,
    manifest_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Compatibility helper for programmatic users with an opened ``ExfatVolume``."""
    return _create_run(
        source,
        plans,
        output,
        binding=_source_binding(source, volume),
        limits=limits,
        manifest_bytes=manifest_bytes,
    )


def resume_recovery(
    source: ImageSource,
    output_dir: Path,
    *,
    planner_result: Any,
    manifest: Any,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Resume only after the caller has reparsed and replanned the internal manifest."""
    root_fd, root_parent_fd, root_name = _open_dir_with_parent(output_dir)
    requested_parent = _requested_parent_proof(
        Path(output_dir).absolute().parent, root_parent_fd
    )
    try:
        _lock_directory(root_fd, "Recovery output")
        entries = set(_listdir_at(root_fd, "recovery output", max_entries=6))
        required_entries = {"run.json", "manifest.jsonl", "records", "files", "work"}
        report_temporary = _state_temporary_name("report.jsonl")
        if entries not in (
            required_entries,
            required_entries | {"report.jsonl"},
            required_entries | {report_temporary},
        ):
            raise OutputError(
                "Recovery output contains unknown or missing root objects."
            )
        run_bytes = _read_regular_at(root_fd, "run.json", max_bytes=MAX_RUN_BYTES)
        run = _json_object(run_bytes, "Run descriptor")
        version = run.get("version")
        expected_run_fields = {
            "format",
            "version",
            "source",
            "limits",
            "candidate_ids",
            "manifest_sha256",
        }
        if version == RUN_VERSION:
            expected_run_fields.add("source_file_state")
        if (
            set(run) != expected_run_fields
            or run.get("format") != "exfat-rescue.run"
            or type(version) is not int
            or version not in {LEGACY_RUN_VERSION, RUN_VERSION}
            or (
                version == RUN_VERSION
                and not _valid_source_file_state(run.get("source_file_state"))
            )
        ):
            raise ManifestError("The run descriptor is malformed.")
        binding = run.get("source")
        if (
            not isinstance(binding, dict)
            or dict(getattr(planner_result, "source_binding", {})) != binding
        ):
            raise ManifestError("The run descriptor is malformed.")
        limits = run.get("limits")
        if (
            not isinstance(limits, dict)
            or set(limits) != set(DEFAULT_RUN_LIMITS)
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 1
                or (key == "max_candidates" and value > HARD_MAX_RECOVERY_CANDIDATES)
                for key, value in limits.items()
            )
        ):
            raise ManifestError("The run descriptor limits are malformed.")
        internal_manifest = getattr(manifest, "raw_bytes", None)
        if (
            not isinstance(internal_manifest, bytes)
            or hashlib.sha256(internal_manifest).hexdigest()
            != run.get("manifest_sha256")
            or not _regular_at_equals(
                root_fd,
                "manifest.jsonl",
                internal_manifest,
                max_bytes=MAX_INTERNAL_MANIFEST_BYTES,
            )
        ):
            raise ManifestError("The immutable internal manifest changed.")
        if (
            getattr(manifest, "plans", None) is None
            or manifest.header.get("source") != binding
        ):
            raise ManifestError("Resume requires a completely validated v2 manifest.")
        from .manifest import validate_manifest_plans

        validate_manifest_plans(manifest, planner_result)
        if source.selected_volume_sha256(
            int(binding["volume_offset_bytes"]), int(binding["volume_length_bytes"])
        ) != binding.get("volume_sha256"):
            raise SourceError("The source image no longer matches this recovery run.")
        all_plans = [
            _validate_plan(plan) for plan in getattr(planner_result, "plans", ())
        ]
        by_id = {plan["candidate_id"]: plan for plan in all_plans}
        candidate_ids = run.get("candidate_ids")
        if (
            not isinstance(candidate_ids, list)
            or len(candidate_ids) > limits["max_candidates"]
            or any(
                not isinstance(value, str) or value not in by_id
                for value in candidate_ids
            )
            or len(candidate_ids) != len(set(candidate_ids))
        ):
            raise ManifestError(
                "Current planner inventory differs from immutable run selection."
            )
        plans = [by_id[value] for value in candidate_ids]
        output_bytes = sum(
            plan["logical_size_bytes"]
            for plan in plans
            if plan["disposition"] == "recoverable"
        )
        if output_bytes > limits["max_output_bytes"]:
            raise ResourceLimitError(
                "Immutable recovery plans exceed the run output limit."
            )
        # Completion is immutable: a valid report makes resume a validating no-op.
        if "report.jsonl" in entries:
            from .verification import verify_recovery

            verified = verify_recovery(output_dir, progress=progress)
            source.assert_unchanged()
            _assert_root_path(root_parent_fd, root_name, root_fd)
            _assert_requested_parent(requested_parent, root_parent_fd)
            return {
                "output": str(output_dir),
                "candidate_count": len(plans),
                "output_bytes": output_bytes,
                "complete": True,
                "resumed": False,
                "verified": verified["ok"],
                **_recovery_result_counts(plans),
            }
        records_fd: int | None = None
        files_fd: int | None = None
        work_fd: int | None = None
        try:
            records_fd = _open_dir_at(root_fd, "records")
            files_fd = _open_dir_at(root_fd, "files")
            work_fd = _open_dir_at(root_fd, "work")
            checkpoints: dict[str, dict[str, Any]] = {}
            published_file_proofs: dict[str, tuple[int, ...]] = {}
            expected_record_names = {
                _record_name(plan["candidate_id"]) for plan in plans
            }
            expected_record_temporaries = {
                _state_temporary_name(name) for name in expected_record_names
            }
            record_entries = set(
                _listdir_at(
                    records_fd,
                    "recovery records",
                    max_entries=len(expected_record_names)
                    + len(expected_record_temporaries),
                )
            )
            if not record_entries.issubset(
                expected_record_names | expected_record_temporaries
            ):
                raise OutputError("Recovery records contain unknown objects.")
            if any(
                name in record_entries and _state_temporary_name(name) in record_entries
                for name in expected_record_names
            ):
                raise OutputError(
                    "Recovery records contain an ambiguous publication state."
                )
            expected_file_names = {
                plan["candidate_id"]
                for plan in plans
                if plan["disposition"] == "recoverable"
            }
            file_entries = set(
                _listdir_at(
                    files_fd,
                    "recovery files",
                    max_entries=len(expected_file_names),
                )
            )
            if not file_entries.issubset(expected_file_names):
                raise OutputError("Recovery files contain unknown objects.")
            expected_work_names = {
                f"{candidate_id}.partial" for candidate_id in expected_file_names
            }
            work_entries = set(
                _listdir_at(
                    work_fd,
                    "recovery work directory",
                    max_entries=len(expected_work_names),
                )
            )
            if not work_entries.issubset(expected_work_names):
                raise OutputError("Recovery work directory contains unknown objects.")
            for index, plan in enumerate(plans, 1):
                name = _record_name(plan["candidate_id"])
                state_temporary = _state_temporary_name(name)
                data_temporary = f"{plan['candidate_id']}.partial"
                if name in record_entries:
                    existing_bytes = _read_regular_at(records_fd, name)
                    existing = _json_object(existing_bytes, "Candidate checkpoint")
                    expected = (
                        _expected_record(source, plan, binding)
                        if plan["disposition"] == "recoverable"
                        else _terminal_record(plan)
                    )
                    if existing_bytes != _canonical(expected) + b"\n":
                        raise OutputError(
                            "Existing candidate checkpoint does not match the current exact plan."
                        )
                    if plan["disposition"] == "recoverable":
                        if data_temporary in work_entries:
                            raise OutputError(
                                "Checkpointed data has an unexpected recovery temporary."
                            )
                        candidate_fd = _open_dir_at(files_fd, plan["candidate_id"])
                        try:
                            if set(
                                _listdir_at(
                                    candidate_fd,
                                    "recovered candidate",
                                    max_entries=1,
                                )
                            ) != {"data"}:
                                raise OutputError(
                                    "Checkpointed candidate directory contains unknown artifacts."
                                )
                            _size, digest, proof = _hash_file_at(
                                candidate_fd,
                                "data",
                                expected_size=expected["logical_size_bytes"],
                            )
                        finally:
                            os.close(candidate_fd)
                        if digest != expected["output_sha256"]:
                            raise OutputError(
                                "Checkpointed recovered data was altered."
                            )
                        published_file_proofs[plan["candidate_id"]] = proof
                    elif plan["candidate_id"] in file_entries:
                        raise OutputError(
                            "A refused candidate unexpectedly has an output directory."
                        )
                    checkpoints[plan["candidate_id"]] = existing
                    if progress is not None:
                        progress(
                            "resume-candidates",
                            index,
                            len(plans),
                            "candidates",
                        )
                    if index % CHECKPOINT_SYNC_INTERVAL == 0:
                        _fsync(records_fd, "recovery checkpoint batch")
                    continue
                if plan["disposition"] != "recoverable":
                    record = _terminal_record(plan)
                    _write_new_at(records_fd, name, _canonical(record) + b"\n")
                    record_entries.discard(state_temporary)
                    record_entries.add(name)
                    checkpoints[plan["candidate_id"]] = record
                    if progress is not None:
                        progress(
                            "resume-candidates",
                            index,
                            len(plans),
                            "candidates",
                        )
                    if index % CHECKPOINT_SYNC_INTERVAL == 0:
                        _fsync(records_fd, "recovery checkpoint batch")
                    continue
                if plan["candidate_id"] not in file_entries:
                    if data_temporary in work_entries:
                        raise OutputError(
                            "A recovery temporary without its candidate directory was left untouched."
                        )
                    record = _write_candidate(
                        source,
                        files_fd,
                        work_fd,
                        plan,
                        binding,
                        published_file_proofs=published_file_proofs,
                    )
                    file_entries.add(plan["candidate_id"])
                else:
                    candidate_fd = _open_dir_at(files_fd, plan["candidate_id"])
                    try:
                        candidate_entries = set(
                            _listdir_at(
                                candidate_fd,
                                "interrupted candidate",
                                max_entries=1,
                            )
                        )
                        if candidate_entries == set():
                            record = _write_candidate(
                                source,
                                files_fd,
                                work_fd,
                                plan,
                                binding,
                                candidate_fd=candidate_fd,
                                resume_temporary=data_temporary in work_entries,
                                published_file_proofs=published_file_proofs,
                            )
                            work_entries.discard(data_temporary)
                        elif candidate_entries != {"data"}:
                            raise OutputError(
                                "Interrupted candidate directory contains unknown artifacts."
                            )
                        else:
                            if data_temporary in work_entries:
                                raise OutputError(
                                    "Published data has an ambiguous recovery temporary."
                                )
                            expected = _expected_record(source, plan, binding)
                            _size, digest, proof = _hash_file_at(
                                candidate_fd,
                                "data",
                                expected_size=expected["logical_size_bytes"],
                            )
                            if digest != expected["output_sha256"]:
                                raise OutputError(
                                    "Published uncheckpointed data does not match the exact plan."
                                )
                            published_file_proofs[plan["candidate_id"]] = proof
                            record = expected
                    finally:
                        os.close(candidate_fd)
                _write_new_at(records_fd, name, _canonical(record) + b"\n")
                record_entries.discard(state_temporary)
                record_entries.add(name)
                checkpoints[plan["candidate_id"]] = record
                if progress is not None:
                    progress(
                        "resume-candidates",
                        index,
                        len(plans),
                        "candidates",
                    )
                if index % CHECKPOINT_SYNC_INTERVAL == 0:
                    _fsync(records_fd, "recovery checkpoint batch")
            if plans and len(plans) % CHECKPOINT_SYNC_INTERVAL:
                _fsync(records_fd, "final recovery checkpoint batch")
            if (
                set(
                    _listdir_at(
                        records_fd,
                        "recovery records",
                        max_entries=len(expected_record_names),
                    )
                )
                != expected_record_names
            ):
                raise OutputError(
                    "Recovery records are not in their final exact state."
                )
            if _listdir_at(work_fd, "recovery work directory", max_entries=0):
                raise OutputError("Recovery work directory is not empty.")
            source.assert_unchanged()
            if source.selected_volume_sha256(
                int(binding["volume_offset_bytes"]), int(binding["volume_length_bytes"])
            ) != binding.get("volume_sha256"):
                raise SourceError(
                    "The source image no longer matches this recovery run."
                )
            recovered_file_proofs = _revalidate_completion_state(
                root_fd,
                root_parent_fd,
                root_name,
                records_fd,
                files_fd,
                work_fd,
                run_bytes=run_bytes,
                manifest_bytes=internal_manifest,
                candidate_ids=candidate_ids,
                recoverable_ids=expected_file_names,
                checkpoints=checkpoints,
                report_complete=False,
                recovered_file_proofs=published_file_proofs,
            )
            source.assert_unchanged()
            report = _completion(records_fd, run, checkpoints)
            _write_new_at(root_fd, "report.jsonl", report)
            source.assert_unchanged()
            recovered_file_proofs = _revalidate_completion_state(
                root_fd,
                root_parent_fd,
                root_name,
                records_fd,
                files_fd,
                work_fd,
                run_bytes=run_bytes,
                manifest_bytes=internal_manifest,
                candidate_ids=candidate_ids,
                recoverable_ids=expected_file_names,
                checkpoints=checkpoints,
                report_complete=True,
                report_bytes=report,
                recovered_file_proofs=recovered_file_proofs,
            )
            source.assert_unchanged()
            _revalidate_completion_state_from_proofs(
                root_fd,
                root_parent_fd,
                root_name,
                records_fd,
                files_fd,
                work_fd,
                run_bytes=run_bytes,
                manifest_bytes=internal_manifest,
                candidate_ids=candidate_ids,
                recoverable_ids=expected_file_names,
                checkpoints=checkpoints,
                report_complete=True,
                report_bytes=report,
                recovered_file_proofs=recovered_file_proofs,
            )
            source.assert_unchanged()
            _assert_requested_parent(requested_parent, root_parent_fd)
            return {
                "output": str(output_dir),
                "candidate_count": len(plans),
                "output_bytes": output_bytes,
                "complete": True,
                "resumed": True,
                **_recovery_result_counts(plans),
            }
        finally:
            if records_fd is not None:
                os.close(records_fd)
            if files_fd is not None:
                os.close(files_fd)
            if work_fd is not None:
                os.close(work_fd)
    except (ValueError, KeyError, TypeError, OverflowError) as exc:
        raise ManifestError("The run descriptor is malformed.") from exc
    finally:
        try:
            os.close(root_fd)
        finally:
            os.close(root_parent_fd)


def _completion(
    records_fd: int,
    run: dict[str, Any],
    checkpoints: Mapping[str, Mapping[str, object]],
) -> bytes:
    """Construct completion only from the exact checkpoint bytes just validated."""
    candidate_ids = run["candidate_ids"]
    _revalidate_checkpoint_bytes(records_fd, candidate_ids, checkpoints)
    lines = [
        _canonical(
            {
                "record_type": "report",
                "run_sha256": hashlib.sha256(_canonical(run)).hexdigest(),
            }
        )
        + b"\n"
    ]
    report_size = len(lines[0])
    if report_size > MAX_REPORT_BYTES:
        raise ResourceLimitError("Recovery report exceeds its cumulative byte limit.")
    digest = hashlib.sha256()
    for line in lines:
        digest.update(line)
    for candidate_id in candidate_ids:
        line = _canonical(checkpoints[candidate_id]) + b"\n"
        report_size += len(line)
        if report_size > MAX_REPORT_BYTES:
            raise ResourceLimitError(
                "Recovery report exceeds its cumulative byte limit."
            )
        digest.update(line)
        lines.append(line)
    complete = (
        _canonical(
            {
                "record_type": "complete",
                "candidate_count": len(candidate_ids),
                "content_record_count": len(lines),
                "content_sha256": digest.hexdigest(),
            }
        )
        + b"\n"
    )
    if report_size + len(complete) > MAX_REPORT_BYTES:
        raise ResourceLimitError("Recovery report exceeds its cumulative byte limit.")
    return b"".join(lines) + complete
