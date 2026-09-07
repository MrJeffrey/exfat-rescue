"""Verified, no-overwrite export of candidate-ID recovery data."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any

from .errors import OutputError, ResourceLimitError, VerificationError
from .manifest import parse_manifest_v2_bytes
from .recovery import (
    MAX_INTERNAL_MANIFEST_BYTES,
    MAX_REPORT_BYTES,
    MAX_RUN_BYTES,
    _assert_published_file,
    _assert_requested_parent,
    _assert_root_path,
    _assert_unchanged_named_file,
    _canonical,
    _check_file_proof_at,
    _file_state_proof,
    _fsync,
    _listdir_at,
    _lock_directory,
    _mkdir_at,
    _new_output_target,
    _open_dir_at,
    _open_dir_with_parent,
    _private_file_state,
    _read_regular_at,
    _record_name,
    _regular_at_equals,
    _rename_noreplace,
    _requested_parent_proof,
    _revalidate_completion_state,
    _validate_output_inventory,
    _write_all,
)
from .source import ProgressCallback, _release_file_cache
from .verification import (
    _json,
    _recovered_checkpoint,
    _report_records,
    _run_descriptor,
    _terminal_checkpoint,
)

_CHUNK = 1024 * 1024
_CATALOG_TEMPORARY = ".catalog.jsonl.partial"
_FORBIDDEN_NAME_CHARACTERS = frozenset('<>:"/\\|?*')


def _safe_export_name(original: str, candidate_id: str) -> str:
    """Preserve a recognizable basename without ever interpreting it as a path."""
    cleaned = "".join(
        "_"
        if character in _FORBIDDEN_NAME_CHARACTERS or ord(character) < 32
        else character
        for character in original
    ).rstrip(" .")
    if cleaned in {"", ".", ".."}:
        cleaned = "recovered"
    encoded = cleaned.encode("utf-8")
    if len(encoded) > 180:
        cleaned = (
            encoded[:180].decode("utf-8", errors="ignore").rstrip(" .") or "recovered"
        )
    return f"{cleaned}--{candidate_id}"


def _export_staging_name(target_name: str) -> str:
    """Return a bounded deterministic sibling used before atomic publication."""
    digest = hashlib.sha256(os.fsencode(target_name)).hexdigest()
    return f".exfat-rescue-export-{digest}"


def _detected_content(sample: bytes) -> str:
    if not sample:
        return "application/x-empty"
    signatures = (
        (b"\xff\xd8\xff", "image/jpeg"),
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"GIF87a", "image/gif"),
        (b"GIF89a", "image/gif"),
        (b"%PDF-", "application/pdf"),
        (b"PK\x03\x04", "application/zip"),
        (b"\x1f\x8b\x08", "application/gzip"),
        (b"7z\xbc\xaf'\x1c", "application/x-7z-compressed"),
        (b"Rar!\x1a\x07", "application/vnd.rar"),
        (b"SQLite format 3\x00", "application/vnd.sqlite3"),
        (b"\x7fELF", "application/x-elf"),
        (b"BM", "image/bmp"),
        (b"8BPS", "image/vnd.adobe.photoshop"),
        (b"II*\x00", "image/tiff"),
        (b"MM\x00*", "image/tiff"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage"),
    )
    for prefix, kind in signatures:
        if sample.startswith(prefix):
            return kind
    if sample.startswith(b"RIFF") and len(sample) >= 12:
        if sample[8:12] == b"WAVE":
            return "audio/wav"
        if sample[8:12] == b"AVI ":
            return "video/x-msvideo"
    if len(sample) >= 12 and sample[4:8] == b"ftyp":
        brand = sample[8:12]
        if brand in {b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1"}:
            return "image/heif"
        return "video/mp4"
    try:
        decoded = sample.decode("utf-8")
    except UnicodeDecodeError:
        return "application/octet-stream"
    if (
        decoded
        and sum(
            character.isprintable() or character in "\r\n\t" for character in decoded
        )
        / len(decoded)
        >= 0.9
    ):
        return "text/plain"
    return "application/octet-stream"


_KIND_EXTENSIONS = {
    "application/gzip": {".gz", ".tgz"},
    "application/pdf": {".pdf"},
    "application/vnd.rar": {".rar"},
    "application/vnd.sqlite3": {".db", ".sqlite", ".sqlite3"},
    "application/x-7z-compressed": {".7z"},
    "application/x-elf": {".elf", ""},
    "application/x-ole-storage": {".doc", ".ppt", ".xls"},
    "application/x-empty": {""},
    "application/zip": {".docx", ".jar", ".odt", ".pptx", ".xlsx", ".zip"},
    "audio/wav": {".wav"},
    "image/bmp": {".bmp"},
    "image/gif": {".gif"},
    "image/heif": {".heic", ".heif"},
    "image/jpeg": {".jpeg", ".jpg"},
    "image/png": {".png"},
    "image/tiff": {".tif", ".tiff"},
    "image/vnd.adobe.photoshop": {".psd"},
    "text/plain": {".csv", ".json", ".log", ".md", ".text", ".txt", ".xml"},
    "video/mp4": {".m4a", ".m4v", ".mov", ".mp4"},
    "video/x-msvideo": {".avi"},
}


def _extension_consistent(name: str, kind: str) -> bool | None:
    expected = _KIND_EXTENSIONS.get(kind)
    if expected is None:
        return None
    return Path(name).suffix.casefold() in expected


def _catalog_line(value: dict[str, object]) -> bytes:
    return _canonical(value) + b"\n"


def _prove_exported_contents(
    exported_fd: int,
    *,
    directory_fd: int,
    name: str,
    logical_size_bytes: int,
    valid_data_bytes: int,
    output_sha256: str,
    source_data_sha256: str,
) -> tuple[int, ...]:
    """Return the exact state bound to one held export-content proof."""
    try:
        initial = os.fstat(exported_fd)
    except OSError as exc:
        raise OutputError(
            f"Could not inspect exported data for proof: {exc.strerror}."
        ) from exc
    _private_file_state(initial, "Exported data")
    try:
        os.lseek(exported_fd, 0, os.SEEK_SET)
    except OSError as exc:
        raise OutputError(
            f"Could not seek exported data for proof: {exc.strerror}."
        ) from exc
    output_digest = hashlib.sha256()
    source_digest = hashlib.sha256()
    copied = 0
    try:
        while copied < logical_size_bytes:
            chunk = os.read(exported_fd, min(_CHUNK, logical_size_bytes - copied))
            if not chunk:
                raise OutputError("Exported data ended before its logical size.")
            output_digest.update(chunk)
            prefix_length = min(len(chunk), max(0, valid_data_bytes - copied))
            source_digest.update(chunk[:prefix_length])
            if copied + len(chunk) > valid_data_bytes:
                tail = chunk[max(0, valid_data_bytes - copied) :]
                if tail.strip(b"\0"):
                    raise OutputError(
                        "Exported data has a nonzero ValidDataLength tail."
                    )
            copied += len(chunk)
        if os.read(exported_fd, 1):
            raise OutputError("Exported data exceeds its logical size.")
    except OSError as exc:
        raise OutputError(
            f"Could not read exported data for proof: {exc.strerror}."
        ) from exc
    if (
        copied != logical_size_bytes
        or output_digest.hexdigest() != output_sha256
        or source_digest.hexdigest() != source_data_sha256
    ):
        raise OutputError("Exported data changed or differs from its recovery record.")
    try:
        final = os.fstat(exported_fd)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise OutputError(
            f"Could not revalidate exported data after proof: {exc.strerror}."
        ) from exc
    _private_file_state(final, "Exported data")
    _private_file_state(named, "Exported data")
    if _file_state_proof(initial) != _file_state_proof(final) or (
        final.st_dev,
        final.st_ino,
    ) != (named.st_dev, named.st_ino):
        raise OutputError("Exported data changed or was replaced during its proof.")
    return _file_state_proof(final)


def _prove_catalog_contents(
    catalog_fd: int,
    *,
    directory_fd: int,
    name: str,
    expected_size: int,
    expected_sha256: str,
) -> tuple[os.stat_result, tuple[int, ...]]:
    """Return the exact state bound to a held catalog-content proof."""
    try:
        initial = os.fstat(catalog_fd)
    except OSError as exc:
        raise OutputError(
            f"Could not inspect export catalog for proof: {exc.strerror}."
        ) from exc
    _private_file_state(initial, "Export catalog temporary")
    try:
        os.lseek(catalog_fd, 0, os.SEEK_SET)
    except OSError as exc:
        raise OutputError(
            f"Could not seek export catalog for proof: {exc.strerror}."
        ) from exc
    digest = hashlib.sha256()
    copied = 0
    try:
        while copied < expected_size:
            chunk = os.read(catalog_fd, min(_CHUNK, expected_size - copied))
            if not chunk:
                raise OutputError("Export catalog ended before its expected size.")
            digest.update(chunk)
            copied += len(chunk)
        if os.read(catalog_fd, 1):
            raise OutputError("Export catalog exceeds its expected size.")
    except OSError as exc:
        raise OutputError(
            f"Could not read export catalog for proof: {exc.strerror}."
        ) from exc
    if digest.hexdigest() != expected_sha256:
        raise OutputError(
            "Export catalog changed or differs from its intended content."
        )
    try:
        final = os.fstat(catalog_fd)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise OutputError(
            f"Could not revalidate export catalog after proof: {exc.strerror}."
        ) from exc
    _private_file_state(final, "Export catalog temporary")
    _private_file_state(named, "Export catalog temporary")
    if _file_state_proof(initial) != _file_state_proof(final) or (
        final.st_dev,
        final.st_ino,
    ) != (named.st_dev, named.st_ino):
        raise OutputError(
            "Export catalog changed or was replaced during its content proof."
        )
    return final, _file_state_proof(final)


def _assert_final_export_state(
    *,
    parent_fd: int,
    staging_name: str,
    destination_fd: int,
    files_fd: int,
    exported_names: set[str],
    exported_file_proofs: dict[str, tuple[int, ...]],
    exported_sizes: dict[str, int],
    catalog_size: int,
    catalog_proof: tuple[int, ...],
) -> None:
    """Rebind and prove every staged object immediately before publication."""

    def prove_names_and_identities() -> None:
        _assert_root_path(
            parent_fd,
            staging_name,
            destination_fd,
            "Export staging directory",
        )
        _assert_root_path(destination_fd, "files", files_fd, "Export files directory")
        if (
            set(_listdir_at(destination_fd, "export", max_entries=2))
            != {"catalog.jsonl", "files"}
            or set(
                _listdir_at(files_fd, "export files", max_entries=len(exported_names))
            )
            != exported_names
        ):
            raise OutputError("Export inventory changed before completion.")

    prove_names_and_identities()
    for exported_name in sorted(exported_names):
        _check_file_proof_at(
            files_fd,
            exported_name,
            expected_size=exported_sizes[exported_name],
            expected_proof=exported_file_proofs[exported_name],
        )
    _check_file_proof_at(
        destination_fd,
        "catalog.jsonl",
        expected_size=catalog_size,
        expected_proof=catalog_proof,
    )
    # Repeat the namespace/identity proof after the per-object proofs so a
    # replacement or addition during those checks cannot escape publication.
    prove_names_and_identities()
    # A forward-only pass admits an A-B-A write: A can change after its proof
    # while B is being checked.  Reprove in the opposite order before the
    # final namespace boundary, without rereading content.
    _check_file_proof_at(
        destination_fd,
        "catalog.jsonl",
        expected_size=catalog_size,
        expected_proof=catalog_proof,
    )
    for exported_name in sorted(exported_names, reverse=True):
        _check_file_proof_at(
            files_fd,
            exported_name,
            expected_size=exported_sizes[exported_name],
            expected_proof=exported_file_proofs[exported_name],
        )
    prove_names_and_identities()


def _descriptor_is_within(candidate_fd: int, root_fd: int) -> bool:
    """Compare a directory and its ancestors to a held protected root."""
    root_state = os.fstat(root_fd)
    current = os.dup(candidate_fd)
    try:
        for _depth in range(1024):
            state = os.fstat(current)
            if (state.st_dev, state.st_ino) == (root_state.st_dev, root_state.st_ino):
                return True
            parent = os.open(
                "..",
                os.O_RDONLY
                | os.O_DIRECTORY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=current,
            )
            parent_state = os.fstat(parent)
            if (parent_state.st_dev, parent_state.st_ino) == (
                state.st_dev,
                state.st_ino,
            ):
                os.close(parent)
                return False
            os.close(current)
            current = parent
    except OSError as exc:
        raise OutputError(
            f"Could not validate export ancestry: {exc.strerror}."
        ) from exc
    finally:
        os.close(current)
    raise OutputError("Export ancestry exceeds its safety bound.")


def _open_export_parent_with_ancestor(path: Path) -> tuple[int, int | None, str]:
    """Open an export parent and retain its requested pathname boundary."""
    path = path.absolute()
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    if path == path.parent:
        try:
            return os.open(path, flags), None, ""
        except OSError as exc:
            raise OutputError(
                f"Could not safely open export parent: {exc.strerror}."
            ) from exc
    ancestor_fd: int | None = None
    parent_fd: int | None = None
    try:
        ancestor_fd = os.open(path.parent, flags)
        before = os.stat(path.name, dir_fd=ancestor_fd, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode):
            raise OutputError("Export parent is not a directory.")
        parent_fd = os.open(path.name, flags, dir_fd=ancestor_fd)
        opened = os.fstat(parent_fd)
        if not stat.S_ISDIR(opened.st_mode) or (
            before.st_dev,
            before.st_ino,
        ) != (opened.st_dev, opened.st_ino):
            raise OutputError("Export parent was replaced while opening.")
    except OSError as exc:
        if parent_fd is not None:
            os.close(parent_fd)
        if ancestor_fd is not None:
            os.close(ancestor_fd)
        raise OutputError(
            f"Could not safely open export parent: {exc.strerror}."
        ) from exc
    except Exception:
        if parent_fd is not None:
            os.close(parent_fd)
        if ancestor_fd is not None:
            os.close(ancestor_fd)
        raise
    return parent_fd, ancestor_fd, path.name


def _assert_export_parent_boundary(
    *,
    parent_fd: int,
    ancestor_fd: int | None,
    parent_name: str,
    requested_parent: Path,
    root_fd: int,
) -> None:
    """Bind export publication to its requested parent and safe ancestry."""
    absolute_fd: int | None = None
    try:
        opened = os.fstat(parent_fd)
        if ancestor_fd is not None:
            named = os.stat(parent_name, dir_fd=ancestor_fd, follow_symlinks=False)
        else:
            named = opened
        absolute_fd = os.open(
            requested_parent,
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        absolute = os.fstat(absolute_fd)
    except OSError as exc:
        raise OutputError(
            f"Could not revalidate export parent: {exc.strerror}."
        ) from exc
    finally:
        if absolute_fd is not None:
            os.close(absolute_fd)
    if not stat.S_ISDIR(opened.st_mode) or not stat.S_ISDIR(named.st_mode):
        raise OutputError("Export parent is no longer a directory.")
    if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino) or (
        opened.st_dev,
        opened.st_ino,
    ) != (absolute.st_dev, absolute.st_ino):
        raise OutputError("Export parent was replaced while the operation was running.")
    if _descriptor_is_within(parent_fd, root_fd):
        raise OutputError("Export destination moved inside the recovery output.")


def export_recovery(
    output_dir: str | Path,
    destination: str | Path,
    *,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Verify one completed recovery and copy its files to recognizable safe names."""
    output_path = Path(os.path.abspath(os.fspath(output_dir)))
    target = _new_output_target(destination)
    staging_name = _export_staging_name(target.name)
    try:
        output_real = output_path.resolve(strict=True)
        parent_real = target.parent.resolve(strict=True)
    except OSError as exc:
        raise OutputError(f"Could not resolve export paths: {exc.strerror}.") from exc
    if output_real == parent_real or output_real in parent_real.parents:
        raise OutputError("Export destination must not be inside the recovery output.")
    for path, label in (
        (target, "destination"),
        (target.with_name(staging_name), "staging state"),
    ):
        try:
            os.lstat(path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise OutputError(
                f"Could not inspect export {label}: {exc.strerror}."
            ) from exc
        else:
            raise OutputError(
                f"Export {label} already exists; it is never overwritten."
            )
    root_fd, root_parent_fd, root_name = _open_dir_with_parent(output_path)
    destination_parent_fd: int | None = None
    destination_ancestor_fd: int | None = None
    destination_parent_name = ""
    destination_fd: int | None = None
    files_fd: int | None = None
    source_files_fd: int | None = None
    records_fd: int | None = None
    work_fd: int | None = None
    catalog_fd: int | None = None
    try:
        requested_output_parent = _requested_parent_proof(
            output_path.parent, root_parent_fd
        )
        _lock_directory(root_fd, "Recovery output")
        run_bytes = _read_regular_at(root_fd, "run.json", max_bytes=MAX_RUN_BYTES)
        manifest_bytes = _read_regular_at(
            root_fd, "manifest.jsonl", max_bytes=MAX_INTERNAL_MANIFEST_BYTES
        )
        report_bytes = _read_regular_at(
            root_fd, "report.jsonl", max_bytes=MAX_REPORT_BYTES
        )
        run = _run_descriptor(run_bytes)
        manifest = parse_manifest_v2_bytes(manifest_bytes)
        if hashlib.sha256(manifest_bytes).hexdigest() != run["manifest_sha256"]:
            raise VerificationError(
                "Immutable internal manifest hash does not match the run descriptor."
            )
        if manifest.header["source"] != run["source"]:
            raise VerificationError(
                "Run descriptor and internal manifest source bindings differ."
            )
        reports = _report_records(report_bytes, run)
        records_fd = _open_dir_at(root_fd, "records")
        source_files_fd = _open_dir_at(root_fd, "files")
        work_fd = _open_dir_at(root_fd, "work")
        plans = {plan.candidate_id: plan for plan in manifest.plans}
        identifiers = run["candidate_ids"]
        if any(candidate_id not in plans for candidate_id in identifiers):
            raise VerificationError(
                "Run selection is absent from the immutable manifest."
            )
        selected = [plans[candidate_id] for candidate_id in identifiers]
        body = reports[1:-1]
        if [record.get("candidate_id") for record, _raw in body] != identifiers:
            raise VerificationError(
                "Recovery report inventory or order does not match the run descriptor."
            )
        checkpoints: dict[str, dict[str, Any]] = {}
        recoverable_ids = {
            plan.candidate_id for plan in selected if plan.disposition == "recoverable"
        }
        recovered: list[dict[str, Any]] = []
        recovered_bytes = 0
        for plan, (record, _raw) in zip(selected, body, strict=True):
            checkpoint = _json(
                _read_regular_at(records_fd, _record_name(plan.candidate_id)),
                "Candidate checkpoint",
            )
            if checkpoint != record:
                raise VerificationError(
                    "Recovery report differs from immutable candidate checkpoint."
                )
            if plan.disposition != "recoverable":
                if checkpoint != _terminal_checkpoint(plan):
                    raise VerificationError(
                        "Terminal candidate checkpoint disagrees with its plan."
                    )
            else:
                _recovered_checkpoint(checkpoint, plan)
                if plan.logical_size_bytes > (
                    run["limits"]["max_output_bytes"] - recovered_bytes
                ):
                    raise VerificationError(
                        "Recovered data exceeds this run's verified-output limit."
                    )
                recovered_bytes += plan.logical_size_bytes
                candidate_fd = _open_dir_at(source_files_fd, plan.candidate_id)
                try:
                    if set(
                        _listdir_at(candidate_fd, "recovered candidate", max_entries=1)
                    ) != {"data"}:
                        raise VerificationError(
                            "Recovered candidate directory contains unknown objects."
                        )
                    data_fd = os.open(
                        "data",
                        os.O_RDONLY
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_NONBLOCK", 0),
                        dir_fd=candidate_fd,
                    )
                    try:
                        state = os.fstat(data_fd)
                        _private_file_state(state, "Recovered data")
                        if state.st_size != plan.logical_size_bytes:
                            raise VerificationError(
                                "Recovered data has an unexpected logical size."
                            )
                    finally:
                        os.close(data_fd)
                except OSError as exc:
                    raise VerificationError(
                        "Recovered data is missing or not safely readable."
                    ) from exc
                finally:
                    os.close(candidate_fd)
                recovered.append(checkpoint)
            checkpoints[plan.candidate_id] = checkpoint
        output_bytes = sum(int(record["logical_size_bytes"]) for record in recovered)
        try:
            _validate_output_inventory(
                root_fd,
                records_fd,
                source_files_fd,
                work_fd,
                candidate_ids=set(identifiers),
                recoverable_ids=recoverable_ids,
                report_complete=True,
            )
        except OutputError as exc:
            raise VerificationError(
                "Recovery output inventory changed during export."
            ) from exc

        (
            destination_parent_fd,
            destination_ancestor_fd,
            destination_parent_name,
        ) = _open_export_parent_with_ancestor(target.parent)
        _assert_export_parent_boundary(
            parent_fd=destination_parent_fd,
            ancestor_fd=destination_ancestor_fd,
            parent_name=destination_parent_name,
            requested_parent=target.parent,
            root_fd=root_fd,
        )
        try:
            available_state = os.fstatvfs(destination_parent_fd)
        except OSError as exc:
            raise OutputError(
                f"Could not inspect export destination capacity: {exc.strerror}."
            ) from exc
        if output_bytes > available_state.f_bavail * available_state.f_frsize:
            raise ResourceLimitError(
                "Export destination does not have enough available space."
            )
        for name, label in (
            (target.name, "destination"),
            (staging_name, "staging state"),
        ):
            try:
                os.stat(name, dir_fd=destination_parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise OutputError(
                    f"Could not inspect export {label}: {exc.strerror}."
                ) from exc
            else:
                raise OutputError(
                    f"Export {label} already exists; it is never overwritten."
                )
        destination_fd = _mkdir_at(destination_parent_fd, staging_name)
        files_fd = _mkdir_at(destination_fd, "files")
        try:
            catalog_fd = os.open(
                _CATALOG_TEMPORARY,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=destination_fd,
            )
        except OSError as exc:
            raise OutputError(
                f"Could not create private export catalog: {exc.strerror}."
            ) from exc
        catalog_state = os.fstat(catalog_fd)
        _private_file_state(catalog_state, "Export catalog temporary")
        catalog_digest = hashlib.sha256()
        catalog_file_digest = hashlib.sha256()
        catalog_size = 0
        header = _catalog_line(
            {
                "record_type": "catalog",
                "format": "exfat-rescue.export-catalog",
                "version": 1,
                "recovery_run_sha256": hashlib.sha256(_canonical(run)).hexdigest(),
                "file_count": len(recovered),
            }
        )
        _write_all(catalog_fd, header, "export catalog")
        catalog_digest.update(header)
        catalog_file_digest.update(header)
        catalog_size += len(header)
        exported_names: set[str] = set()
        source_file_proofs: dict[str, tuple[int, ...]] = {}
        exported_file_proofs: dict[str, tuple[int, ...]] = {}
        exported_sizes: dict[str, int] = {}

        for index, record in enumerate(recovered, 1):
            candidate_id = record["candidate_id"]
            plan = plans[candidate_id]
            exported_name = _safe_export_name(plan.name, candidate_id)
            if exported_name in exported_names:
                raise VerificationError("Export filename collision was detected.")
            exported_names.add(exported_name)
            candidate_fd = _open_dir_at(source_files_fd, candidate_id)
            input_fd: int | None = None
            exported_fd: int | None = None
            try:
                input_fd = os.open(
                    "data",
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_NONBLOCK", 0),
                    dir_fd=candidate_fd,
                )
                input_state = os.fstat(input_fd)
                _private_file_state(input_state, "Recovered data")
                if input_state.st_size != record["logical_size_bytes"]:
                    raise VerificationError(
                        "Recovered data size changed during export."
                    )
                exported_fd = os.open(
                    exported_name,
                    os.O_RDWR
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=files_fd,
                )
                digest = hashlib.sha256()
                source_digest = hashlib.sha256()
                sample = bytearray()
                copied = 0
                while copied < record["logical_size_bytes"]:
                    chunk = os.read(
                        input_fd,
                        min(_CHUNK, record["logical_size_bytes"] - copied),
                    )
                    if not chunk:
                        raise VerificationError(
                            "Recovered data ended before its logical size."
                        )
                    if len(sample) < 4096:
                        sample.extend(chunk[: 4096 - len(sample)])
                    digest.update(chunk)
                    prefix_length = min(
                        len(chunk), max(0, plan.valid_data_bytes - copied)
                    )
                    source_digest.update(chunk[:prefix_length])
                    if copied + len(chunk) > plan.valid_data_bytes:
                        tail = chunk[max(0, plan.valid_data_bytes - copied) :]
                        if tail.strip(b"\0"):
                            raise VerificationError(
                                "Recovered data has a nonzero ValidDataLength tail."
                            )
                    _write_all(exported_fd, chunk, "exported data")
                    copied += len(chunk)
                if os.read(input_fd, 1):
                    raise VerificationError("Recovered data exceeds its logical size.")
                _release_file_cache(input_fd, 0, copied, through_eof=True)
                if (
                    copied != record["logical_size_bytes"]
                    or digest.hexdigest() != record["output_sha256"]
                    or source_digest.hexdigest() != record["source_data_sha256"]
                ):
                    raise VerificationError("Recovered data changed during export.")
                _assert_unchanged_named_file(
                    candidate_fd, "data", input_fd, input_state, "Recovered data"
                )
                source_file_proofs[candidate_id] = _file_state_proof(input_state)
                _fsync(exported_fd, "exported data")
                exported_file_proofs[exported_name] = _prove_exported_contents(
                    exported_fd,
                    directory_fd=files_fd,
                    name=exported_name,
                    logical_size_bytes=record["logical_size_bytes"],
                    valid_data_bytes=plan.valid_data_bytes,
                    output_sha256=record["output_sha256"],
                    source_data_sha256=record["source_data_sha256"],
                )
                _release_file_cache(exported_fd, 0, copied, through_eof=True)
                exported_sizes[exported_name] = record["logical_size_bytes"]
            except OSError as exc:
                raise OutputError(
                    f"Could not safely export recovered data: {exc.strerror}."
                ) from exc
            finally:
                if exported_fd is not None:
                    os.close(exported_fd)
                if input_fd is not None:
                    os.close(input_fd)
                os.close(candidate_fd)

            kind = _detected_content(bytes(sample))
            catalog_record = _catalog_line(
                {
                    "record_type": "file",
                    "candidate_id": candidate_id,
                    "original_name": plan.name,
                    "exported_path": f"files/{exported_name}",
                    "logical_size_bytes": record["logical_size_bytes"],
                    "output_sha256": record["output_sha256"],
                    "detected_content_type": kind,
                    "extension_consistent": _extension_consistent(plan.name, kind),
                }
            )
            _write_all(catalog_fd, catalog_record, "export catalog")
            catalog_digest.update(catalog_record)
            catalog_file_digest.update(catalog_record)
            catalog_size += len(catalog_record)
            if index % 256 == 0:
                _fsync(files_fd, "export file batch")
                _fsync(catalog_fd, "export catalog batch")
            if progress is not None:
                progress("export-files", index, len(recovered), "files")

        _fsync(files_fd, "export files directory")
        try:
            _revalidate_completion_state(
                root_fd,
                root_parent_fd,
                root_name,
                records_fd,
                source_files_fd,
                work_fd,
                run_bytes=run_bytes,
                manifest_bytes=manifest_bytes,
                candidate_ids=identifiers,
                recoverable_ids=recoverable_ids,
                checkpoints=checkpoints,
                report_complete=True,
                report_bytes=report_bytes,
                recovered_file_proofs=source_file_proofs,
            )
        except OutputError as exc:
            raise VerificationError("Recovery state changed during export.") from exc
        for record in recovered:
            exported_name = _safe_export_name(
                plans[record["candidate_id"]].name, record["candidate_id"]
            )
            _check_file_proof_at(
                files_fd,
                exported_name,
                expected_size=record["logical_size_bytes"],
                expected_proof=exported_file_proofs[exported_name],
            )
        completion = _catalog_line(
            {
                "record_type": "complete",
                "file_count": len(recovered),
                "content_record_count": len(recovered) + 1,
                "output_bytes": output_bytes,
                "content_sha256": catalog_digest.hexdigest(),
            }
        )
        _write_all(catalog_fd, completion, "export catalog completion")
        catalog_file_digest.update(completion)
        catalog_size += len(completion)
        _fsync(catalog_fd, "export catalog")
        try:
            staged = os.fstat(catalog_fd)
        except OSError as exc:
            raise OutputError(
                f"Could not inspect export catalog for publication: {exc.strerror}."
            ) from exc
        _private_file_state(staged, "Export catalog temporary")
        if staged.st_size != catalog_size:
            raise OutputError("Export catalog size changed before publication.")
        _rename_noreplace(
            destination_fd, _CATALOG_TEMPORARY, destination_fd, "catalog.jsonl"
        )
        _assert_published_file(
            destination_fd, "catalog.jsonl", catalog_fd, staged, "Export catalog"
        )
        _catalog_state, catalog_proof = _prove_catalog_contents(
            catalog_fd,
            directory_fd=destination_fd,
            name="catalog.jsonl",
            expected_size=catalog_size,
            expected_sha256=catalog_file_digest.hexdigest(),
        )
        _fsync(destination_fd, "export staging directory")
        if not (
            _regular_at_equals(root_fd, "run.json", run_bytes, max_bytes=MAX_RUN_BYTES)
            and _regular_at_equals(
                root_fd,
                "manifest.jsonl",
                manifest_bytes,
                max_bytes=MAX_INTERNAL_MANIFEST_BYTES,
            )
            and _regular_at_equals(
                root_fd, "report.jsonl", report_bytes, max_bytes=MAX_REPORT_BYTES
            )
        ):
            raise VerificationError("Recovery state changed during export.")
        _assert_root_path(root_parent_fd, root_name, root_fd)
        _assert_requested_parent(requested_output_parent, root_parent_fd)
        _fsync(destination_fd, "export staging directory")
        _fsync(destination_parent_fd, "export parent directory")
        _assert_final_export_state(
            parent_fd=destination_parent_fd,
            staging_name=staging_name,
            destination_fd=destination_fd,
            files_fd=files_fd,
            exported_names=exported_names,
            exported_file_proofs=exported_file_proofs,
            exported_sizes=exported_sizes,
            catalog_size=_catalog_state.st_size,
            catalog_proof=catalog_proof,
        )
        _assert_export_parent_boundary(
            parent_fd=destination_parent_fd,
            ancestor_fd=destination_ancestor_fd,
            parent_name=destination_parent_name,
            requested_parent=target.parent,
            root_fd=root_fd,
        )
        try:
            os.stat(target.name, dir_fd=destination_parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise OutputError(
                f"Could not inspect export destination: {exc.strerror}."
            ) from exc
        else:
            raise OutputError(
                "Export destination appeared before publication; it was not overwritten."
            )
        _assert_export_parent_boundary(
            parent_fd=destination_parent_fd,
            ancestor_fd=destination_ancestor_fd,
            parent_name=destination_parent_name,
            requested_parent=target.parent,
            root_fd=root_fd,
        )
        _rename_noreplace(
            destination_parent_fd,
            staging_name,
            destination_parent_fd,
            target.name,
        )
        _fsync(destination_parent_fd, "export parent directory")
        _assert_final_export_state(
            parent_fd=destination_parent_fd,
            staging_name=target.name,
            destination_fd=destination_fd,
            files_fd=files_fd,
            exported_names=exported_names,
            exported_file_proofs=exported_file_proofs,
            exported_sizes=exported_sizes,
            catalog_size=_catalog_state.st_size,
            catalog_proof=catalog_proof,
        )
        _assert_export_parent_boundary(
            parent_fd=destination_parent_fd,
            ancestor_fd=destination_ancestor_fd,
            parent_name=destination_parent_name,
            requested_parent=target.parent,
            root_fd=root_fd,
        )
        _assert_requested_parent(requested_output_parent, root_parent_fd)
        return {
            "ok": True,
            "destination": str(target),
            "file_count": len(recovered),
            "output_bytes": output_bytes,
            "catalog": str(target / "catalog.jsonl"),
        }
    finally:
        if catalog_fd is not None:
            os.close(catalog_fd)
        if files_fd is not None:
            os.close(files_fd)
        if source_files_fd is not None:
            os.close(source_files_fd)
        if records_fd is not None:
            os.close(records_fd)
        if work_fd is not None:
            os.close(work_fd)
        if destination_fd is not None:
            os.close(destination_fd)
        if destination_parent_fd is not None:
            os.close(destination_parent_fd)
        if destination_ancestor_fd is not None:
            os.close(destination_ancestor_fd)
        os.close(root_fd)
        os.close(root_parent_fd)
