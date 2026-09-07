"""Strict, descriptor-relative integrity verification for recovery output."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import (
    ManifestError,
    OutputError,
    SourceError,
    UsageError,
    VerificationError,
)
from .recovery import (
    _ID,
    DEFAULT_RUN_LIMITS,
    HARD_MAX_RECOVERY_CANDIDATES,
    LEGACY_RUN_VERSION,
    MAX_INTERNAL_MANIFEST_BYTES,
    MAX_REPORT_BYTES,
    MAX_RUN_BYTES,
    MAX_STATE_BYTES,
    RUN_VERSION,
    _assert_requested_parent,
    _assert_unchanged_named_file,
    _canonical,
    _file_state_proof,
    _open_dir_at,
    _open_dir_with_parent,
    _private_file_state,
    _read_regular_at,
    _requested_parent_proof,
    _revalidate_completion_state,
    _revalidate_completion_state_from_proofs,
    _valid_source_file_state,
)
from .source import ImageSource, ProgressCallback, _release_file_cache

_MAX_LINE_BYTES = 1024 * 1024


@dataclass(frozen=True)
class _RecoveryPreflight:
    """Descriptor-relative state needed to validate a verification set cheaply."""

    output: Path
    run: dict[str, Any]
    manifest_bytes: bytes
    checkpoint_digests: tuple[bytes, ...]
    recovered_sizes: tuple[int | None, ...]


@dataclass(frozen=True)
class _RecoveryStructurePreflight:
    """Compact no-content state retained after set compatibility is established."""

    output: Path
    candidate_ids: tuple[str, ...]
    checkpoint_digests: tuple[bytes, ...]
    recovered_sizes: tuple[int | None, ...]
    image_size_bytes: int


def _json(value: bytes, label: str) -> dict[str, Any]:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"duplicate key: {key}")
            result[key] = item
        return result

    try:
        result = json.loads(value, object_pairs_hook=no_duplicates)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
    ) as exc:
        raise ManifestError(f"{label} is not strict JSON.") from exc
    if not isinstance(result, dict):
        raise ManifestError(f"{label} is not a JSON object.")
    return result


def _safe_read(fd: int, name: str, label: str, *, max_bytes: int) -> bytes:
    try:
        return _read_regular_at(fd, name, max_bytes=max_bytes)
    except OutputError as exc:
        raise VerificationError(
            f"{label} is not a private regular output object."
        ) from exc


def _safe_dir(fd: int, name: str, label: str) -> int:
    try:
        return _open_dir_at(fd, name)
    except OutputError as exc:
        raise VerificationError(f"{label} is not a private output directory.") from exc


def _safe_listdir(fd: int, label: str, *, max_entries: int) -> list[str]:
    """Return a bounded descriptor-relative inventory.

    ``os.listdir`` constructs an unbounded list before callers can reject an
    unexpected entry.  Verification must instead stop as soon as the first
    entry beyond its fixed expected inventory is encountered.
    """
    try:
        names: list[str] = []
        with os.scandir(fd) as entries:
            for entry in entries:
                if len(names) >= max_entries:
                    raise VerificationError(
                        f"{label} exceeds its bounded expected inventory."
                    )
                names.append(entry.name)
        return names
    except OutputError as exc:
        raise VerificationError(f"Could not safely inspect {label}.") from exc
    except OSError as exc:
        raise VerificationError(
            f"Could not safely inspect {label}: {exc.strerror}."
        ) from exc


def _run_descriptor(data: bytes) -> dict[str, Any]:
    run = _json(data, "Run descriptor")
    expected = {
        "format",
        "version",
        "source",
        "limits",
        "candidate_ids",
        "manifest_sha256",
    }
    version = run.get("version")
    if version == RUN_VERSION:
        expected.add("source_file_state")
    if (
        set(run) != expected
        or run.get("format") != "exfat-rescue.run"
        or type(version) is not int
        or version not in {LEGACY_RUN_VERSION, RUN_VERSION}
        or (
            version == RUN_VERSION
            and not _valid_source_file_state(run.get("source_file_state"))
        )
        or not isinstance(run.get("source"), dict)
        or not isinstance(run.get("manifest_sha256"), str)
        or not _ID.fullmatch(run["manifest_sha256"])
    ):
        raise ManifestError("Recovery run descriptor is malformed.")
    limits = run["limits"]
    if (
        not isinstance(limits, dict)
        or set(limits) != set(DEFAULT_RUN_LIMITS)
        or any(
            type(value) is not int
            or value < 1
            or (key == "max_candidates" and value > HARD_MAX_RECOVERY_CANDIDATES)
            for key, value in limits.items()
        )
    ):
        raise ManifestError("Recovery run descriptor limits are malformed.")
    identifiers = run["candidate_ids"]
    if (
        not isinstance(identifiers, list)
        or len(identifiers) > limits["max_candidates"]
        or any(
            not isinstance(value, str) or not _ID.fullmatch(value)
            for value in identifiers
        )
        or len(identifiers) != len(set(identifiers))
    ):
        raise ManifestError("Recovery run candidate inventory is malformed.")
    return run


def _report_records(
    data: bytes, run: dict[str, Any] | None = None
) -> list[tuple[dict[str, Any], bytes]]:
    if not data.endswith(b"\n") or len(data) > MAX_REPORT_BYTES:
        raise ManifestError("Recovery report violates bounded JSONL framing.")
    lines = data.splitlines(keepends=True)
    if (
        len(lines) < 2
        or _json(lines[-1], "Recovery report").get("record_type") != "complete"
    ):
        raise VerificationError(
            "Recovery run is incomplete: report completion is absent."
        )
    if run is None:
        raise ManifestError("Recovery report requires a validated run descriptor.")
    if (
        len(lines) != len(run["candidate_ids"]) + 2
        or len(lines) > run["limits"]["max_candidates"] + 2
        or any(
            len(line) > _MAX_LINE_BYTES or not line.endswith(b"\n") for line in lines
        )
    ):
        raise ManifestError("Recovery report violates bounded JSONL framing.")
    values = [(_json(line, "Recovery report"), line) for line in lines]
    expected_header = {
        "record_type": "report",
        "run_sha256": hashlib.sha256(_canonical(run)).hexdigest(),
    }
    if values[0][0] != expected_header:
        raise ManifestError(
            "Recovery report does not bind the immutable run descriptor."
        )
    expected_complete = {
        "record_type": "complete",
        "candidate_count": len(run["candidate_ids"]),
        "content_record_count": len(values) - 1,
        "content_sha256": hashlib.sha256(
            b"".join(line for _, line in values[:-1])
        ).hexdigest(),
    }
    complete = values[-1][0]
    if (
        type(complete.get("candidate_count")) is not int
        or type(complete.get("content_record_count")) is not int
        or complete != expected_complete
    ):
        raise ManifestError(
            "Recovery report completion hash, count, or schema is invalid."
        )
    return values


def _terminal_checkpoint(plan: Any) -> dict[str, Any]:
    return {
        "record_type": "candidate",
        "candidate_id": plan.candidate_id,
        "disposition": plan.disposition,
        "reasons": list(plan.reasons),
    }


def _recovered_checkpoint(value: dict[str, Any], plan: Any) -> None:
    expected_keys = {
        "record_type",
        "candidate_id",
        "disposition",
        "output_path",
        "logical_size_bytes",
        "valid_data_bytes",
        "source_extents",
        "source_bytes",
        "zero_filled_bytes",
        "source_data_sha256",
        "output_sha256",
    }
    extents = [
        {"first_cluster": extent.first_cluster, "cluster_count": extent.cluster_count}
        for extent in plan.extents
    ]
    numeric_fields = {
        "logical_size_bytes",
        "valid_data_bytes",
        "source_bytes",
        "zero_filled_bytes",
    }
    source_extents = value.get("source_extents")
    if (
        set(value) != expected_keys
        or any(type(value.get(field)) is not int for field in numeric_fields)
        or not isinstance(source_extents, list)
        or any(
            not isinstance(extent, dict)
            or set(extent) != {"first_cluster", "cluster_count"}
            or type(extent.get("first_cluster")) is not int
            or type(extent.get("cluster_count")) is not int
            for extent in source_extents
        )
        or value.get("record_type") != "candidate"
        or value.get("candidate_id") != plan.candidate_id
        or value.get("disposition") != "recovered"
        or value.get("output_path") != f"files/{plan.candidate_id}/data"
        or value.get("logical_size_bytes") != plan.logical_size_bytes
        or value.get("valid_data_bytes") != plan.valid_data_bytes
        or value.get("source_extents") != extents
        or value.get("source_bytes") != plan.valid_data_bytes
        or value.get("zero_filled_bytes")
        != plan.logical_size_bytes - plan.valid_data_bytes
        or not isinstance(value.get("source_data_sha256"), str)
        or not _ID.fullmatch(value["source_data_sha256"])
        or not isinstance(value.get("output_sha256"), str)
        or not _ID.fullmatch(value["output_sha256"])
    ):
        raise ManifestError(
            "Recovered candidate checkpoint is malformed or disagrees with its plan."
        )


def _hash_and_check_zero_tail(
    fd: int, name: str, valid_bytes: int, expected_size: int
) -> tuple[int, str, str, tuple[int, ...]]:
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
        raise VerificationError(
            "Recovered data is missing or not safely readable."
        ) from exc
    try:
        try:
            state = os.fstat(target)
            _private_file_state(state, "Recovered data")
            if state.st_size != expected_size:
                raise VerificationError(
                    "Recovered data has an unexpected logical size."
                )
        except OutputError as exc:
            raise VerificationError(
                "Recovered data is not a private singly-linked regular file."
            ) from exc
        except OSError as exc:
            raise VerificationError("Recovered data could not be inspected.") from exc
        digest, source_digest, total, position = (
            hashlib.sha256(),
            hashlib.sha256(),
            0,
            0,
        )
        try:
            while total < expected_size:
                chunk = os.read(target, min(1024 * 1024, expected_size - total))
                if not chunk:
                    raise VerificationError(
                        "Recovered data ended before its logical size."
                    )
                digest.update(chunk)
                prefix_length = min(len(chunk), max(0, valid_bytes - position))
                source_digest.update(chunk[:prefix_length])
                if position + len(chunk) > valid_bytes:
                    tail = chunk[max(0, valid_bytes - position) :]
                    if tail.strip(b"\0"):
                        raise VerificationError(
                            "Recovered data has a nonzero ValidDataLength tail."
                        )
                position += len(chunk)
                total += len(chunk)
            if os.read(target, 1):
                raise VerificationError("Recovered data exceeds its logical size.")
            _release_file_cache(target, 0, total, through_eof=True)
        except OSError as exc:
            raise VerificationError("Recovered data could not be read safely.") from exc
        try:
            _assert_unchanged_named_file(fd, name, target, state, "Recovered data")
        except OutputError as exc:
            raise VerificationError(
                "Recovered data changed or was replaced while being verified."
            ) from exc
        return (
            total,
            digest.hexdigest(),
            source_digest.hexdigest(),
            _file_state_proof(state),
        )
    finally:
        os.close(target)


def _reparsed_candidates(
    stored: tuple[dict[str, Any], ...], scanned: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    def key(candidate: dict[str, Any]) -> tuple[object, object]:
        return candidate.get("entry_offset"), candidate.get("entry_set_sha256")

    fields = {
        "entry_offset",
        "name",
        "size_bytes",
        "valid_size_bytes",
        "first_cluster",
        "no_fat_chain",
        "deleted",
        "location",
        "entry_set_sha256",
        "is_directory",
        "attributes",
        "entry_checksum",
    }
    if len(stored) != len(scanned):
        raise VerificationError(
            "Current image metadata inventory does not exactly match the recovery "
            "manifest."
        )
    scanned.sort(key=key)
    stored_ordered = sorted(stored, key=key)
    previous: tuple[object, object] | None = None
    for raw, candidate in zip(stored_ordered, scanned, strict=True):
        current_key = key(raw)
        if (
            current_key == previous
            or current_key != key(candidate)
            or {field: candidate.get(field) for field in fields}
            != {field: raw.get(field) for field in fields}
        ):
            raise VerificationError(
                "Current image metadata no longer matches the recovery manifest."
            )
        previous = current_key
    return scanned


def _preflight_recovery(output_dir: Path) -> _RecoveryPreflight:
    """Reject malformed completed output without reading recovered file contents."""
    try:
        root_fd, root_parent_fd, _root_name = _open_dir_with_parent(output_dir)
    except OutputError as exc:
        raise VerificationError(
            "Recovery output root is not a private output directory."
        ) from exc
    try:
        required_root = {
            "run.json",
            "manifest.jsonl",
            "records",
            "files",
            "work",
            "report.jsonl",
        }
        if (
            set(
                _safe_listdir(
                    root_fd, "recovery output", max_entries=len(required_root)
                )
            )
            != required_root
        ):
            raise VerificationError(
                "Recovery output inventory is incomplete or contains unknown objects."
            )
        run_bytes = _safe_read(
            root_fd, "run.json", "Run descriptor", max_bytes=MAX_RUN_BYTES
        )
        run = _run_descriptor(run_bytes)
        manifest_bytes = _safe_read(
            root_fd,
            "manifest.jsonl",
            "Internal manifest",
            max_bytes=MAX_INTERNAL_MANIFEST_BYTES,
        )
        if hashlib.sha256(manifest_bytes).hexdigest() != run["manifest_sha256"]:
            raise ManifestError(
                "Immutable internal manifest hash does not match the run descriptor."
            )
        from .manifest import parse_manifest_v2_bytes

        manifest = parse_manifest_v2_bytes(manifest_bytes)
        if manifest.header["source"] != run["source"]:
            raise ManifestError(
                "Run descriptor and internal manifest source bindings differ."
            )
        plans = {plan.candidate_id: plan for plan in manifest.plans}
        identifiers = run["candidate_ids"]
        if any(candidate_id not in plans for candidate_id in identifiers):
            raise ManifestError("Run selection is absent from the immutable manifest.")
        selected = [plans[candidate_id] for candidate_id in identifiers]
        report_bytes = _safe_read(
            root_fd, "report.jsonl", "Recovery report", max_bytes=MAX_REPORT_BYTES
        )
        records = _report_records(report_bytes, run)
        body = records[1:-1]
        if [record.get("candidate_id") for record, _ in body] != identifiers:
            raise ManifestError(
                "Recovery report inventory or order does not match the run descriptor."
            )
        checkpoint_digests: list[bytes] = []
        recovered_sizes: list[int | None] = []
        verified_bytes = 0
        for plan, (record, _raw) in zip(selected, body, strict=True):
            if plan.disposition != "recoverable":
                if record != _terminal_checkpoint(plan):
                    raise ManifestError(
                        "Terminal recovery report record disagrees with its plan."
                    )
                recovered_sizes.append(None)
            else:
                _recovered_checkpoint(record, plan)
                if plan.logical_size_bytes > (
                    run["limits"]["max_output_bytes"] - verified_bytes
                ):
                    raise VerificationError(
                        "Recovered data exceeds this run's verified-output limit."
                    )
                verified_bytes += plan.logical_size_bytes
                recovered_sizes.append(plan.logical_size_bytes)
            checkpoint_digests.append(
                hashlib.sha256(_canonical(record) + b"\n").digest()
            )
        records_fd: int | None = None
        files_fd: int | None = None
        work_fd: int | None = None
        try:
            records_fd = _safe_dir(root_fd, "records", "Recovery records")
            files_fd = _safe_dir(root_fd, "files", "Recovery files")
            work_fd = _safe_dir(root_fd, "work", "Recovery work")
            expected_records = {f"{candidate_id}.json" for candidate_id in identifiers}
            expected_files = {
                plan.candidate_id
                for plan in selected
                if plan.disposition == "recoverable"
            }
            if (
                set(
                    _safe_listdir(
                        records_fd,
                        "recovery records",
                        max_entries=len(expected_records),
                    )
                )
                != expected_records
            ):
                raise VerificationError(
                    "Recovery checkpoint inventory is incomplete or contains unknown objects."
                )
            if (
                set(
                    _safe_listdir(
                        files_fd,
                        "recovery files",
                        max_entries=len(expected_files),
                    )
                )
                != expected_files
            ):
                raise VerificationError(
                    "Recovered-file inventory is incomplete or contains unknown objects."
                )
            if _safe_listdir(work_fd, "recovery work directory", max_entries=0):
                raise VerificationError(
                    "Completed recovery contains unexpected work artifacts."
                )
        finally:
            if records_fd is not None:
                os.close(records_fd)
            if files_fd is not None:
                os.close(files_fd)
            if work_fd is not None:
                os.close(work_fd)
        return _RecoveryPreflight(
            output_dir,
            run,
            manifest_bytes,
            tuple(checkpoint_digests),
            tuple(recovered_sizes),
        )
    finally:
        try:
            os.close(root_fd)
        finally:
            os.close(root_parent_fd)


def _validate_source_binding(run: dict[str, Any]) -> dict[str, Any]:
    """Return the strict source binding before any source-content work."""
    binding = run["source"]
    expected_binding_keys = {
        "image_size_bytes",
        "volume_offset_bytes",
        "volume_length_bytes",
        "volume_sha256",
        "cluster_size_bytes",
        "cluster_heap_offset_bytes",
        "source_kind",
        "boot_region",
        "volume_dirty",
        "media_failure",
    }
    if set(binding) != expected_binding_keys or any(
        type(binding[key]) is not int
        for key in expected_binding_keys
        - {
            "volume_sha256",
            "source_kind",
            "boot_region",
            "volume_dirty",
            "media_failure",
        }
    ):
        raise ManifestError("Run source binding is malformed.")
    if (
        type(binding["volume_dirty"]) is not bool
        or type(binding["media_failure"]) is not bool
    ):
        raise ManifestError("Run source status flags are malformed.")
    return binding


def _preflight_candidate_state(preflight: _RecoveryStructurePreflight) -> None:
    """Validate checkpoints and recovered-file shape without reading file content."""
    try:
        root_fd, root_parent_fd, _root_name = _open_dir_with_parent(preflight.output)
    except OutputError as exc:
        raise VerificationError(
            "Recovery output root is not a private output directory."
        ) from exc
    records_fd: int | None = None
    files_fd: int | None = None
    try:
        records_fd = _safe_dir(root_fd, "records", "Recovery records")
        files_fd = _safe_dir(root_fd, "files", "Recovery files")
        for candidate_id, expected_digest, expected_size in zip(
            preflight.candidate_ids,
            preflight.checkpoint_digests,
            preflight.recovered_sizes,
            strict=True,
        ):
            checkpoint_bytes = _safe_read(
                records_fd,
                f"{candidate_id}.json",
                "Candidate checkpoint",
                max_bytes=MAX_STATE_BYTES,
            )
            if hashlib.sha256(checkpoint_bytes).digest() != expected_digest:
                raise ManifestError(
                    "Recovery report differs from immutable candidate checkpoint."
                )
            if expected_size is None:
                continue
            candidate_fd = _safe_dir(files_fd, candidate_id, "Recovered candidate")
            try:
                if set(
                    _safe_listdir(
                        candidate_fd,
                        "recovered candidate",
                        max_entries=1,
                    )
                ) != {"data"}:
                    raise VerificationError(
                        "Recovered candidate directory contains unknown objects."
                    )
                try:
                    data_fd = os.open(
                        "data",
                        os.O_RDONLY
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_NONBLOCK", 0),
                        dir_fd=candidate_fd,
                    )
                except OSError as exc:
                    raise VerificationError(
                        "Recovered data is missing or not safely readable."
                    ) from exc
                try:
                    try:
                        state = os.fstat(data_fd)
                        _private_file_state(state, "Recovered data")
                    except OutputError as exc:
                        raise VerificationError(
                            "Recovered data is not a private singly-linked regular file."
                        ) from exc
                    except OSError as exc:
                        raise VerificationError(
                            "Recovered data could not be inspected."
                        ) from exc
                    if state.st_size != expected_size:
                        raise VerificationError(
                            "Recovered data has an unexpected logical size."
                        )
                finally:
                    os.close(data_fd)
            finally:
                os.close(candidate_fd)
    finally:
        if records_fd is not None:
            os.close(records_fd)
        if files_fd is not None:
            os.close(files_fd)
        try:
            os.close(root_fd)
        finally:
            os.close(root_parent_fd)


def verify_recovery(
    output_dir: Path,
    image: str | Path | None = None,
    *,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Verify a completed recovery run, optionally against a current source image."""
    return _verify_recovery(output_dir, image=image, progress=progress)


def _verify_recovery(
    output_dir: Path,
    *,
    image: str | Path | None = None,
    image_session: _ImageVerificationSession | None = None,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    if image is not None and image_session is not None:
        raise ValueError("image and image_session are mutually exclusive")
    try:
        root_fd, root_parent_fd, root_name = _open_dir_with_parent(Path(output_dir))
    except OutputError as exc:
        raise VerificationError(
            "Recovery output root is not a private output directory."
        ) from exc
    try:
        requested_parent = _requested_parent_proof(
            Path(output_dir).absolute().parent, root_parent_fd
        )
    except OutputError as exc:
        os.close(root_fd)
        os.close(root_parent_fd)
        raise VerificationError(
            "Recovery output parent is not a stable private output parent."
        ) from exc
    source: ImageSource | None = None
    try:
        required_root = {
            "run.json",
            "manifest.jsonl",
            "records",
            "files",
            "work",
            "report.jsonl",
        }
        if (
            set(
                _safe_listdir(
                    root_fd, "recovery output", max_entries=len(required_root)
                )
            )
            != required_root
        ):
            raise VerificationError(
                "Recovery output inventory is incomplete or contains unknown objects."
            )
        run_bytes = _safe_read(
            root_fd, "run.json", "Run descriptor", max_bytes=MAX_RUN_BYTES
        )
        run = _run_descriptor(run_bytes)
        manifest_bytes = _safe_read(
            root_fd,
            "manifest.jsonl",
            "Internal manifest",
            max_bytes=MAX_INTERNAL_MANIFEST_BYTES,
        )
        if hashlib.sha256(manifest_bytes).hexdigest() != run["manifest_sha256"]:
            raise ManifestError(
                "Immutable internal manifest hash does not match the run descriptor."
            )
        from .manifest import parse_manifest_v2_bytes

        manifest = parse_manifest_v2_bytes(manifest_bytes)
        if manifest.header["source"] != run["source"]:
            raise ManifestError(
                "Run descriptor and internal manifest source bindings differ."
            )
        plans = {plan.candidate_id: plan for plan in manifest.plans}
        identifiers = run["candidate_ids"]
        if any(candidate_id not in plans for candidate_id in identifiers):
            raise ManifestError("Run selection is absent from the immutable manifest.")
        selected = [plans[candidate_id] for candidate_id in identifiers]
        report_bytes = _safe_read(
            root_fd, "report.jsonl", "Recovery report", max_bytes=MAX_REPORT_BYTES
        )
        records = _report_records(report_bytes, run)
        body = records[1:-1]
        if [record.get("candidate_id") for record, _ in body] != identifiers:
            raise ManifestError(
                "Recovery report inventory or order does not match the run descriptor."
            )
        records_fd: int | None = None
        files_fd: int | None = None
        work_fd: int | None = None
        try:
            records_fd = _safe_dir(root_fd, "records", "Recovery records")
            files_fd = _safe_dir(root_fd, "files", "Recovery files")
            work_fd = _safe_dir(root_fd, "work", "Recovery work")
            expected_records = {f"{candidate_id}.json" for candidate_id in identifiers}
            expected_files = {
                plan.candidate_id
                for plan in selected
                if plan.disposition == "recoverable"
            }
            if (
                set(
                    _safe_listdir(
                        records_fd,
                        "recovery records",
                        max_entries=len(expected_records),
                    )
                )
                != expected_records
            ):
                raise VerificationError(
                    "Recovery checkpoint inventory is incomplete or contains unknown objects."
                )
            if (
                set(
                    _safe_listdir(
                        files_fd,
                        "recovery files",
                        max_entries=len(expected_files),
                    )
                )
                != expected_files
            ):
                raise VerificationError(
                    "Recovered-file inventory is incomplete or contains unknown objects."
                )
            if _safe_listdir(work_fd, "recovery work directory", max_entries=0):
                raise VerificationError(
                    "Completed recovery contains unexpected work artifacts."
                )
            recovered = 0
            verified_bytes = 0
            checkpoints: dict[str, dict[str, Any]] = {}
            recovered_file_proofs: dict[str, tuple[int, ...]] = {}
            for index, (plan, (record, _)) in enumerate(
                zip(selected, body, strict=True), 1
            ):
                checkpoint = _json(
                    _safe_read(
                        records_fd,
                        f"{plan.candidate_id}.json",
                        "Candidate checkpoint",
                        max_bytes=MAX_STATE_BYTES,
                    ),
                    "Candidate checkpoint",
                )
                if checkpoint != record:
                    raise ManifestError(
                        "Recovery report differs from immutable candidate checkpoint."
                    )
                if plan.disposition != "recoverable":
                    if checkpoint != _terminal_checkpoint(plan):
                        raise ManifestError(
                            "Terminal candidate checkpoint disagrees with its plan."
                        )
                    checkpoints[plan.candidate_id] = checkpoint
                    if progress is not None:
                        progress(
                            "verify-output-candidates",
                            index,
                            len(selected),
                            "candidates",
                        )
                    continue
                _recovered_checkpoint(checkpoint, plan)
                if plan.logical_size_bytes > (
                    run["limits"]["max_output_bytes"] - verified_bytes
                ):
                    raise VerificationError(
                        "Recovered data exceeds this run's verified-output limit."
                    )
                verified_bytes += plan.logical_size_bytes
                candidate_fd = _safe_dir(
                    files_fd, plan.candidate_id, "Recovered candidate"
                )
                try:
                    if set(
                        _safe_listdir(
                            candidate_fd,
                            "recovered candidate",
                            max_entries=1,
                        )
                    ) != {"data"}:
                        raise VerificationError(
                            "Recovered candidate directory contains unknown objects."
                        )
                    size, digest, source_digest, file_proof = _hash_and_check_zero_tail(
                        candidate_fd,
                        "data",
                        plan.valid_data_bytes,
                        plan.logical_size_bytes,
                    )
                finally:
                    os.close(candidate_fd)
                if (
                    size != plan.logical_size_bytes
                    or digest != checkpoint["output_sha256"]
                    or source_digest != checkpoint["source_data_sha256"]
                ):
                    raise VerificationError("Recovered data is altered or incomplete.")
                checkpoints[plan.candidate_id] = checkpoint
                recovered_file_proofs[plan.candidate_id] = file_proof
                recovered += 1
                if progress is not None:
                    progress(
                        "verify-output-candidates",
                        index,
                        len(selected),
                        "candidates",
                    )
            if image is not None:
                source = ImageSource.open(image, progress=progress)
                _verify_image(
                    source,
                    run,
                    manifest,
                    selected,
                    checkpoints,
                    progress=progress,
                )
            elif image_session is not None:
                source = image_session.source
                image_session.verify(
                    manifest_bytes,
                    run,
                    manifest,
                    selected,
                    checkpoints,
                    progress=progress,
                )
            try:
                completion_proof = _revalidate_completion_state(
                    root_fd,
                    root_parent_fd,
                    root_name,
                    records_fd,
                    files_fd,
                    work_fd,
                    run_bytes=run_bytes,
                    manifest_bytes=manifest_bytes,
                    candidate_ids=identifiers,
                    recoverable_ids=expected_files,
                    checkpoints=checkpoints,
                    report_complete=True,
                    report_bytes=report_bytes,
                    recovered_file_proofs=recovered_file_proofs,
                )
            except OutputError as exc:
                raise VerificationError(
                    "Recovery output inventory changed during verification."
                ) from exc
            if source is not None:
                source.assert_unchanged()
            try:
                _revalidate_completion_state_from_proofs(
                    root_fd,
                    root_parent_fd,
                    root_name,
                    records_fd,
                    files_fd,
                    work_fd,
                    run_bytes=run_bytes,
                    manifest_bytes=manifest_bytes,
                    candidate_ids=identifiers,
                    recoverable_ids=expected_files,
                    checkpoints=checkpoints,
                    report_complete=True,
                    report_bytes=report_bytes,
                    recovered_file_proofs=completion_proof,
                )
            except OutputError as exc:
                raise VerificationError(
                    "Recovery output inventory changed during verification."
                ) from exc
            if source is not None:
                source.assert_unchanged()
            try:
                _assert_requested_parent(requested_parent, root_parent_fd)
            except OutputError as exc:
                raise VerificationError(
                    "Recovery output parent changed during verification."
                ) from exc
            return {
                "ok": True,
                "output": str(output_dir),
                "candidate_count": len(identifiers),
                "recovered_count": recovered,
                "image_verified": image is not None or image_session is not None,
            }
        finally:
            if records_fd is not None:
                os.close(records_fd)
            if files_fd is not None:
                os.close(files_fd)
            if work_fd is not None:
                os.close(work_fd)
    finally:
        try:
            try:
                if source is not None and image_session is None:
                    source.close()
            finally:
                os.close(root_fd)
        finally:
            os.close(root_parent_fd)


def _verify_image(
    source: ImageSource,
    run: dict[str, Any],
    manifest: Any,
    selected: list[Any],
    checkpoints: dict[str, dict[str, Any]],
    *,
    progress: ProgressCallback | None = None,
) -> None:
    """Replan immutable candidates and prove recorded bytes against ``source``."""
    from .manifest import validate_manifest_plans
    from .planner import plan_recovery
    from .scanner import scan

    binding = _validate_source_binding(run)
    if source.size != binding["image_size_bytes"]:
        raise SourceError("The supplied image size does not match this recovery run.")
    scanned = scan(
        source,
        max_candidates=manifest.header["scan_options"]["max_candidates"],
        max_scan_clusters=run["limits"]["max_scan_clusters"],
        progress=(
            None
            if progress is None
            else lambda completed, total: progress(
                "verify-scan-clusters", completed, total, "clusters"
            )
        ),
    )
    volume = scanned.volume
    actual_geometry = (
        volume.base_offset,
        volume.boot.volume_bytes,
        volume.boot.cluster_size,
        volume.cluster_offset(2),
        volume.location.source_kind,
        volume.boot_region,
        volume.boot.volume_dirty,
        volume.boot.media_failure,
    )
    recorded_geometry = (
        binding["volume_offset_bytes"],
        binding["volume_length_bytes"],
        binding["cluster_size_bytes"],
        binding["cluster_heap_offset_bytes"],
        binding["source_kind"],
        binding["boot_region"],
        binding["volume_dirty"],
        binding["media_failure"],
    )
    if actual_geometry != recorded_geometry:
        raise SourceError("The supplied image does not match this recovery run.")
    digest = source.selected_volume_sha256(
        binding["volume_offset_bytes"], binding["volume_length_bytes"]
    )
    if digest != binding["volume_sha256"]:
        raise SourceError("The supplied image does not match this recovery run.")
    reparsed = _reparsed_candidates(manifest.candidates, scanned.candidates)
    planned = plan_recovery(
        volume,
        reparsed,
        max_fat_steps=run["limits"]["max_fat_steps"],
        active_owners=scanned.active_owners,
        metadata_complete=scanned.metadata_complete,
        ownership_complete=scanned.ownership_complete,
    )
    validate_manifest_plans(manifest, planned)
    _verify_source_bytes(
        source,
        binding,
        selected,
        checkpoints,
        progress=progress,
    )


def _verify_source_bytes(
    source: ImageSource,
    binding: dict[str, Any],
    selected: list[Any],
    checkpoints: dict[str, dict[str, Any]],
    *,
    progress: ProgressCallback | None = None,
) -> None:
    """Prove selected recovered prefixes against an already-validated image plan."""
    recoverable_count = sum(1 for plan in selected if plan.disposition == "recoverable")
    verified_count = 0
    for plan in selected:
        if plan.disposition != "recoverable":
            continue
        verified_count += 1
        source_hash, remaining = hashlib.sha256(), plan.valid_data_bytes
        for extent in plan.extents:
            offset = (
                binding["cluster_heap_offset_bytes"]
                + (extent.first_cluster - 2) * binding["cluster_size_bytes"]
            )
            take = min(remaining, extent.cluster_count * binding["cluster_size_bytes"])
            while take:
                amount = min(take, 1024 * 1024)
                source_hash.update(source.read_exact(offset, amount))
                source.release_cache(offset, amount)
                offset += amount
                take -= amount
                remaining -= amount
        if (
            remaining
            or source_hash.hexdigest()
            != checkpoints[plan.candidate_id]["source_data_sha256"]
        ):
            raise VerificationError(
                "Current source bytes do not match recovered source-data hash."
            )
        if progress is not None:
            progress(
                "verify-source-candidates",
                verified_count,
                recoverable_count,
                "candidates",
            )
    source.assert_unchanged()


class _ImageVerificationSession:
    """Share one complete image/manifest revalidation across recovery outputs."""

    def __init__(
        self,
        source: ImageSource,
        progress: ProgressCallback | None = None,
    ) -> None:
        self.source = source
        self.progress = progress
        self._manifest_bytes: bytes | None = None
        self._limits: tuple[int, int] | None = None
        self._verified_ids: set[str] = set()

    def verify(
        self,
        manifest_bytes: bytes,
        run: dict[str, Any],
        manifest: Any,
        selected: list[Any],
        checkpoints: dict[str, dict[str, Any]],
        *,
        progress: ProgressCallback | None = None,
    ) -> None:
        identifiers = set(run["candidate_ids"])
        if identifiers & self._verified_ids:
            raise ManifestError(
                "Recovery outputs in one verification set contain duplicate candidates."
            )
        limits = (run["limits"]["max_scan_clusters"], run["limits"]["max_fat_steps"])
        if self._manifest_bytes is None:
            _verify_image(
                self.source,
                run,
                manifest,
                selected,
                checkpoints,
                progress=progress or self.progress,
            )
            self._manifest_bytes = manifest_bytes
            self._limits = limits
        else:
            if manifest_bytes != self._manifest_bytes or limits != self._limits:
                raise ManifestError(
                    "Recovery outputs in one verification set do not share one exact "
                    "manifest and image-validation limits."
                )
            _verify_source_bytes(
                self.source,
                run["source"],
                selected,
                checkpoints,
                progress=progress or self.progress,
            )
        self._verified_ids.update(identifiers)


def verify_recovery_set(
    output_dirs: Iterable[str | Path],
    image: str | Path,
    *,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Verify multiple disjoint recovery outputs with one global image replan."""
    outputs: list[Path] = []
    for output in output_dirs:
        if len(outputs) >= HARD_MAX_RECOVERY_CANDIDATES:
            raise UsageError(
                "A recovery verification set exceeds the supported output count."
            )
        outputs.append(Path(output))
    if not outputs:
        raise UsageError("A recovery verification set requires at least one output.")
    normalized = [Path(os.path.realpath(os.fspath(output))) for output in outputs]
    if len(set(normalized)) != len(normalized):
        raise UsageError(
            "A recovery verification set contains a duplicate output path."
        )
    expected_manifest: bytes | None = None
    expected_limits: tuple[int, int] | None = None
    selected_ids: set[str] = set()
    structure_preflights: list[_RecoveryStructurePreflight] = []
    for output in outputs:
        preflight = _preflight_recovery(output)
        binding = _validate_source_binding(preflight.run)
        limits = (
            preflight.run["limits"]["max_scan_clusters"],
            preflight.run["limits"]["max_fat_steps"],
        )
        if expected_manifest is None:
            expected_manifest = preflight.manifest_bytes
            expected_limits = limits
        elif preflight.manifest_bytes != expected_manifest or limits != expected_limits:
            raise ManifestError(
                "Recovery outputs in one verification set do not share one exact "
                "manifest and image-validation limits."
            )
        identifiers = set(preflight.run["candidate_ids"])
        if identifiers & selected_ids:
            raise ManifestError(
                "Recovery outputs in one verification set contain duplicate candidates."
            )
        selected_ids.update(identifiers)
        structure_preflights.append(
            _RecoveryStructurePreflight(
                preflight.output,
                tuple(preflight.run["candidate_ids"]),
                preflight.checkpoint_digests,
                preflight.recovered_sizes,
                binding["image_size_bytes"],
            )
        )
        del preflight
    del expected_manifest
    for preflight in structure_preflights:
        _preflight_candidate_state(preflight)
    source = ImageSource.open(image, progress=progress)
    try:
        for preflight in structure_preflights:
            if source.size != preflight.image_size_bytes:
                raise SourceError(
                    "The supplied image size does not match this recovery run."
                )
        session = _ImageVerificationSession(source, progress)
        results = [
            _verify_recovery(
                output,
                image_session=session,
                progress=progress,
            )
            for output in outputs
        ]
        source.assert_unchanged()
        return {
            "ok": True,
            "outputs": [str(output) for output in outputs],
            "output_count": len(outputs),
            "candidate_count": sum(result["candidate_count"] for result in results),
            "recovered_count": sum(result["recovered_count"] for result in results),
            "image_verified": True,
            "shared_image_verification": True,
        }
    finally:
        source.close()
