from __future__ import annotations

import hashlib
import itertools
import json
import os
import re
import stat
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ManifestError, OutputError
from .planner import Extent, PlannerResult, RecoveryPlan
from .scanner import HARD_MAX_CANDIDATES
from .source import ImageSource, refuse_output_path

SCHEMA = "https://raw.githubusercontent.com/MrJeffrey/exfat-rescue/main/src/exfat_rescue/schemas/manifest-v1.json"
SCHEMA_V2 = "https://raw.githubusercontent.com/MrJeffrey/exfat-rescue/main/src/exfat_rescue/schemas/manifest-v2.json"
MAX_MANIFEST_LINE_BYTES = 1024 * 1024
DEFAULT_MAX_MANIFEST_RECORDS = HARD_MAX_CANDIDATES + 2
DEFAULT_MAX_MANIFEST_BYTES = 1024 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SCAN_OPTION_FIELDS = {
    "orphan_scan",
    "version",
    "volume_offset_bytes",
    "source_kind",
    "boot_region",
    "max_candidates",
    "max_scan_clusters",
    "max_fat_steps",
}
_REFUSAL_REASONS = {
    "active_bitmap_allocation_conflict",
    "active_bitmap_unavailable",
    "active_file_overlap",
    "active_owner_conflict",
    "cluster_currently_allocated",
    "contiguous_extent_outside_volume",
    "extent_limit",
    "fat_bad_cluster",
    "fat_cycle",
    "fat_invalid_next",
    "fat_overlong_chain",
    "fat_short_chain",
    "fat_truncated_read",
    "fat_work_limit",
    "incomplete_active_metadata",
    "incomplete_active_ownership",
    "invalid_valid_data_length",
    "orphan_metadata_host_allocated",
    "ownership_work_limit",
    "plausible_recovery_overlap",
}


def _integer(value: object, *, minimum: int = 0) -> bool:
    return type(value) is int and value >= minimum


class _DuplicateKey(ValueError):
    pass


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateKey(key)
        value[key] = item
    return value


def _reject_nonstandard_json_constant(value: str) -> Any:
    """Reject JSON extensions such as NaN and Infinity at the decoder boundary."""
    raise ValueError(f"Non-standard JSON constant: {value}")


def _line(record: dict[str, Any]) -> str:
    return (
        json.dumps(
            record,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )


def _path_has_identity(path: Path, identity: tuple[int, int]) -> bool:
    try:
        current = os.lstat(path)
    except OSError:
        return False
    return (current.st_dev, current.st_ino) == identity


def _prove_written_manifest(
    fd: int,
    *,
    expected_digest: str,
    expected_size: int,
    identity: tuple[int, int],
    initial: os.stat_result,
) -> os.stat_result:
    """Content- and state-prove a just-written manifest through its held FD."""
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or (before.st_dev, before.st_ino) != identity
            or before.st_mode != initial.st_mode
            or before.st_uid != initial.st_uid
            or before.st_nlink != initial.st_nlink
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size != expected_size
        ):
            raise OutputError("The manifest changed before its final content proof.")
        os.lseek(fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        remaining = expected_size
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                raise OutputError(
                    "The manifest was truncated during its final content proof."
                )
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1) or digest.hexdigest() != expected_digest:
            raise OutputError("The manifest changed during its final content proof.")
        after = os.fstat(fd)
        if (
            not stat.S_ISREG(after.st_mode)
            or (after.st_dev, after.st_ino) != identity
            or after.st_mode != initial.st_mode
            or after.st_uid != initial.st_uid
            or after.st_nlink != initial.st_nlink
            or after.st_uid != os.geteuid()
            or stat.S_IMODE(after.st_mode) != 0o600
            or after.st_nlink != 1
            or after.st_size != expected_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
        ):
            raise OutputError("The manifest changed during its final content proof.")
        return after
    except OutputError:
        raise
    except OSError as exc:
        raise OutputError(
            f"Could not prove the completed manifest through its open file: {exc.strerror}."
        ) from exc


def _assert_final_manifest_state(
    fd: int,
    path: Path,
    *,
    expected: os.stat_result,
    identity: tuple[int, int],
) -> None:
    """Cheaply close the source-check-to-publication manifest race."""
    try:
        current = os.fstat(fd)
    except OSError as exc:
        raise OutputError(
            f"Could not revalidate the completed manifest through its open file: {exc.strerror}."
        ) from exc
    if (
        current.st_dev,
        current.st_ino,
        current.st_mode,
        current.st_nlink,
        current.st_uid,
        current.st_gid,
        current.st_size,
        current.st_mtime_ns,
        current.st_ctime_ns,
    ) != (
        expected.st_dev,
        expected.st_ino,
        expected.st_mode,
        expected.st_nlink,
        expected.st_uid,
        expected.st_gid,
        expected.st_size,
        expected.st_mtime_ns,
        expected.st_ctime_ns,
    ) or not _path_has_identity(path, identity):
        raise OutputError("The manifest changed after its final content proof.")


def write_manifest(
    source: ImageSource,
    path_value: str | Path,
    candidates: list[dict[str, Any]],
    options: dict[str, Any],
    source_fingerprint: dict[str, object],
    warnings: tuple[str, ...],
) -> Path:
    path = refuse_output_path(source, path_value)
    header = {
        "record_type": "manifest",
        "format": "exfat-rescue.manifest",
        "version": 1,
        "schema": SCHEMA,
        "source": source_fingerprint,
        "scan_options": options,
        "candidate_count": len(candidates),
        "warnings": list(warnings),
    }
    source.assert_unchanged(source_fingerprint)
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise OutputError(
            f"Manifest already exists: '{path}'. Existing files are never overwritten."
        ) from exc
    except OSError as exc:
        raise OutputError(
            f"Could not create manifest '{path}': {exc.strerror}. No existing file was overwritten."
        ) from exc
    proof_fd = -1
    try:
        opened = os.fstat(fd)
        identity = (opened.st_dev, opened.st_ino)
        digest = hashlib.sha256()
        published_digest = hashlib.sha256()
        written_bytes = 0
        proof_fd = os.dup(fd)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
            fd = -1
            # v1 is retained for scan compatibility only.  Its strict schema
            # intentionally does not grow when scanner/planner add v2 fields.
            v1_candidate_keys = {
                "record_type",
                "candidate_id",
                "location",
                "path",
                "path_components",
                "entry_offset",
                "name",
                "size_bytes",
                "valid_size_bytes",
                "first_cluster",
                "no_fat_chain",
                "deleted",
                "is_directory",
                "attributes",
                "modified_at",
                "modified_utc_offset_minutes",
                "entry_checksum",
                "layout",
            }
            for record in itertools.chain(
                (header,),
                (
                    {
                        key: (value[:24] if key == "candidate_id" else value)
                        for key, value in candidate.items()
                        if key in v1_candidate_keys
                    }
                    for candidate in candidates
                ),
            ):
                line = _line(record)
                line_bytes = line.encode("utf-8")
                output.write(line)
                digest.update(line_bytes)
                published_digest.update(line_bytes)
                written_bytes += len(line_bytes)
            output.flush()
            os.fsync(output.fileno())
            source.assert_unchanged(source_fingerprint)
            if not _path_has_identity(path, identity):
                raise OutputError(
                    "The manifest path was replaced while writing; the replacement was left untouched."
                )
            completion = _line(
                {
                    "record_type": "complete",
                    "candidate_count": len(candidates),
                    "content_record_count": len(candidates) + 1,
                    "content_sha256": digest.hexdigest(),
                }
            )
            output.write(completion)
            completion_bytes = completion.encode("utf-8")
            published_digest.update(completion_bytes)
            written_bytes += len(completion_bytes)
            output.flush()
            os.fsync(output.fileno())
            if not _path_has_identity(path, identity):
                raise OutputError(
                    "The manifest path was replaced before completion; the replacement was left untouched."
                )
            source.assert_unchanged(source_fingerprint)
        proof_state = _prove_written_manifest(
            proof_fd,
            expected_digest=published_digest.hexdigest(),
            expected_size=written_bytes,
            identity=identity,
            initial=opened,
        )
        source.assert_unchanged(source_fingerprint)
        _assert_final_manifest_state(
            proof_fd, path, expected=proof_state, identity=identity
        )
        source.assert_unchanged(source_fingerprint)
    except OutputError:
        raise
    except OSError as exc:
        raise OutputError(
            f"Could not create a complete manifest '{path}': {exc.strerror}. The path may contain an incomplete file and is never deleted automatically."
        ) from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if proof_fd >= 0:
            os.close(proof_fd)
    return path


@dataclass(frozen=True)
class ManifestV2:
    header: dict[str, Any]
    plans: tuple[RecoveryPlan, ...]
    source_candidates: tuple[dict[str, Any], ...]
    completion: dict[str, Any]
    raw_bytes: bytes = b""

    @property
    def candidates(self) -> tuple[dict[str, Any], ...]:
        return self.source_candidates


def _plan_record(
    plan: RecoveryPlan, source_candidate: Mapping[str, object]
) -> dict[str, Any]:
    return {
        "record_type": "candidate",
        "candidate_id": plan.candidate_id,
        "entry_offset": plan.entry_offset,
        "entry_set_sha256": plan.entry_set_sha256,
        "name": plan.name,
        "logical_size_bytes": plan.logical_size_bytes,
        "valid_data_bytes": plan.valid_data_bytes,
        "extents": [
            {"first_cluster": x.first_cluster, "cluster_count": x.cluster_count}
            for x in plan.extents
        ],
        "allocation_mode": plan.allocation_mode,
        "metadata_location": plan.metadata_location,
        "disposition": plan.disposition,
        "recovery_basis": plan.recovery_basis,
        "reasons": list(plan.reasons),
        "source_candidate": dict(source_candidate),
    }


def _parse_plan(record: dict[str, Any]) -> RecoveryPlan:
    expected = {
        "record_type",
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
        "source_candidate",
    }
    if set(record) != expected or record.get("record_type") != "candidate":
        raise ManifestError(
            "A v2 candidate record has undeclared, missing, or invalid fields."
        )
    if not isinstance(record["candidate_id"], str) or not _SHA256.fullmatch(
        record["candidate_id"]
    ):
        raise ManifestError("A v2 candidate ID must be a full SHA-256 hex identifier.")
    if not isinstance(record["entry_set_sha256"], str) or not _SHA256.fullmatch(
        record["entry_set_sha256"]
    ):
        raise ManifestError("A v2 candidate entry-set digest is invalid.")
    if not all(
        _integer(record[key])
        for key in ("entry_offset", "logical_size_bytes", "valid_data_bytes")
    ):
        raise ManifestError("A v2 candidate contains an invalid byte offset or size.")
    if record["valid_data_bytes"] > record["logical_size_bytes"]:
        raise ManifestError("A v2 candidate ValidDataLength exceeds DataLength.")
    extents_data = record["extents"]
    if not isinstance(extents_data, list) or len(extents_data) > 4096:
        raise ManifestError("A v2 candidate extent array exceeds its bound.")
    extents: list[Extent] = []
    for item in extents_data:
        if (
            not isinstance(item, dict)
            or set(item) != {"first_cluster", "cluster_count"}
            or not all(_integer(item[key], minimum=1) for key in item)
            or item["first_cluster"] < 2
        ):
            raise ManifestError("A v2 candidate extent is invalid.")
        extents.append(Extent(item["first_cluster"], item["cluster_count"]))
    valid_modes = {"empty", "contiguous", "fat_chain"}
    valid_locations = {"active_directory", "deleted_directory", "orphan"}
    valid_dispositions = {"recoverable", "conflicted", "unrecoverable"}
    bases = {
        None,
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
        not isinstance(record["allocation_mode"], str)
        or not isinstance(record["metadata_location"], str)
        or not isinstance(record["disposition"], str)
        or not (
            record["recovery_basis"] is None
            or isinstance(record["recovery_basis"], str)
        )
        or record["allocation_mode"] not in valid_modes
        or record["metadata_location"] not in valid_locations
        or record["disposition"] not in valid_dispositions
        or record["recovery_basis"] not in bases
    ):
        raise ManifestError(
            "A v2 candidate contains an invalid recovery classification."
        )
    if (
        not isinstance(record["reasons"], list)
        or not all(
            isinstance(value, str) and value in _REFUSAL_REASONS
            for value in record["reasons"]
        )
        or record["reasons"] != sorted(set(record["reasons"]))
    ):
        raise ManifestError("A v2 candidate reasons list is not deterministic.")
    if record["disposition"] == "recoverable" and (
        record["reasons"] or record["recovery_basis"] is None
    ):
        raise ManifestError("A recoverable v2 candidate cannot carry refusal reasons.")
    if record["disposition"] != "recoverable" and (
        not record["reasons"] or record["recovery_basis"] is not None
    ):
        raise ManifestError("A refused v2 candidate requires a stable reason.")
    raw = record["source_candidate"]
    raw_fields = {
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
    if (
        not isinstance(raw, dict)
        or set(raw) != raw_fields
        or raw["entry_offset"] != record["entry_offset"]
        or raw["entry_set_sha256"] != record["entry_set_sha256"]
        or raw["name"] != record["name"]
        or raw["size_bytes"] != record["logical_size_bytes"]
        or raw["valid_size_bytes"] != record["valid_data_bytes"]
        or not isinstance(raw["name"], str)
        or not all(
            _integer(raw[key])
            for key in ("size_bytes", "valid_size_bytes", "first_cluster", "attributes")
        )
        or not all(
            type(raw[key]) is bool
            for key in ("no_fat_chain", "deleted", "is_directory")
        )
        or raw["is_directory"]
        or not isinstance(raw["location"], str)
        or raw["location"] not in {"directory", "orphan"}
        or not isinstance(raw["entry_checksum"], str)
        or not re.fullmatch(r"[0-9a-f]{4}", raw["entry_checksum"])
    ):
        raise ManifestError(
            "A v2 source candidate is invalid or incomplete for replanning."
        )
    return RecoveryPlan(
        record["candidate_id"],
        record["entry_offset"],
        record["entry_set_sha256"],
        record["name"],
        record["logical_size_bytes"],
        record["valid_data_bytes"],
        tuple(extents),
        record["allocation_mode"],
        record["metadata_location"],
        record["disposition"],
        record["recovery_basis"],
        tuple(record["reasons"]),
    )


def _validate_v2_semantics(
    header: dict[str, Any],
    plans: Sequence[RecoveryPlan],
    source_candidates: Sequence[Mapping[str, object]],
) -> None:
    source = header["source"]
    options = header["scan_options"]
    if (
        set(options) != _SCAN_OPTION_FIELDS
        or options.get("orphan_scan") is not True
        or options.get("version") != 2
        or any(
            not _integer(options.get(key), minimum=1)
            for key in ("max_candidates", "max_scan_clusters", "max_fat_steps")
        )
        or options["max_candidates"] > HARD_MAX_CANDIDATES
        or options.get("volume_offset_bytes") != source["volume_offset_bytes"]
        or options.get("source_kind") != source["source_kind"]
        or options.get("boot_region") != source["boot_region"]
        or len(plans) > options["max_candidates"]
    ):
        raise ManifestError("The v2 manifest scan options are invalid or inconsistent.")
    if (
        source["volume_length_bytes"] < 1
        or source["cluster_size_bytes"] < 1
        or source["image_size_bytes"]
        < source["volume_offset_bytes"] + source["volume_length_bytes"]
        or not (
            source["volume_offset_bytes"]
            <= source["cluster_heap_offset_bytes"]
            < source["volume_offset_bytes"] + source["volume_length_bytes"]
        )
    ):
        raise ManifestError("The v2 manifest source geometry is inconsistent.")
    binding_bytes = json.dumps(
        {
            key: source[key]
            for key in (
                "volume_offset_bytes",
                "volume_length_bytes",
                "volume_sha256",
            )
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    for plan, raw in zip(plans, source_candidates, strict=True):
        expected_id = hashlib.sha256(
            binding_bytes
            + b":"
            + str(plan.entry_offset).encode("ascii")
            + b":"
            + plan.entry_set_sha256.encode("ascii")
        ).hexdigest()
        expected_location = (
            "orphan"
            if raw["location"] == "orphan"
            else "deleted_directory"
            if raw["deleted"]
            else "active_directory"
        )
        expected_mode = (
            "empty"
            if plan.logical_size_bytes == 0
            else "contiguous"
            if raw["no_fat_chain"]
            else "fat_chain"
        )
        previous_end: int | None = None
        intervals: list[tuple[int, int]] = []
        for extent in plan.extents:
            if previous_end is not None and extent.first_cluster == previous_end:
                raise ManifestError(
                    "A v2 candidate contains adjacent uncoalesced extents."
                )
            previous_end = extent.first_cluster + extent.cluster_count
            intervals.append((extent.first_cluster, previous_end))
            extent_start = (
                source["cluster_heap_offset_bytes"]
                + (extent.first_cluster - 2) * source["cluster_size_bytes"]
            )
            extent_end = extent_start + (
                extent.cluster_count * source["cluster_size_bytes"]
            )
            if (
                extent_start < source["cluster_heap_offset_bytes"]
                or extent_end
                > source["volume_offset_bytes"] + source["volume_length_bytes"]
            ):
                raise ManifestError(
                    "A v2 candidate extent lies outside the selected cluster heap."
                )
        for previous, current in zip(
            sorted(intervals), sorted(intervals)[1:], strict=False
        ):
            if current[0] < previous[1]:
                raise ManifestError("A v2 candidate contains overlapping extents.")
        cluster_count = sum(extent.cluster_count for extent in plan.extents)
        expected_clusters = (
            plan.logical_size_bytes + source["cluster_size_bytes"] - 1
        ) // source["cluster_size_bytes"]
        prefix = (
            "active"
            if expected_location == "active_directory"
            else "deleted"
            if expected_location == "deleted_directory"
            else "orphan"
        )
        expected_basis = (
            f"{prefix}_empty"
            if expected_mode == "empty"
            else f"{prefix}_{expected_mode}_{'allocated' if prefix == 'active' else 'unallocated'}"
        )
        raw_first_cluster = raw["first_cluster"]
        raw_no_fat_chain = raw["no_fat_chain"]
        allocation_matches = (
            (
                expected_mode == "empty"
                and raw_first_cluster == 0
                and raw_no_fat_chain is False
                and not plan.extents
            )
            or (
                expected_mode == "contiguous"
                and raw_no_fat_chain is True
                and (
                    (plan.disposition == "unrecoverable" and not plan.extents)
                    or (
                        len(plan.extents) == 1
                        and plan.extents[0].first_cluster == raw_first_cluster
                    )
                )
            )
            or (
                expected_mode == "fat_chain"
                and raw_no_fat_chain is False
                and (
                    not plan.extents
                    or plan.extents[0].first_cluster == raw_first_cluster
                )
                and (plan.disposition == "unrecoverable" or bool(plan.extents))
            )
        )
        if (
            plan.candidate_id != expected_id
            or plan.metadata_location != expected_location
            or plan.allocation_mode != expected_mode
            or (
                plan.disposition in {"recoverable", "conflicted"}
                and cluster_count != expected_clusters
            )
            or (
                plan.disposition == "recoverable"
                and plan.recovery_basis != expected_basis
            )
            or not allocation_matches
        ):
            raise ManifestError(
                "A v2 candidate is inconsistent with its source metadata or binding."
            )


def write_manifest_v2(
    source: ImageSource,
    path_value: str | Path,
    planner_result: PlannerResult,
    scan_options: dict[str, Any],
    *,
    warnings: tuple[str, ...] = (),
) -> Path:
    """Write an immutable, deterministic recovery manifest without overwrite."""
    plans = planner_result.plans
    if len(plans) + 2 > DEFAULT_MAX_MANIFEST_RECORDS:
        raise ManifestError("A manifest exceeds the cumulative record limit.")
    seen_ids: set[str] = set()
    previous_id: str | None = None
    for plan in plans:
        if plan.candidate_id in seen_ids:
            raise ManifestError(
                "Cannot write a v2 manifest with duplicate candidate IDs."
            )
        if previous_id is not None and plan.candidate_id < previous_id:
            raise ManifestError(
                "A v2 manifest requires deterministic candidate-ID record order."
            )
        seen_ids.add(plan.candidate_id)
        previous_id = plan.candidate_id
    header = {
        "record_type": "manifest",
        "format": "exfat-rescue.manifest",
        "version": 2,
        "schema": SCHEMA_V2,
        "source": dict(planner_result.source_binding),
        "scan_options": scan_options,
        "candidate_count": len(plans),
        "warnings": sorted(set(warnings)),
    }
    if len(planner_result.source_candidates) != len(plans):
        raise ManifestError(
            "A v2 manifest requires one raw source candidate per recovery plan."
        )
    # Validate the exact serialized seam before creating an output path.  PlannerResult
    # is a public dataclass and callers can construct inconsistent plan/raw pairs that
    # the reader would otherwise reject only after an invalid manifest was published.
    for plan, candidate in zip(plans, planner_result.source_candidates, strict=True):
        if _parse_plan(_plan_record(plan, candidate)) != plan:
            raise ManifestError(
                "A v2 manifest plan is inconsistent with its serialized source candidate."
            )
    _validate_v2_semantics(header, plans, planner_result.source_candidates)

    def records() -> Iterable[dict[str, Any]]:
        yield header
        for plan, candidate in zip(
            plans, planner_result.source_candidates, strict=True
        ):
            yield _plan_record(plan, candidate)

    return _write_v2(
        source,
        path_value,
        records(),
        candidate_count=len(plans),
    )


def _write_v2(
    source: ImageSource,
    path_value: str | Path,
    records: Iterable[dict[str, Any]],
    *,
    candidate_count: int | None = None,
) -> Path:
    # The reader requires the header, every candidate, and the final completion
    # record to fit its cumulative framing limits.  Refuse impossible manifests
    # before creating an output path, while retaining the incomplete-file safety
    # behavior for failures discovered during writing.
    if candidate_count is None:
        if not isinstance(records, Sequence):
            raise ManifestError(
                "A streamed manifest writer requires an explicit candidate count."
            )
        candidate_count = len(records) - 1
    if candidate_count < 0 or candidate_count + 2 > DEFAULT_MAX_MANIFEST_RECORDS:
        raise ManifestError("A manifest exceeds the cumulative record limit.")
    path = refuse_output_path(source, path_value)
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise OutputError(
            f"Could not create manifest '{path}': {exc.strerror}. No existing file was overwritten."
        ) from exc
    proof_fd = -1
    try:
        opened = os.fstat(fd)
        identity = (opened.st_dev, opened.st_ino)
        digest, count, written_bytes = hashlib.sha256(), 0, 0
        published_digest = hashlib.sha256()
        proof_fd = os.dup(fd)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
            fd = -1
            for record in records:
                line = _line(record)
                line_bytes = line.encode("utf-8")
                if len(line_bytes) > MAX_MANIFEST_LINE_BYTES:
                    raise ManifestError(
                        "A manifest record exceeds the 1 MiB line limit."
                    )
                written_bytes += len(line_bytes)
                if written_bytes > DEFAULT_MAX_MANIFEST_BYTES:
                    raise ManifestError("A manifest exceeds the cumulative byte limit.")
                output.write(line)
                digest.update(line_bytes)
                published_digest.update(line_bytes)
                count += 1
            if count != candidate_count + 1:
                raise ManifestError(
                    "A streamed manifest inventory disagrees with its candidate count."
                )
            output.flush()
            os.fsync(output.fileno())
            source.assert_unchanged()
            if not _path_has_identity(path, identity):
                raise OutputError(
                    "The manifest path was replaced before completion; the replacement was left untouched."
                )
            completion = _line(
                {
                    "record_type": "complete",
                    "candidate_count": candidate_count,
                    "content_record_count": count,
                    "content_sha256": digest.hexdigest(),
                }
            )
            completion_bytes = completion.encode("utf-8")
            if (
                len(completion_bytes) > MAX_MANIFEST_LINE_BYTES
                or written_bytes + len(completion_bytes) > DEFAULT_MAX_MANIFEST_BYTES
            ):
                raise ManifestError("A manifest exceeds the cumulative byte limit.")
            output.write(completion)
            published_digest.update(completion_bytes)
            written_bytes += len(completion_bytes)
            output.flush()
            os.fsync(output.fileno())
            if not _path_has_identity(path, identity):
                raise OutputError(
                    "The manifest path was replaced during completion; the replacement was left untouched."
                )
            source.assert_unchanged()
        proof_state = _prove_written_manifest(
            proof_fd,
            expected_digest=published_digest.hexdigest(),
            expected_size=written_bytes,
            identity=identity,
            initial=opened,
        )
        source.assert_unchanged()
        _assert_final_manifest_state(
            proof_fd, path, expected=proof_state, identity=identity
        )
        source.assert_unchanged()
    except (ManifestError, OutputError):
        raise
    except OSError as exc:
        raise OutputError(
            f"Could not create a complete manifest '{path}': {exc.strerror}. The path may contain an incomplete file and is never deleted automatically."
        ) from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if proof_fd >= 0:
            os.close(proof_fd)
    return path


def parse_manifest_v2_bytes(
    data: bytes,
    *,
    max_records: int = DEFAULT_MAX_MANIFEST_RECORDS,
    max_bytes: int = DEFAULT_MAX_MANIFEST_BYTES,
) -> ManifestV2:
    """Parse strict v2 JSONL already obtained through a safe file descriptor.

    Recovery verification deliberately keeps its output root open and must not
    reopen managed paths by name.  This shared parser keeps descriptor-relative
    callers subject to the same framing and schema checks as public manifests.
    """
    if max_records < 2 or max_bytes < 1:
        raise ManifestError("Manifest reader limits must be positive.")
    if len(data) > max_bytes:
        raise ManifestError("The v2 manifest violates bounded JSONL framing.")
    if not data or not data.endswith(b"\n"):
        raise ManifestError("The v2 manifest violates bounded JSONL framing.")

    def parse_record(start: int, end: int) -> dict[str, Any]:
        if end <= start or end - start > MAX_MANIFEST_LINE_BYTES:
            raise ManifestError("The v2 manifest violates bounded JSONL framing.")
        try:
            record = json.loads(
                data[start : end - 1].decode("utf-8"),
                object_pairs_hook=_no_duplicates,
                parse_constant=_reject_nonstandard_json_constant,
            )
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise ManifestError(
                "The v2 manifest contains invalid JSON or duplicate keys."
            ) from exc
        if not isinstance(record, dict):
            raise ManifestError("The v2 manifest record is not an object.")
        return record

    first_end = data.find(b"\n") + 1
    completion_start = data.rfind(b"\n", 0, len(data) - 1) + 1
    if first_end <= 0:
        raise ManifestError("The v2 manifest violates bounded JSONL framing.")
    header = parse_record(0, first_end)
    if completion_start < first_end:
        raise ManifestError(
            "A v2 manifest requires one header and final completion record."
        )
    completion = parse_record(completion_start, len(data))
    if (
        header.get("record_type") != "manifest"
        or completion.get("record_type") != "complete"
    ):
        raise ManifestError(
            "A v2 manifest requires one header and final completion record."
        )
    header_fields = {
        "record_type",
        "format",
        "version",
        "schema",
        "source",
        "scan_options",
        "candidate_count",
        "warnings",
    }
    if (
        set(header) != header_fields
        or header.get("format") != "exfat-rescue.manifest"
        or type(header.get("version")) is not int
        or header.get("version") != 2
        or header.get("schema") != SCHEMA_V2
        or not isinstance(header.get("source"), dict)
        or not isinstance(header.get("scan_options"), dict)
        or not isinstance(header.get("warnings"), list)
        or not _integer(header.get("candidate_count"))
        or any(not isinstance(key, str) for key in header["scan_options"])
        or not all(
            isinstance(warning, str) and warning for warning in header["warnings"]
        )
        or header["warnings"] != sorted(set(header["warnings"]))
    ):
        raise ManifestError(
            "The v2 manifest header is invalid or contains undeclared fields."
        )
    source_fields = {
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
    source = header["source"]
    if (
        set(source) != source_fields
        or any(
            not _integer(source[key])
            for key in source_fields
            - {
                "volume_sha256",
                "source_kind",
                "boot_region",
                "volume_dirty",
                "media_failure",
            }
        )
        or not isinstance(source["volume_sha256"], str)
        or not _SHA256.fullmatch(source["volume_sha256"])
        or not isinstance(source["source_kind"], str)
        or not isinstance(source["boot_region"], str)
        or source["source_kind"] not in {"direct-image", "mbr", "gpt"}
        or source["boot_region"] not in {"primary", "backup"}
        or type(source["volume_dirty"]) is not bool
        or type(source["media_failure"]) is not bool
    ):
        raise ManifestError("The v2 manifest source binding is invalid or incomplete.")
    digest = hashlib.sha256()
    digest.update(memoryview(data)[:first_end])
    plans_list: list[RecoveryPlan] = []
    source_candidates_list: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    previous_id: str | None = None
    offset = first_end
    content_record_count = 1
    while offset < completion_start:
        line_end = data.find(b"\n", offset, completion_start) + 1
        if line_end <= offset:
            raise ManifestError("The v2 manifest violates bounded JSONL framing.")
        content_record_count += 1
        if content_record_count + 1 > max_records:
            raise ManifestError("The v2 manifest violates bounded JSONL framing.")
        record = parse_record(offset, line_end)
        plan = _parse_plan(record)
        if plan.candidate_id in seen_ids or (
            previous_id is not None and plan.candidate_id < previous_id
        ):
            raise ManifestError("The v2 manifest candidate inventory is invalid.")
        seen_ids.add(plan.candidate_id)
        previous_id = plan.candidate_id
        plans_list.append(plan)
        source_candidates_list.append(record["source_candidate"])
        digest.update(memoryview(data)[offset:line_end])
        offset = line_end
    if content_record_count + 1 > max_records:
        raise ManifestError("The v2 manifest violates bounded JSONL framing.")
    plans = tuple(plans_list)
    source_candidates = tuple(source_candidates_list)
    if header["candidate_count"] != len(plans):
        raise ManifestError("The v2 manifest candidate inventory is invalid.")
    expected_completion = {
        "record_type": "complete",
        "candidate_count": len(plans),
        "content_record_count": content_record_count,
        "content_sha256": digest.hexdigest(),
    }
    if (
        type(completion.get("candidate_count")) is not int
        or type(completion.get("content_record_count")) is not int
        or completion != expected_completion
    ):
        raise ManifestError("The v2 manifest completion record does not validate.")
    _validate_v2_semantics(header, plans, source_candidates)
    return ManifestV2(header, plans, source_candidates, completion, data)


def read_manifest_v2(
    path_value: str | Path,
    *,
    max_records: int = DEFAULT_MAX_MANIFEST_RECORDS,
    max_bytes: int = DEFAULT_MAX_MANIFEST_BYTES,
) -> ManifestV2:
    """Read an external v2 manifest without following an output-managed path."""
    path = Path(path_value)
    fd: int | None = None
    try:
        fd = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ManifestError("The manifest must be a regular file.")
        with os.fdopen(fd, "rb") as input_file:
            fd = None
            data = input_file.read(max_bytes + 1)
    except ManifestError:
        raise
    except OSError as exc:
        raise ManifestError(
            f"Could not read manifest '{path}': {exc.strerror}."
        ) from exc
    finally:
        if fd is not None:
            os.close(fd)
    return parse_manifest_v2_bytes(data, max_records=max_records, max_bytes=max_bytes)


def validate_manifest_plans(
    manifest: ManifestV2, planner_result: PlannerResult
) -> None:
    """Require a current replan to match every extraction-relevant field."""
    if dict(manifest.header.get("source", {})) != dict(planner_result.source_binding):
        raise ManifestError(
            "The manifest source binding does not match the current selected volume."
        )
    current = tuple(sorted(planner_result.plans, key=lambda plan: plan.candidate_id))
    stored = tuple(sorted(manifest.plans, key=lambda plan: plan.candidate_id))
    if stored != current:
        raise ManifestError(
            "The manifest candidate plans do not match the current metadata replan."
        )
