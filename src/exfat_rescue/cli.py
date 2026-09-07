from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import os
import stat
import sys
import time
from pathlib import Path

from . import __version__
from .errors import (
    ManifestError,
    OutputError,
    RescueError,
    ResourceLimitError,
    UsageError,
    VerificationError,
)
from .exfat.volume import ExfatVolume
from .exporter import _export_staging_name
from .manifest import (
    DEFAULT_MAX_MANIFEST_BYTES,
    DEFAULT_MAX_MANIFEST_RECORDS,
    MAX_MANIFEST_LINE_BYTES,
    SCHEMA_V2,
    ManifestV2,
    parse_manifest_v2_bytes,
    read_manifest_v2,
    validate_manifest_plans,
    write_manifest_v2,
)
from .planner import (
    DEFAULT_MAX_FAT_STEPS,
    PlannerResult,
    plan_recovery,
)
from .recovery import (
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_RUN_LIMITS,
    HARD_MAX_RECOVERY_CANDIDATES,
    LOCKING_AVAILABLE,
    MAX_INTERNAL_MANIFEST_BYTES,
    MAX_RUN_BYTES,
    _bootstrap_name,
    _open_dir,
    _read_regular_at,
)
from .scanner import (
    DEFAULT_MAX_CANDIDATES,
    DEFAULT_MAX_SCAN_CLUSTERS,
    HARD_MAX_CANDIDATES,
    scan,
)
from .source import ImageSource, preflight_output_path

_EVENT_LOG_VERSION = 1
_EVENT_LOG_MAX_BYTES = 16 * 1024


def _event_time() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")


class _EventLog:
    """Append bounded JSON events to a new private no-follow file."""

    def __init__(self, value: str | Path) -> None:
        self.path = Path(os.path.abspath(os.fspath(value)))
        self._identity: tuple[int, int] | None = None
        parent_fd = self._open_parent()
        try:
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_APPEND
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                fd = os.open(self.path.name, flags, 0o600, dir_fd=parent_fd)
            except OSError as exc:
                raise OutputError(
                    f"Cannot create new event log '{self.path}': {exc.strerror}."
                ) from exc
            try:
                state = os.fstat(fd)
                self._validate(state)
                self._identity = (state.st_dev, state.st_ino)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)

    def _open_parent(self) -> int:
        try:
            return os.open(
                self.path.parent,
                os.O_RDONLY
                | os.O_DIRECTORY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
        except OSError as exc:
            raise OutputError(
                f"Cannot safely open event-log directory '{self.path.parent}': "
                f"{exc.strerror}."
            ) from exc

    @staticmethod
    def _validate(state: os.stat_result) -> None:
        if (
            not stat.S_ISREG(state.st_mode)
            or state.st_nlink != 1
            or state.st_uid != os.geteuid()
            or stat.S_IMODE(state.st_mode) != 0o600
        ):
            raise OutputError(
                "The event log is not a private, singly-linked regular file."
            )

    def append(self, value: dict[str, object]) -> None:
        raw = (
            json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
            + "\n"
        ).encode("ascii")
        if len(raw) > _EVENT_LOG_MAX_BYTES:
            raise OutputError("A progress event exceeds its fixed size limit.")
        parent_fd = self._open_parent()
        try:
            try:
                named = os.stat(
                    self.path.name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise OutputError("The event log was removed or replaced.") from exc
            self._validate(named)
            if (named.st_dev, named.st_ino) != self._identity:
                raise OutputError("The event log was replaced.")
            try:
                fd = os.open(
                    self.path.name,
                    os.O_WRONLY
                    | os.O_APPEND
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_NONBLOCK", 0),
                    dir_fd=parent_fd,
                )
            except OSError as exc:
                raise OutputError(
                    "The event log could not be reopened safely."
                ) from exc
            try:
                opened = os.fstat(fd)
                self._validate(opened)
                if (opened.st_dev, opened.st_ino) != self._identity:
                    raise OutputError("The event log changed while opening.")
                offset = 0
                while offset < len(raw):
                    written = os.write(fd, raw[offset:])
                    if written < 1:
                        raise OutputError(
                            "The event log could not be written completely."
                        )
                    offset += written
                os.fsync(fd)
                after = os.fstat(fd)
                self._validate(after)
                if (after.st_dev, after.st_ino) != self._identity:
                    raise OutputError("The event log changed while writing.")
            except OSError as exc:
                raise OutputError(
                    f"Could not persist the event log: {exc.strerror}."
                ) from exc
            finally:
                os.close(fd)
            try:
                named_after = os.stat(
                    self.path.name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise OutputError("The event log was removed while writing.") from exc
            self._validate(named_after)
            if (
                named_after.st_dev,
                named_after.st_ino,
            ) != self._identity or named_after.st_size != after.st_size:
                raise OutputError("The event log was replaced while writing.")
        finally:
            os.close(parent_fd)


class _ProgressReporter:
    """Throttle human progress and persist complete machine-readable events."""

    def __init__(self, event_log: str | Path | None, *, human: bool) -> None:
        self._log = _EventLog(event_log) if event_log is not None else None
        self._human = human
        self._started: dict[str, float] = {}
        self._last: dict[str, float] = {}
        self._positions: dict[str, tuple[int, int]] = {}

    @property
    def enabled(self) -> bool:
        return self._human or self._log is not None

    def _persist(self, value: dict[str, object]) -> None:
        if self._log is not None:
            self._log.append(
                {
                    "format": "exfat-rescue.event",
                    "version": _EVENT_LOG_VERSION,
                    "timestamp": _event_time(),
                    **value,
                }
            )

    def phase(self, name: str) -> None:
        self._started[name] = time.monotonic()
        self._last.pop(name, None)
        self._positions.pop(name, None)
        self._persist({"event": "phase", "phase": name})

    def __call__(self, phase: str, completed: int, total: int, unit: str) -> None:
        if completed < 0 or total < 0 or completed > total:
            raise ValueError("Progress is outside its bounded total.")
        current = time.monotonic()
        prior = self._positions.get(phase)
        if prior is not None and (prior[0] == prior[1] or completed < prior[0]):
            # A command such as verify-set can execute the same named phase for
            # multiple inputs. A call after completion or a decreasing position
            # begins a new pass, so its rate and ETA need a fresh clock.
            self._started[phase] = current
            self._last.pop(phase, None)
        self._positions[phase] = (completed, total)
        started = self._started.setdefault(phase, current)
        previous = self._last.get(phase)
        if completed != total and previous is not None and current - previous < 30:
            return
        self._last[phase] = current
        elapsed = max(current - started, 0.001)
        rate = completed / elapsed
        eta = (total - completed) / rate if rate > 0 else None
        event: dict[str, object] = {
            "event": "progress",
            "phase": phase,
            "completed": completed,
            "total": total,
            "unit": unit,
            "elapsed_seconds": round(elapsed, 3),
            "rate_per_second": round(rate, 3),
        }
        if eta is not None:
            event["eta_seconds"] = round(eta, 3)
        self._persist(event)
        if self._human:
            percent = 100.0 if total == 0 else 100 * completed / total
            suffix = "" if eta is None else f"; ETA {eta:.0f}s"
            print(
                f"{phase}: {completed}/{total} {unit} "
                f"({percent:.1f}%; {rate:.1f} {unit}/s{suffix})",
                file=sys.stderr,
                flush=True,
            )

    def complete(self, command: str) -> None:
        self._persist({"event": "complete", "command": command})

    def notice(self, name: str, **details: object) -> None:
        self._persist({"event": "notice", "name": name, **details})

    def failed(self, code: str) -> None:
        self._persist({"event": "failed", "error_code": code})


def _best_effort_failure(reporter: _ProgressReporter | None, error_code: str) -> None:
    if reporter is None:
        return
    try:
        reporter.failed(error_code)
    except (OSError, RescueError):
        pass


def _validate_event_log_location(args: argparse.Namespace) -> None:
    """Never let an operational side channel alter managed recovery state."""
    value = getattr(args, "event_log", None)
    if value is None:
        return
    protected: list[str] = []
    if args.command == "verify":
        protected.append(args.output)
    elif args.command == "verify-set":
        protected.extend(args.outputs)
    elif args.command == "export":
        protected.extend((args.output, args.destination))
        destination = Path(os.path.abspath(os.fspath(args.destination)))
        # Export stages under this deterministic sibling before it atomically
        # publishes the requested destination.  An event log at that pathname
        # would otherwise pre-create state that export must refuse.
        if destination.name:
            protected.append(
                destination.with_name(_export_staging_name(destination.name))
            )
    elif args.command == "recover":
        protected.append(args.resume or args.output)
        if args.output:
            output = Path(os.path.abspath(os.fspath(args.output)))
            # New recovery first creates this deterministic sibling.  Treat it
            # as managed state too, so progress logging cannot occupy it.
            if output.name:
                protected.append(output.with_name(_bootstrap_name(output.name)))
    elif args.command == "scan":
        protected.append(args.manifest)
    event_path = Path(os.path.abspath(os.fspath(value))).resolve(strict=False)
    try:
        event_parent = event_path.parent.resolve(strict=True)
    except OSError:
        event_parent = event_path.parent.resolve(strict=False)
    for item in protected:
        root = Path(os.path.abspath(os.fspath(item))).resolve(strict=False)
        if event_path == root or event_parent == root or root in event_parent.parents:
            raise OutputError(
                "The event log must be outside managed recovery and export directories."
            )


def _internal_manifest_bytes(
    planned: PlannerResult,
    options: dict[str, object],
    warnings: tuple[str, ...],
) -> bytes:
    """Canonical v2 bytes retained inside runs when no external manifest was given."""
    unknown_options = set(options) - {
        "max_candidates",
        "max_scan_clusters",
        "max_fat_steps",
    }
    if unknown_options:
        raise ValueError("Internal manifest options contain undeclared fields.")
    binding = dict(planned.source_binding)
    scan_options = {
        "orphan_scan": True,
        "version": 2,
        "volume_offset_bytes": binding["volume_offset_bytes"],
        "source_kind": binding["source_kind"],
        "boot_region": binding["boot_region"],
        "max_candidates": options.get("max_candidates", DEFAULT_MAX_CANDIDATES),
        "max_scan_clusters": options.get(
            "max_scan_clusters", DEFAULT_MAX_SCAN_CLUSTERS
        ),
        "max_fat_steps": options.get("max_fat_steps", DEFAULT_MAX_FAT_STEPS),
    }
    if len(planned.plans) != len(planned.source_candidates):
        raise ValueError("Planner omitted raw candidates required by manifest v2.")
    if len(planned.plans) + 2 > DEFAULT_MAX_MANIFEST_RECORDS:
        raise ManifestError("The internal manifest exceeds its record limit.")
    output = io.BytesIO()
    digest = hashlib.sha256()
    content_record_count = 0
    written_bytes = 0

    def append(record: dict[str, object], *, content: bool) -> None:
        nonlocal content_record_count, written_bytes
        line = (
            json.dumps(
                record,
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        if len(line) > MAX_MANIFEST_LINE_BYTES:
            raise ManifestError("An internal manifest record exceeds its line limit.")
        written_bytes += len(line)
        if written_bytes > DEFAULT_MAX_MANIFEST_BYTES:
            raise ManifestError("The internal manifest exceeds its byte limit.")
        output.write(line)
        if content:
            digest.update(line)
            content_record_count += 1

    append(
        {
            "record_type": "manifest",
            "format": "exfat-rescue.manifest",
            "version": 2,
            "schema": SCHEMA_V2,
            "source": binding,
            "scan_options": scan_options,
            "candidate_count": len(planned.plans),
            "warnings": list(warnings),
        },
        content=True,
    )
    for plan, candidate in zip(planned.plans, planned.source_candidates, strict=True):
        append(
            {
                "record_type": "candidate",
                "candidate_id": plan.candidate_id,
                "entry_offset": plan.entry_offset,
                "entry_set_sha256": plan.entry_set_sha256,
                "name": plan.name,
                "logical_size_bytes": plan.logical_size_bytes,
                "valid_data_bytes": plan.valid_data_bytes,
                "extents": [
                    {
                        "first_cluster": extent.first_cluster,
                        "cluster_count": extent.cluster_count,
                    }
                    for extent in plan.extents
                ],
                "allocation_mode": plan.allocation_mode,
                "metadata_location": plan.metadata_location,
                "disposition": plan.disposition,
                "recovery_basis": plan.recovery_basis,
                "reasons": list(plan.reasons),
                "source_candidate": dict(candidate),
            },
            content=True,
        )
    append(
        {
            "record_type": "complete",
            "candidate_count": len(planned.plans),
            "content_record_count": content_record_count,
            "content_sha256": digest.hexdigest(),
        },
        content=False,
    )
    return output.getvalue()


def _reparsed_manifest_candidates(
    manifest_candidates: tuple[dict[str, object], ...],
    scanned_candidates: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Prove each stored candidate was independently rediscovered byte-for-byte."""

    def key(candidate: dict[str, object]) -> tuple[object, object]:
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
    if len(manifest_candidates) != len(scanned_candidates):
        raise ManifestError(
            "The manifest candidate inventory does not exactly match the current "
            "complete scan."
        )
    scanned_candidates.sort(key=key)
    stored_ordered = sorted(manifest_candidates, key=key)
    previous: tuple[object, object] | None = None
    for stored, candidate in zip(stored_ordered, scanned_candidates, strict=True):
        current_key = key(stored)
        if (
            current_key == previous
            or current_key != key(candidate)
            or {name: candidate.get(name) for name in fields}
            != {name: stored.get(name) for name in fields}
        ):
            raise ManifestError(
                "A manifest candidate was not rediscovered with identical current metadata."
            )
        previous = current_key
    return scanned_candidates


def _emit(payload: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, sort_keys=True, ensure_ascii=False))
    else:
        if payload["command"] == "inspect":
            print(
                f"exFAT image: {payload['image_size_bytes']} bytes; cluster size: {payload['cluster_size_bytes']} bytes; root cluster: {payload['root_cluster']}"
            )
        elif payload["command"] == "scan":
            print(
                f"Scan complete: {payload['candidate_count']} candidate(s). Manifest: {payload['manifest']}"
            )
        elif payload["command"] == "recover":
            print(
                "Recovery complete: "
                f"{payload['recovered_count']} recovered, "
                f"{payload['refused_count']} refused "
                f"({payload['conflicted_count']} conflicted, "
                f"{payload['unrecoverable_count']} unrecoverable), "
                f"{payload['failed_count']} failed. Output: {payload['output']}"
            )
        elif payload["command"] == "export":
            print(
                f"Export complete: {payload['file_count']} file(s). "
                f"Destination: {payload['destination']}"
            )
        else:
            print(f"Verification complete: {payload['candidate_count']} candidate(s).")


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise UsageError(message)


def _validate_cli_limits(args: argparse.Namespace) -> None:
    """Reject non-positive scan and recovery work limits before any I/O."""
    limits: tuple[tuple[str, int | None], ...]
    if args.command == "scan":
        limits = (
            ("--max-candidates", args.max_candidates),
            ("--max-scan-clusters", args.max_scan_clusters),
            ("--max-fat-steps", args.max_fat_steps),
        )
    elif args.command == "recover":
        limits = (
            (
                "--max-output-bytes",
                (
                    DEFAULT_MAX_OUTPUT_BYTES
                    if args.max_output_bytes is None
                    else args.max_output_bytes
                ),
            ),
            (
                "--max-candidates",
                (
                    DEFAULT_MAX_CANDIDATES
                    if args.max_candidates is None
                    else args.max_candidates
                ),
            ),
            (
                "--max-selected-candidates",
                (
                    DEFAULT_RUN_LIMITS["max_candidates"]
                    if args.max_selected_candidates is None
                    else args.max_selected_candidates
                ),
            ),
            (
                "--max-scan-clusters",
                (
                    DEFAULT_MAX_SCAN_CLUSTERS
                    if args.max_scan_clusters is None
                    else args.max_scan_clusters
                ),
            ),
            (
                "--max-fat-steps",
                (
                    DEFAULT_MAX_FAT_STEPS
                    if args.max_fat_steps is None
                    else args.max_fat_steps
                ),
            ),
        )
    else:
        return
    for name, value in limits:
        if value is not None and value <= 0:
            raise UsageError(f"{name} must be positive.")


def _preflight_manifest_selection(
    manifest: ManifestV2,
    requested_ids: list[str],
    *,
    max_selected_candidates: int,
    max_output_bytes: int,
) -> list[str]:
    """Reject manifest-evident recovery selection errors before scanning the image."""
    plans = list(manifest.plans)
    by_id = {plan.candidate_id: plan for plan in plans}
    if len(by_id) != len(plans):
        raise ManifestError("The manifest contains duplicate candidate IDs.")
    selected = requested_ids or [plan.candidate_id for plan in plans]
    if (
        any(
            not isinstance(candidate_id, str)
            or len(candidate_id) != 64
            or any(character not in "0123456789abcdef" for character in candidate_id)
            for candidate_id in selected
        )
        or len(selected) != len(set(selected))
        or any(candidate_id not in by_id for candidate_id in selected)
    ):
        raise UsageError(
            "Candidate selection contains a malformed, unknown, or duplicate ID."
        )
    if len(selected) > max_selected_candidates:
        raise ResourceLimitError(
            "Selected recovery plans exceed the configured candidate limit."
        )
    output_bytes = sum(
        by_id[candidate_id].logical_size_bytes
        for candidate_id in selected
        if by_id[candidate_id].disposition == "recoverable"
    )
    if output_bytes > max_output_bytes:
        raise ResourceLimitError(
            "Selected recoverable output exceeds --max-output-bytes."
        )
    return selected


def build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="exfat-rescue",
        description="Read-only inspection, scanning, recovery, and verification for exFAT disk images.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser(
        "inspect", help="validate and describe an exFAT image or whole-disk image"
    )
    inspect.add_argument(
        "image",
        metavar="IMAGE",
        help="regular exFAT partition image, MBR image, or GPT image",
    )
    inspect.add_argument(
        "--json", action="store_true", help="emit one machine-readable result to stdout"
    )
    scan_parser = commands.add_parser(
        "scan", help="write a deterministic metadata manifest"
    )
    scan_parser.add_argument(
        "image",
        metavar="IMAGE",
        help="regular exFAT partition image, MBR image, or GPT image",
    )
    recover = commands.add_parser(
        "recover", help="recover exact planner-validated files"
    )
    recover.add_argument(
        "image",
        metavar="IMAGE",
        help="regular exFAT partition image, MBR image, or GPT image",
    )
    destination = recover.add_mutually_exclusive_group(required=True)
    destination.add_argument(
        "--output",
        metavar="NEW_DIRECTORY",
        help="new private recovery directory; existing paths are refused",
    )
    destination.add_argument(
        "--resume",
        metavar="OUTPUT_DIRECTORY",
        help="resume or validate an incomplete tool-created recovery directory",
    )
    recover.add_argument(
        "--manifest", metavar="MANIFEST", help="strict v2 manifest to revalidate"
    )
    recover.add_argument(
        "--candidate-id",
        action="append",
        default=[],
        metavar="ID",
        help="recover only this full candidate ID; repeat to select more than one",
    )
    recover.add_argument(
        "--max-output-bytes",
        type=int,
        help=(
            "maximum selected logical output bytes "
            f"(default: {DEFAULT_MAX_OUTPUT_BYTES} bytes, 100 GiB)"
        ),
    )
    recover.add_argument(
        "--max-candidates", type=int, help="maximum retained recovery candidates"
    )
    recover.add_argument(
        "--max-selected-candidates",
        type=int,
        help=(
            "maximum candidates selected into one output "
            f"(default: {DEFAULT_RUN_LIMITS['max_candidates']}; "
            f"maximum: {HARD_MAX_RECOVERY_CANDIDATES})"
        ),
    )
    recover.add_argument(
        "--max-scan-clusters", type=int, help="maximum allocation units to scan"
    )
    recover.add_argument(
        "--max-fat-steps", type=int, help="maximum cumulative FAT-chain steps"
    )
    recover.add_argument(
        "--json", action="store_true", help="emit one machine-readable result"
    )
    recover.add_argument(
        "--event-log",
        metavar="NEW_JSONL_FILE",
        help="persist throttled phase/progress events to a new private JSONL file",
    )
    verify = commands.add_parser("verify", help="verify a completed recovery output")
    verify.add_argument(
        "output", metavar="OUTPUT_DIRECTORY", help="completed recovery directory"
    )
    verify.add_argument(
        "--image", metavar="IMAGE", help="also revalidate plans and source bytes"
    )
    verify.add_argument(
        "--json", action="store_true", help="emit one machine-readable result"
    )
    verify.add_argument(
        "--event-log",
        metavar="NEW_JSONL_FILE",
        help="persist throttled phase/progress events to a new private JSONL file",
    )
    verify_set = commands.add_parser(
        "verify-set",
        help="verify recovery outputs with one shared image revalidation",
    )
    verify_set.add_argument(
        "outputs",
        nargs="+",
        metavar="OUTPUT_DIRECTORY",
        help="completed recovery directories sharing one exact manifest",
    )
    verify_set.add_argument(
        "--image",
        required=True,
        metavar="IMAGE",
        help="revalidate shared plans and each output's source bytes",
    )
    verify_set.add_argument(
        "--json", action="store_true", help="emit one machine-readable result"
    )
    verify_set.add_argument(
        "--event-log",
        metavar="NEW_JSONL_FILE",
        help="persist throttled phase/progress events to a new private JSONL file",
    )
    export = commands.add_parser(
        "export",
        help="verify and copy recovered files to recognizable safe names",
    )
    export.add_argument(
        "output", metavar="OUTPUT_DIRECTORY", help="completed recovery directory"
    )
    export.add_argument(
        "--destination",
        required=True,
        metavar="NEW_DIRECTORY",
        help="new private export directory; existing paths are refused",
    )
    export.add_argument(
        "--json", action="store_true", help="emit one machine-readable result"
    )
    export.add_argument(
        "--event-log",
        metavar="NEW_JSONL_FILE",
        help="persist throttled phase/progress events to a new private JSONL file",
    )
    scan_parser.add_argument(
        "--manifest",
        metavar="PATH",
        required=True,
        help="new JSONL manifest path; never overwritten",
    )
    scan_parser.add_argument(
        "--json", action="store_true", help="emit one machine-readable result to stdout"
    )
    scan_parser.add_argument(
        "--event-log",
        metavar="NEW_JSONL_FILE",
        help="persist throttled phase/progress events to a new private JSONL file",
    )
    scan_parser.add_argument(
        "--max-candidates",
        type=int,
        default=DEFAULT_MAX_CANDIDATES,
        help=(
            f"stop discovery before retaining more than this many candidates "
            f"(default: {DEFAULT_MAX_CANDIDATES}; maximum: {HARD_MAX_CANDIDATES})"
        ),
    )
    scan_parser.add_argument(
        "--max-scan-clusters",
        type=int,
        default=DEFAULT_MAX_SCAN_CLUSTERS,
        help=f"refuse volumes above this allocation-unit count (default: {DEFAULT_MAX_SCAN_CLUSTERS})",
    )
    scan_parser.add_argument(
        "--max-fat-steps",
        type=int,
        default=DEFAULT_MAX_FAT_STEPS,
        help=f"bound cumulative fragmented-file FAT work (default: {DEFAULT_MAX_FAT_STEPS})",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    args = argparse.Namespace(json="--json" in arguments, command=None)
    reporter: _ProgressReporter | None = None
    try:
        args = build_parser().parse_args(arguments)
        if sys.platform not in {"linux", "darwin"} or not LOCKING_AVAILABLE:
            raise UsageError(
                "exfat-rescue operations require Linux or macOS with directory locking support."
            )
        _validate_cli_limits(args)
        if (
            args.command in {"scan", "recover"}
            and args.max_candidates is not None
            and not 1 <= args.max_candidates <= HARD_MAX_CANDIDATES
        ):
            raise UsageError(
                f"--max-candidates must be between 1 and {HARD_MAX_CANDIDATES}."
            )
        if (
            args.command == "recover"
            and args.max_selected_candidates is not None
            and not 1 <= args.max_selected_candidates <= HARD_MAX_RECOVERY_CANDIDATES
        ):
            raise UsageError(
                "--max-selected-candidates must be between 1 and "
                f"{HARD_MAX_RECOVERY_CANDIDATES}."
            )
        _validate_event_log_location(args)
        reporter = _ProgressReporter(
            getattr(args, "event_log", None),
            human=not args.json and args.command != "inspect",
        )
        progress = reporter if reporter.enabled else None
        if args.command == "verify":
            from .verification import verify_recovery

            reporter.phase("verify-output")
            result = verify_recovery(
                args.output,
                args.image,
                progress=progress,
            )
            reporter.complete("verify")
            _emit({"command": "verify", **result}, args.json)
            return 0
        if args.command == "verify-set":
            from .verification import verify_recovery_set

            reporter.phase("verify-output-set")
            result = verify_recovery_set(
                args.outputs,
                args.image,
                progress=progress,
            )
            reporter.complete("verify-set")
            _emit({"command": "verify-set", **result}, args.json)
            return 0
        if args.command == "export":
            from .exporter import export_recovery

            reporter.phase("verify-output")
            result = export_recovery(
                args.output,
                args.destination,
                progress=progress,
            )
            reporter.complete("export")
            _emit({"command": "export", **result}, args.json)
            return 0
        source = ImageSource.open(args.image, progress=progress)
        try:
            if args.command == "inspect":
                volume = ExfatVolume(source)
                source.assert_unchanged()
                _emit(
                    {
                        "ok": True,
                        "command": "inspect",
                        "image_size_bytes": source.size,
                        "bytes_per_sector": volume.boot.bytes_per_sector,
                        "sectors_per_cluster": volume.boot.sectors_per_cluster,
                        "cluster_size_bytes": volume.boot.cluster_size,
                        "root_cluster": volume.boot.root_cluster,
                        "cluster_count": volume.boot.cluster_count,
                        "volume_offset_bytes": volume.base_offset,
                        "source_kind": volume.location.source_kind,
                        "boot_region": volume.boot_region,
                        "volume_dirty": volume.boot.volume_dirty,
                        "media_failure": volume.boot.media_failure,
                    },
                    args.json,
                )
                reporter.complete("inspect")
            elif args.command == "scan":
                manifest_path = preflight_output_path(source, args.manifest)
                reporter.phase("scan-clusters")
                result = scan(
                    source,
                    max_candidates=args.max_candidates,
                    max_scan_clusters=args.max_scan_clusters,
                    progress=(
                        None
                        if progress is None
                        else lambda completed, total: progress(
                            "scan-clusters", completed, total, "clusters"
                        )
                    ),
                )
                options = {
                    "orphan_scan": True,
                    "version": 2,
                    "volume_offset_bytes": result.volume.base_offset,
                    "source_kind": result.volume.location.source_kind,
                    "boot_region": result.volume.boot_region,
                    "max_candidates": args.max_candidates,
                    "max_scan_clusters": args.max_scan_clusters,
                    "max_fat_steps": args.max_fat_steps,
                }
                reporter.phase("plan-recovery")
                planned = plan_recovery(
                    result.volume,
                    result.candidates,
                    max_fat_steps=args.max_fat_steps,
                    active_owners=result.active_owners,
                    metadata_complete=result.metadata_complete,
                    ownership_complete=result.ownership_complete,
                )
                manifest = write_manifest_v2(
                    source,
                    manifest_path,
                    planned,
                    options,
                    warnings=result.warnings,
                )
                reporter.complete("scan")
                _emit(
                    {
                        "ok": True,
                        "command": "scan",
                        "manifest": str(manifest),
                        "candidate_count": len(planned.plans),
                        "source": dict(planned.source_binding),
                        "cluster_size_bytes": result.volume.boot.cluster_size,
                        "volume_offset_bytes": result.volume.base_offset,
                        "source_kind": result.volume.location.source_kind,
                        "boot_region": result.volume.boot_region,
                        "warnings": list(result.warnings),
                        "scanned_clusters": result.scanned_clusters,
                    },
                    args.json,
                )
            else:
                from .recovery import recover_plans, resume_recovery

                if args.resume:
                    if (
                        args.manifest
                        or args.candidate_id
                        or args.max_output_bytes is not None
                        or args.max_candidates is not None
                        or args.max_selected_candidates is not None
                        or args.max_scan_clusters is not None
                        or args.max_fat_steps is not None
                    ):
                        raise UsageError(
                            "Resume forbids manifest replacement, candidate selection, and changed limits."
                        )
                    from .verification import _run_descriptor

                    output_dir = Path(args.resume)
                    root_fd = _open_dir(output_dir)
                    try:
                        run = _run_descriptor(
                            _read_regular_at(
                                root_fd, "run.json", max_bytes=MAX_RUN_BYTES
                            )
                        )
                        internal_manifest = _read_regular_at(
                            root_fd,
                            "manifest.jsonl",
                            max_bytes=MAX_INTERNAL_MANIFEST_BYTES,
                        )
                    finally:
                        os.close(root_fd)
                    manifest = parse_manifest_v2_bytes(internal_manifest)
                    manifest_ids = {plan.candidate_id for plan in manifest.plans}
                    if (
                        hashlib.sha256(internal_manifest).hexdigest()
                        != run["manifest_sha256"]
                        or manifest.header["source"] != run["source"]
                        or any(
                            candidate_id not in manifest_ids
                            for candidate_id in run["candidate_ids"]
                        )
                    ):
                        raise ManifestError(
                            "The immutable resume descriptor and manifest disagree."
                        )
                    binding = run["source"]
                    source_proof_reused = False
                    if run["version"] >= 2:
                        source_proof_reused = source.reuse_selected_volume_digest(
                            binding["volume_offset_bytes"],
                            binding["volume_length_bytes"],
                            binding["volume_sha256"],
                            run["source_file_state"],
                        )
                    reporter.notice(
                        "source-proof",
                        reused=source_proof_reused,
                    )
                    limits = run.get("limits")
                    if not isinstance(limits, dict):
                        raise RescueError("Resume run descriptor has invalid limits.")
                    reporter.phase("scan-clusters")
                    scanned = scan(
                        source,
                        max_candidates=manifest.header["scan_options"][
                            "max_candidates"
                        ],
                        max_scan_clusters=int(
                            limits.get("max_scan_clusters", DEFAULT_MAX_SCAN_CLUSTERS)
                        ),
                        progress=(
                            None
                            if progress is None
                            else lambda completed, total: progress(
                                "scan-clusters", completed, total, "clusters"
                            )
                        ),
                    )
                    reparsed = _reparsed_manifest_candidates(
                        manifest.candidates, scanned.candidates
                    )
                    reporter.phase("plan-recovery")
                    planned = plan_recovery(
                        scanned.volume,
                        reparsed,
                        max_fat_steps=int(limits.get("max_fat_steps", 10_000_000)),
                        active_owners=scanned.active_owners,
                        metadata_complete=scanned.metadata_complete,
                        ownership_complete=scanned.ownership_complete,
                    )
                    validate_manifest_plans(manifest, planned)
                    reporter.phase("resume-recovery")
                    result = resume_recovery(
                        source,
                        output_dir,
                        planner_result=planned,
                        manifest=manifest,
                        progress=progress,
                    )
                    result["source_proof_reused"] = source_proof_reused
                else:
                    max_candidates = (
                        DEFAULT_MAX_CANDIDATES
                        if args.max_candidates is None
                        else args.max_candidates
                    )
                    max_scan_clusters = (
                        DEFAULT_MAX_SCAN_CLUSTERS
                        if args.max_scan_clusters is None
                        else args.max_scan_clusters
                    )
                    max_fat_steps = (
                        DEFAULT_MAX_FAT_STEPS
                        if args.max_fat_steps is None
                        else args.max_fat_steps
                    )
                    max_output_bytes = (
                        DEFAULT_MAX_OUTPUT_BYTES
                        if args.max_output_bytes is None
                        else args.max_output_bytes
                    )
                    max_selected_candidates = (
                        DEFAULT_RUN_LIMITS["max_candidates"]
                        if args.max_selected_candidates is None
                        else args.max_selected_candidates
                    )
                    manifest = (
                        read_manifest_v2(args.manifest) if args.manifest else None
                    )
                    selected: list[str] | None = None
                    if manifest is not None:
                        recorded_limit = manifest.header["scan_options"][
                            "max_candidates"
                        ]
                        if (
                            args.max_candidates is not None
                            and args.max_candidates != recorded_limit
                        ):
                            raise UsageError(
                                "--max-candidates must match the manifest's recorded discovery limit."
                            )
                        max_candidates = recorded_limit
                        selected = _preflight_manifest_selection(
                            manifest,
                            args.candidate_id,
                            max_selected_candidates=max_selected_candidates,
                            max_output_bytes=max_output_bytes,
                        )
                    reporter.phase("scan-clusters")
                    scanned = scan(
                        source,
                        max_candidates=max_candidates,
                        max_scan_clusters=max_scan_clusters,
                        progress=(
                            None
                            if progress is None
                            else lambda completed, total: progress(
                                "scan-clusters", completed, total, "clusters"
                            )
                        ),
                    )
                    if manifest is not None:
                        reparsed = _reparsed_manifest_candidates(
                            manifest.candidates, scanned.candidates
                        )
                        reporter.phase("plan-recovery")
                        planned = plan_recovery(
                            scanned.volume,
                            reparsed,
                            max_fat_steps=max_fat_steps,
                            active_owners=scanned.active_owners,
                            metadata_complete=scanned.metadata_complete,
                            ownership_complete=scanned.ownership_complete,
                        )
                        validate_manifest_plans(manifest, planned)
                        plans = planned.plans
                        manifest_bytes = manifest.raw_bytes
                        binding = dict(planned.source_binding)
                    else:
                        reporter.phase("plan-recovery")
                        planned = plan_recovery(
                            scanned.volume,
                            scanned.candidates,
                            max_fat_steps=max_fat_steps,
                            active_owners=scanned.active_owners,
                            metadata_complete=scanned.metadata_complete,
                            ownership_complete=scanned.ownership_complete,
                        )
                        plans = planned.plans
                        binding = dict(planned.source_binding)
                        manifest_bytes = _internal_manifest_bytes(
                            planned,
                            {
                                "max_candidates": max_candidates,
                                "max_scan_clusters": max_scan_clusters,
                                "max_fat_steps": max_fat_steps,
                            },
                            scanned.warnings,
                        )
                    if selected is None:
                        selected = args.candidate_id or [
                            plan.candidate_id for plan in plans
                        ]
                    reporter.phase("recover-candidates")
                    result = recover_plans(
                        source,
                        plans,
                        args.output,
                        source_binding=binding,
                        manifest_bytes=manifest_bytes,
                        selected_ids=selected,
                        limits={
                            "max_output_bytes": max_output_bytes,
                            "max_candidates": max_selected_candidates,
                            "max_scan_clusters": max_scan_clusters,
                            "max_fat_steps": max_fat_steps,
                        },
                        validated_manifest=manifest,
                        progress=progress,
                    )
                reporter.complete("recover")
                _emit({"ok": True, "command": "recover", **result}, args.json)
        finally:
            source.close()
        return 0
    except KeyboardInterrupt:
        _best_effort_failure(reporter, "cancelled")
        if getattr(args, "json", False):
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": "Operation cancelled; no completion record was published.",
                        "error_code": "cancelled",
                        "exit_code": 130,
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
        else:
            print(
                "exfat-rescue: Operation cancelled; no completion record was published.",
                file=sys.stderr,
            )
        return 130
    except VerificationError as exc:
        _best_effort_failure(reporter, exc.error_code)
        payload = {
            "ok": False,
            "command": getattr(args, "command", "verify"),
            "error": str(exc),
            "error_code": exc.error_code,
            "exit_code": exc.exit_code,
        }
        if getattr(args, "json", False):
            print(json.dumps(payload, sort_keys=True), file=sys.stdout)
        else:
            print(f"Verification failed: {exc}", file=sys.stdout)
        return exc.exit_code
    except RescueError as exc:
        _best_effort_failure(reporter, exc.error_code)
        if getattr(args, "json", False):
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": str(exc),
                        "error_code": exc.error_code,
                        "exit_code": exc.exit_code,
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
        else:
            print(f"exfat-rescue: {exc}", file=sys.stderr)
        return exc.exit_code
    except Exception:  # noqa: BLE001 - CLI boundary must emit the frozen code-1 envelope.
        _best_effort_failure(reporter, "internal_error")
        payload = {
            "ok": False,
            "error": "An unexpected internal error occurred.",
            "error_code": "internal_error",
            "exit_code": 1,
        }
        if getattr(args, "json", False):
            print(json.dumps(payload, sort_keys=True), file=sys.stderr)
        else:
            print(f"exfat-rescue: {payload['error']}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
