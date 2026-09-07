"""Adversarial tests for pre-publication recovery state and writer exclusion."""

from __future__ import annotations

import errno
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from exfat_rescue import recovery
from exfat_rescue.cli import _internal_manifest_bytes
from exfat_rescue.errors import OutputError
from exfat_rescue.manifest import parse_manifest_v2_bytes
from exfat_rescue.planner import plan_recovery
from exfat_rescue.recovery import recover_plans, resume_recovery
from exfat_rescue.scanner import scan
from exfat_rescue.source import ImageSource
from exfat_rescue.verification import _run_descriptor
from tests.fixture import image


class RecoveryBootstrapLockingTests(unittest.TestCase):
    def _prepared(self, root: Path):
        source_path = root / "source.img"
        source_path.write_bytes(image())
        source = ImageSource.open(source_path)
        scanned = scan(source)
        planned = plan_recovery(
            scanned.volume,
            scanned.candidates,
            active_owners=scanned.active_owners,
            metadata_complete=scanned.metadata_complete,
            ownership_complete=scanned.ownership_complete,
        )
        limits = {
            "max_output_bytes": 100_000,
            "max_candidates": 100_000,
            "max_scan_clusters": 50_000_000,
            "max_fat_steps": 10_000_000,
        }
        manifest_bytes = _internal_manifest_bytes(
            planned,
            {key: value for key, value in limits.items() if key != "max_output_bytes"},
            scanned.warnings,
        )
        return source, planned, limits, manifest_bytes

    @staticmethod
    def _recover(source, planned, limits, manifest_bytes, output: Path):
        return recover_plans(
            source,
            planned.plans,
            output,
            source_binding=planned.source_binding,
            manifest_bytes=manifest_bytes,
            selected_ids=[plan.candidate_id for plan in planned.plans],
            limits=limits,
        )

    def test_identical_retry_finishes_interrupted_manifest_or_run_stage(self) -> None:
        for staged_name in ("manifest.jsonl", "run.json"):
            with (
                self.subTest(staged_name=staged_name),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root, output = Path(temporary), Path(temporary) / "output"
                source, planned, limits, manifest_bytes = self._prepared(root)
                original = recovery._write_all

                def interrupt(
                    fd: int,
                    data: bytes,
                    label: str,
                    staged_name: str = staged_name,
                    original=original,
                ) -> None:
                    if label == f"recovery state '{staged_name}'":
                        original(fd, data[:1], label)
                        raise OutputError("injected bootstrap interruption")
                    original(fd, data, label)

                try:
                    with (
                        mock.patch.object(
                            recovery, "_write_all", side_effect=interrupt
                        ),
                        self.assertRaises(OutputError),
                    ):
                        self._recover(source, planned, limits, manifest_bytes, output)
                    bootstrap = root / recovery._bootstrap_name(output.name)
                    self.assertTrue(bootstrap.is_dir())
                    self.assertFalse(output.exists())
                    result = self._recover(
                        source, planned, limits, manifest_bytes, output
                    )
                finally:
                    source.close()
                self.assertTrue(result["complete"])
                self.assertTrue(output.is_dir())

    def test_mismatching_or_unknown_bootstrap_content_is_left_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, output = Path(temporary), Path(temporary) / "output"
            source, planned, limits, manifest_bytes = self._prepared(root)
            bootstrap = root / recovery._bootstrap_name(output.name)
            bootstrap.mkdir(mode=0o700)
            partial = bootstrap / ".manifest.jsonl.partial"
            partial.write_bytes(b"wrong")
            try:
                with self.assertRaises(OutputError):
                    self._recover(source, planned, limits, manifest_bytes, output)
            finally:
                source.close()
            self.assertEqual(partial.read_bytes(), b"wrong")
            self.assertFalse(output.exists())

    def test_unknown_bootstrap_content_is_left_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, output = Path(temporary), Path(temporary) / "output"
            source, planned, limits, manifest_bytes = self._prepared(root)
            bootstrap = root / recovery._bootstrap_name(output.name)
            bootstrap.mkdir(mode=0o700)
            unknown = bootstrap / "foreign"
            unknown.write_bytes(b"do not remove")
            try:
                with self.assertRaises(OutputError):
                    self._recover(source, planned, limits, manifest_bytes, output)
            finally:
                source.close()
            self.assertEqual(unknown.read_bytes(), b"do not remove")
            self.assertFalse(output.exists())

    def test_repeated_nonempty_bootstrap_rejection_does_not_leak_fds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records = root / "records"
            records.mkdir(mode=0o700)
            (records / "foreign").write_bytes(b"x")
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            fd_inventory = Path("/proc/self/fd")
            if not fd_inventory.exists():
                fd_inventory = Path("/dev/fd")
            before = len(os.listdir(fd_inventory))
            try:
                for _ in range(32):
                    with self.assertRaises(OutputError):
                        recovery._stage_bootstrap(
                            descriptor,
                            manifest_bytes=b"manifest\n",
                            run_bytes=b"run\n",
                        )
                after = len(os.listdir(fd_inventory))
            finally:
                os.close(descriptor)
            self.assertEqual(after, before)

    def test_target_race_leaves_bootstrap_and_refuses_ambiguity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, output = Path(temporary), Path(temporary) / "output"
            source, planned, limits, manifest_bytes = self._prepared(root)
            original = recovery._rename_noreplace

            def race(source_fd, source_name, destination_fd, destination_name):
                if destination_name == output.name:
                    os.mkdir(output, 0o700)
                original(source_fd, source_name, destination_fd, destination_name)

            try:
                with (
                    mock.patch.object(recovery, "_rename_noreplace", side_effect=race),
                    self.assertRaises(OutputError),
                ):
                    self._recover(source, planned, limits, manifest_bytes, output)
                with self.assertRaises(OutputError):
                    self._recover(source, planned, limits, manifest_bytes, output)
            finally:
                source.close()
            self.assertTrue((root / recovery._bootstrap_name(output.name)).is_dir())
            self.assertTrue(output.is_dir())

    def test_foreign_object_injected_during_bootstrap_publish_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, output = Path(temporary), Path(temporary) / "output"
            source, planned, limits, manifest_bytes = self._prepared(root)
            original = recovery._rename_noreplace

            def inject(source_fd, source_name, destination_fd, destination_name):
                if source_name.startswith(".exfat-rescue-bootstrap-"):
                    bootstrap_fd = os.open(
                        source_name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=source_fd,
                    )
                    try:
                        foreign_fd = os.open(
                            "foreign",
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o600,
                            dir_fd=bootstrap_fd,
                        )
                        os.close(foreign_fd)
                    finally:
                        os.close(bootstrap_fd)
                original(source_fd, source_name, destination_fd, destination_name)

            try:
                with (
                    mock.patch.object(
                        recovery, "_rename_noreplace", side_effect=inject
                    ),
                    self.assertRaises(OutputError),
                ):
                    self._recover(source, planned, limits, manifest_bytes, output)
            finally:
                source.close()
            self.assertTrue((output / "foreign").is_file())
            self.assertFalse((output / "report.jsonl").exists())

    def test_output_root_replacement_during_extraction_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, output = Path(temporary), Path(temporary) / "output"
            moved = root / "moved-output"
            source, planned, limits, manifest_bytes = self._prepared(root)
            original = recovery._write_new_at
            replaced = False

            def replace(fd: int, name: str, data: bytes) -> None:
                nonlocal replaced
                checkpoint_id = name.removesuffix(".json")
                if (
                    not replaced
                    and name.endswith(".json")
                    and recovery._ID.fullmatch(checkpoint_id)
                ):
                    replaced = True
                    output.rename(moved)
                    output.mkdir(mode=0o700)
                original(fd, name, data)

            try:
                with (
                    mock.patch.object(recovery, "_write_new_at", side_effect=replace),
                    self.assertRaises(OutputError),
                ):
                    self._recover(source, planned, limits, manifest_bytes, output)
            finally:
                source.close()
            self.assertTrue(output.is_dir())
            self.assertFalse((output / "report.jsonl").exists())
            self.assertTrue(moved.is_dir())

    def test_late_root_or_candidate_inventory_injection_is_refused(self) -> None:
        for location in ("root", "candidate"):
            with (
                self.subTest(location=location),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root, output = Path(temporary), Path(temporary) / "output"
                source, planned, limits, manifest_bytes = self._prepared(root)
                plan = next(
                    item for item in planned.plans if item.disposition == "recoverable"
                )
                original_hash = source.selected_volume_sha256
                injection_state = [False]
                expected_parent = (
                    output
                    if location == "root"
                    else output / "files" / plan.candidate_id
                )

                def inject(
                    _source: ImageSource,
                    offset: int,
                    length: int,
                    *,
                    target: Path = expected_parent,
                    published: Path = output,
                    hash_volume=original_hash,
                    state=injection_state,
                ) -> str:
                    digest = hash_volume(offset, length)
                    if published.exists() and not state[0]:
                        state[0] = True
                        (target / "foreign").write_bytes(b"x")
                    return digest

                try:
                    with (
                        mock.patch.object(
                            ImageSource,
                            "selected_volume_sha256",
                            autospec=True,
                            side_effect=inject,
                        ),
                        self.assertRaises(OutputError),
                    ):
                        self._recover(source, planned, limits, manifest_bytes, output)
                finally:
                    source.close()
                self.assertTrue((expected_parent / "foreign").is_file())
                self.assertFalse((output / "report.jsonl").exists())

    def test_resume_post_report_inventory_injection_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, output = Path(temporary), Path(temporary) / "output"
            source, planned, limits, manifest_bytes = self._prepared(root)
            checkpoint = f"{planned.plans[0].candidate_id}.json"
            original_write = recovery._write_new_at

            def interrupt(fd: int, name: str, data: bytes) -> None:
                if name == checkpoint:
                    raise OutputError("injected checkpoint interruption")
                original_write(fd, name, data)

            try:
                with (
                    mock.patch.object(recovery, "_write_new_at", side_effect=interrupt),
                    self.assertRaises(OutputError),
                ):
                    self._recover(source, planned, limits, manifest_bytes, output)

                def inject_before_report(fd: int, name: str, data: bytes) -> None:
                    if name == "report.jsonl":
                        (output / "foreign").write_bytes(b"x")
                    original_write(fd, name, data)

                with (
                    mock.patch.object(
                        recovery, "_write_new_at", side_effect=inject_before_report
                    ),
                    self.assertRaises(OutputError),
                ):
                    resume_recovery(
                        source,
                        output,
                        planner_result=planned,
                        manifest=parse_manifest_v2_bytes(manifest_bytes),
                    )
            finally:
                source.close()
            self.assertTrue((output / "foreign").is_file())

    def test_writer_lock_contention_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with (
                    mock.patch.object(
                        recovery.fcntl,
                        "flock",
                        side_effect=OSError(errno.EAGAIN, "busy"),
                    ),
                    self.assertRaises(OutputError),
                ):
                    recovery._lock_directory(descriptor, "Recovery output")
            finally:
                os.close(descriptor)

    def test_maximum_candidate_run_uses_dedicated_bounded_read_limit(self) -> None:
        identifiers = [
            f"{index:064x}" for index in range(recovery.HARD_MAX_RECOVERY_CANDIDATES)
        ]
        run = {
            "format": "exfat-rescue.run",
            "version": recovery.RUN_VERSION,
            "source": {},
            "source_file_state": {
                "device": 1,
                "inode": 2,
                "mode": 0o100600,
                "link_count": 1,
                "owner": 3,
                "size_bytes": 4,
                "modified_ns": 5,
                "changed_ns": 6,
            },
            "limits": {
                **recovery.DEFAULT_RUN_LIMITS,
                "max_candidates": recovery.HARD_MAX_RECOVERY_CANDIDATES,
            },
            "candidate_ids": identifiers,
            "manifest_sha256": "f" * 64,
        }
        encoded = recovery._canonical(run) + b"\n"
        self.assertGreater(len(encoded), recovery.MAX_STATE_BYTES)
        self.assertLessEqual(len(encoded), recovery.MAX_RUN_BYTES)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "run.json"
            state.write_bytes(encoded)
            state.chmod(0o600)
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                parsed = recovery._read_regular_at(
                    directory_fd, "run.json", max_bytes=recovery.MAX_RUN_BYTES
                )
            finally:
                os.close(directory_fd)
        self.assertEqual(_run_descriptor(parsed), run)

    def test_state_publication_rejects_in_place_write_during_rename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            original = recovery._rename_noreplace

            def mutate(source_fd, source_name, destination_fd, destination_name):
                staged_fd = os.open(
                    source_name, os.O_WRONLY | os.O_NOFOLLOW, dir_fd=source_fd
                )
                try:
                    os.pwrite(staged_fd, b"X", 0)
                finally:
                    os.close(staged_fd)
                original(source_fd, source_name, destination_fd, destination_name)

            try:
                with (
                    mock.patch.object(
                        recovery, "_rename_noreplace", side_effect=mutate
                    ),
                    self.assertRaises(OutputError),
                ):
                    recovery._write_new_at(descriptor, "state.json", b"expected")
            finally:
                os.close(descriptor)

    def test_state_publication_rejects_final_name_replacement_during_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            original = recovery._assert_published_file

            def replace(directory_fd, name, opened_fd, staged, label):
                original(directory_fd, name, opened_fd, staged, label)
                os.rename(
                    name,
                    "opened-original",
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                )
                replacement = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=directory_fd,
                )
                try:
                    os.write(replacement, b"attacker")
                finally:
                    os.close(replacement)

            try:
                with (
                    mock.patch.object(
                        recovery, "_assert_published_file", side_effect=replace
                    ),
                    self.assertRaises(OutputError),
                ):
                    recovery._write_new_at(descriptor, "state.json", b"expected")
            finally:
                os.close(descriptor)
            self.assertEqual((directory / "state.json").read_bytes(), b"attacker")
            self.assertEqual((directory / "opened-original").read_bytes(), b"expected")

    def test_data_publication_rehash_rejects_in_place_write_during_rename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, output = Path(temporary), Path(temporary) / "output"
            source, planned, limits, manifest_bytes = self._prepared(root)
            original = recovery._rename_noreplace

            def mutate(source_fd, source_name, destination_fd, destination_name):
                if destination_name == "data":
                    staged_fd = os.open(
                        source_name, os.O_WRONLY | os.O_NOFOLLOW, dir_fd=source_fd
                    )
                    try:
                        os.pwrite(staged_fd, b"X", 0)
                    finally:
                        os.close(staged_fd)
                original(source_fd, source_name, destination_fd, destination_name)

            try:
                with (
                    mock.patch.object(
                        recovery, "_rename_noreplace", side_effect=mutate
                    ),
                    self.assertRaises(OutputError),
                ):
                    self._recover(source, planned, limits, manifest_bytes, output)
            finally:
                source.close()
