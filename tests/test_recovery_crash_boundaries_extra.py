"""Crash-window and bounded-resume adversarial recovery tests."""

from __future__ import annotations

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
from tests.fixture import image


class RecoveryCrashBoundaryTests(unittest.TestCase):
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
    def _first_recoverable(planned):
        return next(plan for plan in planned.plans if plan.disposition == "recoverable")

    def _recover(self, source, planned, limits, manifest_bytes, output: Path) -> None:
        recover_plans(
            source,
            planned.plans,
            output,
            source_binding=planned.source_binding,
            manifest_bytes=manifest_bytes,
            selected_ids=[plan.candidate_id for plan in planned.plans],
            limits=limits,
        )

    def test_partial_checkpoint_is_not_published_and_resume_completes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, output = Path(temporary), Path(temporary) / "output"
            source, planned, limits, manifest_bytes = self._prepared(root)
            plan = self._first_recoverable(planned)
            checkpoint = f"{plan.candidate_id}.json"
            original = recovery._write_all

            def interrupt(fd: int, data: bytes, label: str) -> None:
                if label == f"recovery state '{checkpoint}'":
                    original(fd, data[:1], label)
                    raise OutputError("injected checkpoint write failure")
                original(fd, data, label)

            try:
                with (
                    mock.patch.object(recovery, "_write_all", side_effect=interrupt),
                    self.assertRaises(OutputError),
                ):
                    self._recover(source, planned, limits, manifest_bytes, output)
                self.assertFalse((output / "records" / checkpoint).exists())
                resumed = resume_recovery(
                    source,
                    output,
                    planner_result=planned,
                    manifest=parse_manifest_v2_bytes(manifest_bytes),
                )
            finally:
                source.close()
            self.assertTrue(resumed["complete"])

    def test_failed_atomic_publication_resumes_safely(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, output = Path(temporary), Path(temporary) / "output"
            source, planned, limits, manifest_bytes = self._prepared(root)
            plan = self._first_recoverable(planned)
            temporary_name = f"{plan.candidate_id}.partial"
            original_publish = recovery._rename_noreplace

            def interrupt(
                source_fd: int,
                source_name: str,
                destination_fd: int,
                destination_name: str,
            ) -> None:
                if source_name == temporary_name and destination_name == "data":
                    raise OutputError("injected publication failure")
                original_publish(
                    source_fd, source_name, destination_fd, destination_name
                )

            try:
                with (
                    mock.patch.object(
                        recovery, "_rename_noreplace", side_effect=interrupt
                    ),
                    self.assertRaises(OutputError),
                ):
                    self._recover(source, planned, limits, manifest_bytes, output)
                work = output / "work" / temporary_name
                self.assertTrue(work.is_file())
                self.assertEqual(os.stat(work).st_nlink, 1)
                resumed = resume_recovery(
                    source,
                    output,
                    planner_result=planned,
                    manifest=parse_manifest_v2_bytes(manifest_bytes),
                )
            finally:
                source.close()
            self.assertTrue(resumed["complete"])
            self.assertFalse(work.exists())
            self.assertTrue((output / "files" / plan.candidate_id / "data").is_file())

    def test_replaced_work_temporary_is_left_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, output = Path(temporary), Path(temporary) / "output"
            source, planned, limits, manifest_bytes = self._prepared(root)
            plan = self._first_recoverable(planned)
            temporary_path = output / "work" / f"{plan.candidate_id}.partial"
            original_publish = recovery._rename_noreplace

            def interrupt(
                source_fd: int,
                source_name: str,
                destination_fd: int,
                destination_name: str,
            ) -> None:
                if source_name == temporary_path.name and destination_name == "data":
                    raise OutputError("injected publication failure")
                original_publish(
                    source_fd, source_name, destination_fd, destination_name
                )

            try:
                with (
                    mock.patch.object(
                        recovery, "_rename_noreplace", side_effect=interrupt
                    ),
                    self.assertRaises(OutputError),
                ):
                    self._recover(source, planned, limits, manifest_bytes, output)
                temporary_path.unlink()
                temporary_path.write_bytes(b"foreign replacement")
                temporary_path.chmod(0o600)
                with self.assertRaises(OutputError):
                    resume_recovery(
                        source,
                        output,
                        planner_result=planned,
                        manifest=parse_manifest_v2_bytes(manifest_bytes),
                    )
                self.assertTrue(temporary_path.exists())
            finally:
                source.close()

    def test_sparse_oversized_data_is_rejected_before_data_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, output = Path(temporary), Path(temporary) / "output"
            source, planned, limits, manifest_bytes = self._prepared(root)
            plan = self._first_recoverable(planned)
            checkpoint = f"{plan.candidate_id}.json"
            original_write = recovery._write_new_at

            def interrupt(fd: int, name: str, data: bytes) -> None:
                if name == checkpoint:
                    raise OutputError("injected checkpoint failure")
                original_write(fd, name, data)

            try:
                with (
                    mock.patch.object(recovery, "_write_new_at", side_effect=interrupt),
                    self.assertRaises(OutputError),
                ):
                    self._recover(source, planned, limits, manifest_bytes, output)
                data_path = output / "files" / plan.candidate_id / "data"
                with data_path.open("r+b") as data:
                    data.truncate(limits["max_output_bytes"] + 1)
                original_open, original_read = recovery.os.open, recovery.os.read
                data_fds: set[int] = set()

                def track_open(name: str, *args, **kwargs) -> int:
                    fd = original_open(name, *args, **kwargs)
                    if name == "data":
                        data_fds.add(fd)
                    return fd

                def prohibit_data_read(fd: int, count: int) -> bytes:
                    if fd in data_fds:
                        raise AssertionError("oversized recovered data was read")
                    return original_read(fd, count)

                with (
                    mock.patch.object(recovery.os, "open", side_effect=track_open),
                    mock.patch.object(
                        recovery.os, "read", side_effect=prohibit_data_read
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

    def test_resume_hash_rejects_named_data_replacement_during_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = root / "data"
            moved = root / "opened-original"
            data.write_bytes(b"expected")
            data.chmod(0o600)
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            original_read = recovery.os.read
            replaced = False

            def replace_after_open(fd: int, count: int) -> bytes:
                nonlocal replaced
                if not replaced:
                    replaced = True
                    data.rename(moved)
                    data.write_bytes(b"attacker")
                    data.chmod(0o600)
                return original_read(fd, count)

            try:
                with (
                    mock.patch.object(
                        recovery.os, "read", side_effect=replace_after_open
                    ),
                    self.assertRaises(OutputError),
                ):
                    recovery._hash_file_at(
                        directory_fd, "data", expected_size=len(b"expected")
                    )
            finally:
                os.close(directory_fd)
            self.assertEqual(data.read_bytes(), b"attacker")
            self.assertEqual(moved.read_bytes(), b"expected")

    def test_resume_rejects_more_than_expected_work_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, output = Path(temporary), Path(temporary) / "output"
            source, planned, limits, manifest_bytes = self._prepared(root)
            plan = self._first_recoverable(planned)
            checkpoint = f"{plan.candidate_id}.json"
            original = recovery._write_new_at

            def interrupt(fd: int, name: str, data: bytes) -> None:
                if name == checkpoint:
                    raise OutputError("injected checkpoint failure")
                original(fd, name, data)

            try:
                with (
                    mock.patch.object(recovery, "_write_new_at", side_effect=interrupt),
                    self.assertRaises(OutputError),
                ):
                    self._recover(source, planned, limits, manifest_bytes, output)
                work = output / "work"
                (work / "unexpected-one").write_bytes(b"x")
                (work / "unexpected-two").write_bytes(b"x")
                with self.assertRaises(OutputError):
                    resume_recovery(
                        source,
                        output,
                        planner_result=planned,
                        manifest=parse_manifest_v2_bytes(manifest_bytes),
                    )
            finally:
                source.close()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
