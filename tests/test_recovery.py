from __future__ import annotations

import errno
import hashlib
import json
import os
import struct
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from exfat_rescue import recovery
from exfat_rescue.cli import _internal_manifest_bytes
from exfat_rescue.errors import (
    ManifestError,
    OutputError,
    ResourceLimitError,
    SourceError,
    UsageError,
    VerificationError,
)
from exfat_rescue.exfat.volume import ExfatVolume
from exfat_rescue.manifest import parse_manifest_v2_bytes
from exfat_rescue.planner import Extent, PlannerResult, RecoveryPlan, plan_recovery
from exfat_rescue.recovery import recover_plans, resume_recovery
from exfat_rescue.scanner import scan
from exfat_rescue.source import ImageSource
from exfat_rescue.verification import verify_recovery
from tests.fixture import image


class RecoveryTests(unittest.TestCase):
    def test_requested_parent_proof_rejects_non_directory_and_wrong_identity(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second"
            first.mkdir(mode=0o700)
            second.mkdir(mode=0o700)
            plain = root / "plain"
            plain.write_bytes(b"not a directory")
            first_fd = os.open(first, os.O_RDONLY | os.O_DIRECTORY)
            try:
                proof = recovery._requested_parent_proof(first, first_fd)
                recovery._assert_requested_parent(proof, first_fd)
                with self.assertRaisesRegex(OutputError, "not a directory"):
                    recovery._requested_parent_proof(plain, first_fd)
                with self.assertRaisesRegex(OutputError, "changed while opening"):
                    recovery._requested_parent_proof(second, first_fd)

                moved = root / "moved"
                first.rename(moved)
                with self.assertRaisesRegex(OutputError, "revalidate requested"):
                    recovery._assert_requested_parent(proof, first_fd)
                first.mkdir(mode=0o700)
                with self.assertRaisesRegex(OutputError, "changed before success"):
                    recovery._assert_requested_parent(proof, first_fd)
            finally:
                os.close(first_fd)

    def test_content_proof_rejects_data_appended_after_expected_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = root / "data"
            data.write_bytes(b"expected")
            data.chmod(0o600)
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            original_read = os.read
            requests: list[int] = []
            appended = False

            def append_after_expected(fd: int, count: int) -> bytes:
                nonlocal appended
                requests.append(count)
                result = original_read(fd, count)
                if result and not appended:
                    appended = True
                    with data.open("ab") as handle:
                        handle.write(b"x")
                return result

            try:
                with (
                    mock.patch("exfat_rescue.recovery.os.read", append_after_expected),
                    self.assertRaises(OutputError),
                ):
                    recovery._hash_file_at(
                        directory_fd, "data", expected_size=len(b"expected")
                    )
            finally:
                os.close(directory_fd)
            self.assertEqual(requests, [len(b"expected"), 1])

    def _planned(self, root: Path, *, populate_data: bool = True):
        source_path = root / "source.img"
        raw = bytearray(image())
        # The fixture's two recoverable files occupy clusters 3 and 4.  Fill
        # their ValidDataLength prefixes with distinguishable source bytes.
        if populate_data:
            heap = struct.unpack_from("<I", raw, 0x58)[0] * 512
            raw[heap + 512 : heap + 522] = b"active-dat"
            raw[heap + 1024 : heap + 1034] = b"deleted-da"
        source_path.write_bytes(raw)
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
            {key: limits[key] for key in limits if key != "max_output_bytes"},
            scanned.warnings,
        )
        return source_path, source, planned, limits, manifest_bytes

    def test_recovery_uses_candidate_id_path_and_zero_fills(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source_path = Path(temporary) / "source.img"
            output = Path(temporary) / "output"
            source_path.write_bytes(image())
            source = ImageSource.open(source_path)
            try:
                volume = ExfatVolume(source)
                binding = {
                    "image_size_bytes": source.size,
                    "volume_offset_bytes": volume.base_offset,
                    "volume_length_bytes": volume.boot.volume_bytes,
                    "volume_sha256": source.selected_volume_sha256(
                        volume.base_offset, volume.boot.volume_bytes
                    ),
                    "cluster_size_bytes": volume.boot.cluster_size,
                    "cluster_heap_offset_bytes": volume.base_offset
                    + volume.boot.heap_offset * volume.boot.bytes_per_sector,
                    "source_kind": volume.location.source_kind,
                    "boot_region": volume.boot_region,
                    "volume_dirty": volume.boot.volume_dirty,
                    "media_failure": volume.boot.media_failure,
                }
                binding_bytes = json.dumps(
                    {
                        key: binding[key]
                        for key in (
                            "volume_offset_bytes",
                            "volume_length_bytes",
                            "volume_sha256",
                        )
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                candidate_id = hashlib.sha256(
                    binding_bytes + b":1:" + b"b" * 64
                ).hexdigest()
                plan = RecoveryPlan(
                    candidate_id,
                    1,
                    "b" * 64,
                    "never-a-path",
                    8,
                    3,
                    (Extent(5, 1),),
                    "contiguous",
                    "active_directory",
                    "recoverable",
                    "active_contiguous_allocated",
                    (),
                )
                raw = {
                    "entry_offset": 1,
                    "name": "never-a-path",
                    "size_bytes": 8,
                    "valid_size_bytes": 3,
                    "first_cluster": 5,
                    "no_fat_chain": True,
                    "deleted": False,
                    "location": "directory",
                    "entry_set_sha256": "b" * 64,
                    "is_directory": False,
                    "attributes": 0,
                    "entry_checksum": "0000",
                }
                manifest_bytes = _internal_manifest_bytes(
                    PlannerResult((plan,), binding, 0, (raw,)), {}, ()
                )
                recover_plans(
                    source,
                    [plan],
                    output,
                    source_binding=binding,
                    manifest_bytes=manifest_bytes,
                    selected_ids=[candidate_id],
                    limits={"max_output_bytes": 8},
                )
            finally:
                source.close()
            data = (output / "files" / candidate_id / "data").read_bytes()
            self.assertEqual(len(data), 8)
            self.assertEqual(data[3:], b"\0" * 5)

    def test_end_to_end_recovery_verify_and_manifest_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path, source, planned, limits, manifest_bytes = self._planned(root)
            try:
                ids = [plan.candidate_id for plan in planned.plans]
                result = recover_plans(
                    source,
                    planned.plans,
                    root / "output",
                    source_binding=planned.source_binding,
                    manifest_bytes=manifest_bytes,
                    selected_ids=ids,
                    limits=limits,
                )
            finally:
                source.close()
            self.assertTrue(result["complete"])
            active = next(plan for plan in planned.plans if plan.name == "Active.txt")
            deleted = next(plan for plan in planned.plans if plan.name == "Deleted.txt")
            self.assertEqual(
                (root / "output" / "files" / active.candidate_id / "data").read_bytes(),
                b"active-dat",
            )
            self.assertEqual(
                (
                    root / "output" / "files" / deleted.candidate_id / "data"
                ).read_bytes(),
                b"deleted-da",
            )
            verified = verify_recovery(root / "output", source_path)
            self.assertTrue(verified["ok"])
            self.assertTrue(verified["image_verified"])

    def test_selection_rejects_unknown_or_duplicate_before_creating_output(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            candidate_id = planned.plans[0].candidate_id
            try:
                for selected in (["f" * 64], [candidate_id, candidate_id]):
                    output = root / ("out-" + str(len(selected)))
                    with self.assertRaises(UsageError):
                        recover_plans(
                            source,
                            planned.plans,
                            output,
                            source_binding=planned.source_binding,
                            manifest_bytes=manifest_bytes,
                            selected_ids=selected,
                            limits=limits,
                        )
                    self.assertFalse(output.exists())
            finally:
                source.close()

    def test_manifest_and_candidate_limit_are_enforced_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            selected = [plan.candidate_id for plan in planned.plans]
            try:
                with self.assertRaises(ManifestError):
                    recover_plans(
                        source,
                        planned.plans,
                        root / "invalid-manifest",
                        source_binding=planned.source_binding,
                        manifest_bytes=b"not a v2 manifest\n",
                        selected_ids=selected,
                        limits=limits,
                    )
                limited = {**limits, "max_candidates": len(planned.plans) - 1}
                with self.assertRaises(ResourceLimitError):
                    recover_plans(
                        source,
                        planned.plans,
                        root / "over-limit",
                        source_binding=planned.source_binding,
                        manifest_bytes=manifest_bytes,
                        selected_ids=selected,
                        limits=limited,
                    )
                with self.assertRaises(ResourceLimitError):
                    recover_plans(
                        source,
                        planned.plans,
                        root / "raised-selected-limit",
                        source_binding=planned.source_binding,
                        manifest_bytes=manifest_bytes,
                        selected_ids=selected,
                        limits={
                            **limits,
                            "max_candidates": recovery.HARD_MAX_RECOVERY_CANDIDATES + 1,
                        },
                    )
            finally:
                source.close()
            self.assertFalse((root / "invalid-manifest").exists())
            self.assertFalse((root / "over-limit").exists())
            self.assertFalse((root / "raised-selected-limit").exists())

    def test_resume_rejects_selection_above_immutable_candidate_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            output = root / "output"
            selected = [plan.candidate_id for plan in planned.plans]
            self.assertGreater(len(selected), 1)
            try:
                recover_plans(
                    source,
                    planned.plans,
                    output,
                    source_binding=planned.source_binding,
                    manifest_bytes=manifest_bytes,
                    selected_ids=selected,
                    limits=limits,
                )
                run_path = output / "run.json"
                run = json.loads(run_path.read_bytes())
                run["limits"]["max_candidates"] = 1
                run_path.write_bytes(recovery._canonical(run) + b"\n")
                (output / "report.jsonl").unlink()

                with self.assertRaises(ManifestError):
                    resume_recovery(
                        source,
                        output,
                        planner_result=planned,
                        manifest=parse_manifest_v2_bytes(manifest_bytes),
                    )
            finally:
                source.close()
            self.assertFalse((output / "report.jsonl").exists())

    def test_completed_resume_refuses_source_changed_during_output_verification(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path, source, planned, limits, manifest_bytes = self._planned(root)
            output = root / "output"
            try:
                recover_plans(
                    source,
                    planned.plans,
                    output,
                    source_binding=planned.source_binding,
                    manifest_bytes=manifest_bytes,
                    selected_ids=[plan.candidate_id for plan in planned.plans],
                    limits=limits,
                )

                def mutate_source_during_verification(*args, **kwargs):
                    with source_path.open("r+b") as handle:
                        handle.seek(0)
                        handle.write(b"x")
                    return {"ok": True}

                with (
                    mock.patch(
                        "exfat_rescue.verification.verify_recovery",
                        side_effect=mutate_source_during_verification,
                    ),
                    self.assertRaises(SourceError),
                ):
                    resume_recovery(
                        source,
                        output,
                        planner_result=planned,
                        manifest=parse_manifest_v2_bytes(manifest_bytes),
                    )
            finally:
                source.close()

    def test_recover_rejects_unhashable_candidate_id_as_usage_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            try:
                with self.assertRaises(UsageError):
                    recover_plans(
                        source,
                        planned.plans,
                        root / "output",
                        source_binding=planned.source_binding,
                        manifest_bytes=manifest_bytes,
                        selected_ids=[{}],
                        limits=limits,
                    )
            finally:
                source.close()
            self.assertFalse((root / "output").exists())

    def test_resume_closes_partially_opened_child_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            output = root / "output"
            try:
                recover_plans(
                    source,
                    planned.plans,
                    output,
                    source_binding=planned.source_binding,
                    manifest_bytes=manifest_bytes,
                    selected_ids=[plan.candidate_id for plan in planned.plans],
                    limits=limits,
                )
                (output / "report.jsonl").unlink()
                original = recovery._open_dir_at
                opened: list[int] = []

                def fail_after_first_child(fd: int, name: str) -> int:
                    if name == "records":
                        result = original(fd, name)
                        opened.append(result)
                        return result
                    raise OutputError("injected child inventory failure")

                with (
                    mock.patch.object(
                        recovery,
                        "_open_dir_at",
                        side_effect=fail_after_first_child,
                    ),
                    self.assertRaisesRegex(
                        OutputError, "injected child inventory failure"
                    ),
                ):
                    resume_recovery(
                        source,
                        output,
                        planner_result=planned,
                        manifest=parse_manifest_v2_bytes(manifest_bytes),
                    )
            finally:
                source.close()
            self.assertEqual(len(opened), 1)
            with self.assertRaises(OSError):
                os.fstat(opened[0])

    def test_resume_rejects_boolean_integer_in_existing_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            output = root / "output"
            try:
                recover_plans(
                    source,
                    planned.plans,
                    output,
                    source_binding=planned.source_binding,
                    manifest_bytes=manifest_bytes,
                    selected_ids=[plan.candidate_id for plan in planned.plans],
                    limits=limits,
                )
                (output / "report.jsonl").unlink()
                checkpoint = next(
                    path
                    for path in (output / "records").iterdir()
                    if json.loads(path.read_bytes()).get("disposition") == "recovered"
                )
                record = json.loads(checkpoint.read_bytes())
                self.assertEqual(record["source_extents"][0]["cluster_count"], 1)
                record["source_extents"][0]["cluster_count"] = True
                checkpoint.write_bytes(recovery._canonical(record) + b"\n")

                with self.assertRaisesRegex(
                    OutputError, "does not match the current exact plan"
                ):
                    resume_recovery(
                        source,
                        output,
                        planner_result=planned,
                        manifest=parse_manifest_v2_bytes(manifest_bytes),
                    )
            finally:
                source.close()
            self.assertFalse((output / "report.jsonl").exists())

    def test_report_size_is_preflighted_at_exact_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            selected = [plan.candidate_id for plan in planned.plans]
            normalized = [recovery._validate_plan(plan) for plan in planned.plans]
            projected = recovery._projected_report_size(normalized)
            try:
                with mock.patch.object(recovery, "MAX_REPORT_BYTES", projected):
                    result = recover_plans(
                        source,
                        planned.plans,
                        root / "at-boundary",
                        source_binding=planned.source_binding,
                        manifest_bytes=manifest_bytes,
                        selected_ids=selected,
                        limits=limits,
                    )
                self.assertTrue(result["complete"])
                self.assertEqual(
                    (root / "at-boundary" / "report.jsonl").stat().st_size,
                    projected,
                )
                with (
                    mock.patch.object(recovery, "MAX_REPORT_BYTES", projected - 1),
                    self.assertRaises(ResourceLimitError),
                ):
                    recover_plans(
                        source,
                        planned.plans,
                        root / "over-report-boundary",
                        source_binding=planned.source_binding,
                        manifest_bytes=manifest_bytes,
                        selected_ids=selected,
                        limits=limits,
                    )
                self.assertFalse((root / "over-report-boundary").exists())
            finally:
                source.close()

    def test_resume_binds_passed_manifest_to_internal_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            manifest = parse_manifest_v2_bytes(manifest_bytes)
            try:
                recover_plans(
                    source,
                    planned.plans,
                    root / "output",
                    source_binding=planned.source_binding,
                    manifest_bytes=manifest_bytes,
                    selected_ids=[plan.candidate_id for plan in planned.plans],
                    limits=limits,
                )
                (root / "output" / "report.jsonl").unlink()
                with self.assertRaises(ManifestError):
                    resume_recovery(
                        source,
                        root / "output",
                        planner_result=planned,
                        manifest=replace(manifest, raw_bytes=b"different"),
                    )
            finally:
                source.close()

    def test_resume_accepts_existing_terminal_refusal_checkpoints(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(
                root, populate_data=False
            )
            manifest = parse_manifest_v2_bytes(manifest_bytes)
            self.assertTrue(
                any(plan.disposition != "recoverable" for plan in planned.plans)
            )
            try:
                recover_plans(
                    source,
                    planned.plans,
                    root / "output",
                    source_binding=planned.source_binding,
                    manifest_bytes=manifest_bytes,
                    selected_ids=[plan.candidate_id for plan in planned.plans],
                    limits=limits,
                )
                (root / "output" / "report.jsonl").unlink()
                result = resume_recovery(
                    source, root / "output", planner_result=planned, manifest=manifest
                )
            finally:
                source.close()
            self.assertTrue(result["complete"])
            self.assertTrue(result["resumed"])

    def test_raised_non_candidate_run_limits_remain_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            manifest = parse_manifest_v2_bytes(manifest_bytes)
            limits = {
                **limits,
                "max_output_bytes": limits["max_output_bytes"] + 1,
                "max_scan_clusters": limits["max_scan_clusters"] + 1,
                "max_fat_steps": limits["max_fat_steps"] + 1,
            }
            output = root / "output"
            try:
                recover_plans(
                    source,
                    planned.plans,
                    output,
                    source_binding=planned.source_binding,
                    manifest_bytes=manifest_bytes,
                    selected_ids=[plan.candidate_id for plan in planned.plans],
                    limits=limits,
                )
                self.assertTrue(verify_recovery(output)["ok"])
                (output / "report.jsonl").unlink()
                result = resume_recovery(
                    source, output, planner_result=planned, manifest=manifest
                )
            finally:
                source.close()
            self.assertTrue(result["complete"])

    def test_existing_output_and_symlink_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            try:
                for name in ("exists", "link"):
                    output = root / name
                    if name == "exists":
                        output.mkdir()
                    else:
                        output.symlink_to(root, target_is_directory=True)
                    with self.assertRaises(OutputError):
                        recover_plans(
                            source,
                            planned.plans,
                            output,
                            source_binding=planned.source_binding,
                            manifest_bytes=manifest_bytes,
                            selected_ids=[plan.candidate_id for plan in planned.plans],
                            limits=limits,
                        )
            finally:
                source.close()

    def test_current_or_root_output_target_is_refused_without_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            previous_directory = Path.cwd()
            try:
                os.chdir(root)
                for output in (".", "", Path("/")):
                    with self.subTest(output=output):
                        before = set(root.iterdir())
                        with (
                            mock.patch.object(
                                recovery, "_prepare_new_run_root"
                            ) as prepare,
                            self.assertRaisesRegex(
                                OutputError,
                                "^Recovery output must name a new directory, not the "
                                "current directory or filesystem root\\.$",
                            ),
                        ):
                            recover_plans(
                                source,
                                planned.plans,
                                output,
                                source_binding=planned.source_binding,
                                manifest_bytes=manifest_bytes,
                                selected_ids=[
                                    plan.candidate_id for plan in planned.plans
                                ],
                                limits=limits,
                            )
                        prepare.assert_not_called()
                        self.assertEqual(set(root.iterdir()), before)
            finally:
                os.chdir(previous_directory)
                source.close()

    def test_resume_adopts_only_exact_published_data_and_cleans_own_temp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            manifest = parse_manifest_v2_bytes(manifest_bytes)
            first_record = f"{planned.plans[0].candidate_id}.json"
            original = recovery._write_new_at

            def interrupt(fd: int, name: str, data: bytes) -> None:
                if name == first_record:
                    raise OutputError("injected checkpoint failure")
                original(fd, name, data)

            try:
                with (
                    mock.patch.object(recovery, "_write_new_at", side_effect=interrupt),
                    self.assertRaises(OutputError),
                ):
                    recover_plans(
                        source,
                        planned.plans,
                        root / "output",
                        source_binding=planned.source_binding,
                        manifest_bytes=manifest_bytes,
                        selected_ids=[plan.candidate_id for plan in planned.plans],
                        limits=limits,
                    )
                # Publication occurred before the deliberately failed checkpoint.
                published = (
                    root / "output" / "files" / planned.plans[0].candidate_id / "data"
                )
                self.assertTrue(published.is_file())
                result = resume_recovery(
                    source, root / "output", planner_result=planned, manifest=manifest
                )
            finally:
                source.close()
            self.assertTrue(result["complete"])
            self.assertTrue(result["resumed"])
            self.assertTrue(verify_recovery(root / "output")["ok"])

    def test_completion_refuses_data_mutated_after_checkpoint_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            output = root / "output"
            recoverable = next(
                plan for plan in planned.plans if plan.disposition == "recoverable"
            )
            checkpoint = f"{recoverable.candidate_id}.json"
            data = output / "files" / recoverable.candidate_id / "data"
            original_write = recovery._write_new_at
            mutated = False

            def mutate_after_checkpoint(fd: int, name: str, content: bytes) -> None:
                nonlocal mutated
                original_write(fd, name, content)
                if name == checkpoint and not mutated:
                    mutated = True
                    with data.open("r+b") as handle:
                        handle.write(b"x")

            try:
                with (
                    mock.patch.object(
                        recovery, "_write_new_at", side_effect=mutate_after_checkpoint
                    ),
                    self.assertRaises(OutputError),
                ):
                    recover_plans(
                        source,
                        planned.plans,
                        output,
                        source_binding=planned.source_binding,
                        manifest_bytes=manifest_bytes,
                        selected_ids=[plan.candidate_id for plan in planned.plans],
                        limits=limits,
                    )
            finally:
                source.close()
            self.assertTrue(mutated)
            self.assertFalse((output / "report.jsonl").exists())

    def test_completion_reuses_one_content_pass_and_detects_late_data_change(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            output = root / "output"
            recoverable_count = sum(
                plan.disposition == "recoverable" for plan in planned.plans
            )
            original_hash = recovery._hash_file_at
            original_fsync = recovery._fsync
            original_cache_release = recovery._release_file_cache
            hash_calls = 0
            cache_releases = 0
            checkpoint_directory_flushes = 0

            def counted_hash(*args, **kwargs):
                nonlocal hash_calls
                hash_calls += 1
                return original_hash(*args, **kwargs)

            def counted_fsync(fd, label):
                nonlocal checkpoint_directory_flushes
                if "checkpoint batch" in label:
                    checkpoint_directory_flushes += 1
                return original_fsync(fd, label)

            def counted_cache_release(*args, **kwargs):
                nonlocal cache_releases
                cache_releases += 1
                return original_cache_release(*args, **kwargs)

            try:
                with (
                    mock.patch.object(
                        recovery, "_hash_file_at", side_effect=counted_hash
                    ),
                    mock.patch.object(recovery, "_fsync", side_effect=counted_fsync),
                    mock.patch.object(
                        recovery,
                        "_release_file_cache",
                        side_effect=counted_cache_release,
                    ),
                ):
                    recover_plans(
                        source,
                        planned.plans,
                        output,
                        source_binding=planned.source_binding,
                        manifest_bytes=manifest_bytes,
                        selected_ids=[plan.candidate_id for plan in planned.plans],
                        limits=limits,
                    )
            finally:
                source.close()
            # The publication proof is retained for the completion boundary.  Its
            # later checks use exact inode/stat proof, not another content read.
            self.assertEqual(hash_calls, recoverable_count)
            self.assertEqual(cache_releases, hash_calls)
            self.assertEqual(checkpoint_directory_flushes, 1)

    def test_completion_proof_final_pass_is_state_only_and_catches_late_directory_change(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path, source, planned, limits, manifest_bytes = self._planned(root)
            output = root / "output"
            try:
                recover_plans(
                    source,
                    planned.plans,
                    output,
                    source_binding=planned.source_binding,
                    manifest_bytes=manifest_bytes,
                    selected_ids=[plan.candidate_id for plan in planned.plans],
                    limits=limits,
                )
            finally:
                source.close()
            root_fd, parent_fd, root_name = recovery._open_dir_with_parent(output)
            records_fd = recovery._open_dir_at(root_fd, "records")
            files_fd = recovery._open_dir_at(root_fd, "files")
            work_fd = recovery._open_dir_at(root_fd, "work")
            try:
                run_bytes = recovery._read_regular_at(root_fd, "run.json")
                run = json.loads(run_bytes)
                report_bytes = recovery._read_regular_at(root_fd, "report.jsonl")
                checkpoints = {
                    candidate_id: json.loads(
                        recovery._read_regular_at(
                            records_fd, recovery._record_name(candidate_id)
                        )
                    )
                    for candidate_id in run["candidate_ids"]
                }
                recoverable_ids = {
                    candidate_id
                    for candidate_id, checkpoint in checkpoints.items()
                    if checkpoint["disposition"] == "recovered"
                }
                proof = recovery._revalidate_completion_state(
                    root_fd,
                    parent_fd,
                    root_name,
                    records_fd,
                    files_fd,
                    work_fd,
                    run_bytes=run_bytes,
                    manifest_bytes=recovery._read_regular_at(root_fd, "manifest.jsonl"),
                    candidate_ids=run["candidate_ids"],
                    recoverable_ids=recoverable_ids,
                    checkpoints=checkpoints,
                    report_complete=True,
                    report_bytes=report_bytes,
                )
                gate = ImageSource.open(source_path)
                try:
                    gate.assert_unchanged()
                    (output / "work" / "late-object").write_bytes(b"x")
                    with (
                        mock.patch.object(
                            recovery, "_regular_at_equals", side_effect=AssertionError
                        ),
                        mock.patch.object(
                            recovery,
                            "_revalidate_checkpoint_bytes",
                            side_effect=AssertionError,
                        ),
                        mock.patch.object(
                            recovery, "_hash_file_at", side_effect=AssertionError
                        ),
                        mock.patch.object(
                            recovery.os, "read", side_effect=AssertionError
                        ),
                        mock.patch.object(
                            recovery.os, "pread", side_effect=AssertionError
                        ),
                        self.assertRaises(OutputError),
                    ):
                        recovery._revalidate_completion_state_from_proofs(
                            root_fd,
                            parent_fd,
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
                            report_bytes=report_bytes,
                            recovered_file_proofs=proof,
                        )
                finally:
                    gate.close()
            finally:
                os.close(work_fd)
                os.close(files_fd)
                os.close(records_fd)
                os.close(root_fd)
                os.close(parent_fd)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            output = root / "output"
            recovered = next(
                plan for plan in planned.plans if plan.disposition == "recoverable"
            )
            data = output / "files" / recovered.candidate_id / "data"
            original_completion = recovery._completion

            def mutate_after_content_proof(*args, **kwargs):
                with data.open("r+b") as handle:
                    handle.write(b"x")
                return original_completion(*args, **kwargs)

            try:
                with (
                    mock.patch.object(
                        recovery,
                        "_completion",
                        side_effect=mutate_after_content_proof,
                    ),
                    self.assertRaises(OutputError),
                ):
                    recover_plans(
                        source,
                        planned.plans,
                        output,
                        source_binding=planned.source_binding,
                        manifest_bytes=manifest_bytes,
                        selected_ids=[plan.candidate_id for plan in planned.plans],
                        limits=limits,
                    )
            finally:
                source.close()

    def test_completion_refuses_data_mutated_after_its_first_final_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            output = root / "output"
            recovered = [
                plan for plan in planned.plans if plan.disposition == "recoverable"
            ]
            self.assertGreaterEqual(len(recovered), 2)
            data = output / "files" / recovered[0].candidate_id / "data"
            original = recovery._check_file_proof_at
            mutated = False

            def mutate_after_first_final_proof(*args, **kwargs):
                nonlocal mutated
                proof = original(*args, **kwargs)
                if not mutated and (output / "report.jsonl").exists():
                    mutated = True
                    with data.open("r+b") as handle:
                        handle.write(b"x")
                return proof

            try:
                with (
                    mock.patch.object(
                        recovery,
                        "_check_file_proof_at",
                        side_effect=mutate_after_first_final_proof,
                    ),
                    self.assertRaises(OutputError),
                ):
                    recover_plans(
                        source,
                        planned.plans,
                        output,
                        source_binding=planned.source_binding,
                        manifest_bytes=manifest_bytes,
                        selected_ids=[plan.candidate_id for plan in planned.plans],
                        limits=limits,
                    )
            finally:
                source.close()
            self.assertTrue(mutated)

    def test_completion_refuses_requested_parent_renamed_after_final_proof(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            requested_parent = root / "requested-parent"
            requested_parent.mkdir()
            _, source, planned, limits, manifest_bytes = self._planned(root)
            output = requested_parent / "output"
            moved_parent = root / "moved-parent"
            original = recovery._revalidate_completion_state_from_proofs
            moved = False

            def move_parent_after_final_proof(*args, **kwargs):
                nonlocal moved
                result = original(*args, **kwargs)
                if not moved:
                    requested_parent.rename(moved_parent)
                    moved = True
                return result

            try:
                with (
                    mock.patch.object(
                        recovery,
                        "_revalidate_completion_state_from_proofs",
                        side_effect=move_parent_after_final_proof,
                    ),
                    self.assertRaises(OutputError),
                ):
                    recover_plans(
                        source,
                        planned.plans,
                        output,
                        source_binding=planned.source_binding,
                        manifest_bytes=manifest_bytes,
                        selected_ids=[plan.candidate_id for plan in planned.plans],
                        limits=limits,
                    )
            finally:
                source.close()
            self.assertTrue(moved)
            self.assertFalse(output.exists())
            self.assertTrue((moved_parent / "output" / "report.jsonl").exists())

    def test_completion_refuses_requested_parent_ancestor_symlink_retarget(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second"
            (first / "parent").mkdir(parents=True)
            (second / "parent").mkdir(parents=True)
            link = root / "link"
            link.symlink_to(first, target_is_directory=True)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            output = link / "parent" / "output"
            original = recovery._revalidate_completion_state_from_proofs
            retargeted = False

            def retarget_after_final_proof(*args, **kwargs):
                nonlocal retargeted
                result = original(*args, **kwargs)
                if not retargeted:
                    link.unlink()
                    link.symlink_to(second, target_is_directory=True)
                    retargeted = True
                return result

            try:
                with (
                    mock.patch.object(
                        recovery,
                        "_revalidate_completion_state_from_proofs",
                        side_effect=retarget_after_final_proof,
                    ),
                    self.assertRaises(OutputError),
                ):
                    recover_plans(
                        source,
                        planned.plans,
                        output,
                        source_binding=planned.source_binding,
                        manifest_bytes=manifest_bytes,
                        selected_ids=[plan.candidate_id for plan in planned.plans],
                        limits=limits,
                    )
            finally:
                source.close()
            self.assertTrue(retargeted)
            self.assertFalse(output.exists())
            self.assertTrue((first / "parent" / "output" / "report.jsonl").exists())

    def test_final_state_proof_rechecks_data_after_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            output = root / "output"
            recovered = next(
                plan for plan in planned.plans if plan.disposition == "recoverable"
            )
            data = output / "files" / recovered.candidate_id / "data"
            original = recovery._named_state_proof
            mutated = False

            def mutate_after_run_proof(fd, name, label):
                nonlocal mutated
                proof = original(fd, name, label)
                if (
                    label == "Recovery run descriptor"
                    and (output / "report.jsonl").exists()
                    and not mutated
                ):
                    mutated = True
                    with data.open("r+b") as handle:
                        handle.write(b"x")
                return proof

            try:
                with (
                    mock.patch.object(
                        recovery,
                        "_named_state_proof",
                        side_effect=mutate_after_run_proof,
                    ),
                    self.assertRaises(OutputError),
                ):
                    recover_plans(
                        source,
                        planned.plans,
                        output,
                        source_binding=planned.source_binding,
                        manifest_bytes=manifest_bytes,
                        selected_ids=[plan.candidate_id for plan in planned.plans],
                        limits=limits,
                    )
            finally:
                source.close()
            self.assertTrue(mutated)

    def test_resume_refuses_requested_parent_renamed_after_final_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            requested_parent = root / "requested-parent"
            requested_parent.mkdir()
            source_path, source, planned, limits, manifest_bytes = self._planned(root)
            output = requested_parent / "output"
            original_write = recovery._write_new_at

            def interrupt_report(fd, name, data):
                if name == "report.jsonl":
                    raise OutputError("injected report interruption")
                return original_write(fd, name, data)

            try:
                with (
                    mock.patch.object(
                        recovery, "_write_new_at", side_effect=interrupt_report
                    ),
                    self.assertRaises(OutputError),
                ):
                    recover_plans(
                        source,
                        planned.plans,
                        output,
                        source_binding=planned.source_binding,
                        manifest_bytes=manifest_bytes,
                        selected_ids=[plan.candidate_id for plan in planned.plans],
                        limits=limits,
                    )
            finally:
                source.close()
            moved_parent = root / "moved-parent"
            original_final = recovery._revalidate_completion_state_from_proofs
            moved = False

            def move_parent_after_final_proof(*args, **kwargs):
                nonlocal moved
                result = original_final(*args, **kwargs)
                if not moved:
                    requested_parent.rename(moved_parent)
                    moved = True
                return result

            resumed_source = ImageSource.open(source_path)
            try:
                with (
                    mock.patch.object(
                        recovery,
                        "_revalidate_completion_state_from_proofs",
                        side_effect=move_parent_after_final_proof,
                    ),
                    self.assertRaises(OutputError),
                ):
                    resume_recovery(
                        resumed_source,
                        output,
                        planner_result=planned,
                        manifest=parse_manifest_v2_bytes(manifest_bytes),
                    )
            finally:
                resumed_source.close()
            self.assertTrue(moved)
            self.assertFalse(output.exists())
            self.assertTrue((moved_parent / "output" / "report.jsonl").exists())

    def test_completion_refuses_late_immutable_state_or_directory_mutation(
        self,
    ) -> None:
        for target in ("checkpoint", "run", "manifest", "records_directory"):
            with (
                self.subTest(target=target),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                _, source, planned, limits, manifest_bytes = self._planned(root)
                output = root / "output"
                checkpoint = (
                    output / "records" / f"{planned.plans[0].candidate_id}.json"
                )
                paths = {
                    "checkpoint": checkpoint,
                    "run": output / "run.json",
                    "manifest": output / "manifest.jsonl",
                    "records_directory": output / "records",
                }
                original = recovery._revalidate_recovered_outputs
                mutated = False

                def mutate_after_data_validation(
                    files_fd,
                    checkpoints,
                    *,
                    original=original,
                    target_path=paths[target],
                    is_directory=target == "records_directory",
                    **kwargs,
                ):
                    nonlocal mutated
                    result = original(files_fd, checkpoints, **kwargs)
                    if mutated:
                        return result
                    mutated = True
                    if is_directory:
                        target_path.chmod(0o755)
                    else:
                        target_path.write_bytes(b"{}")
                        target_path.chmod(0o600)
                    return result

                try:
                    with (
                        mock.patch.object(
                            recovery,
                            "_revalidate_recovered_outputs",
                            side_effect=mutate_after_data_validation,
                        ),
                        self.assertRaises(OutputError),
                    ):
                        recover_plans(
                            source,
                            planned.plans,
                            output,
                            source_binding=planned.source_binding,
                            manifest_bytes=manifest_bytes,
                            selected_ids=[plan.candidate_id for plan in planned.plans],
                            limits=limits,
                        )
                finally:
                    source.close()
                self.assertTrue(mutated)
                self.assertFalse((output / "report.jsonl").exists())

    def test_completion_refuses_source_mutated_during_final_output_proof(self) -> None:
        for target in ("source",):
            with (
                self.subTest(target=target),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                source_path, source, planned, limits, manifest_bytes = self._planned(
                    root
                )
                output = root / "output"
                original = recovery._revalidate_completion_state
                mutated = False

                def mutate_after_final_state(
                    *args, original=original, source_path=source_path, **kwargs
                ) -> None:
                    nonlocal mutated
                    original(*args, **kwargs)
                    if mutated or not kwargs["report_complete"]:
                        return
                    mutated = True
                    with source_path.open("r+b") as handle:
                        handle.write(b"x")

                try:
                    with (
                        mock.patch.object(
                            recovery,
                            "_revalidate_completion_state",
                            side_effect=mutate_after_final_state,
                        ),
                        self.assertRaises((OutputError, SourceError)),
                    ):
                        recover_plans(
                            source,
                            planned.plans,
                            output,
                            source_binding=planned.source_binding,
                            manifest_bytes=manifest_bytes,
                            selected_ids=[plan.candidate_id for plan in planned.plans],
                            limits=limits,
                        )
                finally:
                    source.close()
                self.assertTrue(mutated)

    def test_completion_refuses_output_mutated_by_intervening_source_proof(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _source_path, source, planned, limits, manifest_bytes = self._planned(root)
            output = root / "output"
            candidate_id = next(
                plan.candidate_id
                for plan in planned.plans
                if plan.disposition == "recoverable"
            )
            data = output / "files" / candidate_id / "data"
            original_completion = recovery._revalidate_completion_state
            original_assert = ImageSource.assert_unchanged
            final_output_proof_completed = False
            mutated = False

            def mark_final_output_proof(*args, **kwargs):
                nonlocal final_output_proof_completed
                result = original_completion(*args, **kwargs)
                if kwargs["report_complete"]:
                    final_output_proof_completed = True
                return result

            def mutate_during_source_proof(instance, *args, **kwargs):
                nonlocal mutated
                if final_output_proof_completed and not mutated:
                    mutated = True
                    with data.open("r+b") as handle:
                        handle.write(b"x")
                original_assert(instance, *args, **kwargs)

            try:
                with (
                    mock.patch.object(
                        recovery,
                        "_revalidate_completion_state",
                        side_effect=mark_final_output_proof,
                    ),
                    mock.patch.object(
                        ImageSource, "assert_unchanged", mutate_during_source_proof
                    ),
                    self.assertRaises(OutputError),
                ):
                    recover_plans(
                        source,
                        planned.plans,
                        output,
                        source_binding=planned.source_binding,
                        manifest_bytes=manifest_bytes,
                        selected_ids=[plan.candidate_id for plan in planned.plans],
                        limits=limits,
                    )
            finally:
                source.close()
            self.assertTrue(mutated)

    def test_completion_refuses_output_mutated_after_penultimate_state_proof(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _source_path, source, planned, limits, manifest_bytes = self._planned(root)
            output = root / "output"
            candidate_id = next(
                plan.candidate_id
                for plan in planned.plans
                if plan.disposition == "recoverable"
            )
            data = output / "files" / candidate_id / "data"
            original = recovery._revalidate_completion_state
            mutated = False

            def mutate_after_penultimate_state(*args, **kwargs):
                nonlocal mutated
                result = original(*args, **kwargs)
                if not kwargs["report_complete"] and not mutated:
                    mutated = True
                    with data.open("r+b") as handle:
                        handle.write(b"x")
                return result

            try:
                with (
                    mock.patch.object(
                        recovery,
                        "_revalidate_completion_state",
                        side_effect=mutate_after_penultimate_state,
                    ),
                    self.assertRaises(OutputError),
                ):
                    recover_plans(
                        source,
                        planned.plans,
                        output,
                        source_binding=planned.source_binding,
                        manifest_bytes=manifest_bytes,
                        selected_ids=[plan.candidate_id for plan in planned.plans],
                        limits=limits,
                    )
            finally:
                source.close()
            self.assertTrue(mutated)

    def test_completion_refuses_checkpoint_mutated_after_content_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            output = root / "output"
            original = recovery._revalidate_checkpoint_bytes
            mutated = False

            def mutate_before_report_read(*args, original=original, **kwargs) -> None:
                nonlocal mutated
                original(*args, **kwargs)
                checkpoint = (
                    output / "records" / f"{planned.plans[0].candidate_id}.json"
                )
                if not mutated:
                    mutated = True
                    checkpoint.write_bytes(b"{}")
                    checkpoint.chmod(0o600)

            try:
                with (
                    mock.patch.object(
                        recovery,
                        "_revalidate_checkpoint_bytes",
                        side_effect=mutate_before_report_read,
                    ),
                    self.assertRaises(OutputError),
                ):
                    recover_plans(
                        source,
                        planned.plans,
                        output,
                        source_binding=planned.source_binding,
                        manifest_bytes=manifest_bytes,
                        selected_ids=[plan.candidate_id for plan in planned.plans],
                        limits=limits,
                    )
            finally:
                source.close()
            self.assertTrue(mutated)

    def test_completion_closure_refuses_metadata_changed_during_later_run_proof(
        self,
    ) -> None:
        """The reverse closure must cover metadata and namespace observations."""
        for target in ("checkpoint", "work", "root"):
            with (
                self.subTest(target=target),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                _, source, planned, limits, manifest_bytes = self._planned(root)
                output = root / "output"
                original = recovery._named_state_proof
                mutated = False

                def mutate_after_run_proof(
                    fd,
                    name,
                    label,
                    *,
                    original=original,
                    target=target,
                    output=output,
                    planned=planned,
                ):
                    nonlocal mutated
                    proof = original(fd, name, label)
                    if label == "Recovery run descriptor" and not mutated:
                        mutated = True
                        if target == "checkpoint":
                            checkpoint = (
                                output
                                / "records"
                                / f"{planned.plans[0].candidate_id}.json"
                            )
                            checkpoint.write_bytes(b"{}\n")
                            checkpoint.chmod(0o600)
                        elif target == "work":
                            (output / "work" / "late-object").write_bytes(b"x")
                        else:
                            (output / "late-object").write_bytes(b"x")
                        return proof
                    return proof

                try:
                    with (
                        mock.patch.object(
                            recovery,
                            "_named_state_proof",
                            side_effect=mutate_after_run_proof,
                        ),
                        self.assertRaises(OutputError),
                    ):
                        recover_plans(
                            source,
                            planned.plans,
                            output,
                            source_binding=planned.source_binding,
                            manifest_bytes=manifest_bytes,
                            selected_ids=[plan.candidate_id for plan in planned.plans],
                            limits=limits,
                        )
                finally:
                    source.close()
                self.assertTrue(mutated)

    def test_completion_refuses_report_mutated_after_content_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            output = root / "output"
            original = recovery._regular_at_equals
            mutated = False

            def mutate_after_report_read(fd, name, expected, **kwargs):
                nonlocal mutated
                result = original(fd, name, expected, **kwargs)
                if name == "report.jsonl" and not mutated:
                    mutated = True
                    report = output / "report.jsonl"
                    report.write_bytes(b"{}")
                    report.chmod(0o600)
                return result

            try:
                with (
                    mock.patch.object(
                        recovery,
                        "_regular_at_equals",
                        side_effect=mutate_after_report_read,
                    ),
                    self.assertRaises(OutputError),
                ):
                    recover_plans(
                        source,
                        planned.plans,
                        output,
                        source_binding=planned.source_binding,
                        manifest_bytes=manifest_bytes,
                        selected_ids=[plan.candidate_id for plan in planned.plans],
                        limits=limits,
                    )
            finally:
                source.close()
            self.assertTrue(mutated)

    def test_resume_refuses_altered_or_unexpected_published_object(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            manifest = parse_manifest_v2_bytes(manifest_bytes)
            first_record = f"{planned.plans[0].candidate_id}.json"
            original = recovery._write_new_at

            def interrupt(fd: int, name: str, data: bytes) -> None:
                if name == first_record:
                    raise OutputError("injected checkpoint failure")
                original(fd, name, data)

            try:
                with (
                    mock.patch.object(recovery, "_write_new_at", side_effect=interrupt),
                    self.assertRaises(OutputError),
                ):
                    recover_plans(
                        source,
                        planned.plans,
                        root / "output",
                        source_binding=planned.source_binding,
                        manifest_bytes=manifest_bytes,
                        selected_ids=[plan.candidate_id for plan in planned.plans],
                        limits=limits,
                    )
                published = (
                    root / "output" / "files" / planned.plans[0].candidate_id / "data"
                )
                published.write_bytes(b"altered")
                with self.assertRaises(OutputError):
                    resume_recovery(
                        source,
                        root / "output",
                        planner_result=planned,
                        manifest=manifest,
                    )
            finally:
                source.close()

    def test_atomic_publication_failure_is_structured_and_resumes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            manifest = parse_manifest_v2_bytes(manifest_bytes)
            original_publish = recovery._rename_noreplace

            def fail_data_publication(
                source_fd: int,
                source_name: str,
                destination_fd: int,
                destination_name: str,
            ) -> None:
                if destination_name == "data":
                    raise OSError(errno.EIO, "injected atomic publication failure")
                original_publish(
                    source_fd, source_name, destination_fd, destination_name
                )

            try:
                with (
                    mock.patch.object(
                        recovery,
                        "_rename_noreplace",
                        side_effect=fail_data_publication,
                    ),
                    self.assertRaises(OutputError),
                ):
                    recover_plans(
                        source,
                        planned.plans,
                        root / "output",
                        source_binding=planned.source_binding,
                        manifest_bytes=manifest_bytes,
                        selected_ids=[plan.candidate_id for plan in planned.plans],
                        limits=limits,
                    )
                self.assertFalse((root / "output" / "report.jsonl").exists())
                result = resume_recovery(
                    source, root / "output", planner_result=planned, manifest=manifest
                )
            finally:
                source.close()
            self.assertTrue(result["complete"])
            self.assertTrue(verify_recovery(root / "output")["ok"])

    def test_resume_refuses_symlinked_published_data(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            manifest = parse_manifest_v2_bytes(manifest_bytes)
            first_record = f"{planned.plans[0].candidate_id}.json"
            original = recovery._write_new_at

            def interrupt(fd: int, name: str, data: bytes) -> None:
                if name == first_record:
                    raise OutputError("injected checkpoint failure")
                original(fd, name, data)

            try:
                with (
                    mock.patch.object(recovery, "_write_new_at", side_effect=interrupt),
                    self.assertRaises(OutputError),
                ):
                    recover_plans(
                        source,
                        planned.plans,
                        root / "output",
                        source_binding=planned.source_binding,
                        manifest_bytes=manifest_bytes,
                        selected_ids=[plan.candidate_id for plan in planned.plans],
                        limits=limits,
                    )
                published = (
                    root / "output" / "files" / planned.plans[0].candidate_id / "data"
                )
                published.unlink()
                published.symlink_to(root / "output" / "run.json")
                with self.assertRaises(OutputError):
                    resume_recovery(
                        source,
                        root / "output",
                        planner_result=planned,
                        manifest=manifest,
                    )
            finally:
                source.close()

    def test_verify_detects_tampering_and_source_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path, source, planned, limits, manifest_bytes = self._planned(root)
            try:
                recover_plans(
                    source,
                    planned.plans,
                    root / "output",
                    source_binding=planned.source_binding,
                    manifest_bytes=manifest_bytes,
                    selected_ids=[plan.candidate_id for plan in planned.plans],
                    limits=limits,
                )
            finally:
                source.close()
            active = next(plan for plan in planned.plans if plan.name == "Active.txt")
            (root / "output" / "files" / active.candidate_id / "data").write_bytes(
                b"changed"
            )
            with self.assertRaises(VerificationError):
                verify_recovery(root / "output")
            # The output is intentionally already invalid; use a fresh run to
            # separately prove source binding enforcement.
            source = ImageSource.open(source_path)
            try:
                recover_plans(
                    source,
                    planned.plans,
                    root / "source-run",
                    source_binding=planned.source_binding,
                    manifest_bytes=manifest_bytes,
                    selected_ids=[plan.candidate_id for plan in planned.plans],
                    limits=limits,
                )
            finally:
                source.close()
            mutated = bytearray(source_path.read_bytes())
            mutated[-1] ^= 1
            source_path.write_bytes(mutated)
            with self.assertRaises(SourceError):
                verify_recovery(root / "source-run", source_path)

    def test_verify_refuses_output_permission_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            try:
                recover_plans(
                    source,
                    planned.plans,
                    root / "output",
                    source_binding=planned.source_binding,
                    manifest_bytes=manifest_bytes,
                    selected_ids=[plan.candidate_id for plan in planned.plans],
                    limits=limits,
                )
            finally:
                source.close()
            output = root / "output"
            os.chmod(output, 0o755)
            with self.assertRaises(VerificationError):
                verify_recovery(output)
