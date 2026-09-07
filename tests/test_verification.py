from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from exfat_rescue import recovery, verification
from exfat_rescue.cli import _internal_manifest_bytes
from exfat_rescue.errors import ManifestError, VerificationError
from exfat_rescue.exfat.volume import ExfatVolume
from exfat_rescue.planner import Extent, PlannerResult, RecoveryPlan
from exfat_rescue.recovery import _canonical, recover_plans
from exfat_rescue.source import ImageSource
from exfat_rescue.verification import (
    _hash_and_check_zero_tail,
    _report_records,
    verify_recovery,
)
from tests.fixture import image


class VerificationTests(unittest.TestCase):
    def test_output_hash_rejects_data_appended_after_expected_bytes(self) -> None:
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
                    patch(
                        "exfat_rescue.verification.os.read",
                        append_after_expected,
                    ),
                    self.assertRaises(VerificationError),
                ):
                    _hash_and_check_zero_tail(
                        directory_fd,
                        "data",
                        len(b"expected"),
                        len(b"expected"),
                    )
            finally:
                os.close(directory_fd)
            self.assertEqual(requests, [len(b"expected"), 1])

    def _completed_output(self, temporary: str) -> tuple[Path, str]:
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
                "source_kind": "direct-image",
                "boot_region": "primary",
                "volume_dirty": volume.boot.volume_dirty,
                "media_failure": volume.boot.media_failure,
            }
            binding_id = json.dumps(
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
            ).encode("utf-8")
            candidate_id = hashlib.sha256(binding_id + b":1:" + b"b" * 64).hexdigest()
            plan = RecoveryPlan(
                candidate_id,
                1,
                "b" * 64,
                "not-a-path",
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
                "name": "not-a-path",
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
            planned = PlannerResult((plan,), binding, 0, (raw,))
            manifest = _internal_manifest_bytes(planned, {}, ())
            recover_plans(
                source,
                [plan],
                output,
                source_binding=binding,
                manifest_bytes=manifest,
                selected_ids=[candidate_id],
                limits={"max_output_bytes": 8},
            )
        finally:
            source.close()
        return output, candidate_id

    def test_completed_output_and_zero_tail_verify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output, _ = self._completed_output(temporary)
            self.assertTrue(verify_recovery(output)["ok"])

    def test_verify_reads_each_output_content_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output, _candidate_id = self._completed_output(temporary)
            with (
                patch.object(
                    verification,
                    "_hash_and_check_zero_tail",
                    wraps=verification._hash_and_check_zero_tail,
                ) as content_check,
                patch.object(
                    recovery,
                    "_hash_file_at",
                    wraps=recovery._hash_file_at,
                ) as redundant_rehash,
                patch.object(
                    verification,
                    "_release_file_cache",
                    wraps=verification._release_file_cache,
                ) as cache_release,
            ):
                result = verify_recovery(output)

            self.assertTrue(result["ok"])
            self.assertEqual(content_check.call_count, 1)
            self.assertEqual(redundant_rehash.call_count, 0)
            self.assertEqual(cache_release.call_count, 1)
            self.assertEqual(cache_release.call_args.args[1:], (0, 8))
            self.assertEqual(cache_release.call_args.kwargs, {"through_eof": True})

    def test_nonzero_tail_is_a_completed_verification_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output, candidate_id = self._completed_output(temporary)
            data = output / "files" / candidate_id / "data"
            with data.open("r+b") as handle:
                handle.seek(3)
                handle.write(b"x")
            with self.assertRaises(VerificationError):
                verify_recovery(output)

    def test_unknown_root_object_is_a_completed_verification_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output, _ = self._completed_output(temporary)
            (output / "unexpected").write_text("no")
            with self.assertRaises(VerificationError):
                verify_recovery(output)

    def test_symlinked_data_is_a_completed_verification_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output, candidate_id = self._completed_output(temporary)
            data = output / "files" / candidate_id / "data"
            data.unlink()
            data.symlink_to("../../run.json")
            with self.assertRaises(VerificationError):
                verify_recovery(output)

    def test_manifest_tamper_is_integrity_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output, _ = self._completed_output(temporary)
            manifest = output / "manifest.jsonl"
            content = manifest.read_bytes()
            manifest.write_bytes(content.replace(b"manifest", b"manifEst", 1))
            with self.assertRaises(ManifestError):
                verify_recovery(output)

    def test_incomplete_report_is_a_verification_failure(self) -> None:
        with self.assertRaises(VerificationError):
            _report_records(b'{"record_type":"report"}\n')

    def test_hardlinked_data_is_a_completed_verification_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output, candidate_id = self._completed_output(temporary)
            data = output / "files" / candidate_id / "data"
            os.link(data, output / "files" / candidate_id / "extra")
            with self.assertRaises(VerificationError):
                verify_recovery(output)

    def test_false_source_prefix_hash_is_rejected_without_image(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output, candidate_id = self._completed_output(temporary)
            checkpoint_path = output / "records" / f"{candidate_id}.json"
            checkpoint = json.loads(checkpoint_path.read_bytes())
            checkpoint["source_data_sha256"] = "0" * 64
            checkpoint_line = _canonical(checkpoint) + b"\n"
            checkpoint_path.write_bytes(checkpoint_line)

            report_path = output / "report.jsonl"
            report = [
                json.loads(line) for line in report_path.read_bytes().splitlines()
            ]
            report[1] = checkpoint
            content = b"".join(_canonical(record) + b"\n" for record in report[:-1])
            report[-1]["content_sha256"] = hashlib.sha256(content).hexdigest()
            report_path.write_bytes(content + _canonical(report[-1]) + b"\n")
            with self.assertRaises(VerificationError):
                verify_recovery(output)

    def test_oversized_sparse_data_is_refused_before_any_content_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = root / "data"
            data.write_bytes(b"")
            data.chmod(0o600)
            with data.open("r+b") as handle:
                handle.truncate(1024**4)
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with (
                    patch("exfat_rescue.verification.os.read") as read,
                    self.assertRaises(VerificationError),
                ):
                    _hash_and_check_zero_tail(fd, "data", 0, 0)
                read.assert_not_called()
            finally:
                os.close(fd)

    def test_hash_rejects_named_data_replacement_during_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = root / "data"
            moved = root / "opened-original"
            data.write_bytes(b"expected")
            data.chmod(0o600)
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            original_read = os.read
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
                    patch(
                        "exfat_rescue.verification.os.read",
                        side_effect=replace_after_open,
                    ),
                    self.assertRaises(VerificationError),
                ):
                    _hash_and_check_zero_tail(
                        directory_fd,
                        "data",
                        len(b"expected"),
                        len(b"expected"),
                    )
            finally:
                os.close(directory_fd)
            self.assertEqual(data.read_bytes(), b"attacker")
            self.assertEqual(moved.read_bytes(), b"expected")

    def test_verify_rejects_output_root_replacement_before_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, _candidate_id = self._completed_output(temporary)
            moved = root / "moved-output"
            from exfat_rescue import verification

            original = verification._hash_and_check_zero_tail
            replaced = False

            def replace(*args, **kwargs):
                nonlocal replaced
                result = original(*args, **kwargs)
                if not replaced:
                    replaced = True
                    output.rename(moved)
                    output.mkdir(mode=0o700)
                return result

            with (
                patch.object(
                    verification, "_hash_and_check_zero_tail", side_effect=replace
                ),
                self.assertRaises(VerificationError),
            ):
                verify_recovery(output)
            self.assertTrue(output.is_dir())
            self.assertTrue(moved.is_dir())

    def test_verify_rejects_late_root_or_candidate_inventory_injection(self) -> None:
        from exfat_rescue import verification

        for location in ("root", "candidate"):
            with (
                self.subTest(location=location),
                tempfile.TemporaryDirectory() as temporary,
            ):
                output, candidate_id = self._completed_output(temporary)
                original = verification._hash_and_check_zero_tail
                injection_state = [False]
                expected_parent = (
                    output if location == "root" else output / "files" / candidate_id
                )

                def inject(
                    *args,
                    target: Path = expected_parent,
                    hash_file=original,
                    state=injection_state,
                    **kwargs,
                ):
                    result = hash_file(*args, **kwargs)
                    if not state[0]:
                        state[0] = True
                        (target / "foreign").write_bytes(b"x")
                    return result

                with (
                    patch.object(
                        verification, "_hash_and_check_zero_tail", side_effect=inject
                    ),
                    self.assertRaises(VerificationError),
                ):
                    verify_recovery(output)
                self.assertTrue((expected_parent / "foreign").is_file())

    def test_verify_rejects_data_mutated_during_final_inventory_check(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output, candidate_id = self._completed_output(temporary)
            data = output / "files" / candidate_id / "data"
            from exfat_rescue import recovery

            original_inventory = recovery._validate_output_inventory
            mutated = False

            def mutate_after_inventory(*args, **kwargs) -> None:
                nonlocal mutated
                original_inventory(*args, **kwargs)
                if kwargs["report_complete"] and not mutated:
                    mutated = True
                    with data.open("r+b") as handle:
                        handle.write(b"x")

            with (
                patch.object(
                    recovery,
                    "_validate_output_inventory",
                    side_effect=mutate_after_inventory,
                ),
                self.assertRaises(VerificationError),
            ):
                verify_recovery(output)
            self.assertTrue(mutated)

    def test_verify_rejects_late_immutable_state_or_directory_mutation(self) -> None:
        from exfat_rescue import recovery

        for target in ("checkpoint", "run", "manifest", "records_directory"):
            with (
                self.subTest(target=target),
                tempfile.TemporaryDirectory() as temporary,
            ):
                output, candidate_id = self._completed_output(temporary)
                paths = {
                    "checkpoint": output / "records" / f"{candidate_id}.json",
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

                with (
                    patch.object(
                        recovery,
                        "_revalidate_recovered_outputs",
                        side_effect=mutate_after_data_validation,
                    ),
                    self.assertRaises(VerificationError),
                ):
                    verify_recovery(output)
                self.assertTrue(mutated)

    def test_verify_closure_refuses_metadata_changed_during_later_run_proof(
        self,
    ) -> None:
        """Verification must receive the common reverse metadata closure."""
        for target in ("checkpoint", "work", "root"):
            with (
                self.subTest(target=target),
                tempfile.TemporaryDirectory() as temporary,
            ):
                output, candidate_id = self._completed_output(temporary)
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
                    candidate_id=candidate_id,
                ):
                    nonlocal mutated
                    proof = original(fd, name, label)
                    if label == "Recovery run descriptor" and not mutated:
                        mutated = True
                        if target == "checkpoint":
                            checkpoint = output / "records" / f"{candidate_id}.json"
                            checkpoint.write_bytes(b"{}\n")
                            checkpoint.chmod(0o600)
                        elif target == "work":
                            (output / "work" / "late-object").write_bytes(b"x")
                        else:
                            (output / "late-object").write_bytes(b"x")
                    return proof

                with (
                    patch.object(
                        recovery,
                        "_named_state_proof",
                        side_effect=mutate_after_run_proof,
                    ),
                    self.assertRaises(VerificationError),
                ):
                    verify_recovery(output)
                self.assertTrue(mutated)

    def test_verify_refuses_requested_parent_renamed_before_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            requested_parent = root / "requested-parent"
            requested_parent.mkdir()
            output, _candidate_id = self._completed_output(str(requested_parent))
            moved_parent = root / "moved-parent"
            original = verification._revalidate_completion_state_from_proofs
            moved = False

            def move_parent_after_final_proof(*args, **kwargs):
                nonlocal moved
                result = original(*args, **kwargs)
                if not moved:
                    requested_parent.rename(moved_parent)
                    moved = True
                return result

            with (
                patch.object(
                    verification,
                    "_revalidate_completion_state_from_proofs",
                    side_effect=move_parent_after_final_proof,
                ),
                self.assertRaisesRegex(VerificationError, "parent changed"),
            ):
                verify_recovery(output)

            self.assertTrue(moved)
            self.assertFalse(output.exists())
            self.assertTrue((moved_parent / "output" / "report.jsonl").is_file())

    def test_verify_refuses_requested_parent_ancestor_symlink_retarget(
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
            requested_parent = link / "parent"
            output, _candidate_id = self._completed_output(str(requested_parent))
            original = verification._revalidate_completion_state_from_proofs
            retargeted = False

            def retarget_after_final_proof(*args, **kwargs):
                nonlocal retargeted
                result = original(*args, **kwargs)
                if not retargeted:
                    link.unlink()
                    link.symlink_to(second, target_is_directory=True)
                    retargeted = True
                return result

            with (
                patch.object(
                    verification,
                    "_revalidate_completion_state_from_proofs",
                    side_effect=retarget_after_final_proof,
                ),
                self.assertRaisesRegex(VerificationError, "parent changed"),
            ):
                verify_recovery(output)

            self.assertTrue(retargeted)
            self.assertFalse(output.exists())
            self.assertTrue((first / "parent" / "output" / "report.jsonl").is_file())

    def test_excessive_candidate_directory_entries_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output, candidate_id = self._completed_output(temporary)
            candidate_dir = output / "files" / candidate_id
            for index in range(128):
                (candidate_dir / f"unexpected-{index}").write_bytes(b"")
            with self.assertRaises(VerificationError):
                verify_recovery(output)

    def test_cumulative_verification_bytes_respect_run_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output, _ = self._completed_output(temporary)
            run_path = output / "run.json"
            run = json.loads(run_path.read_bytes())
            run["limits"]["max_output_bytes"] = 4
            run_path.write_bytes(_canonical(run))

            report_path = output / "report.jsonl"
            report = [
                json.loads(line) for line in report_path.read_bytes().splitlines()
            ]
            report[0]["run_sha256"] = hashlib.sha256(_canonical(run)).hexdigest()
            content = b"".join(_canonical(record) + b"\n" for record in report[:-1])
            report[-1]["content_sha256"] = hashlib.sha256(content).hexdigest()
            report_path.write_bytes(content + _canonical(report[-1]) + b"\n")

            with self.assertRaises(VerificationError):
                verify_recovery(output)
