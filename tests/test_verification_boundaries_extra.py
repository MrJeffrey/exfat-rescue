from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from exfat_rescue.errors import (
    ManifestError,
    SourceError,
    UsageError,
    VerificationError,
)
from exfat_rescue.recovery import _canonical, recover_plans
from exfat_rescue.source import ImageSource
from exfat_rescue.verification import (
    _reparsed_candidates,
    verify_recovery,
    verify_recovery_set,
)
from tests import test_recovery_boundaries as recovery_boundaries


class VerificationBoundaryExtraTests(unittest.TestCase):
    def _completed_from_scanned_metadata(self, root: Path):
        """Create a completed run whose immutable metadata can be replanned."""
        source_path, source, planned, limits, manifest_bytes = (
            recovery_boundaries.RecoveryBoundaryTests()._planned(root)
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
        finally:
            source.close()
        return source_path, root / "output"

    def _completed_set_from_scanned_metadata(self, root: Path):
        source_path, source, planned, limits, manifest_bytes = (
            recovery_boundaries.RecoveryBoundaryTests()._planned(root)
        )
        recoverable = [
            plan for plan in planned.plans if plan.disposition == "recoverable"
        ]
        outputs = [root / "output-1", root / "output-2"]
        self.assertEqual(len(recoverable), len(outputs))
        try:
            for output, plan in zip(outputs, recoverable, strict=True):
                recover_plans(
                    source,
                    planned.plans,
                    output,
                    source_binding=planned.source_binding,
                    manifest_bytes=manifest_bytes,
                    selected_ids=[plan.candidate_id],
                    limits=limits,
                )
        finally:
            source.close()
        return source_path, outputs, planned, limits, manifest_bytes

    def test_image_reparse_requires_the_complete_candidate_inventory(self) -> None:
        retained = {"entry_offset": 1, "entry_set_sha256": "a" * 64}
        omitted = {"entry_offset": 2, "entry_set_sha256": "b" * 64}
        with self.assertRaises(VerificationError):
            _reparsed_candidates((retained,), [retained, omitted])

    def test_image_verification_replans_and_rehashes_the_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source_path, output = self._completed_from_scanned_metadata(Path(temporary))

            result = verify_recovery(output, source_path)

            self.assertTrue(result["ok"])
            self.assertTrue(result["image_verified"])
            self.assertEqual(result["candidate_count"], 3)
            self.assertEqual(result["recovered_count"], 2)

    def test_image_verification_set_reuses_one_global_replan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source_path, outputs, _planned, _limits, _manifest_bytes = (
                self._completed_set_from_scanned_metadata(Path(temporary))
            )
            from exfat_rescue import verification

            original = verification._verify_image
            with (
                patch.object(
                    verification, "_verify_image", wraps=original
                ) as global_verify,
                patch.object(
                    ImageSource,
                    "sha256_region",
                    autospec=True,
                    wraps=ImageSource.sha256_region,
                ) as volume_hash,
            ):
                result = verify_recovery_set(outputs, source_path)

            self.assertTrue(result["ok"])
            self.assertTrue(result["image_verified"])
            self.assertTrue(result["shared_image_verification"])
            self.assertEqual(result["output_count"], 2)
            self.assertEqual(result["candidate_count"], 2)
            self.assertEqual(result["recovered_count"], 2)
            self.assertEqual(global_verify.call_count, 1)
            self.assertEqual(volume_hash.call_count, 0)

    def test_image_verification_set_rejects_duplicate_output_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source_path, outputs, _planned, _limits, _manifest_bytes = (
                self._completed_set_from_scanned_metadata(Path(temporary))
            )

            with self.assertRaises(UsageError):
                verify_recovery_set([outputs[0], outputs[0]], source_path)

    def test_image_verification_set_rejects_overlapping_selections(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path, outputs, planned, limits, manifest_bytes = (
                self._completed_set_from_scanned_metadata(root)
            )
            duplicate = root / "duplicate-selection"
            source = ImageSource.open(source_path)
            try:
                recoverable = next(
                    plan for plan in planned.plans if plan.disposition == "recoverable"
                )
                recover_plans(
                    source,
                    planned.plans,
                    duplicate,
                    source_binding=planned.source_binding,
                    manifest_bytes=manifest_bytes,
                    selected_ids=[recoverable.candidate_id],
                    limits=limits,
                )
            finally:
                source.close()

            with self.assertRaises(ManifestError):
                verify_recovery_set([outputs[0], duplicate], source_path)

    def test_image_verification_set_requires_identical_replan_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source_path, outputs, _planned, _limits, _manifest_bytes = (
                self._completed_set_from_scanned_metadata(Path(temporary))
            )
            run_path = outputs[1] / "run.json"
            run = json.loads(run_path.read_bytes())
            run["limits"]["max_fat_steps"] += 1
            run_path.write_bytes(_canonical(run) + b"\n")

            report_path = outputs[1] / "report.jsonl"
            report = [
                json.loads(line) for line in report_path.read_bytes().splitlines()
            ]
            report[0]["run_sha256"] = hashlib.sha256(_canonical(run)).hexdigest()
            content = b"".join(_canonical(record) + b"\n" for record in report[:-1])
            report[-1]["content_sha256"] = hashlib.sha256(content).hexdigest()
            report_path.write_bytes(content + _canonical(report[-1]) + b"\n")

            from exfat_rescue import verification

            original_read = verification._safe_read
            checkpoint_reads = 0

            def count_checkpoint_reads(*args, **kwargs):
                nonlocal checkpoint_reads
                if args[2] == "Candidate checkpoint":
                    checkpoint_reads += 1
                return original_read(*args, **kwargs)

            with (
                patch.object(verification, "_verify_image") as verify_image,
                patch.object(verification, "_hash_and_check_zero_tail") as hash_output,
                patch.object(
                    verification, "_safe_read", side_effect=count_checkpoint_reads
                ),
                self.assertRaises(ManifestError),
            ):
                verify_recovery_set(outputs, source_path)

            verify_image.assert_not_called()
            hash_output.assert_not_called()
            self.assertEqual(checkpoint_reads, 0)

    def test_set_preflight_rejects_late_malformed_checkpoint_before_image_io(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source_path, outputs, _planned, _limits, _manifest_bytes = (
                self._completed_set_from_scanned_metadata(Path(temporary))
            )
            checkpoint = next((outputs[1] / "records").iterdir())
            checkpoint.write_text(
                json.dumps(json.loads(checkpoint.read_bytes()), indent=2),
                encoding="utf-8",
            )
            from exfat_rescue import verification

            with (
                patch.object(verification, "_verify_image") as verify_image,
                patch.object(verification, "_hash_and_check_zero_tail") as hash_output,
                self.assertRaisesRegex(
                    ManifestError, "differs from immutable candidate checkpoint"
                ),
            ):
                verify_recovery_set(outputs, source_path)

            verify_image.assert_not_called()
            hash_output.assert_not_called()

    def test_set_preflight_rejects_late_malformed_report_before_image_io(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source_path, outputs, _planned, _limits, _manifest_bytes = (
                self._completed_set_from_scanned_metadata(Path(temporary))
            )
            report_path = outputs[1] / "report.jsonl"
            report = [
                json.loads(line) for line in report_path.read_bytes().splitlines()
            ]
            recovered = next(
                record for record in report if record.get("disposition") == "recovered"
            )
            recovered["output_sha256"] = "invalid"
            checkpoint = outputs[1] / "records" / f"{recovered['candidate_id']}.json"
            checkpoint.write_bytes(_canonical(recovered) + b"\n")
            content = b"".join(_canonical(record) + b"\n" for record in report[:-1])
            report[-1]["content_sha256"] = hashlib.sha256(content).hexdigest()
            report_path.write_bytes(content + _canonical(report[-1]) + b"\n")
            from exfat_rescue import verification

            with (
                patch.object(verification, "_verify_image") as verify_image,
                patch.object(verification, "_hash_and_check_zero_tail") as hash_output,
                self.assertRaises(ManifestError),
            ):
                verify_recovery_set(outputs, source_path)

            verify_image.assert_not_called()
            hash_output.assert_not_called()

    def test_set_input_count_is_bounded_before_output_preflight(self) -> None:
        from exfat_rescue import verification

        with (
            patch.object(verification, "HARD_MAX_RECOVERY_CANDIDATES", 1),
            patch.object(verification, "_preflight_recovery") as preflight,
            self.assertRaisesRegex(UsageError, "supported output count"),
        ):
            verify_recovery_set(iter(("first", "second")), "image")
        preflight.assert_not_called()

    def test_unhashable_run_candidate_id_is_a_manifest_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _source_path, output = self._completed_from_scanned_metadata(
                Path(temporary)
            )
            run_path = output / "run.json"
            run = json.loads(run_path.read_bytes())
            run["candidate_ids"] = [{}]
            run_path.write_bytes(_canonical(run) + b"\n")

            with self.assertRaises(ManifestError):
                verify_recovery(output)

    def test_recovered_checkpoint_rejects_boolean_extent_integer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _source_path, output = self._completed_from_scanned_metadata(
                Path(temporary)
            )
            report_path = output / "report.jsonl"
            report = [
                json.loads(line) for line in report_path.read_bytes().splitlines()
            ]
            recovered = next(
                record for record in report if record.get("disposition") == "recovered"
            )
            self.assertEqual(recovered["source_extents"][0]["cluster_count"], 1)
            recovered["source_extents"][0]["cluster_count"] = True
            checkpoint = output / "records" / f"{recovered['candidate_id']}.json"
            checkpoint.write_bytes(_canonical(recovered) + b"\n")
            content = b"".join(_canonical(record) + b"\n" for record in report[:-1])
            report[-1]["content_sha256"] = hashlib.sha256(content).hexdigest()
            report_path.write_bytes(content + _canonical(report[-1]) + b"\n")

            with self.assertRaises(ManifestError):
                verify_recovery(output)

    def test_report_completion_rejects_boolean_integer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _source_path, outputs, _planned, _limits, _manifest_bytes = (
                self._completed_set_from_scanned_metadata(Path(temporary))
            )
            output = outputs[0]
            report_path = output / "report.jsonl"
            report = [
                json.loads(line) for line in report_path.read_bytes().splitlines()
            ]
            self.assertEqual(report[-1]["candidate_count"], 1)
            report[-1]["candidate_count"] = True
            report_path.write_bytes(
                b"".join(_canonical(record) + b"\n" for record in report)
            )

            with self.assertRaises(ManifestError):
                verify_recovery(output)

    def test_output_validation_closes_partially_opened_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _source_path, output = self._completed_from_scanned_metadata(
                Path(temporary)
            )
            from exfat_rescue import verification

            for validate in (
                lambda: verification._preflight_recovery(output),
                lambda: verify_recovery(output),
            ):
                with self.subTest(validate=validate.__code__.co_firstlineno):
                    original = verification._safe_dir
                    opened: list[int] = []

                    def fail_after_first_directory(
                        fd: int,
                        name: str,
                        label: str,
                        original=original,
                        opened=opened,
                    ) -> int:
                        if name == "records":
                            result = original(fd, name, label)
                            opened.append(result)
                            return result
                        raise VerificationError("injected inventory failure")

                    with (
                        patch.object(
                            verification,
                            "_safe_dir",
                            side_effect=fail_after_first_directory,
                        ),
                        self.assertRaisesRegex(
                            VerificationError, "injected inventory failure"
                        ),
                    ):
                        validate()
                    self.assertEqual(len(opened), 1)
                    with self.assertRaises(OSError):
                        os.fstat(opened[0])

    def test_image_verification_rejects_output_mutated_by_final_source_gate(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source_path, output = self._completed_from_scanned_metadata(Path(temporary))
            from exfat_rescue import verification

            candidate_id = next((output / "files").iterdir()).name
            data = output / "files" / candidate_id / "data"
            original_verify_image = verification._verify_image
            original_assert = ImageSource.assert_unchanged
            verified_image = False
            mutated = False

            def mark_image_verified(*args, **kwargs) -> None:
                nonlocal verified_image
                original_verify_image(*args, **kwargs)
                verified_image = True

            def mutate_output_after_image_proof(instance, *args, **kwargs) -> None:
                nonlocal mutated
                if verified_image and not mutated:
                    mutated = True
                    with data.open("r+b") as handle:
                        handle.write(b"x")
                original_assert(instance, *args, **kwargs)

            with (
                patch.object(
                    verification,
                    "_verify_image",
                    side_effect=mark_image_verified,
                ),
                patch.object(
                    ImageSource, "assert_unchanged", mutate_output_after_image_proof
                ),
                self.assertRaises(VerificationError),
            ):
                verify_recovery(output, source_path)
            self.assertTrue(mutated)

    def test_image_verification_rejects_a_same_size_different_image(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path, output = self._completed_from_scanned_metadata(root)
            replacement = root / "replacement.img"
            replacement.write_bytes(source_path.read_bytes())
            with replacement.open("r+b") as handle:
                handle.seek(-1, 2)
                original = handle.read(1)
                handle.seek(-1, 2)
                handle.write(bytes([original[0] ^ 0xFF]))

            with self.assertRaises(SourceError):
                verify_recovery(output, replacement)

    def test_run_source_binding_must_match_the_internal_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, _, output = recovery_boundaries.RecoveryBoundaryTests()._completed(
                root
            )
            run_path = output / "run.json"
            run = json.loads(run_path.read_bytes())
            run["source"]["source_kind"] = "tampered-source-kind"
            run_path.write_bytes(_canonical(run))

            with self.assertRaises(ManifestError):
                verify_recovery(output)

    def test_completed_work_artifact_is_a_verification_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, _, output = recovery_boundaries.RecoveryBoundaryTests()._completed(
                root
            )
            (output / "work" / "orphaned.tmp").write_bytes(b"unfinished")

            with self.assertRaises(VerificationError):
                verify_recovery(output)

    def test_extra_recovered_candidate_object_is_a_verification_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, planned, _, output = (
                recovery_boundaries.RecoveryBoundaryTests()._completed(root)
            )
            recovered = next(
                plan for plan in planned.plans if plan.disposition == "recoverable"
            )
            candidate_dir = output / "files" / recovered.candidate_id
            (candidate_dir / "unexpected").write_bytes(b"not data")

            with self.assertRaises(VerificationError):
                verify_recovery(output)
