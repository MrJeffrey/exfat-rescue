from __future__ import annotations

import errno
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from exfat_rescue import recovery
from exfat_rescue.cli import _internal_manifest_bytes, main
from exfat_rescue.errors import (
    ManifestError,
    OutputError,
    ResourceLimitError,
    VerificationError,
)
from exfat_rescue.exfat.volume import ExfatVolume
from exfat_rescue.manifest import parse_manifest_v2_bytes
from exfat_rescue.planner import Extent, PlannerResult, RecoveryPlan, plan_recovery
from exfat_rescue.recovery import recover_plans, resume_recovery
from exfat_rescue.scanner import scan
from exfat_rescue.source import ImageSource
from exfat_rescue.verification import (
    _recovered_checkpoint,
    _report_records,
    _run_descriptor,
    verify_recovery,
)
from tests.fixture import image


class RecoveryBoundaryTests(unittest.TestCase):
    def _planned(self, root: Path):
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
            {key: limits[key] for key in limits if key != "max_output_bytes"},
            scanned.warnings,
        )
        return source_path, source, planned, limits, manifest_bytes

    def _completed(self, root: Path):
        source_path = root / "source.img"
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
                "volume_dirty": False,
                "media_failure": False,
            }
            identity_binding = json.dumps(
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
                identity_binding + b":1:" + b"b" * 64
            ).hexdigest()
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
            limits = {
                "max_output_bytes": 8,
                "max_candidates": 100_000,
                "max_scan_clusters": 50_000_000,
                "max_fat_steps": 10_000_000,
            }
            manifest_bytes = _internal_manifest_bytes(
                planned,
                {key: limits[key] for key in limits if key != "max_output_bytes"},
                (),
            )
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
        return source_path, planned, manifest_bytes, root / "output"

    def test_malformed_v2_run_report_and_checkpoint_schemas_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, planned, manifest_bytes, output = self._completed(root)
            with self.assertRaises(ManifestError):
                parse_manifest_v2_bytes(
                    manifest_bytes.replace(b'"version":2', b'"version":3', 1)
                )

            run = json.loads((output / "run.json").read_bytes())
            run["limits"] = {"max_candidates": 1}
            with self.assertRaises(ManifestError):
                _run_descriptor(recovery._canonical(run))

            invalid_version = json.loads((output / "run.json").read_bytes())
            invalid_version["version"] = True
            with self.assertRaises(ManifestError):
                _run_descriptor(recovery._canonical(invalid_version))

            valid_run = json.loads((output / "run.json").read_bytes())
            malformed_report = (
                recovery._canonical(
                    {
                        "record_type": "report",
                        "run_sha256": hashlib.sha256(
                            recovery._canonical(valid_run)
                        ).hexdigest(),
                    }
                )
                + b"\n"
                + recovery._canonical({"record_type": "complete"})
                + b"\n"
            )
            with self.assertRaises(ManifestError):
                _report_records(malformed_report, valid_run)

            plan = next(
                plan for plan in planned.plans if plan.disposition == "recoverable"
            )
            with self.assertRaises(ManifestError):
                _recovered_checkpoint(
                    {
                        "record_type": "candidate",
                        "candidate_id": plan.candidate_id,
                        "disposition": "recovered",
                    },
                    plan,
                )

    def test_output_write_faults_are_translated_and_short_writes_refused(self) -> None:
        with (
            mock.patch.object(
                recovery.os, "write", side_effect=OSError(errno.ENOSPC, "full")
            ),
            self.assertRaises(ResourceLimitError),
        ):
            recovery._write_all(123, b"state", "state")
        with (
            mock.patch.object(recovery.os, "write", return_value=0),
            self.assertRaises(OutputError),
        ):
            recovery._write_all(123, b"state", "state")

    def test_source_binding_or_plan_mismatch_fails_before_output_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, source, planned, limits, manifest_bytes = self._planned(root)
            target = root / "must-not-exist"
            bad_binding = dict(planned.source_binding)
            bad_binding["source_kind"] = "wrong-binding"
            try:
                with self.assertRaises(ManifestError):
                    recover_plans(
                        source,
                        planned.plans,
                        target,
                        source_binding=bad_binding,
                        manifest_bytes=manifest_bytes,
                        selected_ids=[plan.candidate_id for plan in planned.plans],
                        limits=limits,
                    )
            finally:
                source.close()
            self.assertFalse(target.exists())

    def test_create_run_enforces_candidate_limit_without_exhausting_iterable(
        self,
    ) -> None:
        consumed: list[int] = []

        def unbounded_plans():
            index = 0
            while True:
                consumed.append(index)
                yield {
                    "candidate_id": f"{index:064x}",
                    "entry_offset": index,
                    "entry_set_sha256": "a" * 64,
                    "name": "refused",
                    "logical_size_bytes": 0,
                    "valid_data_bytes": 0,
                    "extents": [],
                    "allocation_mode": "empty",
                    "metadata_location": "orphan",
                    "disposition": "unrecoverable",
                    "recovery_basis": None,
                    "reasons": ["synthetic"],
                }
                index += 1

        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "output"
            with self.assertRaises(ResourceLimitError):
                recovery._create_run(
                    object(),
                    unbounded_plans(),
                    target,
                    binding={},
                    limits={**recovery.DEFAULT_RUN_LIMITS, "max_candidates": 2},
                    manifest_bytes=b"manifest",
                )
            self.assertEqual(consumed, [0, 1, 2])
            self.assertFalse(target.exists())

    def test_resume_rejects_unknown_inventory_and_malformed_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, planned, manifest_bytes, output = self._completed(root)
            manifest = parse_manifest_v2_bytes(manifest_bytes)
            (output / "report.jsonl").unlink()
            (output / "records" / "unexpected.json").write_text("{}", encoding="utf-8")
            source = ImageSource.open(root / "source.img")
            try:
                with self.assertRaises(OutputError):
                    resume_recovery(
                        source, output, planner_result=planned, manifest=manifest
                    )
            finally:
                source.close()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, planned, manifest_bytes, output = self._completed(root)
            manifest = parse_manifest_v2_bytes(manifest_bytes)
            (output / "report.jsonl").unlink()
            first = planned.plans[0].candidate_id
            (output / "records" / f"{first}.json").write_text("{}\n", encoding="utf-8")
            source = ImageSource.open(root / "source.img")
            try:
                with self.assertRaises(OutputError):
                    resume_recovery(
                        source, output, planner_result=planned, manifest=manifest
                    )
            finally:
                source.close()

    def test_verification_checks_source_prefix_after_output_digest_is_rebound(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, planned, _, output = self._completed(Path(temporary))
            plan = next(
                plan for plan in planned.plans if plan.disposition == "recoverable"
            )
            data_path = output / "files" / plan.candidate_id / "data"
            with data_path.open("r+b") as data:
                prefix = data.read(1)
                data.seek(0)
                data.write(bytes([prefix[0] ^ 0xFF]))

            checkpoint_path = output / "records" / f"{plan.candidate_id}.json"
            checkpoint = json.loads(checkpoint_path.read_bytes())
            checkpoint["output_sha256"] = hashlib.sha256(
                data_path.read_bytes()
            ).hexdigest()
            checkpoint_path.write_bytes(recovery._canonical(checkpoint) + b"\n")

            report_path = output / "report.jsonl"
            report = [
                json.loads(line) for line in report_path.read_bytes().splitlines()
            ]
            record_index = 1 + [item["candidate_id"] for item in report[1:-1]].index(
                plan.candidate_id
            )
            report[record_index] = checkpoint
            content = b"".join(
                recovery._canonical(item) + b"\n" for item in report[:-1]
            )
            report[-1]["content_sha256"] = hashlib.sha256(content).hexdigest()
            report_path.write_bytes(content + recovery._canonical(report[-1]) + b"\n")

            with self.assertRaises(VerificationError):
                verify_recovery(output)

    def test_cli_resume_option_conflict_is_usage_error_before_output_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source.img"
            source.write_bytes(image())
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = main(
                    [
                        "recover",
                        str(source),
                        "--resume",
                        str(Path(temporary) / "not-opened"),
                        "--candidate-id",
                        "a" * 64,
                        "--json",
                    ]
                )
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(stderr.getvalue())["error_code"], "usage_error")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
