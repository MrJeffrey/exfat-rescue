from __future__ import annotations

import hashlib
import io
import json
import struct
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from exfat_rescue.cli import _reparsed_manifest_candidates, main
from exfat_rescue.errors import ManifestError
from exfat_rescue.exporter import _export_staging_name
from exfat_rescue.manifest import read_manifest_v2, write_manifest_v2
from exfat_rescue.planner import plan_recovery
from exfat_rescue.recovery import _bootstrap_name
from exfat_rescue.scanner import HARD_MAX_CANDIDATES, scan
from exfat_rescue.source import ImageSource
from tests.fixture import entry, image


class RecoveryCliTests(unittest.TestCase):
    def _call(self, *arguments: str) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(list(arguments))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_scan_manifest_recover_verify_and_resume_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.img"
            manifest = root / "candidates.jsonl"
            output = root / "output"
            source.write_bytes(image())
            code, stdout, _ = self._call(
                "scan",
                str(source),
                "--manifest",
                str(manifest),
                "--max-candidates",
                str(HARD_MAX_CANDIDATES),
                "--json",
            )
            self.assertEqual(code, 0)
            self.assertTrue(json.loads(stdout)["ok"])
            parsed = read_manifest_v2(manifest)
            self.assertTrue(parsed.plans)
            self.assertEqual(
                parsed.header["scan_options"]["max_candidates"],
                HARD_MAX_CANDIDATES,
            )
            mismatch = root / "mismatched-limit-output"
            code, _stdout, stderr = self._call(
                "recover",
                str(source),
                "--manifest",
                str(manifest),
                "--output",
                str(mismatch),
                "--max-candidates",
                "100000",
                "--json",
            )
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(stderr)["error_code"], "usage_error")
            self.assertFalse(mismatch.exists())
            code, stdout, _ = self._call(
                "recover",
                str(source),
                "--manifest",
                str(manifest),
                "--output",
                str(output),
                "--max-selected-candidates",
                str(HARD_MAX_CANDIDATES),
                "--json",
            )
            self.assertEqual(code, 0)
            self.assertTrue(json.loads(stdout)["complete"])
            run = json.loads((output / "run.json").read_bytes())
            self.assertEqual(run["limits"]["max_candidates"], HARD_MAX_CANDIDATES)
            code, stdout, _ = self._call(
                "verify", str(output), "--image", str(source), "--json"
            )
            self.assertEqual(code, 0)
            self.assertTrue(json.loads(stdout)["image_verified"])
            code, stdout, _ = self._call(
                "verify-set", str(output), "--image", str(source), "--json"
            )
            self.assertEqual(code, 0)
            verification_set = json.loads(stdout)
            self.assertEqual(verification_set["command"], "verify-set")
            self.assertTrue(verification_set["shared_image_verification"])
            self.assertEqual(verification_set["output_count"], 1)
            with mock.patch.object(
                ImageSource,
                "sha256_region",
                autospec=True,
                wraps=ImageSource.sha256_region,
            ) as resume_hash:
                code, stdout, _ = self._call(
                    "recover", str(source), "--resume", str(output), "--json"
                )
            self.assertEqual(code, 0)
            resumed = json.loads(stdout)
            self.assertTrue(resumed["complete"])
            self.assertTrue(resumed["source_proof_reused"])
            self.assertEqual(resume_hash.call_count, 0)

            state = source.stat()
            source.touch()
            if source.stat().st_mtime_ns == state.st_mtime_ns:
                source.chmod(0o600)
            calls = 0
            original = ImageSource.sha256_region

            def counted_hash_region(
                current: ImageSource,
                offset: int,
                length: int,
                *,
                chunk_size: int = 1024 * 1024,
            ) -> str:
                nonlocal calls
                calls += 1
                return original(current, offset, length, chunk_size=chunk_size)

            with mock.patch.object(
                ImageSource,
                "sha256_region",
                autospec=True,
                side_effect=counted_hash_region,
            ):
                code, stdout, _ = self._call(
                    "recover", str(source), "--resume", str(output), "--json"
                )
            self.assertEqual(code, 0)
            self.assertFalse(json.loads(stdout)["source_proof_reused"])
            self.assertEqual(calls, 0)

    def test_manifest_reparse_requires_the_complete_candidate_inventory(self) -> None:
        retained = {"entry_offset": 1, "entry_set_sha256": "a" * 64}
        omitted = {"entry_offset": 2, "entry_set_sha256": "b" * 64}
        with self.assertRaises(ManifestError):
            _reparsed_manifest_candidates((retained,), [retained, omitted])

    def test_recovery_fuses_selected_volume_hash_into_cluster_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "source.img"
            source_path.write_bytes(image())
            original = ImageSource.sha256_region
            calls = 0

            def counted_hash_region(
                source: ImageSource,
                offset: int,
                length: int,
                *,
                chunk_size: int = 1024 * 1024,
            ) -> str:
                nonlocal calls
                calls += 1
                return original(source, offset, length, chunk_size=chunk_size)

            with mock.patch.object(
                ImageSource,
                "sha256_region",
                autospec=True,
                side_effect=counted_hash_region,
            ):
                code, stdout, _stderr = self._call(
                    "recover",
                    str(source_path),
                    "--output",
                    str(root / "output"),
                    "--json",
                )

            self.assertEqual(code, 0)
            self.assertTrue(json.loads(stdout)["complete"])
            self.assertEqual(calls, 0)

    def test_recovery_event_log_records_phases_progress_and_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.img"
            output = root / "output"
            event_log = root / "events.jsonl"
            source.write_bytes(image())

            code, stdout, stderr = self._call(
                "recover",
                str(source),
                "--output",
                str(output),
                "--event-log",
                str(event_log),
                "--json",
            )

            self.assertEqual(code, 0)
            self.assertEqual(stderr, "")
            self.assertTrue(json.loads(stdout)["complete"])
            self.assertEqual(event_log.stat().st_mode & 0o777, 0o600)
            events = [json.loads(line) for line in event_log.read_bytes().splitlines()]
            self.assertTrue(events)
            self.assertTrue(
                all(
                    event["format"] == "exfat-rescue.event" and event["version"] == 1
                    for event in events
                )
            )
            phases = {event.get("phase") for event in events}
            self.assertIn("scan-clusters", phases)
            self.assertIn("plan-recovery", phases)
            self.assertNotIn("hash-volume", phases)
            self.assertIn("recover-candidates", phases)
            self.assertEqual(events[-1]["event"], "complete")
            self.assertEqual(events[-1]["command"], "recover")

    def test_event_log_cannot_occupy_recovery_bootstrap_or_export_staging(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.img"
            output = root / "recovery"
            bootstrap = output.with_name(_bootstrap_name(output.name))
            source.write_bytes(image())

            code, _stdout, stderr = self._call(
                "recover",
                str(source),
                "--output",
                str(output),
                "--event-log",
                str(bootstrap),
                "--json",
            )

            self.assertEqual(code, 5)
            self.assertEqual(json.loads(stderr)["error_code"], "unsafe_output")
            self.assertFalse(output.exists())
            self.assertFalse(bootstrap.exists())

            destination = root / "exported"
            staging = destination.with_name(_export_staging_name(destination.name))
            code, _stdout, stderr = self._call(
                "export",
                str(root / "missing-recovery"),
                "--destination",
                str(destination),
                "--event-log",
                str(staging),
                "--json",
            )

            self.assertEqual(code, 5)
            self.assertEqual(json.loads(stderr)["error_code"], "unsafe_output")
            self.assertFalse(destination.exists())
            self.assertFalse(staging.exists())

    def test_root_recovery_and_export_targets_reject_before_event_log_creation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.img"
            source.write_bytes(image())
            recovery_log = root / "recovery-events.jsonl"

            code, _stdout, stderr = self._call(
                "recover",
                str(source),
                "--output",
                "/",
                "--event-log",
                str(recovery_log),
                "--json",
            )

            self.assertEqual(code, 5)
            self.assertEqual(json.loads(stderr)["error_code"], "unsafe_output")
            self.assertFalse(recovery_log.exists())

            export_log = root / "export-events.jsonl"
            code, _stdout, stderr = self._call(
                "export",
                str(root / "missing-recovery"),
                "--destination",
                "/",
                "--event-log",
                str(export_log),
                "--json",
            )

            self.assertEqual(code, 5)
            self.assertEqual(json.loads(stderr)["error_code"], "unsafe_output")
            self.assertFalse(export_log.exists())

    def test_valid_subset_manifest_cannot_hide_a_deleted_extent_overlap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "source.img"
            manifest_path = root / "subset.jsonl"
            output = root / "unsafe-output"
            data = bytearray(image())
            heap = struct.unpack_from("<I", data, 0x58)[0] * 512
            orphan = entry("orphan.txt", deleted=True, first_cluster=4)
            data[heap + 512 : heap + 512 + len(orphan)] = orphan
            source_path.write_bytes(data)
            source = ImageSource.open(source_path)
            try:
                scanned = scan(source)
                deleted = [
                    candidate
                    for candidate in scanned.candidates
                    if candidate["name"] == "Deleted.txt"
                ]
                subset = plan_recovery(
                    scanned.volume,
                    deleted,
                    active_owners=scanned.active_owners,
                    metadata_complete=scanned.metadata_complete,
                    ownership_complete=scanned.ownership_complete,
                )
                self.assertEqual(subset.plans[0].disposition, "recoverable")
                write_manifest_v2(
                    source,
                    manifest_path,
                    subset,
                    {
                        "orphan_scan": True,
                        "version": 2,
                        "volume_offset_bytes": scanned.volume.base_offset,
                        "source_kind": scanned.volume.location.source_kind,
                        "boot_region": scanned.volume.boot_region,
                        "max_candidates": 100,
                        "max_scan_clusters": 50_000_000,
                        "max_fat_steps": 10_000_000,
                    },
                )
                selected_id = subset.plans[0].candidate_id
            finally:
                source.close()

            code, _stdout, stderr = self._call(
                "recover",
                str(source_path),
                "--manifest",
                str(manifest_path),
                "--candidate-id",
                selected_id,
                "--output",
                str(output),
                "--json",
            )
            self.assertEqual(code, 7)
            self.assertEqual(json.loads(stderr)["error_code"], "invalid_manifest")
            self.assertFalse(output.exists())

    def test_unknown_or_duplicate_candidate_is_exit_two_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, manifest = root / "source.img", root / "candidates.jsonl"
            source.write_bytes(image())
            self.assertEqual(
                self._call("scan", str(source), "--manifest", str(manifest))[0], 0
            )
            candidate_id = read_manifest_v2(manifest).plans[0].candidate_id
            for selected, output in (
                ("f" * 64, root / "unknown"),
                (candidate_id, root / "duplicate"),
            ):
                arguments = [
                    "recover",
                    str(source),
                    "--manifest",
                    str(manifest),
                    "--output",
                    str(output),
                    "--candidate-id",
                    selected,
                    "--json",
                ]
                if output.name == "duplicate":
                    arguments.extend(["--candidate-id", candidate_id])
                code, _, stderr = self._call(*arguments)
                self.assertEqual(code, 2)
                self.assertFalse(output.exists())
                self.assertEqual(json.loads(stderr)["exit_code"], 2)

    def test_hostile_manifest_list_type_is_json_manifest_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, manifest = root / "source.img", root / "candidates.jsonl"
            source.write_bytes(image())
            self.assertEqual(
                self._call("scan", str(source), "--manifest", str(manifest))[0], 0
            )
            records = [json.loads(line) for line in manifest.read_bytes().splitlines()]
            records[0]["warnings"] = ["warning", 1]
            content = b"".join(
                json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
                + b"\n"
                for record in records[:-1]
            )
            records[-1] = {
                "record_type": "complete",
                "candidate_count": len(records) - 2,
                "content_record_count": len(records) - 1,
                "content_sha256": hashlib.sha256(content).hexdigest(),
            }
            manifest.write_bytes(
                content
                + json.dumps(
                    records[-1], sort_keys=True, separators=(",", ":")
                ).encode()
                + b"\n"
            )
            code, _stdout, stderr = self._call(
                "recover",
                str(source),
                "--manifest",
                str(manifest),
                "--output",
                str(root / "output"),
                "--json",
            )
            self.assertEqual(code, 7)
            self.assertEqual(json.loads(stderr)["error_code"], "invalid_manifest")

    def test_scan_max_candidates_accepts_hard_ceiling_and_rejects_hard_plus_one(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, manifest = root / "source.img", root / "candidates.jsonl"
            source.write_bytes(image())
            code, _stdout, _stderr = self._call(
                "scan",
                str(source),
                "--manifest",
                str(manifest),
                "--max-candidates",
                str(HARD_MAX_CANDIDATES),
                "--json",
            )
            self.assertEqual(code, 0)
            self.assertTrue(manifest.exists())
            code, _stdout, stderr = self._call(
                "scan",
                str(source),
                "--manifest",
                str(root / "too-many.jsonl"),
                "--max-candidates",
                str(HARD_MAX_CANDIDATES + 1),
                "--json",
            )
            self.assertEqual(code, 2)
            error = json.loads(stderr)
            self.assertEqual(error["error_code"], "usage_error")
            self.assertIn(str(HARD_MAX_CANDIDATES), error["error"])
            self.assertFalse((root / "too-many.jsonl").exists())

    def test_recovery_selected_candidate_limit_is_bounded(self) -> None:
        code, _stdout, stderr = self._call(
            "recover",
            "source.img",
            "--output",
            "output",
            "--max-selected-candidates",
            str(HARD_MAX_CANDIDATES + 1),
            "--json",
        )
        self.assertEqual(code, 2)
        error = json.loads(stderr)
        self.assertEqual(error["error_code"], "usage_error")
        self.assertIn("--max-selected-candidates", error["error"])

    def test_nonpositive_limits_fail_before_source_scan_or_event_log(self) -> None:
        cases = (
            ("scan", "--max-candidates"),
            ("scan", "--max-scan-clusters"),
            ("scan", "--max-fat-steps"),
            ("recover", "--max-output-bytes"),
            ("recover", "--max-candidates"),
            ("recover", "--max-selected-candidates"),
            ("recover", "--max-scan-clusters"),
            ("recover", "--max-fat-steps"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for command, option in cases:
                for value in ("0", "-1"):
                    with self.subTest(command=command, option=option, value=value):
                        image = root / f"{command}-{option[2:]}-{value}.img"
                        event_log = root / f"{command}-{option[2:]}-{value}.jsonl"
                        output = root / f"{command}-{option[2:]}-{value}-output"
                        arguments = [
                            command,
                            str(image),
                            "--event-log",
                            str(event_log),
                            option,
                            value,
                            "--json",
                        ]
                        if command == "scan":
                            arguments.extend(["--manifest", str(output)])
                        else:
                            arguments.extend(["--output", str(output)])
                        with (
                            mock.patch(
                                "exfat_rescue.cli.ImageSource.open"
                            ) as source_open,
                            mock.patch("exfat_rescue.cli.scan") as scanner,
                            mock.patch("exfat_rescue.cli._EventLog") as event_log_open,
                        ):
                            code, _stdout, stderr = self._call(*arguments)
                        self.assertEqual(code, 2)
                        self.assertEqual(
                            json.loads(stderr)["error_code"], "usage_error"
                        )
                        self.assertIn(option, json.loads(stderr)["error"])
                        source_open.assert_not_called()
                        scanner.assert_not_called()
                        event_log_open.assert_not_called()
                        self.assertFalse(event_log.exists())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
