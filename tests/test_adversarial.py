from __future__ import annotations

import hashlib
import json
import os
import random
import stat
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from exfat_rescue.cli import main
from exfat_rescue.errors import (
    FormatError,
    ManifestError,
    OutputError,
    ResourceLimitError,
    SourceError,
)
from exfat_rescue.exfat.entries import parse_entry_set
from exfat_rescue.exfat.volume import ExfatVolume
from exfat_rescue.manifest import read_manifest_v2, write_manifest
from exfat_rescue.scanner import HARD_MAX_CANDIDATES, scan
from exfat_rescue.source import ImageSource
from tests.fixture import entry, image


class AdversarialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "synthetic.img"
        self.path.write_bytes(image())

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_source_change_during_scan_is_refused(self) -> None:
        original = ExfatVolume.read_cluster
        mutated = False

        def mutate_once(volume: ExfatVolume, cluster: int) -> bytes:
            nonlocal mutated
            data = original(volume, cluster)
            if not mutated:
                mutated = True
                with self.path.open("r+b") as writer:
                    writer.seek(-1, os.SEEK_END)
                    writer.write(b"x")
                    writer.flush()
                    os.fsync(writer.fileno())
            return data

        source = ImageSource.open(self.path)
        try:
            with (
                patch.object(ExfatVolume, "read_cluster", new=mutate_once),
                self.assertRaises(SourceError),
            ):
                scan(source)
        finally:
            source.close()

    def test_candidate_and_cluster_limits_fail_closed(self) -> None:
        source = ImageSource.open(self.path)
        try:
            with self.assertRaises(ResourceLimitError) as configured:
                scan(source, max_candidates=2)
            self.assertIn(
                f"supported maximum is {HARD_MAX_CANDIDATES}",
                str(configured.exception),
            )
            with (
                patch("exfat_rescue.scanner.HARD_MAX_CANDIDATES", 2),
                self.assertRaises(ResourceLimitError) as hard,
            ):
                scan(source, max_candidates=2)
            self.assertIn("supported candidate ceiling of 2", str(hard.exception))
            self.assertIn("complete manifest cannot be produced", str(hard.exception))
            with self.assertRaises(ResourceLimitError):
                scan(source, max_scan_clusters=1)
        finally:
            source.close()

    def test_manifest_preflight_happens_before_scan(self) -> None:
        manifest = Path(self.temp.name) / "exists.jsonl"
        manifest.write_text("keep", encoding="utf-8")
        stderr = StringIO()
        with (
            patch("exfat_rescue.cli.scan") as scanner,
            redirect_stderr(stderr),
        ):
            self.assertEqual(
                main(["scan", str(self.path), "--manifest", str(manifest)]), 5
            )
        scanner.assert_not_called()
        self.assertEqual(manifest.read_text(encoding="utf-8"), "keep")

    def test_manifest_open_failure_after_preflight_is_stable_json(self) -> None:
        manifest = Path(self.temp.name) / "permission-lost.jsonl"
        original_open = os.open

        def deny_final_path(path, *args, **kwargs):
            if Path(path) == manifest:
                raise PermissionError(13, "synthetic permission loss")
            return original_open(path, *args, **kwargs)

        stderr = StringIO()
        with (
            patch("exfat_rescue.manifest.os.open", new=deny_final_path),
            redirect_stderr(stderr),
        ):
            exit_code = main(
                [
                    "scan",
                    str(self.path),
                    "--manifest",
                    str(manifest),
                    "--json",
                ]
            )
        response = json.loads(stderr.getvalue())
        self.assertEqual(exit_code, 5)
        self.assertEqual(response["error_code"], "unsafe_output")
        self.assertEqual(response["exit_code"], 5)
        self.assertFalse(manifest.exists())

    def test_json_cancellation_is_machine_readable(self) -> None:
        stderr = StringIO()
        with (
            patch("exfat_rescue.cli.ImageSource.open", side_effect=KeyboardInterrupt),
            redirect_stderr(stderr),
        ):
            self.assertEqual(main(["inspect", str(self.path), "--json"]), 130)
        response = json.loads(stderr.getvalue())
        self.assertEqual(response["error_code"], "cancelled")
        self.assertEqual(response["exit_code"], 130)

    def test_unsafe_path_components_are_not_candidates(self) -> None:
        source = ImageSource.open(self.path)
        try:
            volume = ExfatVolume(source)
            for name in (".", "..", "../escape", "back\\slash", "line\nbreak"):
                with self.subTest(name=name):
                    self.assertIsNone(parse_entry_set(entry(name), 0, volume, 0))
        finally:
            source.close()

    def test_structured_random_mutations_do_not_escape_domain_errors(self) -> None:
        generator = random.Random(0xEFA7)
        original = image()
        for case in range(100):
            mutated = bytearray(original)
            for _ in range(generator.randint(1, 8)):
                offset = generator.randrange(len(mutated))
                mutated[offset] ^= generator.randrange(1, 256)
            path = Path(self.temp.name) / f"mutated-{case}.img"
            path.write_bytes(mutated)
            source = ImageSource.open(path)
            try:
                try:
                    scan(source, max_candidates=100, max_scan_clusters=100)
                except (FormatError, ResourceLimitError):
                    pass
            finally:
                source.close()

    def test_manifest_records_validate_against_packaged_schema(self) -> None:
        import importlib.resources

        import jsonschema

        manifest = Path(self.temp.name) / "manifest.jsonl"
        self.assertEqual(
            main(
                [
                    "scan",
                    str(self.path),
                    "--manifest",
                    str(manifest),
                    "--json",
                ]
            ),
            0,
        )
        schema_path = importlib.resources.files("exfat_rescue.schemas").joinpath(
            "manifest-v2.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        lines = manifest.read_bytes().splitlines(keepends=True)
        records = [json.loads(line) for line in lines]
        for record in records:
            jsonschema.validate(record, schema)
        completion = records[-1]
        self.assertEqual(completion["record_type"], "complete")
        self.assertEqual(completion["content_record_count"], len(records) - 1)
        self.assertEqual(
            completion["candidate_count"],
            sum(record["record_type"] == "candidate" for record in records),
        )
        self.assertEqual(
            completion["content_sha256"],
            hashlib.sha256(b"".join(lines[:-1])).hexdigest(),
        )
        self.assertEqual(stat.S_IMODE(manifest.stat().st_mode), 0o600)

    def test_failed_manifest_write_leaves_detectable_partial_output(self) -> None:
        manifest = Path(self.temp.name) / "partial.jsonl"
        source = ImageSource.open(self.path)
        try:
            result = scan(source)
            options = {
                "orphan_scan": True,
                "version": 1,
                "volume_offset_bytes": result.volume.base_offset,
                "source_kind": result.volume.location.source_kind,
                "boot_region": result.volume.boot_region,
                "max_candidates": 100_000,
                "max_scan_clusters": 50_000_000,
            }
            with (
                patch(
                    "exfat_rescue.manifest.json.dumps",
                    side_effect=OSError("synthetic write failure"),
                ),
                self.assertRaises(OutputError),
            ):
                write_manifest(
                    source,
                    manifest,
                    result.candidates,
                    options,
                    result.source_fingerprint,
                    result.warnings,
                )
        finally:
            source.close()
        self.assertTrue(manifest.exists())
        records = [
            json.loads(line)
            for line in manifest.read_text(encoding="utf-8").splitlines()
        ]
        self.assertFalse(records)

    def test_replacement_race_never_deletes_the_replacement(self) -> None:
        manifest = Path(self.temp.name) / "replaced.jsonl"
        source = ImageSource.open(self.path)
        try:
            result = scan(source)
            options = {
                "orphan_scan": True,
                "version": 1,
                "volume_offset_bytes": result.volume.base_offset,
                "source_kind": result.volume.location.source_kind,
                "boot_region": result.volume.boot_region,
                "max_candidates": 100_000,
                "max_scan_clusters": 50_000_000,
            }
            original_assert = ImageSource.assert_unchanged
            calls = 0

            def replace_path(
                instance: ImageSource, fingerprint: dict[str, object] | None = None
            ) -> None:
                nonlocal calls
                calls += 1
                original_assert(instance, fingerprint)
                if instance is source and calls == 2:
                    manifest.unlink()
                    manifest.write_text("UNRELATED USER FILE", encoding="utf-8")

            with (
                patch.object(ImageSource, "assert_unchanged", new=replace_path),
                self.assertRaises(OutputError),
            ):
                write_manifest(
                    source,
                    manifest,
                    result.candidates,
                    options,
                    result.source_fingerprint,
                    result.warnings,
                )
        finally:
            source.close()
        self.assertEqual(manifest.read_text(encoding="utf-8"), "UNRELATED USER FILE")

    def test_legacy_writer_rejects_mutation_during_final_source_check(self) -> None:
        manifest = Path(self.temp.name) / "legacy-mutated.jsonl"
        source = ImageSource.open(self.path)
        try:
            result = scan(source)
            options = {
                "orphan_scan": True,
                "version": 1,
                "volume_offset_bytes": result.volume.base_offset,
                "source_kind": result.volume.location.source_kind,
                "boot_region": result.volume.boot_region,
                "max_candidates": 100_000,
                "max_scan_clusters": 50_000_000,
            }
            original_assert = ImageSource.assert_unchanged
            calls = 0

            def mutate_output(
                instance: ImageSource, fingerprint: dict[str, object] | None = None
            ) -> None:
                nonlocal calls
                original_assert(instance, fingerprint)
                if instance is source:
                    calls += 1
                    if calls == 2:
                        with manifest.open("r+b") as output:
                            output.seek(0)
                            output.write(b"X")
                            output.flush()
                            os.fsync(output.fileno())

            with (
                patch.object(ImageSource, "assert_unchanged", new=mutate_output),
                self.assertRaises(OutputError),
            ):
                write_manifest(
                    source,
                    manifest,
                    result.candidates,
                    options,
                    result.source_fingerprint,
                    result.warnings,
                )
            self.assertTrue(manifest.exists())
            self.assertNotEqual(manifest.read_bytes()[:1], b"{")
        finally:
            source.close()

    def test_legacy_writer_rechecks_source_after_completion_write(self) -> None:
        manifest = Path(self.temp.name) / "legacy-source-mutated.jsonl"
        source = ImageSource.open(self.path)
        try:
            result = scan(source)
            options = {
                "orphan_scan": True,
                "version": 1,
                "volume_offset_bytes": result.volume.base_offset,
                "source_kind": result.volume.location.source_kind,
                "boot_region": result.volume.boot_region,
                "max_candidates": 100_000,
                "max_scan_clusters": 50_000_000,
            }
            import exfat_rescue.manifest as manifest_module

            original_line = manifest_module._line
            mutated = False

            def mutate_source(record: dict[str, object]) -> str:
                nonlocal mutated
                line = original_line(record)
                if record.get("record_type") == "complete" and not mutated:
                    mutated = True
                    with self.path.open("r+b") as image_file:
                        image_file.seek(-1, os.SEEK_END)
                        image_file.write(b"X")
                        image_file.flush()
                        os.fsync(image_file.fileno())
                return line

            with (
                patch("exfat_rescue.manifest._line", new=mutate_source),
                self.assertRaises(SourceError),
            ):
                write_manifest(
                    source,
                    manifest,
                    result.candidates,
                    options,
                    result.source_fingerprint,
                    result.warnings,
                )
            self.assertTrue(manifest.exists())
        finally:
            source.close()

    def test_legacy_writer_rechecks_source_after_final_manifest_state(self) -> None:
        manifest = Path(self.temp.name) / "legacy-source-state-mutated.jsonl"
        source = ImageSource.open(self.path)
        try:
            result = scan(source)
            options = {
                "orphan_scan": True,
                "version": 1,
                "volume_offset_bytes": result.volume.base_offset,
                "source_kind": result.volume.location.source_kind,
                "boot_region": result.volume.boot_region,
                "max_candidates": 100_000,
                "max_scan_clusters": 50_000_000,
            }
            import exfat_rescue.manifest as manifest_module

            original_assert = manifest_module._assert_final_manifest_state

            def assert_then_mutate(*args: object, **kwargs: object) -> None:
                original_assert(*args, **kwargs)
                with self.path.open("r+b") as image_file:
                    image_file.seek(-1, os.SEEK_END)
                    image_file.write(b"X")
                    image_file.flush()
                    os.fsync(image_file.fileno())

            with (
                patch(
                    "exfat_rescue.manifest._assert_final_manifest_state",
                    new=assert_then_mutate,
                ),
                self.assertRaises(SourceError),
            ):
                write_manifest(
                    source,
                    manifest,
                    result.candidates,
                    options,
                    result.source_fingerprint,
                    result.warnings,
                )
            self.assertTrue(manifest.exists())
        finally:
            source.close()

    def test_scan_refuses_manifest_mutated_during_final_source_check(self) -> None:
        manifest = Path(self.temp.name) / "scan-mutated.jsonl"
        original_assert = ImageSource.assert_unchanged

        def mutate_output(
            instance: ImageSource, fingerprint: dict[str, object] | None = None
        ) -> None:
            original_assert(instance, fingerprint)
            if manifest.exists():
                with manifest.open("r+b") as output:
                    output.seek(0)
                    output.write(b"X")
                    output.flush()
                    os.fsync(output.fileno())

        with patch.object(ImageSource, "assert_unchanged", new=mutate_output):
            self.assertEqual(
                main(["scan", str(self.path), "--manifest", str(manifest)]), 5
            )
        self.assertTrue(manifest.exists())
        with self.assertRaises(ManifestError):
            read_manifest_v2(manifest)

    def test_hostile_manifest_enum_types_are_json_manifest_errors(self) -> None:
        manifest = Path(self.temp.name) / "hostile-enums.jsonl"
        self.assertEqual(main(["scan", str(self.path), "--manifest", str(manifest)]), 0)
        records = [json.loads(line) for line in manifest.read_bytes().splitlines()]
        for path, value in (
            ((1, "allocation_mode"), []),
            ((1, "metadata_location"), {}),
            ((1, "disposition"), []),
            ((1, "recovery_basis"), {}),
            ((1, "source_candidate", "location"), []),
            ((0, "source", "source_kind"), {}),
            ((0, "source", "boot_region"), []),
        ):
            changed = json.loads(json.dumps(records))
            target: object = changed
            for component in path[:-1]:
                target = target[component]  # type: ignore[index]
            target[path[-1]] = value  # type: ignore[index]
            content = b"".join(
                json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
                + b"\n"
                for record in changed[:-1]
            )
            changed[-1] = {
                "record_type": "complete",
                "candidate_count": len(changed) - 2,
                "content_record_count": len(changed) - 1,
                "content_sha256": hashlib.sha256(content).hexdigest(),
            }
            manifest.write_bytes(
                content
                + json.dumps(
                    changed[-1], sort_keys=True, separators=(",", ":")
                ).encode()
                + b"\n"
            )
            stderr = StringIO()
            with self.subTest(path=path, value=value), redirect_stderr(stderr):
                code = main(
                    [
                        "recover",
                        str(self.path),
                        "--manifest",
                        str(manifest),
                        "--output",
                        str(Path(self.temp.name) / "output"),
                        "--json",
                    ]
                )
            self.assertEqual(code, 7)
            self.assertEqual(
                json.loads(stderr.getvalue())["error_code"], "invalid_manifest"
            )


if __name__ == "__main__":
    unittest.main()
