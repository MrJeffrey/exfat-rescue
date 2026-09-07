from __future__ import annotations

import hashlib
import importlib.resources
import json
import os
import struct
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from exfat_rescue.cli import main
from exfat_rescue.errors import FormatError, SourceError
from exfat_rescue.exfat.volume import ExfatVolume
from exfat_rescue.scanner import scan
from exfat_rescue.source import ImageSource
from tests.fixture import gpt_image, image, mbr_image, refresh_boot_checksums


class MVPTests(unittest.TestCase):
    def test_manifest_schema_is_packaged(self) -> None:
        schema_path = importlib.resources.files("exfat_rescue.schemas").joinpath(
            "manifest-v2.json"
        )
        self.assertTrue(schema_path.is_file())
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(schema["title"], "exfat-rescue JSONL record v2")

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "synthetic.img"
        self.path.write_bytes(image())

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_inspect_valid_image_and_json_cli(self) -> None:
        stdout = StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(main(["inspect", str(self.path), "--json"]), 0)
        response = json.loads(stdout.getvalue())
        self.assertTrue(response["ok"])
        self.assertEqual(response["source_kind"], "direct-image")
        self.assertEqual(response["volume_offset_bytes"], 0)
        source = ImageSource.open(self.path)
        try:
            self.assertEqual(ExfatVolume(source).boot.cluster_size, 512)
        finally:
            source.close()

    def test_deterministic_active_deleted_orphan_scan(self) -> None:
        source = ImageSource.open(self.path)
        try:
            one = scan(source)
            two = scan(source)
        finally:
            source.close()
        self.assertEqual(one.candidates, two.candidates)
        self.assertEqual(
            [item["name"] for item in one.candidates],
            [item["name"] for item in two.candidates],
        )
        self.assertEqual(
            {item["name"] for item in one.candidates},
            {"Active.txt", "Deleted.txt", "orphan.txt"},
        )
        self.assertTrue(any(item["location"] == "orphan" for item in one.candidates))

    def test_scan_progress_has_an_exact_zero_baseline(self) -> None:
        source = ImageSource.open(self.path)
        events: list[tuple[int, int]] = []
        try:
            result = scan(
                source,
                progress=lambda completed, total: events.append((completed, total)),
            )
        finally:
            source.close()
        self.assertEqual(events[0], (0, result.scanned_clusters))
        self.assertEqual(events[-1], (result.scanned_clusters, result.scanned_clusters))

    def test_corrupt_and_truncated_images_rejected(self) -> None:
        corrupt = Path(self.temp.name) / "corrupt.img"
        corrupt.write_bytes(image(corrupt_boot=True))
        source = ImageSource.open(corrupt)
        with self.assertRaises(FormatError):
            ExfatVolume(source)
        source.close()

        oversized_cluster = bytearray(image())
        oversized_cluster[0x6C:0x6E] = bytes((12, 20))
        oversized_cluster[12 * 512 + 0x6C : 12 * 512 + 0x6E] = bytes((12, 20))
        refresh_boot_checksums(oversized_cluster)
        oversized_path = Path(self.temp.name) / "oversized-cluster.img"
        oversized_path.write_bytes(oversized_cluster)
        source = ImageSource.open(oversized_path)
        with self.assertRaises(FormatError):
            ExfatVolume(source)
        source.close()

        outside_fat = bytearray(image())
        struct.pack_into("<II", outside_fat, 0x50, 19, 2)
        struct.pack_into("<II", outside_fat, 12 * 512 + 0x50, 19, 2)
        refresh_boot_checksums(outside_fat)
        outside_fat_path = Path(self.temp.name) / "outside-fat.img"
        outside_fat_path.write_bytes(outside_fat)
        source = ImageSource.open(outside_fat_path)
        with self.assertRaises(FormatError):
            ExfatVolume(source)
        source.close()
        truncated = Path(self.temp.name) / "truncated.img"
        truncated.write_bytes(image(truncated=True))
        source = ImageSource.open(truncated)
        with self.assertRaises(FormatError):
            ExfatVolume(source)
        source.close()

    def test_manifest_refuses_existing_and_source_alias(self) -> None:
        manifest = Path(self.temp.name) / "manifest.jsonl"
        self.assertEqual(main(["scan", str(self.path), "--manifest", str(manifest)]), 0)
        self.assertEqual(main(["scan", str(self.path), "--manifest", str(manifest)]), 5)
        self.assertEqual(
            main(["scan", str(self.path), "--manifest", str(self.path)]), 5
        )
        records = [json.loads(line) for line in manifest.read_text().splitlines()]
        self.assertEqual(records[0]["version"], 2)
        self.assertEqual(records[0]["scan_options"]["source_kind"], "direct-image")

    def test_source_open_is_never_writable(self) -> None:
        original = os.open
        seen: list[int] = []

        def guarded(path, flags, *args, **kwargs):
            if Path(path) == self.path:
                seen.append(flags)
                self.assertFalse(
                    flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
                )
            return original(path, flags, *args, **kwargs)

        manifest = Path(self.temp.name) / "source-proof.jsonl"
        with (
            patch("exfat_rescue.source.os.open", side_effect=guarded),
            redirect_stdout(StringIO()),
        ):
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
        self.assertEqual(len(seen), 1)

    def test_source_descriptor_closes_if_post_open_validation_fails(self) -> None:
        real_open = os.open
        real_close = os.close
        descriptor = real_open(self.path, os.O_RDONLY)
        with (
            patch("exfat_rescue.source.os.open", return_value=descriptor),
            patch("exfat_rescue.source.os.fstat", side_effect=OSError("synthetic")),
            patch("exfat_rescue.source.os.close", wraps=real_close) as close,
            self.assertRaises(SourceError),
        ):
            ImageSource.open(self.path)
        close.assert_called_once_with(descriptor)

    def test_non_regular_source_rejected(self) -> None:
        with self.assertRaises(SourceError):
            ImageSource.open(self.temp.name)

    def test_names_are_preserved_without_case_or_unicode_normalization(self) -> None:
        # exFAT stores UTF-16 names. The manifest preserves the forensic spelling;
        # callers, not the scanner, decide whether names collide after normalization.
        from exfat_rescue.exfat.entries import parse_entry_set
        from tests.fixture import entry

        source = ImageSource.open(self.path)
        try:
            volume = ExfatVolume(source)
            for name in ("report", "report", "REPORT", "e\u0301", "é"):
                parsed = parse_entry_set(entry(name), 0, volume, 0)
                self.assertEqual(parsed["name"], name)
        finally:
            source.close()

    def test_timestamp_only_claims_a_timezone_when_exfat_records_one(self) -> None:
        from exfat_rescue.exfat.entries import parse_entry_set
        from tests.fixture import entry

        source = ImageSource.open(self.path)
        try:
            volume = ExfatVolume(source)
            unknown = parse_entry_set(entry("unknown.txt"), 0, volume, 0)
            known = parse_entry_set(
                entry("known.txt", utc_offset_quarters=8), 0, volume, 0
            )
        finally:
            source.close()

        self.assertIsNone(unknown["modified_utc_offset_minutes"])
        self.assertNotIn("+", unknown["modified_at"])
        self.assertEqual(known["modified_utc_offset_minutes"], 120)
        self.assertTrue(known["modified_at"].endswith("+02:00"))

    def test_active_entry_rejects_deleted_secondary_types(self) -> None:
        from exfat_rescue.exfat.entries import entry_set_checksum, parse_entry_set
        from tests.fixture import entry

        mixed = bytearray(entry("mixed.txt"))
        mixed[32] = 0x40
        struct.pack_into("<H", mixed, 2, entry_set_checksum(mixed))
        source = ImageSource.open(self.path)
        try:
            volume = ExfatVolume(source)
            self.assertIsNone(parse_entry_set(mixed, 0, volume, 0))
        finally:
            source.close()

    def test_json_error_is_machine_readable(self) -> None:
        bad = Path(self.temp.name) / "not-exfat.img"
        bad.write_bytes(b"x" * 512)
        stderr = StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(main(["inspect", str(bad), "--json"]), 4)
        message = json.loads(stderr.getvalue())
        self.assertEqual(message["exit_code"], 4)
        self.assertEqual(message["error_code"], "invalid_exfat_image")
        self.assertFalse(message["ok"])

    def test_mbr_and_gpt_discovery_and_scan_match_direct_image(self) -> None:
        expected_digest = hashlib.sha256(image()).hexdigest()
        direct = ImageSource.open(self.path)
        try:
            expected = scan(direct)
            with patch.object(
                ImageSource,
                "sha256_region",
                autospec=True,
                side_effect=AssertionError("scan failed to retain its fused digest"),
            ):
                self.assertEqual(
                    direct.selected_volume_sha256(
                        expected.volume.base_offset, expected.volume.boot.volume_bytes
                    ),
                    expected_digest,
                )
        finally:
            direct.close()
        for kind, contents, offset in (
            ("mbr", mbr_image(), 512),
            ("gpt", gpt_image(), 34 * 512),
        ):
            path = Path(self.temp.name) / f"{kind}.img"
            path.write_bytes(contents)
            source = ImageSource.open(path)
            try:
                result = scan(source)
                self.assertEqual(result.volume.location.source_kind, kind)
                self.assertEqual(result.volume.base_offset, offset)
                self.assertEqual(
                    sorted(x["name"] for x in result.candidates),
                    sorted(x["name"] for x in expected.candidates),
                )
                with patch.object(
                    ImageSource,
                    "sha256_region",
                    autospec=True,
                    side_effect=AssertionError(
                        "partition scan failed to retain its fused digest"
                    ),
                ):
                    self.assertEqual(
                        source.selected_volume_sha256(
                            result.volume.base_offset,
                            result.volume.boot.volume_bytes,
                        ),
                        expected_digest,
                    )
            finally:
                source.close()

    def test_scan_rejects_a_conflicting_resume_digest(self) -> None:
        source = ImageSource.open(self.path)
        try:
            volume = ExfatVolume(source)
            self.assertTrue(
                source.reuse_selected_volume_digest(
                    volume.base_offset,
                    volume.boot.volume_bytes,
                    "0" * 64,
                    source.proof_state(),
                )
            )
            with self.assertRaises(SourceError):
                scan(source)
        finally:
            source.close()

    def test_ambiguous_and_corrupt_partition_tables_refused(self) -> None:
        for name, contents in (
            ("ambiguous.img", mbr_image(ambiguous=True)),
            ("bad-gpt.img", gpt_image(corrupt_table=True)),
            ("short-gpt.img", gpt_image(truncated_table=True)),
        ):
            path = Path(self.temp.name) / name
            path.write_bytes(contents)
            source = ImageSource.open(path)
            try:
                with self.assertRaises(FormatError):
                    ExfatVolume(source)
            finally:
                source.close()
