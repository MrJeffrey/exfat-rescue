from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from exfat_rescue.errors import FormatError
from exfat_rescue.exfat.volume import ExfatVolume
from exfat_rescue.scanner import scan
from exfat_rescue.source import ImageSource
from tests.fixture import image, refresh_boot_checksums


class BootRegionValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def volume(self, contents: bytes) -> ExfatVolume:
        path = Path(self.temp.name) / "image.img"
        path.write_bytes(contents)
        self.addCleanup(lambda: None)
        source = ImageSource.open(path)
        self.addCleanup(source.close)
        return ExfatVolume(source)

    def both(self, data: bytearray, offset: int, value: bytes) -> None:
        data[offset : offset + len(value)] = value
        data[12 * 512 + offset : 12 * 512 + offset + len(value)] = value
        refresh_boot_checksums(data)

    def test_bad_primary_checksum_uses_valid_backup(self) -> None:
        data = bytearray(image())
        data[11 * 512] ^= 1
        volume = self.volume(bytes(data))
        self.assertEqual(volume.boot_region, "backup")

    def test_both_boot_region_checksums_corrupt_are_rejected(self) -> None:
        data = bytearray(image())
        data[11 * 512] ^= 1
        data[23 * 512] ^= 1
        with self.assertRaises(FormatError):
            self.volume(bytes(data))

    def test_must_be_zero_number_of_fats_and_revision_are_validated(self) -> None:
        for offset, value in ((0x0B, b"\x01"), (0x6E, b"\x03"), (0x68, b"\x01\x02")):
            data = bytearray(image())
            self.both(data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(FormatError):
                self.volume(bytes(data))

    def test_fat_heap_overlap_is_rejected(self) -> None:
        data = bytearray(image())
        self.both(data, 0x58, struct.pack("<I", 24))
        with self.assertRaises(FormatError):
            self.volume(bytes(data))

    def test_cluster_count_must_match_declared_heap_geometry(self) -> None:
        data = bytearray(image())
        # A valid boot checksum cannot make trailing whole allocation units
        # invisible to a bounded scanner.
        self.both(data, 0x5C, struct.pack("<I", 15))
        with self.assertRaises(FormatError):
            self.volume(bytes(data))

    def test_minimum_volume_and_extended_boot_signatures_are_validated(self) -> None:
        data = bytearray(image())
        self.both(data, 0x48, struct.pack("<Q", 1024))
        with self.assertRaises(FormatError):
            self.volume(bytes(data))

        data = bytearray(image())
        self.both(data, 0x5C, struct.pack("<I", 2))
        with self.assertRaises(FormatError):
            self.volume(bytes(data))

        data = bytearray(image())
        self.both(data, 2 * 512 - 4, b"\0" * 4)
        with self.assertRaises(FormatError):
            self.volume(bytes(data))

    def test_active_second_fat_is_selected(self) -> None:
        volume = self.volume(image(number_of_fats=2, active_second_fat=True))
        self.assertEqual(volume.boot.active_fat, 1)
        self.assertEqual(volume.fat_next(2), 0x12345678)

    def test_contiguous_cluster_reads_are_exact_and_bounded(self) -> None:
        volume = self.volume(image())
        self.assertEqual(
            volume.read_clusters(2, 2),
            volume.read_cluster(2) + volume.read_cluster(3),
        )
        for first_cluster, count in ((1, 1), (2, 0), (2, True), (17, 2)):
            with (
                self.subTest(first_cluster=first_cluster, count=count),
                self.assertRaises(FormatError),
            ):
                volume.read_clusters(first_cluster, count)
        with (
            patch.object(ImageSource, "read_at", autospec=True, return_value=b""),
            self.assertRaises(FormatError),
        ):
            volume.read_clusters(2, 1)

    def test_backup_fallback_uses_current_main_active_fat_flag(self) -> None:
        data = bytearray(image(number_of_fats=2))
        struct.pack_into("<H", data, 0x6A, 1)
        struct.pack_into("<H", data, 12 * 512 + 0x6A, 0)
        data[11 * 512] ^= 1
        volume = self.volume(bytes(data))
        self.assertEqual(volume.boot_region, "backup")
        self.assertEqual(volume.boot.active_fat, 1)
        self.assertEqual(volume.fat_next(2), 0xFFFFFFFF)
        self.assertIn(
            "backup_geometry_with_main_active_fat", scan(volume.source).warnings
        )

    def test_backup_geometry_uses_all_current_main_volume_flags(self) -> None:
        data = bytearray(image(number_of_fats=2))
        # VolumeDirty and MediaFailure are current-state bits. They are not
        # covered by the boot checksum and must not come from the backup.
        struct.pack_into("<H", data, 0x6A, 0x0007)
        struct.pack_into("<H", data, 12 * 512 + 0x6A, 0)
        data[11 * 512] ^= 1
        volume = self.volume(bytes(data))
        self.assertEqual(volume.boot_region, "backup")
        self.assertEqual(volume.boot.flags, 0x0007)
        self.assertTrue(volume.boot.volume_dirty)
        self.assertTrue(volume.boot.media_failure)

    def test_clear_to_zero_volume_flag_is_accepted(self) -> None:
        data = bytearray(image())
        self.both(data, 0x6A, struct.pack("<H", 0x0008))
        self.assertEqual(self.volume(bytes(data)).boot.flags, 0x0008)

    def test_backup_fallback_rejects_reserved_current_main_volume_flag(self) -> None:
        data = bytearray(image())
        struct.pack_into("<H", data, 0x6A, 0x0010)
        data[11 * 512] ^= 1
        with self.assertRaises(FormatError):
            self.volume(bytes(data))
