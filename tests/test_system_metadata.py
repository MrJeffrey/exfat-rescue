from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from exfat_rescue.errors import FormatError
from exfat_rescue.exfat.entries import entry_set_checksum, parse_entry_set
from exfat_rescue.exfat.volume import ChainStatus, ExfatVolume
from exfat_rescue.scanner import scan
from exfat_rescue.source import ImageSource
from tests.fixture import entry, image, refresh_boot_checksums, upcase_checksum


class SystemMetadataTests(unittest.TestCase):
    def test_full_uncompressed_upcase_table_accepts_literal_final_ffff(self) -> None:
        mapping = [
            code_unit - 0x20 if 0x61 <= code_unit <= 0x7A else code_unit
            for code_unit in range(0x10000)
        ]
        encoded = struct.pack("<65536H", *mapping)
        self.assertEqual(ExfatVolume._decompress_upcase(encoded), tuple(mapping))

    def test_upcase_decoder_rejects_expansion_beyond_unicode_word_space(self) -> None:
        encoded = struct.pack("<65537H", *(0 for _ in range(65537)))
        with self.assertRaisesRegex(FormatError, "expands beyond"):
            ExfatVolume._decompress_upcase(encoded)

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def volume(self, contents: bytes) -> ExfatVolume:
        path = Path(self.temp.name) / "image.img"
        path.write_bytes(contents)
        source = ImageSource.open(path)
        self.addCleanup(source.close)
        return ExfatVolume(source)

    @staticmethod
    def heap(data: bytes | bytearray) -> int:
        return struct.unpack_from("<I", data, 0x58)[0] * 512

    def test_bitmap_and_mandatory_upcase_table_are_loaded(self) -> None:
        metadata = self.volume(image()).load_system_metadata()
        self.assertEqual(metadata.active_bitmap.identifier, 0)
        self.assertTrue(metadata.active_bitmap.is_allocated(2))
        self.assertFalse(metadata.active_bitmap.is_allocated(4))
        self.assertEqual(metadata.upcase_table.uppercase(ord("a")), ord("A"))

    def test_active_bitmap_follows_active_fat(self) -> None:
        data = bytearray(image(number_of_fats=2))
        # The first bitmap says root is free; the second remains the valid fixture.
        heap = self.heap(data)
        data[heap + (7 - 2) * 512] &= ~1
        for base in (0, 12 * 512):
            struct.pack_into("<H", data, base + 0x6A, 1)
        refresh_boot_checksums(data)
        metadata = self.volume(bytes(data)).load_system_metadata()
        self.assertEqual(metadata.active_bitmap.identifier, 1)
        self.assertTrue(metadata.active_bitmap.is_allocated(2))

    def test_missing_duplicate_and_invalid_bitmap_identifiers_are_rejected(
        self,
    ) -> None:
        for change in ("missing", "duplicate", "identifier"):
            data = bytearray(image(number_of_fats=2))
            root = self.heap(data)
            if change == "missing":
                data[root + 32] = 0
            elif change == "duplicate":
                data[root + 33] = 0
            else:
                data[root + 1] = 2
            with self.subTest(change=change), self.assertRaises(FormatError):
                self.volume(bytes(data)).load_system_metadata()

    def test_upcase_checksum_and_compression_are_validated(self) -> None:
        data = bytearray(image())
        data[self.heap(data) + (8 - 2) * 512] ^= 1
        with self.assertRaises(FormatError):
            self.volume(bytes(data)).load_system_metadata()

    def test_overlong_upcase_data_length_is_rejected_before_chain_read(self) -> None:
        data = bytearray(image())
        root_upcase = self.heap(data) + 32
        struct.pack_into("<Q", data, root_upcase + 24, 0x20002)
        volume = self.volume(bytes(data))
        original = volume._read_chain_data

        def reject_overlong(chain, length, *, max_bytes):
            if length > 0x20000:
                self.fail("overlong Up-case Table reached _read_chain_data")
            return original(chain, length, max_bytes=max_bytes)

        with (
            patch.object(volume, "_read_chain_data", side_effect=reject_overlong),
            self.assertRaisesRegex(FormatError, "canonical UTF-16"),
        ):
            volume.load_system_metadata()

        data = bytearray(image())
        root_upcase = self.heap(data) + 32
        upcase_offset = self.heap(data) + (8 - 2) * 512
        identity = struct.pack("<HHHH", 0xFFFF, 0xFFFF, 0xFFFF, 1)
        data[upcase_offset : upcase_offset + len(identity)] = identity
        struct.pack_into("<Q", data, root_upcase + 24, len(identity))
        struct.pack_into("<I", data, root_upcase + 4, upcase_checksum(identity))
        with self.assertRaises(FormatError):
            self.volume(bytes(data)).load_system_metadata()

        data = bytearray(image())
        upcase_offset = self.heap(data) + (8 - 2) * 512
        struct.pack_into("<HHHH", data, upcase_offset, 0xFFFF, 0, 0xFFFF, 1)
        root_upcase = self.heap(data) + 32
        struct.pack_into(
            "<I",
            data,
            root_upcase + 4,
            upcase_checksum(data[upcase_offset : upcase_offset + 8]),
        )
        with self.assertRaises(FormatError):
            self.volume(bytes(data)).load_system_metadata()

    def test_name_hash_is_required_for_active_entries(self) -> None:
        volume = self.volume(image())
        record = bytearray(entry("name.txt"))
        record[36] ^= 1
        struct.pack_into("<H", record, 2, entry_set_checksum(record))
        self.assertIsNone(parse_entry_set(record, 0, volume, 0))

    def test_chain_statuses_distinguish_exact_and_invalid_terminators(self) -> None:
        fat = 24 * 512

        # Reopen each mutation because ImageSource deliberately exposes read-only bytes.
        cases = (
            (3, 0xFFFFFFF8, 1, ChainStatus.INVALID_NEXT),
            (3, 0xFFFFFFFF, 1, ChainStatus.EXACT),
            (3, 0xFFFFFFF7, 1, ChainStatus.BAD_CLUSTER),
            (3, 3, 2, ChainStatus.CYCLE),
            (3, 0xFFFFFFFF, 2, ChainStatus.SHORT),
            (3, 4, 1, ChainStatus.OVERLONG),
            (3, 4, 2, ChainStatus.EXACT),
        )
        for first, next_value, expected, status in cases:
            data = bytearray(image())
            struct.pack_into("<I", data, fat + first * 4, next_value)
            if status is ChainStatus.OVERLONG or (
                status is ChainStatus.EXACT and next_value == 4
            ):
                struct.pack_into("<I", data, fat + 4 * 4, 0xFFFFFFFF)
            with self.subTest(status=status):
                result = self.volume(bytes(data)).cluster_chain(
                    first, cap=8, expected_clusters=expected
                )
                self.assertEqual(result.status, status)

    def test_chain_reports_truncated_reads_and_work_limits(self) -> None:
        volume = self.volume(image())
        with patch.object(volume, "fat_next", side_effect=FormatError("truncated")):
            self.assertEqual(
                volume.cluster_chain(3, cap=8).status, ChainStatus.TRUNCATED_READ
            )
        self.assertEqual(volume.cluster_chain(3, cap=0).status, ChainStatus.WORK_LIMIT)

    def test_system_metadata_uses_each_bitmap_fat_and_active_bitmap_owns_all_metadata(
        self,
    ) -> None:
        data = bytearray(image(number_of_fats=2))
        for base in (0, 12 * 512):
            struct.pack_into("<H", data, base + 0x6A, 1)
        refresh_boot_checksums(data)
        fat = 24 * 512
        heap = self.heap(data)
        # Make each bitmap two clusters long. Bitmap 0 is described only by
        # FAT 0 and bitmap 1 only by FAT 1; loading both through ActiveFat
        # would make bitmap 0 appear short.
        for record_offset in (0, 32):
            struct.pack_into("<Q", data, heap + record_offset + 24, 513)
        struct.pack_into("<I", data, fat + 7 * 4, 10)
        struct.pack_into("<I", data, fat + 10 * 4, 0xFFFFFFFF)
        struct.pack_into("<I", data, fat + 512 + 8 * 4, 11)
        struct.pack_into("<I", data, fat + 512 + 11 * 4, 0xFFFFFFFF)
        # The active copy must account for both bitmap allocations, root, and
        # the Up-case Table, including the second cluster of each bitmap.
        active_bitmap = heap + (8 - 2) * 512
        for cluster in (2, 3, 7, 8, 9, 10, 11):
            data[active_bitmap + (cluster - 2) // 8] |= 1 << ((cluster - 2) % 8)
        metadata = self.volume(bytes(data)).system_metadata()
        self.assertEqual(metadata.active_bitmap.identifier, 1)
        self.assertEqual(metadata.bitmaps[0].clusters, (7, 10))
        self.assertEqual(metadata.bitmaps[1].clusters, (8, 11))
        self.assertEqual(
            metadata.root_clusters + metadata.bitmaps[0].clusters,
            (2, 7, 10),
        )

    def test_system_metadata_rejects_free_system_clusters_and_reserved_bitmap_bits(
        self,
    ) -> None:
        for cluster in (2, 7, 8):
            data = bytearray(image())
            heap = self.heap(data)
            data[heap + (7 - 2) * 512 + (cluster - 2) // 8] &= ~(
                1 << ((cluster - 2) % 8)
            )
            with self.subTest(cluster=cluster), self.assertRaises(FormatError):
                self.volume(bytes(data)).system_metadata()

        data = bytearray(image())
        heap = self.heap(data)
        struct.pack_into("<Q", data, heap + 24, 3)
        data[heap + (7 - 2) * 512 + 2] = 1
        with self.assertRaises(FormatError):
            self.volume(bytes(data)).system_metadata()

    def test_root_unknown_critical_primary_and_secondary_are_rejected(self) -> None:
        data = bytearray(image())
        root = self.heap(data)
        # The first unused record follows the fixture's metadata and two File
        # entry sets.  0x84 is an unknown critical primary.
        data[root + 8 * 32] = 0x84
        with self.assertRaises(FormatError):
            self.volume(bytes(data)).system_metadata()

        data = bytearray(image())
        # Replace the active File set's Stream Extension with an unknown
        # critical secondary. It cannot safely be ignored.
        data[root + 4 * 32] = 0xC2
        with self.assertRaises(FormatError):
            self.volume(bytes(data)).system_metadata()

    def test_root_standalone_in_use_secondaries_are_rejected(self) -> None:
        for entry_type in (0xC0, 0xC1, 0xE0, 0xE1):
            with self.subTest(entry_type=hex(entry_type)):
                data = bytearray(image())
                root = self.heap(data)
                data[root + 8 * 32] = entry_type
                with self.assertRaisesRegex(FormatError, "standalone in-use secondary"):
                    self.volume(bytes(data)).system_metadata()

    def test_root_generic_benign_sets_are_consumed_and_block_planning(self) -> None:
        data = bytearray(image())
        root = self.heap(data)
        # A generic benign primary declares two secondaries. They are consumed
        # as its set, then rejected because their allocation semantics are not
        # known, rather than being misdiagnosed as detached records.
        data[root + 8 * 32] = 0xA2
        data[root + 8 * 32 + 1] = 2
        data[root + 9 * 32] = 0xE0
        data[root + 10 * 32] = 0xE1
        volume = self.volume(bytes(data))
        volume.system_metadata()
        result = scan(volume.source)
        self.assertIn(
            "active_uninterpreted_benign_directory_entry_set", result.warnings
        )
        self.assertNotIn("active_standalone_secondary_directory_entry", result.warnings)
        self.assertFalse(result.metadata_complete)
        self.assertFalse(result.ownership_complete)

    def test_root_volume_guid_is_validated_before_being_ignored(self) -> None:
        def volume_guid() -> bytearray:
            record = bytearray(32)
            record[0] = 0xA0
            record[6:22] = bytes(range(1, 17))
            struct.pack_into("<H", record, 2, entry_set_checksum(record))
            return record

        data = bytearray(image())
        root = self.heap(data)
        record = volume_guid()
        data[root + 8 * 32 : root + 9 * 32] = record
        volume = self.volume(bytes(data))
        volume.system_metadata()
        result = scan(volume.source)
        self.assertTrue(result.metadata_complete)
        self.assertTrue(result.ownership_complete)
        self.assertNotIn(
            "active_uninterpreted_benign_directory_entry_set", result.warnings
        )

        cases = (
            ("secondary-count", ((1, 1),)),
            ("checksum", ((2, 1),)),
            ("flags", ((4, 1),)),
            ("null-guid", tuple((index, 0) for index in range(6, 22))),
            ("reserved", ((22, 1),)),
            ("duplicate", ()),
        )
        for name, changes in cases:
            with self.subTest(name=name):
                data = bytearray(image())
                root = self.heap(data)
                record = volume_guid()
                for offset, value in changes:
                    record[offset] = value
                data[root + 8 * 32 : root + 9 * 32] = record
                if name == "duplicate":
                    data[root + 9 * 32 : root + 10 * 32] = volume_guid()
                with self.assertRaises(FormatError):
                    self.volume(bytes(data)).system_metadata()

    def test_volume_label_count_duplicates_and_reserved_bytes_are_rejected(
        self,
    ) -> None:
        root_label = 8 * 32
        cases = (
            ("character-count", ((root_label + 0, 0x83), (root_label + 1, 12))),
            ("reserved", ((root_label + 0, 0x83), (root_label + 24, 1))),
            (
                "malformed-utf16",
                (
                    (root_label + 0, 0x83),
                    (root_label + 1, 1),
                    (root_label + 2, 0),
                    (root_label + 3, 0xD8),
                ),
            ),
            (
                "forbidden-character",
                (
                    (root_label + 0, 0x83),
                    (root_label + 1, 1),
                    (root_label + 2, ord("/")),
                ),
            ),
            (
                "duplicate",
                (
                    (root_label + 0, 0x83),
                    (root_label + 32, 0x83),
                ),
            ),
        )
        for name, changes in cases:
            with self.subTest(name=name):
                data = bytearray(image())
                root = self.heap(data)
                for offset, value in changes:
                    data[root + offset] = value
                with self.assertRaises(FormatError):
                    self.volume(bytes(data)).system_metadata()

    def test_invalid_and_bounded_root_chains_are_rejected(self) -> None:
        fat = 24 * 512
        data = bytearray(image())
        struct.pack_into("<I", data, fat + 2 * 4, 1)
        with self.assertRaises(FormatError):
            self.volume(bytes(data)).system_metadata()

        data = bytearray(image())
        struct.pack_into("<I", data, fat + 2 * 4, 3)
        struct.pack_into("<I", data, fat + 3 * 4, 0xFFFFFFFF)
        with self.assertRaises(FormatError):
            self.volume(bytes(data)).system_metadata(max_chain_clusters=1)

    def test_scan_reports_complete_active_system_file_and_vendor_ownership(
        self,
    ) -> None:
        data = bytearray(image())
        root = self.heap(data)
        active = root + 2 * 32
        # Extend the active File entry set with a benign Vendor Allocation
        # stream at cluster 10. The ordinary candidate parser need not recover
        # vendor data, but its allocation must remain unavailable to recovery.
        data[active + 1] = 3
        vendor = active + 3 * 32
        data[vendor] = 0xE1
        data[vendor + 1] = 3
        data[vendor + 2 : vendor + 18] = b"vendor-guid-1234"
        struct.pack_into("<I", data, vendor + 20, 10)
        struct.pack_into("<Q", data, vendor + 24, 512)
        data[root + 6 * 32 : root + 9 * 32] = b"\0" * (3 * 32)
        set_bytes = data[active : active + 4 * 32]
        struct.pack_into("<H", data, active + 2, entry_set_checksum(set_bytes))
        bitmap = self.heap(data) + (7 - 2) * 512
        data[bitmap + (10 - 2) // 8] |= 1 << ((10 - 2) % 8)
        path = Path(self.temp.name) / "owned.img"
        path.write_bytes(data)
        source = ImageSource.open(path)
        self.addCleanup(source.close)
        result = scan(source)
        self.assertTrue(result.ownership_complete)
        self.assertEqual(result.active_owners[2], "system")
        self.assertEqual(result.active_owners[3], f"file:{active}")
        self.assertEqual(result.active_owners[10], f"file:{active}")
