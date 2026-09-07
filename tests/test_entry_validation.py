from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from exfat_rescue.exfat.entries import entry_set_checksum, parse_entry_set
from exfat_rescue.exfat.volume import ExfatVolume
from exfat_rescue.source import ImageSource
from tests.fixture import entry, image


class StreamEntryValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        path = Path(self.temp.name) / "entry.img"
        path.write_bytes(image())
        self.source = ImageSource.open(path)
        self.volume = ExfatVolume(self.source)

    def tearDown(self) -> None:
        self.source.close()
        self.temp.cleanup()

    def parse(self, record: bytes):
        return parse_entry_set(record, 0, self.volume, 0)

    @staticmethod
    def vendor_secondary(
        kind: int,
        *,
        deleted: bool = False,
        flags: int | None = None,
        guid: bytes = b"vendor-guid-1234",
        first_cluster: int = 4,
        data_length: int = 512,
    ) -> bytes:
        record = bytearray(32)
        if kind == 0:
            record[0] = 0x60 if deleted else 0xE0
            record[1] = 0 if flags is None else flags
        elif kind == 1:
            record[0] = 0x61 if deleted else 0xE1
            record[1] = 3 if flags is None else flags
            struct.pack_into("<I", record, 20, first_cluster)
            struct.pack_into("<Q", record, 24, data_length)
        else:
            raise ValueError("unknown vendor secondary kind")
        record[2:18] = guid
        return bytes(record)

    @staticmethod
    def with_vendor_secondaries(record: bytes, *vendors: bytes) -> bytes:
        result = bytearray(record)
        result[1] += len(vendors)
        result.extend(b"".join(vendors))
        struct.pack_into("<H", result, 2, entry_set_checksum(result))
        return bytes(result)

    def test_empty_file_uses_allocation_possible_without_no_fat_chain(self) -> None:
        parsed = self.parse(
            entry(
                "empty.txt", size=0, valid_size=0, first_cluster=0, no_fat_chain=False
            )
        )
        self.assertIsNotNone(parsed)
        self.assertFalse(parsed["no_fat_chain"])

    def test_invalid_stream_flags_are_rejected(self) -> None:
        for flags in (0, 2, 4, 0xFF):
            record = bytearray(entry("flags.txt"))
            record[33] = flags
            struct.pack_into("<H", record, 2, entry_set_checksum(record))
            with self.subTest(flags=flags):
                self.assertIsNone(self.parse(record))

    def test_file_attributes_reject_reserved_bits_for_active_and_deleted_sets(
        self,
    ) -> None:
        for deleted in (False, True):
            for attributes in (0x0008, 0x0040, 0x8000):
                record = bytearray(entry("reserved-attributes.txt", deleted=deleted))
                struct.pack_into("<H", record, 4, attributes)
                struct.pack_into("<H", record, 2, entry_set_checksum(record))
                with self.subTest(deleted=deleted, attributes=f"{attributes:#06x}"):
                    self.assertIsNone(self.parse(record))

    def test_file_attributes_accept_all_defined_bits(self) -> None:
        record = bytearray(
            entry(
                "defined-attributes.txt",
                directory=True,
                size=512,
                valid_size=512,
                first_cluster=3,
            )
        )
        struct.pack_into("<H", record, 4, 0x0037)
        struct.pack_into("<H", record, 2, entry_set_checksum(record))
        parsed = self.parse(record)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["attributes"], 0x0037)

    def test_reserved_stream_fields_are_rejected(self) -> None:
        for offset in (34, 38, 48):
            record = bytearray(entry("reserved.txt"))
            record[offset] = 1
            struct.pack_into("<H", record, 2, entry_set_checksum(record))
            with self.subTest(offset=offset):
                self.assertIsNone(self.parse(record))

    def test_cluster_and_directory_length_invariants_are_enforced(self) -> None:
        self.assertIsNone(
            self.parse(
                entry(
                    "empty-chain.txt",
                    size=0,
                    valid_size=0,
                    first_cluster=0,
                    no_fat_chain=True,
                )
            )
        )
        self.assertIsNone(
            self.parse(
                entry(
                    "bad-empty.txt",
                    size=0,
                    valid_size=0,
                    first_cluster=3,
                    no_fat_chain=False,
                )
            )
        )
        self.assertIsNone(
            self.parse(
                entry(
                    "bad-directory",
                    directory=True,
                    size=512,
                    valid_size=1,
                    first_cluster=3,
                )
            )
        )
        for size in (0, 513):
            with self.subTest(directory_size=size):
                self.assertIsNone(
                    self.parse(
                        entry(
                            "bad-directory-length",
                            directory=True,
                            size=size,
                            valid_size=size,
                            first_cluster=3 if size else 0,
                            no_fat_chain=bool(size),
                        )
                    )
                )

    def test_timestamp_reserved_two_second_values_are_unknown(self) -> None:
        base = (46 << 25) | (1 << 21) | (2 << 16)
        for double_seconds, expected in (
            (29, "2026-01-02T00:00:58"),
            (30, None),
            (31, None),
        ):
            record = bytearray(entry("timestamp.txt"))
            struct.pack_into("<I", record, 12, base | double_seconds)
            struct.pack_into("<H", record, 2, entry_set_checksum(record))
            with self.subTest(double_seconds=double_seconds):
                parsed = self.parse(record)
                self.assertIsNotNone(parsed)
                self.assertEqual(parsed["modified_at"], expected)

    def test_valid_vendor_extension_and_allocation_follow_file_names(self) -> None:
        record = self.with_vendor_secondaries(
            entry("vendor.txt"),
            self.vendor_secondary(0),
            self.vendor_secondary(1),
        )
        parsed = self.parse(record)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["name"], "vendor.txt")
        self.assertEqual(parsed["first_cluster"], 3)

    def test_vendor_secondaries_follow_every_file_name_entry(self) -> None:
        name = "two-name-entries.txt"
        record = self.with_vendor_secondaries(
            entry(name), self.vendor_secondary(0), self.vendor_secondary(1)
        )
        parsed = self.parse(record)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["name"], name)

    def test_deleted_vendor_secondaries_use_deleted_entry_types(self) -> None:
        record = self.with_vendor_secondaries(
            entry("deleted-vendor.txt", deleted=True),
            self.vendor_secondary(0, deleted=True),
            self.vendor_secondary(1, deleted=True),
        )
        parsed = self.parse(record)
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed["deleted"])

    def test_vendor_entries_must_follow_the_complete_name_series(self) -> None:
        record = bytearray(
            self.with_vendor_secondaries(entry("ordered.txt"), self.vendor_secondary(0))
        )
        # Put the benign secondary before the required File Name entry.
        record[64:96], record[96:128] = record[96:128], record[64:96]
        struct.pack_into("<H", record, 2, entry_set_checksum(record))
        self.assertIsNone(self.parse(record))

    def test_unknown_or_duplicate_critical_secondaries_are_rejected(self) -> None:
        record = bytearray(
            self.with_vendor_secondaries(
                entry("critical.txt"), self.vendor_secondary(0)
            )
        )
        record[96] = 0xC2
        struct.pack_into("<H", record, 2, entry_set_checksum(record))
        self.assertIsNone(self.parse(record))

        record = bytearray(
            self.with_vendor_secondaries(
                entry("duplicate.txt"), self.vendor_secondary(0)
            )
        )
        record[96] = 0xC0
        struct.pack_into("<H", record, 2, entry_set_checksum(record))
        self.assertIsNone(self.parse(record))

    def test_vendor_secondary_state_flags_and_reserved_data_are_validated(self) -> None:
        invalid = (
            self.vendor_secondary(0, flags=1),
            self.vendor_secondary(0, guid=b"\0" * 16),
            self.vendor_secondary(1, flags=0),
            self.vendor_secondary(1, flags=7),
            self.vendor_secondary(1, guid=b"\0" * 16),
            self.vendor_secondary(1, first_cluster=0, data_length=1),
            self.vendor_secondary(1, first_cluster=4, data_length=0, flags=3),
            self.vendor_secondary(1, first_cluster=17, data_length=1024, flags=3),
        )
        for vendor in invalid:
            with self.subTest(vendor=vendor):
                self.assertIsNone(
                    self.parse(
                        self.with_vendor_secondaries(entry("invalid.txt"), vendor)
                    )
                )

    def test_deleted_sets_reject_active_vendor_secondary(self) -> None:
        record = self.with_vendor_secondaries(
            entry("mixed-vendor.txt", deleted=True), self.vendor_secondary(0)
        )
        self.assertIsNone(self.parse(record))

    def test_primary_and_file_name_reserved_fields_are_rejected(self) -> None:
        for offset in (6, 25, 65, 64 + 2 + len("reserved.txt") * 2):
            record = bytearray(entry("reserved.txt"))
            record[offset] = 1
            struct.pack_into("<H", record, 2, entry_set_checksum(record))
            with self.subTest(offset=offset):
                self.assertIsNone(self.parse(record))


if __name__ == "__main__":
    unittest.main()
