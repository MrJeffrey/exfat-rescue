from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from exfat_rescue.errors import FormatError, ResourceLimitError
from exfat_rescue.exfat.entries import entry_set_checksum
from exfat_rescue.exfat.volume import MINIMUM_VOLUME_BYTES, BootSector, ExfatVolume
from exfat_rescue.planner import plan_recovery
from exfat_rescue.scanner import (
    OwnershipExtent,
    _active_allocation_extents,
    _active_file_allocation_extents,
    _candidate_entry_offsets,
    _claim_overlaps_metadata_owner,
    _maximum_selected_volume_bytes,
    scan,
)
from exfat_rescue.source import ImageSource
from tests.fixture import (
    entry,
    image,
    refresh_boot_checksums,
    set_active_bitmap_allocations,
)


class FakeAllocationVolume:
    def __init__(
        self,
        *,
        allocated: set[int],
        fat: dict[int, int] | None = None,
        cluster_count: int = 16,
    ) -> None:
        self.boot = SimpleNamespace(cluster_size=512, cluster_count=cluster_count)
        self.allocated = allocated
        self.fat = fat or {}

    def valid_cluster(self, cluster: int) -> bool:
        return 2 <= cluster < self.boot.cluster_count + 2

    def cluster_is_allocated(self, cluster: int) -> bool:
        return cluster in self.allocated

    def fat_next(self, cluster: int) -> int:
        following = self.fat.get(cluster, 0xFFFFFFFF)
        if following == -1:
            raise FormatError("synthetic FAT failure")
        return following


def active_vendor_set(*, primary_cluster: int, vendor_cluster: int) -> bytes:
    """An ownership-parser-only active File set with a Vendor Allocation."""
    records = bytearray(128)
    records[0], records[1] = 0x85, 3
    records[32], records[33] = 0xC0, 3
    struct.pack_into("<I", records, 52, primary_cluster)
    struct.pack_into("<Q", records, 56, 512)
    records[64], records[65] = 0xE1, 3
    records[66] = 1  # non-null vendor GUID
    struct.pack_into("<I", records, 84, vendor_cluster)
    struct.pack_into("<Q", records, 88, 512)
    records[96] = 0xC1
    return bytes(records)


class ScannerBoundaryTests(unittest.TestCase):
    def scan_bytes(self, contents: bytes | bytearray, **scan_kwargs):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "boundaries.img"
        path.write_bytes(contents)
        source = ImageSource.open(path)
        self.addCleanup(source.close)
        return scan(source, **scan_kwargs)

    @staticmethod
    def place_cross_cluster_orphan(
        data: bytearray, *, name: str = "cross-orphan", first_cluster: int = 5
    ) -> int:
        """Place a three-entry deleted set across clusters 10 and 11."""
        heap = struct.unpack_from("<I", data, 0x58)[0] * 512
        offset = heap + (10 - 2) * 512 + 480
        record = entry(name, deleted=True, first_cluster=first_cluster)
        assert len(record) == 96
        data[offset : offset + len(record)] = record
        return offset

    def test_candidate_marker_search_preserves_alignment_and_complete_slots(
        self,
    ) -> None:
        data = bytearray(99)
        data[0] = 0x85
        data[1] = 0x05
        data[32] = 0x05
        data[64] = 0x85
        data[96] = 0x85

        for block in (bytes(data), memoryview(data)):
            with self.subTest(block_type=type(block).__name__):
                self.assertEqual(list(_candidate_entry_offsets(block)), [0, 32, 64])

    def test_compact_active_claim_metadata_intersection_does_not_expand_clusters(
        self,
    ) -> None:
        """A huge valid contiguous file must not create a cluster-sized loop."""
        claim = OwnershipExtent(2, 10**18, "file:synthetic")
        self.assertTrue(_claim_overlaps_metadata_owner(claim, (10**18 - 1,)))
        self.assertFalse(_claim_overlaps_metadata_owner(claim, (10**18,)))

    def test_orphan_scan_batches_the_contiguous_cluster_heap(self) -> None:
        contents = image()
        with (
            patch.object(
                ExfatVolume,
                "read_clusters",
                autospec=True,
                wraps=ExfatVolume.read_clusters,
            ) as batched_read,
            patch.object(
                ImageSource,
                "release_cache",
                autospec=True,
                wraps=ImageSource.release_cache,
            ) as cache_release,
        ):
            result = self.scan_bytes(contents)

        self.assertEqual(result.scanned_clusters, 16)
        self.assertEqual(batched_read.call_count, 1)
        self.assertEqual(batched_read.call_args.args[1:], (2, 16))
        released = [call.args for call in cache_release.call_args_list]
        self.assertEqual(
            released,
            [
                (unittest.mock.ANY, 0, result.volume.cluster_offset(2)),
                (
                    unittest.mock.ANY,
                    result.volume.cluster_offset(2),
                    16 * result.volume.boot.cluster_size,
                ),
            ],
        )
        self.assertTrue(all(isinstance(args[0], ImageSource) for args in released))

    def test_orphan_entry_set_crossing_clusters_is_discovered(self) -> None:
        data = bytearray(image())
        offset = self.place_cross_cluster_orphan(data)

        # One cluster per read also exercises the carry across batch release.
        with patch("exfat_rescue.scanner._SCAN_READ_BYTES", 512):
            result = self.scan_bytes(data)

        cross = [item for item in result.candidates if item["name"] == "cross-orphan"]
        self.assertEqual(
            [(item["location"], item["entry_offset"]) for item in cross],
            [("orphan", offset)],
        )

    def test_maximum_orphan_entry_set_crossing_three_clusters_is_discovered(
        self,
    ) -> None:
        data = bytearray(image())
        heap = struct.unpack_from("<I", data, 0x58)[0] * 512
        offset = heap + (10 - 2) * 512 + 480
        name = "x" * 255
        record = entry(name, deleted=True, first_cluster=5)
        self.assertEqual(len(record), 19 * 32)
        data[offset : offset + len(record)] = record

        with patch("exfat_rescue.scanner._SCAN_READ_BYTES", 512):
            result = self.scan_bytes(data)

        self.assertEqual(
            [
                (item["location"], item["entry_offset"])
                for item in result.candidates
                if item["name"] == name
            ],
            [("orphan", offset)],
        )

    def test_cross_cluster_orphan_participates_in_overlap_planning(self) -> None:
        data = bytearray(image())
        self.place_cross_cluster_orphan(data, first_cluster=5)
        root = struct.unpack_from("<I", data, 0x58)[0] * 512
        directory_deleted = entry("directory-overlap", deleted=True, first_cluster=5)
        data[root + 256 : root + 256 + len(directory_deleted)] = directory_deleted

        result = self.scan_bytes(data)
        planned = plan_recovery(
            result.volume,
            result.candidates,
            active_owners=result.active_owners,
            metadata_complete=result.metadata_complete,
            ownership_complete=result.ownership_complete,
        )
        overlapping = {
            plan.name: plan
            for plan in planned.plans
            if plan.name in {"cross-orphan", "directory-overlap"}
        }
        self.assertEqual(set(overlapping), {"cross-orphan", "directory-overlap"})
        for plan in overlapping.values():
            self.assertEqual(plan.disposition, "conflicted")
            self.assertIn("plausible_recovery_overlap", plan.reasons)

    def test_cross_cluster_orphan_with_allocated_trailing_host_is_conflicted(
        self,
    ) -> None:
        data = bytearray(image())
        self.place_cross_cluster_orphan(data)
        set_active_bitmap_allocations(data, {2, 3, 7, 8, 11})

        result = self.scan_bytes(data)
        planned = plan_recovery(
            result.volume,
            result.candidates,
            active_owners=result.active_owners,
            metadata_complete=result.metadata_complete,
            ownership_complete=result.ownership_complete,
        )

        cross = next(
            item for item in result.candidates if item["name"] == "cross-orphan"
        )
        self.assertEqual(cross["metadata_host_clusters"], (10, 11))
        plan = next(item for item in planned.plans if item.name == "cross-orphan")
        self.assertEqual(plan.disposition, "conflicted")
        self.assertIn("orphan_metadata_host_allocated", plan.reasons)

    def test_allocated_cross_host_orphan_still_conflicts_with_shared_data(self) -> None:
        data = bytearray(image())
        self.place_cross_cluster_orphan(data, first_cluster=5)
        root = struct.unpack_from("<I", data, 0x58)[0] * 512
        directory_deleted = entry("directory-overlap", deleted=True, first_cluster=5)
        data[root + 256 : root + 256 + len(directory_deleted)] = directory_deleted
        set_active_bitmap_allocations(data, {2, 3, 7, 8, 11})

        result = self.scan_bytes(data)
        planned = plan_recovery(
            result.volume,
            result.candidates,
            active_owners=result.active_owners,
            metadata_complete=result.metadata_complete,
            ownership_complete=result.ownership_complete,
        )
        overlapping = {
            plan.name: plan
            for plan in planned.plans
            if plan.name in {"cross-orphan", "directory-overlap"}
        }

        self.assertEqual(set(overlapping), {"cross-orphan", "directory-overlap"})
        for plan in overlapping.values():
            self.assertEqual(plan.disposition, "conflicted")
            self.assertIn("plausible_recovery_overlap", plan.reasons)
        self.assertIn(
            "orphan_metadata_host_allocated", overlapping["cross-orphan"].reasons
        )

    def test_padded_selected_volume_is_charged_to_the_scan_limit(self) -> None:
        data = bytearray(image())
        padded_sectors = 4_000_000
        for offset in (0x48, 12 * 512 + 0x48):
            struct.pack_into("<Q", data, offset, padded_sectors)
        for offset in (0x58, 12 * 512 + 0x58):
            struct.pack_into("<I", data, offset, padded_sectors - 16)
        refresh_boot_checksums(data)

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "padded.img"
        path.write_bytes(data)
        with path.open("r+b") as handle:
            handle.truncate(padded_sectors * 512)
        source = ImageSource.open(path)
        self.addCleanup(source.close)

        with self.assertRaisesRegex(ResourceLimitError, "outside its minimum"):
            scan(source, max_scan_clusters=16)

    def test_exact_cluster_limit_budgets_mandatory_fats_and_tail_sector(self) -> None:
        cluster_count = 262_145
        bytes_per_sector = 512
        fat_length = (
            (cluster_count + 2) * 4 + bytes_per_sector - 1
        ) // bytes_per_sector
        for number_of_fats, sectors_per_cluster, remainder in (
            (1, 1, 0),
            (2, 1, 0),
            (2, 64, 63),
        ):
            with self.subTest(
                number_of_fats=number_of_fats,
                sectors_per_cluster=sectors_per_cluster,
                remainder=remainder,
            ):
                heap_offset = 24 + fat_length * number_of_fats
                volume_length = (
                    heap_offset + cluster_count * sectors_per_cluster + remainder
                )
                boot = BootSector(
                    bytes_per_sector,
                    sectors_per_cluster,
                    24,
                    fat_length,
                    heap_offset,
                    cluster_count,
                    2,
                    volume_length,
                    1,
                    0x0100,
                    0,
                    number_of_fats,
                )
                self.assertEqual(
                    (boot.volume_length - boot.heap_offset) // boot.sectors_per_cluster,
                    cluster_count,
                )
                if number_of_fats == 1 and sectors_per_cluster == 1:
                    self.assertGreater(
                        boot.volume_bytes,
                        MINIMUM_VOLUME_BYTES + cluster_count * boot.cluster_size,
                    )
                self.assertLessEqual(
                    boot.volume_bytes,
                    _maximum_selected_volume_bytes(boot, cluster_count),
                )

    def test_active_allocation_handles_empty_and_invalid_streams(self) -> None:
        volume = FakeAllocationVolume(allocated={3})
        self.assertEqual(
            _active_allocation_extents(volume, 0, 0, True, limit=1), ((), 0)
        )
        self.assertEqual(
            _active_allocation_extents(volume, 3, 0, True, limit=1), (None, 0)
        )
        self.assertEqual(
            _active_allocation_extents(volume, 1, 512, True, limit=1), (None, 0)
        )
        self.assertEqual(
            _active_allocation_extents(volume, 3, 1024, True, limit=1), (None, 0)
        )

    def test_active_allocation_tracks_contiguous_and_fat_work(self) -> None:
        contiguous = FakeAllocationVolume(allocated={3, 4})
        extents, work = _active_allocation_extents(contiguous, 3, 1024, True, limit=2)
        self.assertEqual(extents, (OwnershipExtent(3, 5, ""),))
        self.assertEqual(work, 2)

        fragmented = FakeAllocationVolume(allocated={3, 5}, fat={3: 5, 5: 0xFFFFFFFF})
        extents, work = _active_allocation_extents(fragmented, 3, 1024, False, limit=2)
        self.assertEqual(
            extents, (OwnershipExtent(3, 4, ""), OwnershipExtent(5, 6, ""))
        )
        self.assertEqual(work, 2)

    def test_active_allocation_charges_the_late_failing_unit(self) -> None:
        volume = FakeAllocationVolume(allocated={3}, fat={3: 5})
        self.assertEqual(
            _active_allocation_extents(volume, 3, 1024, False, limit=2), (None, 2)
        )
        volume = FakeAllocationVolume(allocated={3, 5}, fat={3: 5, 5: -1})
        self.assertEqual(
            _active_allocation_extents(volume, 3, 1024, False, limit=2), (None, 2)
        )

    def test_active_file_parser_accounts_for_vendor_allocations(self) -> None:
        volume = FakeAllocationVolume(allocated={3, 4})
        extents, work = _active_file_allocation_extents(
            volume, active_vendor_set(primary_cluster=3, vendor_cluster=4), limit=2
        )
        self.assertEqual(work, 2)
        self.assertEqual(
            extents,
            (
                OwnershipExtent(3, 4, "", primary_stream=True),
                OwnershipExtent(4, 5, ""),
            ),
        )

        malformed = bytearray(active_vendor_set(primary_cluster=3, vendor_cluster=4))
        malformed[66:82] = b"\0" * 16
        self.assertEqual(
            _active_file_allocation_extents(volume, bytes(malformed), limit=2),
            (None, 1),
        )

    def test_malformed_active_file_set_marks_metadata_and_ownership_incomplete(
        self,
    ) -> None:
        data = bytearray(image())
        root = struct.unpack_from("<I", data, 0x58)[0] * 512
        metadata_end = root + 64
        child = root + 512
        directory = entry("child", directory=True, first_cluster=3, size=512)
        data[metadata_end : metadata_end + len(directory)] = directory
        data[metadata_end + len(directory) : root + 512] = b"\0" * (
            512 - (metadata_end - root) - len(directory)
        )
        data[child : child + 96] = entry("bad-active", first_cluster=4)
        data[child + 32] = 0xC2  # File primary with a non-stream secondary.
        set_active_bitmap_allocations(data, {2, 3, 4, 7, 8})

        result = self.scan_bytes(data)
        self.assertIn("active_file_allocation_incomplete", result.warnings)
        self.assertIn("active_file_entry_set_invalid", result.warnings)
        self.assertFalse(result.metadata_complete)
        self.assertFalse(result.ownership_complete)

    def test_malformed_active_directory_is_not_traversed(self) -> None:
        for size in (0, 513):
            with self.subTest(directory_size=size):
                data = bytearray(image())
                root = struct.unpack_from("<I", data, 0x58)[0] * 512
                metadata_end = root + 64
                malformed = entry(
                    "malformed-directory",
                    directory=True,
                    size=size,
                    valid_size=size,
                    first_cluster=3 if size else 0,
                    no_fat_chain=bool(size),
                )
                data[metadata_end : metadata_end + len(malformed)] = malformed
                data[metadata_end + len(malformed) : root + 512] = b"\0" * (
                    512 - (metadata_end - root) - len(malformed)
                )
                child = root + 512
                trailing = entry("must-not-be-traversed", corrupt=True)
                data[child : child + len(trailing)] = trailing
                set_active_bitmap_allocations(data, {2, 3, 7, 8})

                result = self.scan_bytes(data)

                self.assertIn("active_file_entry_set_invalid", result.warnings)
                self.assertFalse(result.metadata_complete)
                self.assertFalse(result.ownership_complete)
                self.assertFalse(
                    any(
                        candidate["path_components"]
                        == ("malformed-directory", "must-not-be-traversed")
                        for candidate in result.candidates
                    )
                )

    def test_short_active_directory_chain_is_not_recovery_eligible(self) -> None:
        data = bytearray(image())
        root = struct.unpack_from("<I", data, 0x58)[0] * 512
        metadata_end = root + 64
        child = entry(
            "short-directory",
            directory=True,
            first_cluster=3,
            size=1024,
            valid_size=1024,
            no_fat_chain=False,
        )
        data[metadata_end : metadata_end + len(child)] = child
        data[metadata_end + len(child) : root + 512] = b"\0" * (
            512 - (metadata_end - root) - len(child)
        )
        set_active_bitmap_allocations(data, {2, 3, 7, 8})

        result = self.scan_bytes(data)
        planned = plan_recovery(
            result.volume,
            result.candidates,
            active_owners=result.active_owners,
            metadata_complete=result.metadata_complete,
            ownership_complete=result.ownership_complete,
        )

        self.assertIn("directory_chain_incomplete", result.warnings)
        self.assertFalse(result.metadata_complete)
        self.assertFalse(result.ownership_complete)
        self.assertFalse(
            any(plan.disposition == "recoverable" for plan in planned.plans)
        )

    def test_reserved_active_file_attributes_mark_scan_incomplete(self) -> None:
        data = bytearray(image())
        root = struct.unpack_from("<I", data, 0x58)[0] * 512
        metadata_end = root + 64
        child = root + 512
        directory = entry("child", directory=True, first_cluster=3, size=512)
        data[metadata_end : metadata_end + len(directory)] = directory
        data[metadata_end + len(directory) : root + 512] = b"\0" * (
            512 - (metadata_end - root) - len(directory)
        )
        invalid = bytearray(entry("reserved-attributes", first_cluster=4))
        struct.pack_into("<H", invalid, 4, 0x0008)
        struct.pack_into("<H", invalid, 2, entry_set_checksum(invalid))
        data[child : child + len(invalid)] = invalid
        data[child + len(invalid) : child + 512] = b"\0" * (512 - len(invalid))
        set_active_bitmap_allocations(data, {2, 3, 4, 7, 8})

        result = self.scan_bytes(data)

        self.assertIn("active_file_entry_set_invalid", result.warnings)
        self.assertFalse(result.metadata_complete)
        self.assertFalse(result.ownership_complete)

    def test_active_allocation_work_budget_is_shared_after_directory_work(self) -> None:
        data = bytearray(image())
        root = struct.unpack_from("<I", data, 0x58)[0] * 512
        metadata_end = root + 64
        data[metadata_end : root + 512] = b"\0" * (512 - (metadata_end - root))
        records = (
            entry("first", first_cluster=3, size=8 * 512),
            entry("late", first_cluster=11, size=7 * 512),
            entry("after", first_cluster=3, size=512),
        )
        offset = metadata_end
        for record in records:
            data[offset : offset + len(record)] = record
            offset += len(record)
        set_active_bitmap_allocations(data, set(range(2, 17)) | {7, 8})

        limits: list[int] = []
        original = _active_file_allocation_extents

        def observe(*args, **kwargs):
            limits.append(kwargs["limit"])
            return original(*args, **kwargs)

        with patch(
            "exfat_rescue.scanner._active_file_allocation_extents", side_effect=observe
        ):
            result = self.scan_bytes(data, max_scan_clusters=16)
        self.assertEqual(limits, [15, 7, 0])
        self.assertIn("active_file_allocation_incomplete", result.warnings)

    def test_missing_directory_end_marker_is_not_treated_as_complete(self) -> None:
        data = bytearray(image())
        root = struct.unpack_from("<I", data, 0x58)[0] * 512
        child = root + 512
        directory = entry("child", directory=True, first_cluster=3, size=512)
        data[root + 64 : root + 64 + len(directory)] = directory
        data[root + 64 + len(directory) : root + 512] = b"\0" * (448 - len(directory))
        data[child : child + 512] = (b"\x01" + b"\0" * 31) * 16
        set_active_bitmap_allocations(data, {2, 3, 7, 8})

        result = self.scan_bytes(data)
        self.assertIn("directory_missing_end_marker", result.warnings)
        self.assertFalse(result.metadata_complete)
        self.assertFalse(result.ownership_complete)

    def test_truncated_entry_set_and_depth_limit_are_safety_warnings(self) -> None:
        data = bytearray(image())
        root = struct.unpack_from("<I", data, 0x58)[0] * 512
        child = root + 512
        directory = entry("child", directory=True, first_cluster=3, size=512)
        data[root + 64 : root + 64 + len(directory)] = directory
        data[root + 64 + len(directory) : root + 512] = b"\0" * (448 - len(directory))
        data[child : child + 416] = (b"\x01" + b"\0" * 31) * 13
        record = entry("x" * 31, first_cluster=3)
        data[child + 416 : child + 512] = record[:96]
        set_active_bitmap_allocations(data, {2, 3, 7, 8})
        result = self.scan_bytes(data)
        self.assertIn("directory_entry_set_truncated", result.warnings)

        data = bytearray(image())
        root = struct.unpack_from("<I", data, 0x58)[0] * 512
        data[root + 64 : root + 512] = b"\0" * 448
        child = entry("child", directory=True, first_cluster=3, size=512)
        data[root + 64 : root + 64 + len(child)] = child
        set_active_bitmap_allocations(data, {2, 3, 7, 8})
        with patch("exfat_rescue.scanner.MAX_DIRECTORY_DEPTH", 0):
            result = self.scan_bytes(data)
        self.assertIn("directory_depth_limit_reached", result.warnings)
        self.assertFalse(result.metadata_complete)
