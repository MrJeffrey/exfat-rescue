from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from exfat_rescue.errors import ResourceLimitError
from exfat_rescue.exfat.volume import ExfatVolume
from exfat_rescue.planner import plan_recovery
from exfat_rescue.scanner import _directory_clusters, _new_completed_owners, scan
from exfat_rescue.source import ImageSource
from tests.fixture import (
    entry,
    image,
    refresh_boot_checksums,
    set_active_bitmap_allocations,
)

ROOT_SYSTEM_METADATA_BYTES = 64


def cluster_offset(data: bytes | bytearray, cluster: int) -> int:
    bytes_per_sector = 1 << data[0x6C]
    sectors_per_cluster = 1 << data[0x6D]
    heap_sector = struct.unpack_from("<I", data, 0x58)[0]
    return (
        heap_sector * bytes_per_sector
        + (cluster - 2) * bytes_per_sector * sectors_per_cluster
    )


class DirectorySemanticsTests(unittest.TestCase):
    def scan_bytes(self, contents: bytes | bytearray):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "directory.img"
        path.write_bytes(contents)
        source = ImageSource.open(path)
        self.addCleanup(source.close)
        return scan(source)

    def test_contiguous_directory_uses_its_declared_length(self) -> None:
        data = bytearray(image())
        root = cluster_offset(data, 2)
        first_directory_cluster = cluster_offset(data, 3)
        second_directory_cluster = cluster_offset(data, 4)
        data[root + ROOT_SYSTEM_METADATA_BYTES : root + 512] = b"\0" * (
            512 - ROOT_SYSTEM_METADATA_BYTES
        )
        directory = entry(
            "Photos",
            directory=True,
            first_cluster=3,
            size=1024,
            no_fat_chain=True,
        )
        data[
            root + ROOT_SYSTEM_METADATA_BYTES : root
            + ROOT_SYSTEM_METADATA_BYTES
            + len(directory)
        ] = directory
        set_active_bitmap_allocations(data, {2, 3, 4, 5, 7, 8})
        filler = (b"\x01" + b"\0" * 31) * 16
        data[first_directory_cluster : first_directory_cluster + 512] = filler
        child = entry("second-cluster.jpg", first_cluster=5)
        data[second_directory_cluster : second_directory_cluster + len(child)] = child

        result = self.scan_bytes(data)
        recovered = next(
            item for item in result.candidates if item["name"] == "second-cluster.jpg"
        )
        self.assertEqual(recovered["location"], "directory")
        self.assertEqual(recovered["path_components"], ["Photos", "second-cluster.jpg"])
        self.assertTrue(result.ownership_complete)
        self.assertNotIn("active_allocation_overlap", result.warnings)

    def test_end_of_directory_applies_to_the_entire_chain(self) -> None:
        data = bytearray(image())
        fat_sector = struct.unpack_from("<I", data, 0x50)[0]
        struct.pack_into("<I", data, fat_sector * 512 + 2 * 4, 3)
        result = self.scan_bytes(data)
        recovered = next(
            item for item in result.candidates if item["name"] == "orphan.txt"
        )
        self.assertEqual(recovered["location"], "orphan")
        self.assertIsNone(recovered["path_components"])

    def test_active_children_require_unique_upcased_names(self) -> None:
        for duplicate_name in ("Active.txt", "active.TXT"):
            with self.subTest(duplicate_name=duplicate_name):
                data = bytearray(image())
                root = cluster_offset(data, 2)
                first = entry("Active.txt", first_cluster=3)
                duplicate = entry(duplicate_name, first_cluster=4)
                duplicate_start = root + ROOT_SYSTEM_METADATA_BYTES + len(first)
                data[duplicate_start : duplicate_start + len(duplicate)] = duplicate
                set_active_bitmap_allocations(data, {2, 3, 4, 7, 8})

                result = self.scan_bytes(data)

                self.assertIn("active_directory_duplicate_name", result.warnings)
                self.assertFalse(result.metadata_complete)
                self.assertFalse(result.ownership_complete)
                self.assertEqual(
                    sum(
                        candidate["name"] in {"Active.txt", "active.TXT"}
                        for candidate in result.candidates
                    ),
                    2,
                )

    def test_unknown_critical_child_entry_makes_ownership_incomplete(self) -> None:
        data = bytearray(image())
        root = cluster_offset(data, 2)
        child = cluster_offset(data, 3)
        data[root + ROOT_SYSTEM_METADATA_BYTES : root + 512] = b"\0" * (
            512 - ROOT_SYSTEM_METADATA_BYTES
        )
        directory = entry("Child", directory=True, first_cluster=3, size=512)
        data[
            root + ROOT_SYSTEM_METADATA_BYTES : root
            + ROOT_SYSTEM_METADATA_BYTES
            + len(directory)
        ] = directory
        set_active_bitmap_allocations(data, {2, 3, 7, 8})
        for entry_type in (0x84, 0x81):  # Unknown and root-only critical primaries.
            with self.subTest(entry_type=entry_type):
                data[child] = entry_type
                result = self.scan_bytes(data)
                self.assertFalse(result.metadata_complete)
                self.assertFalse(result.ownership_complete)
                self.assertIn(
                    "active_unknown_critical_directory_entry", result.warnings
                )

    def test_standalone_child_secondary_prevents_certified_planning(self) -> None:
        data = bytearray(image())
        root = cluster_offset(data, 2)
        child = cluster_offset(data, 3)
        data[root + ROOT_SYSTEM_METADATA_BYTES : root + 512] = b"\0" * (
            512 - ROOT_SYSTEM_METADATA_BYTES
        )
        directory = entry("Child", directory=True, first_cluster=3, size=512)
        data[
            root + ROOT_SYSTEM_METADATA_BYTES : root
            + ROOT_SYSTEM_METADATA_BYTES
            + len(directory)
        ] = directory
        set_active_bitmap_allocations(data, {2, 3, 7, 8})
        # 0xE0 is an in-use benign secondary. It is harmless only inside a
        # consumed entry set; standing alone makes this directory incomplete.
        data[child] = 0xE0
        deleted = entry("child-deleted.txt", deleted=True, first_cluster=4)
        data[child + 32 : child + 32 + len(deleted)] = deleted

        result = self.scan_bytes(data)

        self.assertIn("active_standalone_secondary_directory_entry", result.warnings)
        self.assertFalse(result.metadata_complete)
        self.assertFalse(result.ownership_complete)
        planned = plan_recovery(
            result.volume,
            result.candidates,
            active_owners=result.active_owners,
            metadata_complete=result.metadata_complete,
            ownership_complete=result.ownership_complete,
        )
        self.assertTrue(planned.plans)
        self.assertTrue(
            all(plan.disposition != "recoverable" for plan in planned.plans)
        )
        self.assertTrue(
            all("incomplete_active_metadata" in plan.reasons for plan in planned.plans)
        )

    def test_generic_benign_child_set_is_not_misclassified_as_detached(self) -> None:
        data = bytearray(image())
        root = cluster_offset(data, 2)
        child = cluster_offset(data, 3)
        data[root + ROOT_SYSTEM_METADATA_BYTES : root + 512] = b"\0" * (
            512 - ROOT_SYSTEM_METADATA_BYTES
        )
        directory = entry("Child", directory=True, first_cluster=3, size=512)
        data[
            root + ROOT_SYSTEM_METADATA_BYTES : root
            + ROOT_SYSTEM_METADATA_BYTES
            + len(directory)
        ] = directory
        set_active_bitmap_allocations(data, {2, 3, 7, 8})
        data[child], data[child + 1] = 0xA2, 2
        data[child + 32], data[child + 64] = 0xE0, 0xE1
        deleted = entry("generic-set.txt", deleted=True, first_cluster=4)
        data[child + 96 : child + 96 + len(deleted)] = deleted

        result = self.scan_bytes(data)

        self.assertIn(
            "active_uninterpreted_benign_directory_entry_set", result.warnings
        )
        self.assertNotIn("active_standalone_secondary_directory_entry", result.warnings)
        self.assertFalse(result.metadata_complete)
        planned = plan_recovery(
            result.volume,
            result.candidates,
            active_owners=result.active_owners,
            metadata_complete=result.metadata_complete,
            ownership_complete=result.ownership_complete,
        )
        self.assertTrue(planned.plans)
        self.assertTrue(
            all(plan.disposition != "recoverable" for plan in planned.plans)
        )

        # Volume GUID is optional only in the root directory. A child record
        # has no validated root-metadata meaning and therefore remains
        # conservative rather than inheriting the root exception.
        data[child : child + 512] = b"\0" * 512
        data[child] = 0xA0
        data[child + 32 : child + 32 + len(deleted)] = deleted
        child_guid_result = self.scan_bytes(data)
        self.assertIn(
            "active_uninterpreted_benign_directory_entry_set",
            child_guid_result.warnings,
        )
        self.assertFalse(child_guid_result.metadata_complete)

    def test_entry_set_can_cross_a_directory_cluster_boundary(self) -> None:
        data = bytearray(image())
        root = cluster_offset(data, 2)
        next_cluster = cluster_offset(data, 3)
        fat_sector = struct.unpack_from("<I", data, 0x50)[0]
        struct.pack_into("<I", data, fat_sector * 512 + 2 * 4, 3)
        data[root + ROOT_SYSTEM_METADATA_BYTES : next_cluster + 512] = b"\0" * (
            1024 - ROOT_SYSTEM_METADATA_BYTES
        )
        data[root + ROOT_SYSTEM_METADATA_BYTES : root + 480] = (
            b"\x01" + b"\0" * 31
        ) * 13
        long_name = "boundary-" + "x" * 191
        record = entry(long_name, first_cluster=4)
        data[root + 480 : root + 480 + len(record)] = record

        result = self.scan_bytes(data)
        recovered = next(
            item for item in result.candidates if item["name"] == long_name
        )
        self.assertEqual(recovered["location"], "directory")
        self.assertEqual(recovered["path_components"], [long_name])

    def test_child_cannot_claim_a_cluster_owned_by_its_parent(self) -> None:
        data = bytearray(image())
        root = cluster_offset(data, 2)
        next_cluster = cluster_offset(data, 3)
        fat_sector = struct.unpack_from("<I", data, 0x50)[0]
        struct.pack_into("<I", data, fat_sector * 512 + 2 * 4, 3)
        data[root + ROOT_SYSTEM_METADATA_BYTES : next_cluster + 512] = b"\0" * (
            1024 - ROOT_SYSTEM_METADATA_BYTES
        )
        alias = entry("Alias", directory=True, first_cluster=3, size=512)
        alias_start = root + ROOT_SYSTEM_METADATA_BYTES
        data[alias_start : alias_start + len(alias)] = alias
        filler_start = alias_start + len(alias)
        filler_records = (512 - filler_start + root) // 32
        data[filler_start : root + 512] = (b"\x01" + b"\0" * 31) * filler_records
        target = entry("target.txt", first_cluster=4)
        data[next_cluster : next_cluster + len(target)] = target

        result = self.scan_bytes(data)
        recovered = next(
            item for item in result.candidates if item["name"] == "target.txt"
        )
        self.assertEqual(recovered["path_components"], ["target.txt"])
        self.assertIn("overlapping_directory_allocation", result.warnings)

    def test_two_directories_sharing_allocation_are_downgraded(self) -> None:
        data = bytearray(image())
        root = cluster_offset(data, 2)
        shared = cluster_offset(data, 3)
        data[root + ROOT_SYSTEM_METADATA_BYTES : root + 512] = b"\0" * (
            512 - ROOT_SYSTEM_METADATA_BYTES
        )
        first = entry("First", directory=True, first_cluster=3, size=512)
        second = entry("Second", directory=True, first_cluster=3, size=512)
        first_start = root + ROOT_SYSTEM_METADATA_BYTES
        data[first_start : first_start + len(first)] = first
        data[first_start + len(first) : first_start + len(first) + len(second)] = second
        target = entry("shared.txt", first_cluster=4)
        data[shared : shared + len(target)] = target

        result = self.scan_bytes(data)
        recovered = next(
            item for item in result.candidates if item["name"] == "shared.txt"
        )
        self.assertEqual(recovered["location"], "orphan")
        self.assertIsNone(recovered["path_components"])
        self.assertIn("overlapping_directory_allocation", result.warnings)

    def test_cross_cluster_candidate_in_shared_allocation_is_downgraded(self) -> None:
        data = bytearray(image())
        root = cluster_offset(data, 2)
        first_cluster = cluster_offset(data, 3)
        data[root + ROOT_SYSTEM_METADATA_BYTES : root + 512] = b"\0" * (
            512 - ROOT_SYSTEM_METADATA_BYTES
        )
        first = entry(
            "First", directory=True, first_cluster=3, size=1024, no_fat_chain=True
        )
        second = entry(
            "Second", directory=True, first_cluster=4, size=512, no_fat_chain=True
        )
        first_start = root + ROOT_SYSTEM_METADATA_BYTES
        data[first_start : first_start + len(first)] = first
        data[first_start + len(first) : first_start + len(first) + len(second)] = second
        set_active_bitmap_allocations(data, {2, 3, 4, 7, 8})
        data[first_cluster : first_cluster + 480] = (b"\x01" + b"\0" * 31) * 15
        long_name = "shared-boundary-" + "x" * 176
        candidate = entry(long_name, first_cluster=5)
        data[first_cluster + 480 : first_cluster + 480 + len(candidate)] = candidate

        result = self.scan_bytes(data)
        recovered = next(
            item for item in result.candidates if item["name"] == long_name
        )
        self.assertEqual(recovered["location"], "orphan")
        self.assertIsNone(recovered["path_components"])
        self.assertIn("overlapping_directory_allocation", result.warnings)

    def test_directory_ownership_is_passed_without_whole_map_copies(self) -> None:
        data = bytearray(image())
        root = cluster_offset(data, 2)
        data[root + ROOT_SYSTEM_METADATA_BYTES : root + 512] = b"\0" * (
            512 - ROOT_SYSTEM_METADATA_BYTES
        )
        directory = entry("Child", directory=True, first_cluster=3, size=512)
        data[
            root + ROOT_SYSTEM_METADATA_BYTES : root
            + ROOT_SYSTEM_METADATA_BYTES
            + len(directory)
        ] = directory
        seen_ownership_maps = []

        def inspect_owned(*args, **kwargs):
            owned = kwargs["owned"]
            self.assertIsInstance(owned, dict)
            seen_ownership_maps.append(owned)
            return _directory_clusters(*args, **kwargs)

        with patch(
            "exfat_rescue.scanner._directory_clusters", side_effect=inspect_owned
        ):
            self.scan_bytes(data)
        self.assertGreaterEqual(len(seen_ownership_maps), 2)
        self.assertEqual(len({id(owned) for owned in seen_ownership_maps}), 1)

    def test_impossible_contiguous_directory_is_bounded_before_allocation(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "bounded.img"
        path.write_bytes(image())
        source = ImageSource.open(path)
        self.addCleanup(source.close)
        volume = ExfatVolume(source)

        with self.assertRaises(ResourceLimitError):
            _directory_clusters(
                volume,
                3,
                no_fat_chain=True,
                size_bytes=(1 << 64) - 1,
                owned={},
                remaining_cluster_budget=100,
                remaining_work_budget=100,
            )

    def test_completed_allocation_owner_is_downgraded_only_once(self) -> None:
        owners = {3: 2, 4: 2, 5: 2}
        completed = {2}
        downgraded: set[int] = set()

        self.assertEqual(_new_completed_owners({3}, owners, completed, downgraded), {2})
        self.assertEqual(
            _new_completed_owners({4, 5}, owners, completed, downgraded), set()
        )
        self.assertEqual(downgraded, {2})

    def test_rejected_aliases_consume_the_directory_work_budget(self) -> None:
        data = bytearray(image())
        cluster_count = 100
        fat_sector = struct.unpack_from("<I", data, 0x50)[0]
        old_heap_sector = struct.unpack_from("<I", data, 0x58)[0]
        heap_sector = 2048 - cluster_count
        old_heap = old_heap_sector * 512
        heap = heap_sector * 512
        data[heap : heap + 16 * 512] = data[old_heap : old_heap + 16 * 512]
        for boot_start in (0, 12 * 512):
            struct.pack_into("<I", data, boot_start + 0x5C, cluster_count)
            struct.pack_into("<I", data, boot_start + 0x58, heap_sector)
        for cluster in range(2, cluster_count + 2):
            next_cluster = cluster + 1 if cluster < cluster_count + 1 else 0xFFFFFFFF
            struct.pack_into("<I", data, fat_sector * 512 + cluster * 4, next_cluster)
        root = heap
        set_active_bitmap_allocations(data, set(range(2, cluster_count + 2)))
        struct.pack_into("<I", data, fat_sector * 512 + 2 * 4, 0xFFFFFFFF)
        struct.pack_into("<I", data, fat_sector * 512 + 7 * 4, 0xFFFFFFFF)
        struct.pack_into("<I", data, fat_sector * 512 + 8 * 4, 0xFFFFFFFF)
        data[root + ROOT_SYSTEM_METADATA_BYTES : root + 512] = b"\0" * (
            512 - ROOT_SYSTEM_METADATA_BYTES
        )
        first = entry(
            "FirstAlias",
            directory=True,
            first_cluster=3,
            size=99 * 512,
            no_fat_chain=True,
        )
        second = entry(
            "SecondAlias",
            directory=True,
            first_cluster=4,
            size=98 * 512,
            no_fat_chain=True,
        )
        third = entry(
            "ThirdAlias",
            directory=True,
            first_cluster=5,
            size=4 * 512,
            no_fat_chain=True,
        )
        first_start = root + ROOT_SYSTEM_METADATA_BYTES
        data[first_start : first_start + len(first)] = first
        data[first_start + len(first) : first_start + len(first) + len(second)] = second
        third_start = first_start + len(first) + len(second)
        data[third_start : third_start + len(third)] = third
        refresh_boot_checksums(data)

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "alias-budget.img"
        path.write_bytes(data)
        source = ImageSource.open(path)
        self.addCleanup(source.close)
        with self.assertRaises(ResourceLimitError):
            scan(source, max_candidates=20, max_scan_clusters=cluster_count)

    def test_repeated_fat_convergence_consumes_the_shared_work_budget(self) -> None:
        data = bytearray(image())
        cluster_count = 100
        fat_sector = struct.unpack_from("<I", data, 0x50)[0]
        heap_sector = 2048 - cluster_count
        for boot_start in (0, 12 * 512):
            struct.pack_into("<I", data, boot_start + 0x5C, cluster_count)
            struct.pack_into("<I", data, boot_start + 0x58, heap_sector)
        for cluster in range(3, 50):
            struct.pack_into("<I", data, fat_sector * 512 + cluster * 4, cluster + 1)
        refresh_boot_checksums(data)

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "fat-budget.img"
        path.write_bytes(data)
        source = ImageSource.open(path)
        self.addCleanup(source.close)
        volume = ExfatVolume(source)
        owners = {50: 2}
        remaining_work = 100

        first = _directory_clusters(
            volume,
            3,
            no_fat_chain=False,
            size_bytes=None,
            owned=owners,
            remaining_cluster_budget=100,
            remaining_work_budget=remaining_work,
        )
        self.assertEqual(first[2], {50})
        remaining_work -= first[3]
        second = _directory_clusters(
            volume,
            4,
            no_fat_chain=False,
            size_bytes=None,
            owned=owners,
            remaining_cluster_budget=100,
            remaining_work_budget=remaining_work,
        )
        self.assertEqual(second[2], {50})
        remaining_work -= second[3]
        third = _directory_clusters(
            volume,
            5,
            no_fat_chain=False,
            size_bytes=None,
            owned=owners,
            remaining_cluster_budget=100,
            remaining_work_budget=remaining_work,
        )
        remaining_work -= third[3]
        self.assertEqual(remaining_work, 0)
        with self.assertRaises(ResourceLimitError):
            _directory_clusters(
                volume,
                6,
                no_fat_chain=False,
                size_bytes=None,
                owned=owners,
                remaining_cluster_budget=100,
                remaining_work_budget=remaining_work,
            )


if __name__ == "__main__":
    unittest.main()
