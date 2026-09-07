from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from exfat_rescue.planner import plan_recovery
from exfat_rescue.scanner import ActiveOwnership, OwnershipExtent, scan
from exfat_rescue.source import ImageSource
from tests.fixture import image


class PlannerTests(unittest.TestCase):
    def test_planner_returns_immutable_bound_plans(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.img"
            path.write_bytes(image())
            source = ImageSource.open(path)
            try:
                result = scan(source)
                planned = plan_recovery(result.volume, result.candidates)
            finally:
                source.close()
        self.assertEqual(
            tuple(sorted(planned.plans, key=lambda plan: plan.candidate_id)),
            planned.plans,
        )
        self.assertEqual(len(planned.source_binding["volume_sha256"]), 64)
        self.assertTrue(all(len(plan.candidate_id) == 64 for plan in planned.plans))
        self.assertTrue(all(len(plan.entry_set_sha256) == 64 for plan in planned.plans))

    def test_descending_acyclic_fat_chain_is_recoverable(self) -> None:
        class Boot:
            cluster_size = 512
            cluster_count = 16
            volume_bytes = 8192
            heap_offset = 0
            bytes_per_sector = 512

        class Volume:
            boot = Boot()
            base_offset = 0
            boot_region = "primary"
            location = type("Location", (), {"source_kind": "direct-image"})()
            source = type(
                "Source",
                (),
                {"size": 8192, "selected_volume_sha256": lambda *_: "a" * 64},
            )()

            @staticmethod
            def valid_cluster(cluster: int) -> bool:
                return 2 <= cluster < 18

            @staticmethod
            def fat_next(cluster: int) -> int:
                return {3: 7, 7: 5}.get(cluster, 0xFFFFFFFF)

            @staticmethod
            def cluster_is_allocated(_cluster: int) -> bool:
                return True

        candidate = {
            "candidate_id": "ignored",
            "entry_offset": 64,
            "entry_set_sha256": "b" * 64,
            "name": "x",
            "size_bytes": 3 * 512,
            "valid_size_bytes": 3 * 512,
            "first_cluster": 3,
            "no_fat_chain": False,
            "deleted": False,
            "location": "directory",
            "is_directory": False,
            "attributes": 0,
            "entry_checksum": "0000",
        }
        result = plan_recovery(Volume(), [candidate], ownership_complete=True)
        self.assertEqual(result.plans[0].disposition, "recoverable")
        self.assertEqual(
            tuple(extent.first_cluster for extent in result.plans[0].extents),
            (3, 7, 5),
        )

    def test_repeated_fat_cluster_is_reported_as_cycle(self) -> None:
        class Boot:
            cluster_size = 512
            cluster_count = 16
            volume_bytes = 8192
            heap_offset = 0
            bytes_per_sector = 512

        class Volume:
            boot = Boot()
            base_offset = 0
            boot_region = "primary"
            location = type("Location", (), {"source_kind": "direct-image"})()
            source = type(
                "Source",
                (),
                {"size": 8192, "selected_volume_sha256": lambda *_: "a" * 64},
            )()

            @staticmethod
            def valid_cluster(cluster: int) -> bool:
                return 2 <= cluster < 18

            @staticmethod
            def fat_next(cluster: int) -> int:
                return {3: 4, 4: 5, 5: 3}[cluster]

            @staticmethod
            def cluster_is_allocated(_cluster: int) -> bool:
                return True

        candidate = {
            "entry_offset": 64,
            "entry_set_sha256": "b" * 64,
            "name": "cycle",
            "size_bytes": 4 * 512,
            "valid_size_bytes": 4 * 512,
            "first_cluster": 3,
            "no_fat_chain": False,
            "deleted": False,
            "location": "directory",
            "is_directory": False,
            "attributes": 0,
            "entry_checksum": "0000",
        }
        result = plan_recovery(Volume(), [candidate], ownership_complete=True)
        self.assertEqual(result.plans[0].reasons, ("fat_cycle",))

    def test_large_contiguous_active_claim_is_one_interval(self) -> None:
        """Ownership storage must not grow one Python object per data cluster."""

        class Boot:
            cluster_size = 512
            cluster_count = 2_000_000
            volume_bytes = cluster_count * cluster_size
            heap_offset = 0
            bytes_per_sector = 512

        class Volume:
            boot = Boot()
            base_offset = 0
            boot_region = "primary"
            location = type("Location", (), {"source_kind": "direct-image"})()
            source = type(
                "Source",
                (),
                {
                    "size": Boot.volume_bytes,
                    "selected_volume_sha256": lambda *_: "c" * 64,
                },
            )()

            @staticmethod
            def valid_cluster(cluster: int) -> bool:
                return 2 <= cluster < Boot.cluster_count + 2

            @staticmethod
            def cluster_is_allocated(_cluster: int) -> bool:
                return True

        candidate = {
            "entry_offset": 512,
            "entry_set_sha256": "d" * 64,
            "name": "large",
            "size_bytes": 1_500_000 * 512,
            "valid_size_bytes": 1_500_000 * 512,
            "first_cluster": 2,
            "no_fat_chain": True,
            "deleted": False,
            "location": "directory",
            "is_directory": False,
            "attributes": 0,
            "entry_checksum": "0000",
        }
        ownership = ActiveOwnership(
            exact={},
            file_extents=(
                OwnershipExtent(2, 1_500_002, "file:512", primary_stream=True),
            ),
        )
        result = plan_recovery(
            Volume(),
            [candidate],
            active_owners=ownership,
            ownership_complete=True,
            max_cluster_operations=1_500_000,
        )
        self.assertEqual(len(ownership.file_extents), 1)
        self.assertEqual(result.plans[0].disposition, "recoverable")
        self.assertEqual(result.plans[0].extents[0].cluster_count, 1_500_000)

    def test_deleted_candidate_conflicts_with_compact_active_claim(self) -> None:
        class Boot:
            cluster_size = 512
            cluster_count = 16
            volume_bytes = 8192
            heap_offset = 0
            bytes_per_sector = 512

        class Volume:
            boot = Boot()
            base_offset = 0
            boot_region = "primary"
            location = type("Location", (), {"source_kind": "direct-image"})()
            source = type(
                "Source",
                (),
                {"size": 8192, "selected_volume_sha256": lambda *_: "e" * 64},
            )()

            @staticmethod
            def valid_cluster(cluster: int) -> bool:
                return 2 <= cluster < 18

            @staticmethod
            def cluster_is_allocated(_cluster: int) -> bool:
                return False

        candidate = {
            "entry_offset": 768,
            "entry_set_sha256": "f" * 64,
            "name": "deleted",
            "size_bytes": 2 * 512,
            "valid_size_bytes": 2 * 512,
            "first_cluster": 6,
            "no_fat_chain": True,
            "deleted": True,
            "location": "directory",
            "is_directory": False,
            "attributes": 0,
            "entry_checksum": "0000",
        }
        ownership = ActiveOwnership(
            exact={}, file_extents=(OwnershipExtent(5, 8, "file:123"),)
        )
        result = plan_recovery(
            Volume(), [candidate], active_owners=ownership, ownership_complete=True
        )
        self.assertEqual(result.plans[0].disposition, "conflicted")
        self.assertIn("active_owner_conflict", result.plans[0].reasons)

        # A Vendor Allocation in the same File entry set is not that file's
        # primary stream, so it must remain unavailable even with the same
        # entry-offset owner label.
        active_vendor_overlap = {**candidate, "deleted": False}
        vendor_ownership = ActiveOwnership(
            exact={}, file_extents=(OwnershipExtent(5, 8, "file:768"),)
        )
        result = plan_recovery(
            Volume(),
            [active_vendor_overlap],
            active_owners=vendor_ownership,
            ownership_complete=True,
        )
        self.assertIn("active_owner_conflict", result.plans[0].reasons)

    def test_stale_nonactive_overlap_does_not_conflict_active_file(self) -> None:
        class Boot:
            cluster_size = 512
            cluster_count = 16
            volume_bytes = 8192
            heap_offset = 0
            bytes_per_sector = 512

        class Volume:
            boot = Boot()
            base_offset = 0
            boot_region = "primary"
            location = type("Location", (), {"source_kind": "direct-image"})()
            source = type(
                "Source",
                (),
                {"size": 8192, "selected_volume_sha256": lambda *_: "1" * 64},
            )()

            @staticmethod
            def valid_cluster(cluster: int) -> bool:
                return 2 <= cluster < 18

            @staticmethod
            def cluster_is_allocated(_cluster: int) -> bool:
                return True

        active = {
            "entry_offset": 64,
            "entry_set_sha256": "2" * 64,
            "name": "active",
            "size_bytes": 512,
            "valid_size_bytes": 512,
            "first_cluster": 3,
            "no_fat_chain": True,
            "deleted": False,
            "location": "directory",
            "is_directory": False,
            "attributes": 0,
            "entry_checksum": "0000",
        }
        stale = {**active, "entry_offset": 96, "deleted": True, "name": "stale"}
        result = plan_recovery(
            Volume(),
            [active, stale],
            active_owners=ActiveOwnership(
                exact={},
                file_extents=(OwnershipExtent(3, 4, "file:64", primary_stream=True),),
            ),
            ownership_complete=True,
        )
        by_name = {plan.name: plan for plan in result.plans}
        self.assertEqual(by_name["active"].disposition, "recoverable")
        self.assertNotIn("active_file_overlap", by_name["active"].reasons)
        self.assertEqual(by_name["stale"].disposition, "conflicted")

    def test_empty_files_have_factual_recovery_bases(self) -> None:
        class Boot:
            cluster_size = 512
            cluster_count = 16
            volume_bytes = 8192
            heap_offset = 0
            bytes_per_sector = 512

        class Volume:
            boot = Boot()
            base_offset = 0
            boot_region = "primary"
            location = type("Location", (), {"source_kind": "direct-image"})()
            source = type(
                "Source",
                (),
                {"size": 8192, "selected_volume_sha256": lambda *_: "3" * 64},
            )()

            @staticmethod
            def valid_cluster(cluster: int) -> bool:
                return 2 <= cluster < 18

            @staticmethod
            def cluster_is_allocated(_cluster: int) -> bool:
                return False

            @staticmethod
            def cluster_offset(cluster: int) -> int:
                return (cluster - 2) * 512

        candidate = {
            "entry_offset": 0,
            "entry_set_sha256": "4" * 64,
            "name": "empty",
            "size_bytes": 0,
            "valid_size_bytes": 0,
            "first_cluster": 0,
            "no_fat_chain": False,
            "deleted": False,
            "location": "directory",
            "is_directory": False,
            "attributes": 0,
            "entry_checksum": "0000",
        }
        cases = (
            ({**candidate, "location": "directory"}, "active_empty"),
            ({**candidate, "deleted": True}, "deleted_empty"),
            ({**candidate, "location": "orphan"}, "orphan_empty"),
        )
        for item, basis in cases:
            with self.subTest(basis=basis):
                result = plan_recovery(Volume(), [item], ownership_complete=True)
                self.assertEqual(result.plans[0].recovery_basis, basis)
