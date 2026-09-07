"""Release-evidence tests for each recoverable classification and streaming bounds."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from exfat_rescue.cli import _internal_manifest_bytes
from exfat_rescue.planner import Extent, PlannerResult, RecoveryPlan
from exfat_rescue.recovery import recover_plans
from exfat_rescue.source import ImageSource
from exfat_rescue.verification import verify_recovery


class RecoveryBasisAndMemoryTests(unittest.TestCase):
    """Exercise the public extraction seam with independently constructed plans."""

    _CLUSTER_SIZE = 16

    @staticmethod
    def _candidate_id(binding: dict[str, object], entry: int, entry_hash: str) -> str:
        identity = json.dumps(
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
        ).encode("utf-8")
        return hashlib.sha256(
            identity
            + b":"
            + str(entry).encode("ascii")
            + b":"
            + entry_hash.encode("ascii")
        ).hexdigest()

    def _plans_and_source(
        self, root: Path
    ) -> tuple[ImageSource, PlannerResult, bytes, dict[str, bytes]]:
        """Create one exact source layout for all nine recovery bases.

        Contiguous candidates use adjacent physical clusters. FAT-chain candidates
        deliberately use non-adjacent clusters, proving that extraction follows the
        validated extent sequence rather than a contiguous source range.
        """
        cluster_size = self._CLUSTER_SIZE
        layouts = (
            ("active", "contiguous", (2, 3)),
            ("deleted", "contiguous", (4, 5)),
            ("orphan", "contiguous", (6, 7)),
            ("active", "fat_chain", (8, 11)),
            ("deleted", "fat_chain", (12, 15)),
            ("orphan", "fat_chain", (16, 19)),
            ("active", "empty", ()),
            ("deleted", "empty", ()),
            ("orphan", "empty", ()),
        )
        # Cluster 20 is sufficient for the highest non-adjacent FAT extent.
        source_path = root / "synthetic-source.img"
        raw = bytearray(19 * cluster_size)
        expected: dict[str, bytes] = {}
        metadata: list[tuple[str, str, tuple[int, ...], bytes]] = []
        for index, (location, mode, clusters) in enumerate(layouts, start=1):
            basis = f"{location}_{mode}_{'allocated' if location == 'active' else 'unallocated'}"
            if mode == "empty":
                basis = f"{location}_empty"
                expected[basis] = b""
                metadata.append((location, mode, clusters, b""))
                continue
            # 17 valid bytes cross the cluster boundary, and the last four
            # logical bytes must be zero-filled rather than copied from source.
            content = (f"{basis}:{index:02d}".encode("ascii"))[:17]
            self.assertEqual(len(content), 17)
            raw[(clusters[0] - 2) * cluster_size : (clusters[0] - 1) * cluster_size] = (
                content[:16]
            )
            raw[(clusters[1] - 2) * cluster_size] = content[16]
            expected[basis] = content + b"\0" * 4
            metadata.append((location, mode, clusters, content))
        source_path.write_bytes(raw)
        source = ImageSource.open(source_path)
        binding: dict[str, object] = {
            "image_size_bytes": source.size,
            "volume_offset_bytes": 0,
            "volume_length_bytes": source.size,
            "volume_sha256": source.selected_volume_sha256(0, source.size),
            "cluster_size_bytes": cluster_size,
            "cluster_heap_offset_bytes": 0,
            "source_kind": "direct-image",
            "boot_region": "primary",
            "volume_dirty": False,
            "media_failure": False,
        }
        pairs: list[tuple[RecoveryPlan, dict[str, object]]] = []
        for entry, (location, mode, clusters, content) in enumerate(metadata, start=1):
            entry_hash = f"{entry:064x}"
            candidate_id = self._candidate_id(binding, entry, entry_hash)
            deleted = location == "deleted"
            raw_location = "orphan" if location == "orphan" else "directory"
            extents = (
                ()
                if mode == "empty"
                else (Extent(clusters[0], 2),)
                if mode == "contiguous"
                else tuple(Extent(cluster, 1) for cluster in clusters)
            )
            logical_size = 0 if mode == "empty" else 21
            valid_size = len(content)
            basis = (
                f"{location}_empty"
                if mode == "empty"
                else f"{location}_{mode}_{'allocated' if location == 'active' else 'unallocated'}"
            )
            plan = RecoveryPlan(
                candidate_id,
                entry,
                entry_hash,
                basis,
                logical_size,
                valid_size,
                extents,
                mode,
                f"{location}_directory" if location != "orphan" else "orphan",
                "recoverable",
                basis,
                (),
            )
            raw_candidate: dict[str, object] = {
                "entry_offset": entry,
                "name": basis,
                "size_bytes": logical_size,
                "valid_size_bytes": valid_size,
                "first_cluster": clusters[0] if clusters else 0,
                "no_fat_chain": mode == "contiguous",
                "deleted": deleted,
                "location": raw_location,
                "entry_set_sha256": entry_hash,
                "is_directory": False,
                "attributes": 0,
                "entry_checksum": "0000",
            }
            pairs.append((plan, raw_candidate))
        pairs.sort(key=lambda pair: pair[0].candidate_id)
        planned = PlannerResult(
            tuple(pair[0] for pair in pairs),
            binding,
            0,
            tuple(pair[1] for pair in pairs),
        )
        manifest = _internal_manifest_bytes(
            planned,
            {"max_candidates": 100, "max_scan_clusters": 1000, "max_fat_steps": 1000},
            (),
        )
        return source, planned, manifest, expected

    def test_exact_bytes_for_every_recovery_basis(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, planned, manifest, expected = self._plans_and_source(root)
            try:
                result = recover_plans(
                    source,
                    planned.plans,
                    root / "output",
                    source_binding=planned.source_binding,
                    manifest_bytes=manifest,
                    selected_ids=[plan.candidate_id for plan in planned.plans],
                    limits={
                        "max_output_bytes": 9 * 21,
                        "max_candidates": 100,
                        "max_scan_clusters": 1000,
                        "max_fat_steps": 1000,
                    },
                )
            finally:
                source.close()
            self.assertTrue(result["complete"])
            report = [
                json.loads(line)
                for line in (root / "output" / "report.jsonl").read_text().splitlines()
            ]
            records = {
                record["candidate_id"]: record
                for record in report
                if record["record_type"] == "candidate"
            }
            self.assertEqual(len(records), 9)
            for plan in planned.plans:
                data = (
                    root / "output" / "files" / plan.candidate_id / "data"
                ).read_bytes()
                self.assertEqual(data, expected[plan.recovery_basis or ""])
                record = records[plan.candidate_id]
                source_data = data[: plan.valid_data_bytes]
                self.assertEqual(
                    record["source_data_sha256"],
                    hashlib.sha256(source_data).hexdigest(),
                )
                self.assertEqual(
                    record["output_sha256"], hashlib.sha256(data).hexdigest()
                )
                self.assertEqual(
                    record["zero_filled_bytes"], len(data) - len(source_data)
                )
            verified = verify_recovery(root / "output")
            self.assertTrue(verified["ok"])
            self.assertFalse(verified["image_verified"])

    def test_peak_rss_is_not_proportional_to_logical_recovery_size(self) -> None:
        """Compare isolated 2 MiB and 48 MiB recoveries without platform units.

        Each child reports bytes, normalizing macOS's byte and Linux's KiB
        ``ru_maxrss`` conventions. The 24 MiB additive allowance absorbs allocator
        and interpreter-startup noise while still failing if the 48 MiB output is
        materialized in memory.
        """
        program = textwrap.dedent(
            """
            import hashlib, json, resource, sys, tempfile
            from pathlib import Path
            from exfat_rescue.cli import _internal_manifest_bytes
            from exfat_rescue.planner import Extent, PlannerResult, RecoveryPlan
            from exfat_rescue.recovery import recover_plans
            from exfat_rescue.source import ImageSource

            size = int(sys.argv[1])
            cluster_size = 1024 * 1024
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                image = root / "source.img"
                with image.open("wb") as stream:
                    stream.truncate(size)
                source = ImageSource.open(image)
                try:
                    binding = {
                        "image_size_bytes": size, "volume_offset_bytes": 0,
                        "volume_length_bytes": size,
                        "volume_sha256": source.selected_volume_sha256(0, size),
                        "cluster_size_bytes": cluster_size,
                        "cluster_heap_offset_bytes": 0, "source_kind": "direct-image",
                        "boot_region": "primary", "volume_dirty": False,
                        "media_failure": False,
                    }
                    entry_hash = "a" * 64
                    identity = json.dumps({key: binding[key] for key in (
                        "volume_offset_bytes", "volume_length_bytes", "volume_sha256")},
                        sort_keys=True, separators=(",", ":")).encode()
                    candidate_id = hashlib.sha256(identity + b":1:" + entry_hash.encode()).hexdigest()
                    clusters = size // cluster_size
                    plan = RecoveryPlan(candidate_id, 1, entry_hash, "stream", size, size,
                        (Extent(2, clusters),), "contiguous", "active_directory",
                        "recoverable", "active_contiguous_allocated", ())
                    raw = {"entry_offset": 1, "name": "stream", "size_bytes": size,
                        "valid_size_bytes": size, "first_cluster": 2, "no_fat_chain": True,
                        "deleted": False, "location": "directory", "entry_set_sha256": entry_hash,
                        "is_directory": False, "attributes": 0, "entry_checksum": "0000"}
                    planned = PlannerResult((plan,), binding, 0, (raw,))
                    manifest = _internal_manifest_bytes(planned, {"max_candidates": 1,
                        "max_scan_clusters": clusters, "max_fat_steps": clusters}, ())
                    recover_plans(source, planned.plans, root / "output", source_binding=binding,
                        manifest_bytes=manifest, selected_ids=[candidate_id], limits={
                        "max_output_bytes": size, "max_candidates": 1,
                        "max_scan_clusters": clusters, "max_fat_steps": clusters})
                finally:
                    source.close()
            rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            print(rss if sys.platform == "darwin" else rss * 1024)
            """
        )

        def peak(size: int) -> int:
            completed = subprocess.run(
                [sys.executable, "-c", program, str(size)],
                check=True,
                capture_output=True,
                text=True,
                timeout=120,
            )
            return int(completed.stdout.strip())

        small = peak(2 * 1024 * 1024)
        large = peak(48 * 1024 * 1024)
        self.assertLessEqual(large, small + 24 * 1024 * 1024)
