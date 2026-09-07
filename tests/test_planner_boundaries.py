"""Adversarial contract tests for recovery planning and manifest semantics."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from typing import Any

from exfat_rescue.errors import FormatError, ManifestError, ResourceLimitError
from exfat_rescue.manifest import parse_manifest_v2_bytes, validate_manifest_plans
from exfat_rescue.planner import PlannerResult, plan_recovery
from exfat_rescue.scanner import ActiveOwnership


class _Boot:
    cluster_size = 512
    cluster_count = 32
    volume_bytes = cluster_count * cluster_size
    heap_offset = 0
    bytes_per_sector = 512


class _Volume:
    boot = _Boot()
    base_offset = 0
    boot_region = "primary"
    location = type("Location", (), {"source_kind": "direct-image"})()
    source = type(
        "Source",
        (),
        {
            "size": _Boot.volume_bytes,
            "selected_volume_sha256": lambda *_: "a" * 64,
        },
    )()

    def __init__(
        self, *, allocated: set[int] | None = None, fat: dict[int, int] | None = None
    ) -> None:
        self.allocated = allocated if allocated is not None else set()
        self.fat = fat if fat is not None else {}

    @staticmethod
    def valid_cluster(cluster: int) -> bool:
        return 2 <= cluster < _Boot.cluster_count + 2

    def fat_next(self, cluster: int) -> int:
        return self.fat.get(cluster, 0xFFFFFFFF)

    def cluster_is_allocated(self, cluster: int) -> bool:
        return cluster in self.allocated

    @staticmethod
    def cluster_offset(cluster: int) -> int:
        return (cluster - 2) * _Boot.cluster_size


def _candidate(**updates: object) -> dict[str, Any]:
    value: dict[str, Any] = {
        "entry_offset": 0,
        "entry_set_sha256": "b" * 64,
        "name": "file",
        "size_bytes": 512,
        "valid_size_bytes": 512,
        "first_cluster": 2,
        "no_fat_chain": True,
        "deleted": False,
        "location": "directory",
        "is_directory": False,
        "attributes": 0,
        "entry_checksum": "0000",
    }
    value.update(updates)
    return value


def _manifest_bytes(plan: object, raw: dict[str, Any]) -> bytes:
    """Make a fully hashed, otherwise canonical one-plan v2 manifest."""
    plan_value = plan
    record = {
        "record_type": "candidate",
        "candidate_id": plan_value.candidate_id,
        "entry_offset": plan_value.entry_offset,
        "entry_set_sha256": plan_value.entry_set_sha256,
        "name": plan_value.name,
        "logical_size_bytes": plan_value.logical_size_bytes,
        "valid_data_bytes": plan_value.valid_data_bytes,
        "extents": [
            {"first_cluster": item.first_cluster, "cluster_count": item.cluster_count}
            for item in plan_value.extents
        ],
        "allocation_mode": plan_value.allocation_mode,
        "metadata_location": plan_value.metadata_location,
        "disposition": plan_value.disposition,
        "recovery_basis": plan_value.recovery_basis,
        "reasons": list(plan_value.reasons),
        "source_candidate": raw,
    }
    header = {
        "record_type": "manifest",
        "format": "exfat-rescue.manifest",
        "version": 2,
        "schema": "https://raw.githubusercontent.com/MrJeffrey/exfat-rescue/main/src/exfat_rescue/schemas/manifest-v2.json",
        "source": {
            "image_size_bytes": _Boot.volume_bytes,
            "volume_offset_bytes": 0,
            "volume_length_bytes": _Boot.volume_bytes,
            "volume_sha256": "a" * 64,
            "cluster_size_bytes": 512,
            "cluster_heap_offset_bytes": 0,
            "source_kind": "direct-image",
            "boot_region": "primary",
            "volume_dirty": False,
            "media_failure": False,
        },
        "scan_options": {
            "orphan_scan": True,
            "version": 2,
            "volume_offset_bytes": 0,
            "source_kind": "direct-image",
            "boot_region": "primary",
            "max_candidates": 10,
            "max_scan_clusters": 100,
            "max_fat_steps": 100,
        },
        "candidate_count": 1,
        "warnings": [],
    }
    lines = [
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        for value in (header, record)
    ]
    completion = {
        "record_type": "complete",
        "candidate_count": 1,
        "content_record_count": 2,
        "content_sha256": hashlib.sha256(b"".join(lines)).hexdigest(),
    }
    return (
        b"".join(lines)
        + json.dumps(completion, sort_keys=True, separators=(",", ":")).encode()
        + b"\n"
    )


class PlannerBoundaryTests(unittest.TestCase):
    def _one(self, volume: _Volume, candidate: dict[str, Any], **kwargs: object):
        return plan_recovery(
            volume, [candidate], ownership_complete=True, **kwargs
        ).plans[0]

    def test_recovery_basis_paths_and_empty_file_are_deterministic(self) -> None:
        cases = (
            ("active_contiguous_allocated", _Volume(allocated={2}), _candidate()),
            (
                "active_fat_chain_allocated",
                _Volume(allocated={2}),
                _candidate(no_fat_chain=False),
            ),
            ("deleted_contiguous_unallocated", _Volume(), _candidate(deleted=True)),
            (
                "deleted_fat_chain_unallocated",
                _Volume(),
                _candidate(deleted=True, no_fat_chain=False),
            ),
            ("orphan_contiguous_unallocated", _Volume(), _candidate(location="orphan")),
            (
                "orphan_fat_chain_unallocated",
                _Volume(),
                _candidate(location="orphan", no_fat_chain=False),
            ),
        )
        for expected, volume, candidate in cases:
            with self.subTest(expected=expected):
                plan = self._one(volume, candidate)
                self.assertEqual(
                    (plan.disposition, plan.recovery_basis, plan.reasons),
                    ("recoverable", expected, ()),
                )
        empty = self._one(
            _Volume(),
            _candidate(
                size_bytes=0,
                valid_size_bytes=0,
                first_cluster=0,
                no_fat_chain=False,
                deleted=True,
            ),
        )
        self.assertEqual(empty.allocation_mode, "empty")
        self.assertEqual(empty.extents, ())
        self.assertEqual(
            (empty.disposition, empty.recovery_basis),
            ("recoverable", "deleted_empty"),
        )

    def test_exact_fat_refusal_paths_do_not_retain_extents(self) -> None:
        cases = {
            "fat_bad_cluster": _Volume(fat={2: 0xFFFFFFF7}),
            "fat_invalid_next": _Volume(fat={2: 0xFFFFFFF6}),
            "fat_short_chain": _Volume(fat={2: 0xFFFFFFFF}),
            "fat_cycle": _Volume(fat={2: 3, 3: 2}),
            "fat_overlong_chain": _Volume(fat={2: 3}),
        }
        for reason, volume in cases.items():
            size = (
                1536
                if reason == "fat_cycle"
                else 1024
                if reason == "fat_short_chain"
                else 512
            )
            with self.subTest(reason=reason):
                plan = self._one(
                    volume,
                    _candidate(
                        size_bytes=size, valid_size_bytes=size, no_fat_chain=False
                    ),
                )
                self.assertEqual(
                    (plan.disposition, plan.reasons, plan.extents),
                    ("unrecoverable", (reason,), ()),
                )
        descending = self._one(
            _Volume(allocated={3, 4}, fat={4: 3}),
            _candidate(
                first_cluster=4,
                size_bytes=1024,
                valid_size_bytes=1024,
                no_fat_chain=False,
            ),
        )
        self.assertEqual(
            (descending.disposition, descending.recovery_basis),
            ("recoverable", "active_fat_chain_allocated"),
        )

    def test_refusal_and_cumulative_work_paths(self) -> None:
        candidate = _candidate()
        cases = (
            ("incomplete_active_metadata", _Volume(), {"metadata_complete": False}),
            ("incomplete_active_ownership", _Volume(), {"ownership_complete": False}),
            (
                "invalid_valid_data_length",
                _Volume(),
                {"candidate": _candidate(valid_size_bytes=513)},
            ),
            (
                "contiguous_extent_outside_volume",
                _Volume(),
                {"candidate": _candidate(first_cluster=34)},
            ),
            (
                "fat_work_limit",
                _Volume(),
                {"candidate": _candidate(no_fat_chain=False), "max_fat_steps": 0},
            ),
            ("ownership_work_limit", _Volume(), {"max_cluster_operations": 0}),
        )
        for reason, volume, options in cases:
            with self.subTest(reason=reason):
                item = options.get("candidate", candidate)
                kwargs = {
                    key: value for key, value in options.items() if key != "candidate"
                }
                kwargs.setdefault("ownership_complete", True)
                plan = plan_recovery(volume, [item], **kwargs).plans[0]
                self.assertEqual(
                    (plan.disposition, plan.reasons), ("unrecoverable", (reason,))
                )
        with self.assertRaises(ResourceLimitError):
            plan_recovery(_Volume(), [candidate], max_fat_steps=-1)
        with self.assertRaises(ResourceLimitError):
            plan_recovery(_Volume(), [candidate], max_extents_per_candidate=4097)

    def test_remaining_refusal_paths_are_explicit_and_bounded(self) -> None:
        unavailable = _Volume()
        unavailable.cluster_is_allocated = None  # type: ignore[method-assign]
        cases = (
            ("active_bitmap_unavailable", unavailable, _candidate(), {}),
            (
                "extent_limit",
                _Volume(fat={2: 4, 4: 6, 6: 0xFFFFFFFF}),
                _candidate(size_bytes=1536, valid_size_bytes=1536, no_fat_chain=False),
                {"max_extents_per_candidate": 1},
            ),
            (
                "orphan_metadata_host_allocated",
                _Volume(allocated={2}),
                _candidate(location="orphan", first_cluster=3),
                {},
            ),
        )
        for reason, volume, candidate, kwargs in cases:
            with self.subTest(reason=reason):
                plan = self._one(volume, candidate, **kwargs)
                expected_disposition = (
                    "conflicted"
                    if reason == "orphan_metadata_host_allocated"
                    else "unrecoverable"
                )
                self.assertEqual(
                    (plan.disposition, plan.reasons),
                    (expected_disposition, (reason,)),
                )

        truncated = _Volume()

        def raise_truncated(_: int) -> int:
            raise FormatError("truncated FAT")

        truncated.fat_next = raise_truncated  # type: ignore[method-assign]
        plan = self._one(truncated, _candidate(no_fat_chain=False))
        self.assertEqual(plan.reasons, ("fat_truncated_read",))

    def test_allocation_ownership_and_overlap_conflicts_are_symmetric(self) -> None:
        active = self._one(_Volume(), _candidate())
        self.assertEqual(active.reasons, ("active_bitmap_allocation_conflict",))
        deleted = self._one(_Volume(allocated={2}), _candidate(deleted=True))
        self.assertEqual(deleted.reasons, ("cluster_currently_allocated",))
        owners = ActiveOwnership(exact={2: "file:99"}, file_extents=())
        owned = self._one(_Volume(allocated={2}), _candidate(), active_owners=owners)
        self.assertEqual(owned.reasons, ("active_owner_conflict",))
        first, second = (
            _candidate(entry_offset=5),
            _candidate(entry_offset=6, entry_set_sha256="c" * 64),
        )
        deleted_result = plan_recovery(
            _Volume(),
            [{**first, "deleted": True}, {**second, "deleted": True}],
            ownership_complete=True,
        )
        self.assertTrue(
            all(
                plan.reasons == ("plausible_recovery_overlap",)
                for plan in deleted_result.plans
            )
        )

    def test_malformed_orphan_metadata_host_hints_fail_closed(self) -> None:
        candidate = _candidate(
            location="orphan",
            metadata_host_clusters=(2, 4),
        )
        plan = self._one(_Volume(), candidate)

        self.assertEqual(
            (plan.disposition, plan.reasons),
            ("conflicted", ("orphan_metadata_host_allocated",)),
        )

    def test_source_binding_candidate_ids_and_order_are_stable(self) -> None:
        first = _candidate(entry_offset=8, entry_set_sha256="c" * 64)
        second = _candidate(entry_offset=4, entry_set_sha256="d" * 64)
        one = plan_recovery(
            _Volume(allocated={2}), [first, second], ownership_complete=True
        )
        two = plan_recovery(
            _Volume(allocated={2}), [second, first], ownership_complete=True
        )
        self.assertEqual(one, two)
        self.assertEqual(one.source_binding["volume_sha256"], "a" * 64)
        altered = _Volume(allocated={2})
        altered.base_offset = 512
        changed = plan_recovery(altered, [first, second], ownership_complete=True)
        self.assertNotEqual(one.plans[0].candidate_id, changed.plans[0].candidate_id)


class ManifestBoundaryTests(unittest.TestCase):
    def _valid(self) -> tuple[bytes, object, dict[str, Any]]:
        raw = _candidate()
        plan = plan_recovery(
            _Volume(allocated={2}), [raw], ownership_complete=True
        ).plans[0]
        return _manifest_bytes(plan, raw), plan, raw

    def test_manifest_rejects_semantic_empty_and_basis_mismatches(self) -> None:
        content, _, _ = self._valid()
        records = [json.loads(line) for line in content.splitlines()]
        mutations = (
            ("empty has extent", (1, "logical_size_bytes"), 0),
            (
                "basis wrong for active",
                (1, "recovery_basis"),
                "deleted_contiguous_unallocated",
            ),
            ("conflicted needs expected allocation", (1, "disposition"), "conflicted"),
            ("extent outside heap", (1, "extents", 0, "first_cluster"), 34),
            (
                "uncoalesced extent",
                (1, "extents"),
                [
                    {"first_cluster": 2, "cluster_count": 1},
                    {"first_cluster": 3, "cluster_count": 1},
                ],
            ),
        )
        for label, path, value in mutations:
            with self.subTest(label=label):
                changed = copy.deepcopy(records)
                target: Any = changed
                for item in path[:-1]:
                    target = target[item]
                target[path[-1]] = value
                if label == "empty has extent":
                    changed[1]["valid_data_bytes"] = 0
                    changed[1]["source_candidate"]["valid_size_bytes"] = 0
                body = b"".join(
                    json.dumps(item, sort_keys=True, separators=(",", ":")).encode()
                    + b"\n"
                    for item in changed[:-1]
                )
                changed[-1]["content_sha256"] = hashlib.sha256(body).hexdigest()
                encoded = (
                    body
                    + json.dumps(
                        changed[-1], sort_keys=True, separators=(",", ":")
                    ).encode()
                    + b"\n"
                )
                with self.assertRaises(ManifestError):
                    parse_manifest_v2_bytes(encoded)

    def test_manifest_plan_validation_requires_exact_source_binding_and_plan(
        self,
    ) -> None:
        content, plan, raw = self._valid()
        manifest = parse_manifest_v2_bytes(content)
        current = PlannerResult((plan,), dict(manifest.header["source"]), 0, (raw,))
        validate_manifest_plans(manifest, current)
        changed_binding = dict(manifest.header["source"])
        changed_binding["volume_sha256"] = "f" * 64
        with self.assertRaises(ManifestError):
            validate_manifest_plans(
                manifest, PlannerResult((plan,), changed_binding, 0, (raw,))
            )
