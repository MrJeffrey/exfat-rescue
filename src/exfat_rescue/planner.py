"""Bounded, conservative recovery allocation planning.

This module deliberately does not extract data.  Its output is an immutable
description of a *currently provable* allocation, suitable for the recovery
writer to consume after it has revalidated the source.
"""

from __future__ import annotations

import hashlib
import json
from bisect import bisect_left, bisect_right
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from .errors import FormatError, ResourceLimitError

MAX_EXTENTS_PER_CANDIDATE = 4096
DEFAULT_MAX_FAT_STEPS = 10_000_000


@dataclass(frozen=True)
class Extent:
    first_cluster: int
    cluster_count: int


@dataclass(frozen=True)
class RecoveryPlan:
    candidate_id: str
    entry_offset: int
    entry_set_sha256: str
    name: str
    logical_size_bytes: int
    valid_data_bytes: int
    extents: tuple[Extent, ...]
    allocation_mode: Literal["empty", "contiguous", "fat_chain"]
    metadata_location: Literal["active_directory", "deleted_directory", "orphan"]
    disposition: Literal["recoverable", "conflicted", "unrecoverable"]
    recovery_basis: str | None
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class PlannerResult:
    plans: tuple[RecoveryPlan, ...]
    source_binding: Mapping[str, object]
    cumulative_fat_steps: int
    source_candidates: tuple[Mapping[str, object], ...] = ()


def _clusters_for_size(size: int, cluster_size: int) -> int:
    return (size + cluster_size - 1) // cluster_size if size else 0


def _coalesce(clusters: Sequence[int], cap: int) -> tuple[Extent, ...] | None:
    if not clusters:
        return ()
    extents: list[Extent] = []
    first = previous = clusters[0]
    for cluster in clusters[1:]:
        if cluster == previous + 1:
            previous = cluster
            continue
        extents.append(Extent(first, previous - first + 1))
        if len(extents) > cap:
            return None
        first = previous = cluster
    extents.append(Extent(first, previous - first + 1))
    return tuple(extents) if len(extents) <= cap else None


def _metadata_location(
    candidate: dict[str, Any],
) -> Literal["active_directory", "deleted_directory", "orphan"]:
    if candidate.get("location") == "orphan":
        return "orphan"
    return "deleted_directory" if candidate.get("deleted") else "active_directory"


def _bitmap_allocated(volume: Any, cluster: int) -> bool | None:
    """Adapt the strict system-metadata API while keeping this boundary pure.

    Workstream A supplies ``cluster_is_allocated``.  The small fallback keeps
    planner unit tests useful with deliberately tiny fake volumes; it is never
    a substitute for the scanner's required system-metadata validation.
    """
    method = getattr(volume, "cluster_is_allocated", None)
    if callable(method):
        return bool(method(cluster))
    bitmap = getattr(volume, "active_bitmap", None)
    if bitmap is None:
        metadata = getattr(volume, "system_metadata", None)
        if callable(metadata):
            bitmap = metadata().active_bitmap.data
    if isinstance(bitmap, (bytes, bytearray)):
        index = cluster - 2
        if index < 0 or index // 8 >= len(bitmap):
            return None
        return bool(bitmap[index // 8] & (1 << (index % 8)))
    return None


def _orphan_metadata_hosts(
    volume: Any, candidate: dict[str, Any]
) -> tuple[int, ...] | None:
    """Return scanner-recorded orphan entry hosts, failing closed on bad hints.

    V2 manifests intentionally retain their established serialized candidate
    shape.  Source revalidation therefore uses freshly scanned candidates,
    whose bounded tuple covers every physical heap cluster occupied by the
    entry set.  Older or externally constructed candidates have no tuple and
    retain the historic single-host check.  A present malformed tuple is never
    permitted to narrow that check.
    """
    first = (
        int(candidate.get("entry_offset", 0)) - volume.cluster_offset(2)
    ) // volume.boot.cluster_size + 2
    recorded = candidate.get("metadata_host_clusters")
    if recorded is None:
        return (first,)
    if (
        type(recorded) is not tuple
        or not 1 <= len(recorded) <= 3
        or any(type(host) is not int for host in recorded)
        or recorded[0] != first
        or recorded != tuple(range(first, first + len(recorded)))
        or any(not volume.valid_cluster(host) for host in recorded)
    ):
        return None
    return recorded


def _system_owners(volume: Any) -> set[int]:
    owners = getattr(volume, "active_system_owners", None)
    if callable(owners):
        return set(owners())
    if owners is not None:
        return set(owners)
    metadata = getattr(volume, "system_metadata", None)
    if callable(metadata):
        system = metadata()
        return set(system.active_bitmap.clusters) | set(system.upcase_table.clusters)
    return set()


def _strict_fat_extents(
    volume: Any,
    first: int,
    expected: int,
    remaining_steps: int,
    extent_cap: int,
) -> tuple[tuple[Extent, ...] | None, str | None, int]:
    if expected == 0:
        return (), None, 0
    if expected > remaining_steps:
        return None, "fat_work_limit", 0
    extents: list[Extent] = []
    current = first
    extent_first = 0
    extent_count = 0
    # The extent cap gives an exact, bounded cycle index: completed contiguous
    # runs are held as sorted intervals, while the current run is checked
    # directly. This avoids a per-cluster `seen` set on long chains.
    seen_starts: list[int] = []
    seen_ends: list[int] = []
    for position in range(expected):
        if not volume.valid_cluster(current):
            return None, "fat_invalid_next", position
        if extent_count and current == extent_first + extent_count:
            extent_count += 1
        else:
            if extent_count:
                extents.append(Extent(extent_first, extent_count))
                if len(extents) > extent_cap:
                    return None, "extent_limit", position
                insertion = bisect_left(seen_starts, extent_first)
                seen_starts.insert(insertion, extent_first)
                seen_ends.insert(insertion, extent_first + extent_count)
            extent_first, extent_count = current, 1
        try:
            next_cluster = volume.fat_next(current)
        except FormatError:
            return None, "fat_truncated_read", position + 1
        if next_cluster == 0xFFFFFFF7:
            return None, "fat_bad_cluster", position + 1
        if next_cluster >= 0xFFFFFFF6 and next_cluster != 0xFFFFFFFF:
            return None, "fat_invalid_next", position + 1
        if next_cluster != 0xFFFFFFFF:
            if not volume.valid_cluster(next_cluster):
                return None, "fat_invalid_next", position + 1
            if extent_first <= next_cluster < extent_first + extent_count:
                return None, "fat_cycle", position + 1
            previous = bisect_right(seen_starts, next_cluster) - 1
            if previous >= 0 and next_cluster < seen_ends[previous]:
                return None, "fat_cycle", position + 1
        if position + 1 < expected:
            if next_cluster == 0xFFFFFFFF:
                return None, "fat_short_chain", position + 1
            current = next_cluster
        elif next_cluster != 0xFFFFFFFF:
            return None, "fat_overlong_chain", position + 1
    extents.append(Extent(extent_first, extent_count))
    if len(extents) > extent_cap:
        return None, "extent_limit", expected
    return tuple(extents), None, expected


def _extent_clusters(extents: Sequence[Extent]) -> Iterator[int]:
    for extent in extents:
        yield from range(
            extent.first_cluster, extent.first_cluster + extent.cluster_count
        )


def _claims_conflict(
    extents: Sequence[Extent],
    claims: Sequence[Any],
    claim_starts: Sequence[int],
    own_label: str,
) -> bool:
    """Check compact active-stream claims without expanding either side."""
    for extent in extents:
        end = extent.first_cluster + extent.cluster_count
        position = bisect_left(claim_starts, end)
        # A complete scanner has already rejected overlapping active claims, so
        # only the predecessor can overlap this extent; the first following
        # claim begins at or beyond its end.
        first = max(0, position - 1)
        for claim_index in range(first, len(claims)):
            claim = claims[claim_index]
            claim_first = int(claim.first_cluster)
            claim_end = int(claim.end_cluster)
            if claim_first >= end:
                break
            claim_owner = str(claim.owner)
            if (
                extent.first_cluster < claim_end
                and claim_first < end
                and (claim_owner != own_label or not claim.primary_stream)
            ):
                return True
    return False


def plan_recovery(
    volume: Any,
    candidates: list[dict[str, Any]],
    *,
    max_fat_steps: int = DEFAULT_MAX_FAT_STEPS,
    max_extents_per_candidate: int = MAX_EXTENTS_PER_CANDIDATE,
    max_cluster_operations: int | None = None,
    active_owners: dict[int, str] | None = None,
    metadata_complete: bool = True,
    ownership_complete: bool = False,
) -> PlannerResult:
    """Return globally planned candidates in deterministic candidate-ID order.

    A missing validated allocation bitmap/system-metadata result is a refusal,
    not an invitation to infer allocation from FAT contents.  ``active_owners``
    is intentionally injectable for the scanner's validated directory walk.
    """
    if (
        max_fat_steps < 0
        or not 1 <= max_extents_per_candidate <= MAX_EXTENTS_PER_CANDIDATE
    ):
        raise ResourceLimitError(
            "Planner limits are outside the supported bounded range."
        )
    if max_cluster_operations is None:
        max_cluster_operations = max_fat_steps
    if max_cluster_operations < 0:
        raise ResourceLimitError(
            "Planner cluster-operation limit must be non-negative."
        )
    source = getattr(volume, "source", None)
    location_info = getattr(volume, "location", None)
    offset = int(getattr(volume, "base_offset", 0))
    length = int(getattr(getattr(volume, "boot", None), "volume_bytes", 0))
    binding: dict[str, object] = {
        "volume_offset_bytes": offset,
        "volume_length_bytes": length,
    }
    if source is not None:
        binding.update(
            {
                "image_size_bytes": int(getattr(source, "size", 0)),
                "volume_sha256": source.selected_volume_sha256(offset, length),
                "cluster_size_bytes": int(volume.boot.cluster_size),
                "cluster_heap_offset_bytes": int(
                    volume.base_offset
                    + volume.boot.heap_offset * volume.boot.bytes_per_sector
                ),
            }
        )
    if location_info is not None:
        binding["source_kind"] = str(getattr(location_info, "source_kind", ""))
    binding["boot_region"] = str(getattr(volume, "boot_region", ""))
    binding["volume_dirty"] = bool(getattr(volume.boot, "volume_dirty", False))
    binding["media_failure"] = bool(getattr(volume.boot, "media_failure", False))
    binding_bytes = json.dumps(
        {
            key: binding[key]
            for key in ("volume_offset_bytes", "volume_length_bytes", "volume_sha256")
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    # Scanner ownership is split into a bounded exact metadata map and compact
    # active-file intervals.  Accept a plain mapping for focused unit tests and
    # older callers, but never coerce the compact index into a per-cluster dict.
    if active_owners is not None and hasattr(active_owners, "exact"):
        owners = dict(active_owners.exact)
        active_claims = tuple(active_owners.file_extents)
    else:
        owners = dict(active_owners or {})
        active_claims = ()
    active_claims = tuple(
        sorted(
            active_claims,
            key=lambda claim: (claim.first_cluster, claim.end_cluster, claim.owner),
        )
    )
    active_claim_starts = tuple(claim.first_cluster for claim in active_claims)
    for cluster in _system_owners(volume):
        owners.setdefault(cluster, "system")
    raw: list[dict[str, Any]] = []
    remaining_steps = max_fat_steps
    bitmap_available = (
        callable(getattr(volume, "cluster_is_allocated", None))
        or isinstance(getattr(volume, "active_bitmap", None), (bytes, bytearray))
        or callable(getattr(volume, "system_metadata", None))
    )
    for candidate in sorted(
        candidates,
        key=lambda item: (
            str(item.get("candidate_id", "")),
            int(item.get("entry_offset", 0)),
        ),
    ):
        size = int(candidate.get("size_bytes", 0))
        valid = int(candidate.get("valid_size_bytes", 0))
        location = _metadata_location(candidate)
        count = _clusters_for_size(size, volume.boot.cluster_size)
        mode: Literal["empty", "contiguous", "fat_chain"] = (
            "empty"
            if not count
            else "contiguous"
            if candidate.get("no_fat_chain")
            else "fat_chain"
        )
        extents: tuple[Extent, ...] = ()
        reason: str | None = None
        if not metadata_complete:
            reason = "incomplete_active_metadata"
        elif not ownership_complete:
            reason = "incomplete_active_ownership"
        elif valid < 0 or valid > size:
            reason = "invalid_valid_data_length"
        elif not bitmap_available:
            reason = "active_bitmap_unavailable"
        elif mode == "contiguous":
            first = int(candidate.get("first_cluster", 0))
            if (
                not volume.valid_cluster(first)
                or first + count > volume.boot.cluster_count + 2
            ):
                reason = "contiguous_extent_outside_volume"
            else:
                # ``range`` is deliberately retained: a hostile contiguous
                # DataLength must not allocate a Python object per cluster.
                extents = (Extent(first, count),)
        elif mode == "fat_chain":
            extents_result, reason, used = _strict_fat_extents(
                volume,
                int(candidate.get("first_cluster", 0)),
                count,
                remaining_steps,
                max_extents_per_candidate,
            )
            extents = extents_result or ()
            remaining_steps -= used
        if reason is None and len(extents) > max_extents_per_candidate:
            reason, extents = "extent_limit", ()
        raw.append(
            {
                "candidate": candidate,
                "size": size,
                "valid": valid,
                "location": location,
                "mode": mode,
                "extents": extents,
                "reason": reason,
            }
        )

    # Global ownership and plausible recovery overlap checks occur before any
    # selection.  They are deliberately symmetric and deterministic.
    claimed_intervals: list[tuple[int, int, int]] = []
    ambiguous: set[int] = set()
    remaining_interval_operations = max_cluster_operations
    for index, item in enumerate(raw):
        if item["reason"] is None:
            extents = item["extents"]
            if len(extents) > remaining_interval_operations:
                item["reason"] = "ownership_work_limit"
                item["extents"] = ()
                continue
            remaining_interval_operations -= len(extents)
            for extent in extents:
                start, end = (
                    extent.first_cluster,
                    extent.first_cluster + extent.cluster_count,
                )
                claimed_intervals.append((start, end, index))
    claimed_intervals.sort()
    group_indices: set[int] = set()
    group_end = -1
    for start, end, index in claimed_intervals:
        if start >= group_end:
            non_active = {
                member
                for member in group_indices
                if raw[member]["location"] != "active_directory"
            }
            if len(non_active) > 1:
                ambiguous.update(non_active)
            group_indices = {index}
            group_end = end
        else:
            group_indices.add(index)
            group_end = max(group_end, end)
    non_active = {
        member
        for member in group_indices
        if raw[member]["location"] != "active_directory"
    }
    if len(non_active) > 1:
        ambiguous.update(non_active)
    plans: list[RecoveryPlan] = []
    for index, item in enumerate(raw):
        candidate = item["candidate"]
        reasons: list[str] = []
        disposition: Literal["recoverable", "conflicted", "unrecoverable"]
        basis: str | None = None
        if item["reason"]:
            disposition = "unrecoverable"
            reasons.append(item["reason"])
        else:
            active = item["location"] == "active_directory"
            disposition = "recoverable"
            cluster_count = sum(extent.cluster_count for extent in item["extents"])
            # Allocation-bitmap and bounded exact-owner probes are cluster work.
            # Charge it before beginning so a hostile candidate cannot evade the
            # cumulative limit by failing late in its extent.
            if cluster_count > max_cluster_operations:
                disposition, reasons = "unrecoverable", ["ownership_work_limit"]
                allocation_bad = owner_conflicts = False
            else:
                max_cluster_operations -= cluster_count
                allocation_bad = any(
                    _bitmap_allocated(volume, cluster) is not active
                    for cluster in _extent_clusters(item["extents"])
                )
                own_label = f"file:{int(candidate.get('entry_offset', -1))}"
                owner_conflicts = any(
                    owner is not None and (not active or owner != own_label)
                    for owner in (
                        owners.get(cluster)
                        for cluster in _extent_clusters(item["extents"])
                    )
                ) or _claims_conflict(
                    item["extents"], active_claims, active_claim_starts, own_label
                )
            if index in ambiguous:
                reasons.append(
                    "active_file_overlap" if active else "plausible_recovery_overlap"
                )
            if allocation_bad:
                reasons.append(
                    "active_bitmap_allocation_conflict"
                    if active
                    else "cluster_currently_allocated"
                )
            if owner_conflicts:
                reasons.append("active_owner_conflict")
            # Heap-only/orphan metadata itself must be free.  A validated active
            # directory is an ownership context, so its entry host is exempt.
            if item["location"] == "orphan":
                hosts = _orphan_metadata_hosts(volume, candidate)
                if hosts is None or any(
                    _bitmap_allocated(volume, host) is not False for host in hosts
                ):
                    reasons.append("orphan_metadata_host_allocated")
            if disposition != "unrecoverable":
                disposition = "conflicted" if reasons else "recoverable"
            if disposition == "recoverable":
                prefix = (
                    "active"
                    if active
                    else "deleted"
                    if item["location"] == "deleted_directory"
                    else "orphan"
                )
                suffix = (
                    "empty"
                    if item["mode"] == "empty"
                    else "contiguous"
                    if item["mode"] == "contiguous"
                    else "fat_chain"
                )
                basis = (
                    f"{prefix}_empty"
                    if suffix == "empty"
                    else f"{prefix}_{suffix}_allocated"
                    if active
                    else f"{prefix}_{suffix}_unallocated"
                )
        entry_digest = str(candidate.get("entry_set_sha256", ""))
        candidate_id = hashlib.sha256(
            binding_bytes
            + b":"
            + str(candidate.get("entry_offset", 0)).encode("ascii")
            + b":"
            + entry_digest.encode("ascii")
        ).hexdigest()
        plans.append(
            RecoveryPlan(
                candidate_id=candidate_id,
                entry_offset=int(candidate.get("entry_offset", 0)),
                entry_set_sha256=entry_digest,
                name=str(candidate.get("name", "")),
                logical_size_bytes=item["size"],
                valid_data_bytes=item["valid"],
                extents=tuple(item["extents"]),
                allocation_mode=item["mode"],
                metadata_location=item["location"],
                disposition=disposition,
                recovery_basis=basis,
                reasons=tuple(sorted(set(reasons))),
            )
        )
    ordered = tuple(sorted(plans, key=lambda plan: plan.candidate_id))
    raw_by_offset = {int(item.get("entry_offset", -1)): item for item in candidates}
    source_candidates = tuple(
        {
            key: raw_by_offset[plan.entry_offset].get(key)
            for key in (
                "entry_offset",
                "name",
                "size_bytes",
                "valid_size_bytes",
                "first_cluster",
                "no_fat_chain",
                "deleted",
                "location",
                "entry_set_sha256",
                "is_directory",
                "attributes",
                "entry_checksum",
            )
        }
        for plan in ordered
    )
    return PlannerResult(
        ordered,
        binding,
        max_fat_steps - remaining_steps,
        source_candidates,
    )


# A concise alias makes the boundary easy to find from recovery.py.
plan = plan_recovery
