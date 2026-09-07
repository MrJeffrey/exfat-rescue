from __future__ import annotations

import hashlib
import re
from bisect import bisect_left
from collections.abc import Callable, Collection, Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from .errors import FormatError, ResourceLimitError
from .exfat.entries import DELETED_FILE, FILE, parse_entry_set
from .exfat.volume import MINIMUM_VOLUME_BYTES, VOLUME_GUID, ExfatVolume
from .source import ImageSource

DEFAULT_MAX_CANDIDATES = 100_000
HARD_MAX_CANDIDATES = 500_000
DEFAULT_MAX_SCAN_CLUSTERS = 50_000_000
MAX_DIRECTORY_CLUSTERS = 8192
MAX_DIRECTORY_DEPTH = 32
VENDOR_ALLOCATION = 0xE1
MAX_ACTIVE_FILE_EXTENTS = 4096
_HASH_CHUNK = 1024 * 1024
_SCAN_READ_BYTES = 4 * 1024 * 1024
_FILE_ENTRY_MARKERS = re.compile(bytes((FILE,)) + b"|" + bytes((DELETED_FILE,)))
# An exFAT File entry set has a primary plus at most 18 secondaries.  Keep
# enough of the preceding physical cluster to complete a set which begins at
# its final aligned slot.  This is bounded independently of cluster size and
# works across read-batch boundaries as well as ordinary cluster boundaries.
_ORPHAN_ENTRY_CARRY_BYTES = 18 * 32


def _maximum_selected_volume_bytes(boot: Any, max_scan_clusters: int) -> int:
    """Bound complete-volume hash work without rejecting mandatory format bytes."""
    bytes_per_sector = boot.bytes_per_sector
    minimum_fat_sectors = (
        (boot.cluster_count + 2) * 4 + bytes_per_sector - 1
    ) // bytes_per_sector
    mandatory_fat_bytes = minimum_fat_sectors * bytes_per_sector * boot.number_of_fats
    maximum_post_heap_remainder = boot.cluster_size - bytes_per_sector
    return (
        MINIMUM_VOLUME_BYTES
        + mandatory_fat_bytes
        + max_scan_clusters * boot.cluster_size
        + maximum_post_heap_remainder
    )


def _candidate_entry_offsets(data: bytes | memoryview) -> Iterator[int]:
    """Yield aligned complete-slot File entry offsets without a Python slot loop."""
    entry_types = bytes(data[: len(data) - 31 : 32])
    for match in _FILE_ENTRY_MARKERS.finditer(entry_types):
        yield match.start() * 32


def _upcased_name_key(name: str, mapping: tuple[int, ...]) -> tuple[int, ...]:
    """Return the exact exFAT up-cased UTF-16 key used for name uniqueness."""
    encoded = name.encode("utf-16-le", "surrogatepass")
    return tuple(
        mapping[encoded[index] | (encoded[index + 1] << 8)]
        for index in range(0, len(encoded), 2)
    )


@dataclass(frozen=True)
class OwnershipExtent:
    """A compact, inclusive/exclusive allocation claim for active file data."""

    first_cluster: int
    end_cluster: int
    owner: str
    primary_stream: bool = False


@dataclass(frozen=True)
class ActiveOwnership:
    """Exact owners for metadata plus compact claims for active file streams.

    The scanner must account for active streams that it cannot offer as ordinary
    candidates (for example, streams with Vendor Allocation secondaries), but
    retaining every cluster in a large NoFatChain file makes memory proportional
    to recovered file size.  This index keeps file ownership as intervals while
    retaining the small, bounded directory/system map needed by the directory
    walker.
    """

    exact: Mapping[int, str]
    file_extents: tuple[OwnershipExtent, ...]

    def owner_at(self, cluster: int) -> str | None:
        owner = self.exact.get(cluster)
        if owner is not None:
            return owner
        for claim in self.file_extents:
            if claim.first_cluster <= cluster < claim.end_cluster:
                return claim.owner
        return None

    def __getitem__(self, cluster: int) -> str:
        owner = self.owner_at(cluster)
        if owner is None:
            raise KeyError(cluster)
        return owner


def _claim_overlaps_metadata_owner(
    claim: OwnershipExtent, metadata_owner_clusters: tuple[int, ...]
) -> bool:
    """Test a compact file interval against sorted exact metadata ownership.

    Metadata ownership is deliberately retained as a bounded exact map, while
    active file ownership remains an interval. Do not expand the latter back
    into one Python operation per cluster merely to test this intersection.
    """
    position = bisect_left(metadata_owner_clusters, claim.first_cluster)
    return (
        position < len(metadata_owner_clusters)
        and metadata_owner_clusters[position] < claim.end_cluster
    )


@dataclass(frozen=True)
class ScanResult:
    volume: ExfatVolume
    candidates: list[dict[str, Any]]
    source_fingerprint: dict[str, object]
    warnings: tuple[str, ...]
    scanned_clusters: int
    active_owners: ActiveOwnership
    metadata_complete: bool
    ownership_complete: bool


def _active_allocation_extents(
    volume: ExfatVolume,
    first_cluster: int,
    size_bytes: int,
    no_fat_chain: bool,
    *,
    limit: int,
) -> tuple[tuple[OwnershipExtent, ...] | None, int]:
    """Validate active allocation without a per-cluster ownership structure."""
    if size_bytes == 0:
        return ((), 0) if first_cluster == 0 else (None, 0)
    count = (size_bytes + volume.boot.cluster_size - 1) // volume.boot.cluster_size
    if count > limit or not volume.valid_cluster(first_cluster):
        return None, 0
    if no_fat_chain:
        if first_cluster + count > volume.boot.cluster_count + 2:
            return None, 0
        for position, cluster in enumerate(range(first_cluster, first_cluster + count)):
            if not volume.cluster_is_allocated(cluster):
                return None, position + 1
        return (OwnershipExtent(first_cluster, first_cluster + count, ""),), count
    extents: list[OwnershipExtent] = []
    current = first_cluster
    extent_first = 0
    extent_count = 0
    for position in range(count):
        if not volume.valid_cluster(current) or not volume.cluster_is_allocated(
            current
        ):
            return None, position + 1
        if extent_count and current == extent_first + extent_count:
            extent_count += 1
        else:
            if extent_count:
                extents.append(
                    OwnershipExtent(extent_first, extent_first + extent_count, "")
                )
                if len(extents) >= MAX_ACTIVE_FILE_EXTENTS:
                    return None, position + 1
            extent_first, extent_count = current, 1
        try:
            following = volume.fat_next(current)
        except FormatError:
            return None, position + 1
        if position + 1 < count:
            if following == 0xFFFFFFFF or following >= 0xFFFFFFF6:
                return None, position + 1
            if not volume.valid_cluster(following):
                return None, position + 1
            current = following
        elif following != 0xFFFFFFFF:
            return None, position + 1
    extents.append(OwnershipExtent(extent_first, extent_first + extent_count, ""))
    return tuple(extents), count


def _active_file_allocation_extents(
    volume: ExfatVolume, entry_bytes: bytes, *, limit: int
) -> tuple[tuple[OwnershipExtent, ...] | None, int]:
    """Validate active stream and Vendor Allocation ownership claims.

    Vendor Allocation is benign, but its allocation is not ignorable: treating
    it as free could make a deleted-file plan overwrite an active vendor stream.
    The normal candidate parser deliberately accepts only RC's recoverable File
    shape, so this lightweight ownership parser also covers otherwise skipped
    active File entry sets containing benign secondaries.
    """
    if len(entry_bytes) < 64 or entry_bytes[0] != FILE:
        return None, 0
    secondaries = entry_bytes[1]
    if len(entry_bytes) != (secondaries + 1) * 32 or secondaries < 1:
        return None, 0
    stream = entry_bytes[32:64]
    if stream[0] != 0xC0:
        return None, 0
    stream_flags = stream[1]
    if stream_flags & ~0x03 or not stream_flags & 1:
        return None, 0
    first_cluster = int.from_bytes(stream[20:24], "little")
    data_length = int.from_bytes(stream[24:32], "little")
    allocated = _active_allocation_extents(
        volume,
        first_cluster,
        data_length,
        bool(stream_flags & 2),
        limit=limit,
    )
    allocations, used = allocated
    if allocations is None:
        return None, used
    result = [
        OwnershipExtent(
            claim.first_cluster, claim.end_cluster, claim.owner, primary_stream=True
        )
        for claim in allocations
    ]
    remaining = limit - used
    for offset in range(64, len(entry_bytes), 32):
        secondary = entry_bytes[offset : offset + 32]
        if secondary[0] != VENDOR_ALLOCATION:
            continue
        flags = secondary[1]
        first_cluster = int.from_bytes(secondary[20:24], "little")
        data_length = int.from_bytes(secondary[24:32], "little")
        if flags & ~0x03 or not flags & 1 or not any(secondary[2:18]):
            return None, limit - remaining
        allocated = _active_allocation_extents(
            volume,
            first_cluster,
            data_length,
            bool(flags & 2),
            limit=remaining,
        )
        allocation, work = allocated
        if allocation is None:
            return None, limit - remaining + work
        result.extend(allocation)
        remaining -= work
    return tuple(result), limit - remaining


def _candidate(
    fingerprint: str,
    item: dict[str, Any],
    location: str,
    path_components: list[str] | None,
    entry_set_sha256: str,
) -> dict[str, Any]:
    candidate_id = hashlib.sha256(
        f"{fingerprint}:{item['entry_offset']}:{entry_set_sha256}".encode()
    ).hexdigest()
    return {
        "record_type": "candidate",
        "candidate_id": candidate_id,
        "entry_set_sha256": entry_set_sha256,
        "location": location,
        "path": "/".join(path_components) if path_components else None,
        "path_components": path_components,
        **item,
        "layout": {
            "first_cluster": item["first_cluster"],
            "contiguous": item["no_fat_chain"],
        },
    }


def _directory_clusters(
    volume: ExfatVolume,
    first_cluster: int,
    *,
    no_fat_chain: bool,
    size_bytes: int | None,
    owned: Collection[int],
    remaining_cluster_budget: int,
    remaining_work_budget: int,
) -> tuple[list[int], bool, set[int], int]:
    if remaining_cluster_budget < 1 or remaining_work_budget < 1:
        raise ResourceLimitError(
            "Directory allocations reached the configured tracking or work limit."
        )
    if no_fat_chain:
        count = max(
            1,
            ((size_bytes or 0) + volume.boot.cluster_size - 1)
            // volume.boot.cluster_size,
        )
        if (
            count > remaining_cluster_budget
            or count > remaining_work_budget
            or not volume.valid_cluster(first_cluster)
            or first_cluster + count > volume.boot.cluster_count + 2
        ):
            raise ResourceLimitError(
                "A contiguous directory allocation exceeds the volume geometry or configured tracking limit."
            )
        clusters = list(range(first_cluster, first_cluster + count))
        return (
            clusters,
            True,
            {cluster for cluster in clusters if cluster in owned},
            count,
        )
    if size_bytes is None:
        cap = MAX_DIRECTORY_CLUSTERS
    else:
        cap = max(
            1,
            (size_bytes + volume.boot.cluster_size - 1) // volume.boot.cluster_size,
        )
    clusters, complete = volume.cluster_chain(
        first_cluster,
        cap=min(cap, remaining_cluster_budget, remaining_work_budget),
        forbidden=owned,
        expected_clusters=cap if size_bytes is not None else None,
    )
    if complete:
        return clusters, True, set(), max(1, len(clusters))
    blocked = volume.fat_next(clusters[-1]) if clusters else first_cluster
    overlaps = {blocked} if blocked in owned else set()
    return clusters, False, overlaps, max(1, len(clusters))


def _new_completed_owners(
    overlaps: Collection[int],
    directory_owners: dict[int, int],
    completed_directories: set[int],
    downgraded_directories: set[int],
) -> set[int]:
    owners = {
        owner
        for overlap in overlaps
        if (owner := directory_owners.get(overlap)) is not None
        and owner in completed_directories
        and owner not in downgraded_directories
    }
    downgraded_directories.update(owners)
    return owners


def scan(
    source: ImageSource,
    *,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
    max_scan_clusters: int = DEFAULT_MAX_SCAN_CLUSTERS,
    progress: Callable[[int, int], None] | None = None,
) -> ScanResult:
    if not 1 <= max_candidates <= HARD_MAX_CANDIDATES or max_scan_clusters < 1:
        raise ResourceLimitError(
            f"--max-candidates must be between 1 and {HARD_MAX_CANDIDATES}."
        )
    volume = ExfatVolume(source)
    if volume.boot.cluster_count > max_scan_clusters:
        raise ResourceLimitError(
            f"The volume declares {volume.boot.cluster_count} clusters, above the configured scan limit of {max_scan_clusters}. Increase --max-scan-clusters only after verifying the image geometry."
        )
    # The complete selected-volume proof below intentionally reads the regions
    # before and after the cluster heap as well as the heap itself.  ClusterCount
    # alone therefore cannot bound the scan: a checksum-valid boot region could
    # otherwise declare a tiny heap inside an arbitrarily large sparse volume.
    #
    # A minimum-size exFAT volume is allowed as fixed format overhead.  The
    # format also requires one or two FATs large enough to address every
    # cluster, and VolumeLength may include a final partial allocation unit.
    # Budget those unavoidable bytes separately so a caller that sets the scan
    # limit to the exact ClusterCount does not reject valid geometry.  Any
    # additional alignment/padding space must fit within unused cluster work.
    maximum_volume_bytes = _maximum_selected_volume_bytes(
        volume.boot, max_scan_clusters
    )
    if volume.boot.volume_bytes > maximum_volume_bytes:
        raise ResourceLimitError(
            "The selected exFAT volume requires hashing more than the configured "
            "scan limit permits outside its minimum format overhead. Increase "
            "--max-scan-clusters only after verifying the image geometry."
        )
    # RC planning is gated on the mandatory root system metadata.  Scanning a
    # manifest remains read-only, but is not eligible for recovery without it.
    system_metadata = volume.system_metadata(max_chain_clusters=max_scan_clusters)
    upcase_mapping = system_metadata.upcase_table.mapping
    source_fingerprint = source.fingerprint()
    fingerprint_value = str(source_fingerprint["value"])
    found: dict[int, dict[str, Any]] = {}
    visited: set[int] = set()
    directory_owners: dict[int, int] = {}
    directory_allocations: dict[int, set[int]] = {}
    completed_directories: set[int] = set()
    downgraded_directories: set[int] = set()
    # Directory and active-stream validation are one finite work budget. It
    # prevents repeated malformed active sets from evading resource bounds by
    # failing only after inspecting a late allocation unit.
    active_allocation_work_remaining = max_scan_clusters
    candidate_offsets_by_cluster: dict[int, set[int]] = {}
    warnings: set[str] = set()
    active_file_extents: list[OwnershipExtent] = []
    ownership_complete = True
    if volume.boot_region == "backup" and volume.boot.number_of_fats == 2:
        warnings.add("backup_geometry_with_main_active_fat")

    def candidate_limit_message(kind: str) -> str:
        if max_candidates < HARD_MAX_CANDIDATES:
            return (
                f"The scan reached the configured {kind} limit of {max_candidates}. "
                f"Increase --max-candidates only after verifying available memory; "
                f"the supported maximum is {HARD_MAX_CANDIDATES}."
            )
        return (
            f"The scan reached the supported {kind} ceiling of "
            f"{HARD_MAX_CANDIDATES}; a complete manifest cannot be produced "
            "within this release's bounded format."
        )

    def add(
        item: dict[str, Any],
        location: str,
        components: list[str] | None,
        entry_bytes: bytes,
    ) -> None:
        if item["entry_offset"] in found:
            return
        if len(found) >= max_candidates:
            raise ResourceLimitError(candidate_limit_message("candidate"))
        candidate = _candidate(
            fingerprint_value,
            item,
            location,
            components,
            hashlib.sha256(entry_bytes).hexdigest(),
        )
        # The complete File entry set can cross up to three minimum-size heap
        # clusters.  Keep its actual physical hosts with the in-memory scan
        # candidate so planning can reject allocated metadata without dropping
        # the candidate from the global data-overlap proof.  This deliberately
        # is not a manifest field: source revalidation replans from a fresh
        # scan, while v2's serialized source-candidate shape remains stable.
        heap_start = volume.cluster_offset(2)
        first_host = (item["entry_offset"] - heap_start) // volume.boot.cluster_size + 2
        last_host = (
            item["entry_offset"] + len(entry_bytes) - 1 - heap_start
        ) // volume.boot.cluster_size + 2
        candidate["metadata_host_clusters"] = tuple(range(first_host, last_host + 1))
        found[item["entry_offset"]] = candidate
        if location == "directory":
            candidate_cluster = (
                item["entry_offset"] - heap_start
            ) // volume.boot.cluster_size + 2
            candidate_offsets_by_cluster.setdefault(candidate_cluster, set()).add(
                item["entry_offset"]
            )

    def downgrade_overlapping_candidates(clusters: set[int]) -> None:
        for cluster in clusters:
            for entry_offset in candidate_offsets_by_cluster.get(cluster, set()):
                candidate = found[entry_offset]
                candidate["location"] = "orphan"
                candidate["path"] = None
                candidate["path_components"] = None

    def reject_overlapping_directory(overlaps: set[int]) -> None:
        warnings.add("overlapping_directory_allocation")
        for owner in _new_completed_owners(
            overlaps,
            directory_owners,
            completed_directories,
            downgraded_directories,
        ):
            downgrade_overlapping_candidates(directory_allocations[owner])

    def record_active_file_owners(
        entry_bytes: bytes, absolute: int, *, include_primary: bool
    ) -> None:
        nonlocal ownership_complete, active_allocation_work_remaining
        result = _active_file_allocation_extents(
            volume, entry_bytes, limit=active_allocation_work_remaining
        )
        allocations, work = result
        active_allocation_work_remaining -= work
        if allocations is None:
            warnings.add("active_file_allocation_incomplete")
            ownership_complete = False
            return
        allocations = tuple(
            claim
            for claim in allocations
            if include_primary or not claim.primary_stream
        )
        if len(active_file_extents) + len(allocations) > max_candidates * 10:
            warnings.add("active_file_allocation_incomplete")
            ownership_complete = False
            return
        owner = f"file:{absolute}"
        active_file_extents.extend(
            OwnershipExtent(
                claim.first_cluster,
                claim.end_cluster,
                owner,
                primary_stream=claim.primary_stream,
            )
            for claim in allocations
        )

    def walk(
        cluster: int,
        parent: list[str],
        *,
        no_fat_chain: bool = False,
        size_bytes: int | None = None,
        depth: int = 0,
    ) -> None:
        nonlocal active_allocation_work_remaining, ownership_complete
        if depth > MAX_DIRECTORY_DEPTH:
            warnings.add("directory_depth_limit_reached")
            return
        if cluster in visited:
            if cluster not in directory_allocations:
                warnings.add("directory_cycle_or_duplicate_reference")
            else:
                reject_overlapping_directory({cluster})
            return
        if len(visited) >= max_candidates:
            raise ResourceLimitError(candidate_limit_message("metadata-directory"))
        visited.add(cluster)
        clusters, complete, overlaps, work_units = _directory_clusters(
            volume,
            cluster,
            no_fat_chain=no_fat_chain,
            size_bytes=size_bytes,
            owned=directory_owners,
            remaining_cluster_budget=max_candidates * 10 - len(directory_owners),
            remaining_work_budget=active_allocation_work_remaining,
        )
        active_allocation_work_remaining -= work_units
        if overlaps:
            reject_overlapping_directory(overlaps)
            return
        if not complete:
            warnings.add("directory_chain_incomplete")
        if any(not volume.cluster_is_allocated(current) for current in clusters):
            warnings.add("active_directory_allocation_incomplete")
            ownership_complete = False
            return
        if len(directory_owners) + len(clusters) > max_candidates * 10:
            raise ResourceLimitError(
                "Directory allocations exceeded ten times the configured candidate limit; refusing an image that would require excessive tracking memory."
            )
        for current in clusters:
            directory_owners[current] = cluster
        directory_allocations[cluster] = set(clusters)
        carry = b""
        carry_absolute = 0
        carry_is_benign_set = False
        active_name_keys: set[tuple[int, ...]] = set()
        for current in clusters:
            data = volume.read_cluster(current)
            prefix_length = len(carry)
            buffer = carry + data
            offset = 0
            carry = b""
            carried_benign_set = carry_is_benign_set
            carry_is_benign_set = False
            while offset + 32 <= len(buffer):
                absolute = (
                    carry_absolute + offset
                    if offset < prefix_length
                    else volume.cluster_offset(current) + offset - prefix_length
                )
                entry_type = buffer[offset]
                if entry_type == 0:
                    completed_directories.add(cluster)
                    return
                if entry_type not in (FILE, DELETED_FILE):
                    if entry_type & 0xE0 == 0xA0:
                        secondaries = buffer[offset + 1]
                        total_length = (secondaries + 1) * 32
                        if offset + total_length > len(buffer):
                            carry = buffer[offset:]
                            carry_absolute = absolute
                            carry_is_benign_set = True
                            break
                        secondaries_are_structural = all(
                            secondary[0] & 0xC0 == 0xC0
                            for secondary in (
                                buffer[position : position + 32]
                                for position in range(
                                    offset + 32, offset + total_length, 32
                                )
                            )
                        )
                        if not secondaries_are_structural:
                            warnings.add("active_benign_directory_entry_set_invalid")
                            ownership_complete = False
                        elif (
                            depth == 0 and entry_type == VOLUME_GUID and not secondaries
                        ):
                            # load_system_metadata has already established the
                            # complete, allocation-free root Volume GUID form.
                            pass
                        else:
                            # The generic template proves this is one set, but
                            # an unfamiliar benign primary or secondary can
                            # still carry allocation fields. Do not split it
                            # into standalone records, and do not certify it.
                            warnings.add(
                                "active_uninterpreted_benign_directory_entry_set"
                            )
                            ownership_complete = False
                        offset += total_length
                        continue
                    # An in-use critical entry that the RC walker does not
                    # understand makes a child directory structurally
                    # unknowable. Generic benign primary sets were consumed
                    # above; inactive records remain skippable.
                    if depth > 0 and entry_type & 0xC0 == 0xC0:
                        # The primary File branch consumes every valid
                        # secondary as a set. Reaching an in-use secondary
                        # here means it is detached, so even a benign type
                        # cannot safely be ignored.
                        warnings.add("active_standalone_secondary_directory_entry")
                        ownership_complete = False
                    elif depth > 0 and entry_type & 0x80 and not entry_type & 0x20:
                        warnings.add("active_unknown_critical_directory_entry")
                        ownership_complete = False
                    offset += 32
                    continue
                secondaries = buffer[offset + 1]
                total_length = (secondaries + 1) * 32
                if 2 <= secondaries <= 18 and offset + total_length > len(buffer):
                    carry = buffer[offset:]
                    carry_absolute = absolute
                    break
                item = parse_entry_set(buffer, offset, volume, absolute)
                if entry_type == FILE:
                    if not 1 <= secondaries <= 18 or offset + total_length > len(
                        buffer
                    ):
                        warnings.add("active_file_allocation_incomplete")
                        ownership_complete = False
                    else:
                        record_active_file_owners(
                            buffer[offset : offset + total_length],
                            absolute,
                            include_primary=not bool(item and item["is_directory"]),
                        )
                    if item is None:
                        warnings.add("active_file_entry_set_invalid")
                        ownership_complete = False
                    else:
                        name_key = _upcased_name_key(item["name"], upcase_mapping)
                        if name_key in active_name_keys:
                            warnings.add("active_directory_duplicate_name")
                            ownership_complete = False
                        else:
                            active_name_keys.add(name_key)
                if not item:
                    offset += 32
                    continue
                child_components = [*parent, item["name"]]
                if item["is_directory"] and not item["deleted"]:
                    walk(
                        item["first_cluster"],
                        child_components,
                        no_fat_chain=item["no_fat_chain"],
                        size_bytes=item["size_bytes"],
                        depth=depth + 1,
                    )
                elif not item["is_directory"]:
                    add(
                        item,
                        "directory",
                        child_components,
                        buffer[offset : offset + total_length],
                    )
                offset += total_length
        if carry:
            warnings.add(
                "active_benign_directory_entry_set_incomplete"
                if carry_is_benign_set or carried_benign_set
                else "directory_entry_set_truncated"
            )
            ownership_complete = False
        else:
            # An in-use directory with no EOD marker is structurally invalid.
            warnings.add("directory_missing_end_marker")
            ownership_complete = False
        completed_directories.add(cluster)

    walk(volume.boot.root_cluster, [])
    # The orphan scan below is already a mandatory, sequential read of every
    # cluster in the heap.  Build the selected-volume content proof from that same
    # pass instead of rereading the entire image afterward.  exFAT geometry has
    # already proved the heap lies inside the declared selected volume.
    volume_start = volume.base_offset
    volume_end = volume_start + volume.boot.volume_bytes
    heap_start = volume.cluster_offset(2)
    heap_end = heap_start + volume.boot.cluster_count * volume.boot.cluster_size
    if not volume_start <= heap_start <= heap_end <= volume_end:
        raise FormatError("The exFAT cluster heap is outside the selected volume.")
    selected_volume_hash = hashlib.sha256()

    def hash_region(offset: int, length: int) -> None:
        remaining, position = length, offset
        while remaining:
            amount = min(remaining, _HASH_CHUNK)
            selected_volume_hash.update(source.read_exact(position, amount))
            source.release_cache(position, amount)
            position += amount
            remaining -= amount

    total_clusters = volume.boot.cluster_count
    if progress is not None:
        progress(0, total_clusters)
    hash_region(volume_start, heap_start - volume_start)
    clusters_per_read = max(1, _SCAN_READ_BYTES // volume.boot.cluster_size)
    scanned = 0
    orphan_carry = b""

    def scan_orphan_entries(data: bytes | memoryview, buffer_start: int) -> None:
        for offset in _candidate_entry_offsets(data):
            absolute = buffer_start + offset
            if absolute in found:
                continue
            item = parse_entry_set(data, offset, volume, absolute)
            if item and not item["is_directory"]:
                total_length = (data[offset + 1] + 1) * 32
                # Retain structurally valid candidates even when their entry
                # metadata occupies allocated clusters.  The planner records
                # that conflict, but retaining the candidate is essential for
                # a symmetric global proof of overlaps with other deleted data.
                add(
                    item,
                    "orphan",
                    None,
                    bytes(data[offset : offset + total_length]),
                )

    for first_cluster in range(2, volume.boot.cluster_count + 2, clusters_per_read):
        cluster_count = min(clusters_per_read, volume.boot.cluster_count - scanned)
        batch = volume.read_clusters(first_cluster, cluster_count)
        selected_volume_hash.update(batch)
        batch_view = memoryview(batch)
        for index in range(cluster_count):
            cluster = first_cluster + index
            begin = index * volume.boot.cluster_size
            data = batch_view[begin : begin + volume.boot.cluster_size]
            # The ordinary path remains zero-copy over the batch.  Only the
            # fixed 576-byte bridge across the physical boundary is copied.
            if orphan_carry:
                bridge = orphan_carry + data[:_ORPHAN_ENTRY_CARRY_BYTES]
                scan_orphan_entries(
                    bridge, volume.cluster_offset(cluster) - len(orphan_carry)
                )
            scan_orphan_entries(data, volume.cluster_offset(cluster))
            # A maximum-size 608-byte entry set can occupy three 512-byte
            # clusters when its primary is the final slot of the first one.
            # Retain the trailing window of the *stream*, not merely the
            # current cluster, so that minimum-size clusters keep the first
            # 64 bytes needed by the next bridge.
            if len(data) >= _ORPHAN_ENTRY_CARRY_BYTES:
                orphan_carry = bytes(data[-_ORPHAN_ENTRY_CARRY_BYTES:])
            else:
                orphan_carry = (orphan_carry + bytes(data))[-_ORPHAN_ENTRY_CARRY_BYTES:]
        source.release_cache(volume.cluster_offset(first_cluster), len(batch))
        scanned += cluster_count
        if progress and (scanned == total_clusters or scanned % 8192 == 0):
            progress(scanned, total_clusters)

    hash_region(heap_end, volume_end - heap_end)
    source.assert_unchanged(source_fingerprint)
    source.remember_selected_volume_digest(
        volume_start, volume.boot.volume_bytes, selected_volume_hash.hexdigest()
    )
    system_owners = volume.active_system_owners()
    owners: dict[int, str] = {cluster: "system" for cluster in system_owners}
    for cluster, owner in directory_owners.items():
        # The root allocation is necessarily also system metadata.  Every other
        # directory/system collision makes active ownership ambiguous.
        if cluster in owners and cluster not in volume.system_metadata().root_clusters:
            warnings.add("active_allocation_overlap")
            ownership_complete = False
        else:
            owners.setdefault(cluster, f"directory:{owner}")
    sorted_file_extents = tuple(
        sorted(
            active_file_extents,
            key=lambda claim: (claim.first_cluster, claim.end_cluster, claim.owner),
        )
    )
    metadata_owner_clusters = tuple(sorted(owners))
    previous: OwnershipExtent | None = None
    for claim in sorted_file_extents:
        if previous is not None and claim.first_cluster < previous.end_cluster:
            warnings.add("active_file_allocation_overlap")
            ownership_complete = False
        previous = (
            claim
            if previous is None or claim.end_cluster > previous.end_cluster
            else previous
        )
        # Directory/system ownership is intentionally bounded by the directory
        # traversal limit. Keep the file side compact too: a binary search of
        # sorted exact owner keys proves interval overlap without walking every
        # cluster of a potentially multi-terabyte active file.
        if _claim_overlaps_metadata_owner(claim, metadata_owner_clusters):
            warnings.add("active_allocation_overlap")
            ownership_complete = False
    metadata_complete = not bool(
        warnings
        & {
            "directory_chain_incomplete",
            "directory_entry_set_truncated",
            "directory_depth_limit_reached",
            "overlapping_directory_allocation",
            "directory_cycle_or_duplicate_reference",
            "active_file_allocation_incomplete",
            "active_file_allocation_overlap",
            "active_file_entry_set_invalid",
            "active_unknown_critical_directory_entry",
            "active_standalone_secondary_directory_entry",
            "active_benign_directory_entry_set_invalid",
            "active_benign_directory_entry_set_incomplete",
            "active_uninterpreted_benign_directory_entry_set",
            "active_directory_allocation_incomplete",
            "active_directory_duplicate_name",
            "active_allocation_overlap",
            "directory_missing_end_marker",
        }
    )
    return ScanResult(
        volume=volume,
        candidates=sorted(
            found.values(),
            key=lambda candidate: (
                candidate["candidate_id"],
                candidate["entry_offset"],
            ),
        ),
        source_fingerprint=source_fingerprint,
        warnings=tuple(sorted(warnings)),
        scanned_clusters=total_clusters,
        active_owners=ActiveOwnership(owners, sorted_file_extents),
        metadata_complete=metadata_complete,
        ownership_complete=ownership_complete and metadata_complete,
    )
