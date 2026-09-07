from __future__ import annotations

import struct
import zlib
from collections.abc import Collection
from dataclasses import dataclass, replace
from enum import Enum

from ..errors import FormatError
from ..source import ImageSource

SECTOR_SIZE = 512
MINIMUM_VOLUME_BYTES = 1 << 20
MAX_GPT_ENTRIES = 4096
MAX_GPT_ENTRY_SIZE = 4096
BOOT_REGION_SECTORS = 12
MAX_CLUSTER_COUNT = 0xFFFFFFF5
FAT_END_OF_CHAIN = 0xFFFFFFFF
FAT_BAD_CLUSTER = 0xFFFFFFF7
ALLOCATION_BITMAP = 0x81
UPCASE_TABLE = 0x82
VOLUME_LABEL = 0x83
FILE_DIRECTORY = 0x85
VOLUME_GUID = 0xA0
STREAM_EXTENSION = 0xC0
FILE_NAME = 0xC1
MAX_SYSTEM_METADATA_CHAIN_CLUSTERS = 1_000_000
MAX_SYSTEM_METADATA_BYTES = 64 * 1024 * 1024
MAX_ROOT_METADATA_RECORDS = 100_000
MAX_UPCASE_TABLE_BYTES = 0x20000
_FORBIDDEN_VOLUME_LABEL_CHARACTERS = frozenset('"*/:<>?\\\\|')


class ChainStatus(str, Enum):
    """The precise reason a FAT walk did, or did not, establish an exact chain."""

    EXACT = "exact"
    CYCLE = "cycle"
    SHORT = "short"
    OVERLONG = "overlong"
    BAD_CLUSTER = "bad_cluster"
    INVALID_NEXT = "invalid_next"
    TRUNCATED_READ = "truncated_read"
    FORBIDDEN = "forbidden"
    WORK_LIMIT = "work_limit"


@dataclass(frozen=True)
class ChainResult:
    clusters: tuple[int, ...]
    status: ChainStatus

    @property
    def exact(self) -> bool:
        return self.status is ChainStatus.EXACT

    def __iter__(self):
        """Compatibility for the scanner's existing ``clusters, complete`` use."""
        yield list(self.clusters)
        yield self.exact


@dataclass(frozen=True)
class AllocationBitmap:
    identifier: int
    first_cluster: int
    data_length: int
    clusters: tuple[int, ...]
    data: bytes

    def is_allocated(self, cluster: int) -> bool:
        if cluster < 2 or cluster - 2 >= len(self.data) * 8:
            raise FormatError("Allocation bitmap query is outside the cluster range.")
        bit = cluster - 2
        return bool(self.data[bit // 8] & (1 << (bit % 8)))


@dataclass(frozen=True)
class UpcaseTable:
    first_cluster: int
    data_length: int
    checksum: int
    clusters: tuple[int, ...]
    mapping: tuple[int, ...]

    def uppercase(self, code_unit: int) -> int:
        return self.mapping[code_unit]


@dataclass(frozen=True)
class SystemMetadata:
    bitmaps: tuple[AllocationBitmap, ...]
    active_bitmap: AllocationBitmap
    upcase_table: UpcaseTable
    root_clusters: tuple[int, ...]


@dataclass(frozen=True)
class BootSector:
    bytes_per_sector: int
    sectors_per_cluster: int
    fat_offset: int
    fat_length: int
    heap_offset: int
    cluster_count: int
    root_cluster: int
    volume_length: int
    serial: int
    revision: int
    flags: int
    number_of_fats: int

    @property
    def cluster_size(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster

    @property
    def volume_bytes(self) -> int:
        return self.volume_length * self.bytes_per_sector

    @property
    def active_fat(self) -> int:
        return (self.flags & 1) if self.number_of_fats == 2 else 0

    @property
    def volume_dirty(self) -> bool:
        """Whether the current main boot region reports an unclean volume."""
        return bool(self.flags & 0x0002)

    @property
    def media_failure(self) -> bool:
        """Whether the current main boot region reports a media failure."""
        return bool(self.flags & 0x0004)

    @classmethod
    def parse(cls, data: bytes, available_bytes: int) -> BootSector:
        if len(data) < SECTOR_SIZE:
            raise FormatError("Image is truncated before a complete exFAT boot sector.")
        if data[:3] != b"\xeb\x76\x90":
            raise FormatError("The exFAT JumpBoot field is invalid.")
        if data[3:11] != b"EXFAT   ":
            raise FormatError(
                "No exFAT boot sector was found in this image or its supported partition tables."
            )
        if data[510:512] != b"\x55\xaa":
            raise FormatError("The exFAT boot-sector signature is missing or corrupt.")
        if any(data[0x0B:0x40]):
            raise FormatError("The exFAT MustBeZero field is not zero.")
        bps_shift, spc_shift, number_of_fats = data[0x6C], data[0x6D], data[0x6E]
        if not 9 <= bps_shift <= 12 or spc_shift > 25 or bps_shift + spc_shift > 25:
            raise FormatError("The exFAT allocation-unit geometry is invalid.")
        values = struct.unpack_from("<QIIIIIIHHBB", data, 0x48)
        (
            volume_length,
            fat_offset,
            fat_length,
            heap_offset,
            cluster_count,
            root_cluster,
            serial,
            revision,
            flags,
            _,
            _,
        ) = values
        bps, spc = 1 << bps_shift, 1 << spc_shift
        minimum_volume_sectors = MINIMUM_VOLUME_BYTES // bps
        if volume_length < minimum_volume_sectors:
            raise FormatError("The exFAT VolumeLength describes less than 1 MiB.")
        if not all((fat_length, heap_offset, cluster_count)):
            raise FormatError(
                "The exFAT boot sector has required zero geometry fields."
            )
        if revision != 0x0100:
            raise FormatError(
                "This release supports exFAT filesystem revision 1.00 only."
            )
        _validate_number_of_fats_and_flags(number_of_fats, flags)
        if fat_offset < BOOT_REGION_SECTORS * 2:
            raise FormatError("The exFAT FATOffset must begin after both boot regions.")
        if cluster_count < 2 + number_of_fats:
            raise FormatError("The exFAT ClusterCount is below the structural minimum.")
        if cluster_count > MAX_CLUSTER_COUNT:
            raise FormatError(
                "The exFAT ClusterCount exceeds the specification ceiling."
            )
        if root_cluster < 2 or root_cluster >= cluster_count + 2:
            raise FormatError(
                "The exFAT root directory cluster is outside the cluster heap."
            )
        if volume_length * bps > available_bytes:
            raise FormatError(
                "The image or selected partition is shorter than its declared exFAT volume."
            )
        if (
            fat_offset + fat_length * number_of_fats > volume_length
            or fat_length * bps < (cluster_count + 2) * 4
        ):
            raise FormatError("The exFAT FAT extends outside the declared volume.")
        if (
            heap_offset < fat_offset + fat_length * number_of_fats
            or heap_offset >= volume_length
            or heap_offset + cluster_count * spc > volume_length
        ):
            raise FormatError(
                "The exFAT cluster heap extends outside the declared volume."
            )
        expected_cluster_count = min(
            (volume_length - heap_offset) // spc, MAX_CLUSTER_COUNT
        )
        if cluster_count != expected_cluster_count:
            raise FormatError(
                "The exFAT ClusterCount does not match the declared volume geometry."
            )
        return cls(
            bps,
            spc,
            fat_offset,
            fat_length,
            heap_offset,
            cluster_count,
            root_cluster,
            volume_length,
            serial,
            revision,
            flags,
            number_of_fats,
        )


def _validate_number_of_fats_and_flags(number_of_fats: int, flags: int) -> None:
    """Validate fields that must remain coherent when main flags are substituted."""
    if number_of_fats not in (1, 2):
        raise FormatError("The exFAT NumberOfFats field must be 1 or 2.")
    if number_of_fats == 1 and flags & 1:
        raise FormatError("The exFAT ActiveFat flag requires two FATs.")
    if flags & ~0x000F:
        raise FormatError("The exFAT VolumeFlags reserved bits are nonzero.")


@dataclass(frozen=True)
class VolumeLocation:
    base_offset: int
    available_bytes: int
    source_kind: str
    boot_region: str


def _boot_checksum(region: bytes, bytes_per_sector: int) -> int:
    checksum = 0
    for index, byte in enumerate(region[:-bytes_per_sector]):
        if index in (0x6A, 0x6B, 0x70):
            continue
        checksum = (((checksum << 31) | (checksum >> 1)) + byte) & 0xFFFFFFFF
    return checksum


def _valid_boot_region(
    source: ImageSource, offset: int, available_bytes: int
) -> BootSector | None:
    sector = source.read_at(offset, SECTOR_SIZE)
    try:
        boot = BootSector.parse(sector, available_bytes)
    except FormatError:
        return None
    region_size = BOOT_REGION_SECTORS * boot.bytes_per_sector
    if region_size > available_bytes:
        return None
    region = source.read_at(offset, region_size)
    if len(region) != region_size:
        return None
    expected = _boot_checksum(region, boot.bytes_per_sector)
    extended_signature = b"\x00\x00\x55\xaa"
    if any(
        region[
            (sector + 1) * boot.bytes_per_sector - 4 : (sector + 1)
            * boot.bytes_per_sector
        ]
        != extended_signature
        for sector in range(1, 9)
    ):
        return None
    checksum_sector = region[-boot.bytes_per_sector :]
    if len(checksum_sector) != boot.bytes_per_sector or any(
        struct.unpack_from("<I", checksum_sector, index)[0] != expected
        for index in range(0, boot.bytes_per_sector, 4)
    ):
        return None
    return boot


def _select_boot_region(
    source: ImageSource, offset: int, available_bytes: int
) -> tuple[BootSector, str] | None:
    primary_sector = source.read_at(offset, SECTOR_SIZE)
    primary = _valid_boot_region(source, offset, available_bytes)
    if primary:
        return primary, "primary"
    # The primary may be damaged, so test every supported logical-sector size
    # for the backup boot region rather than trusting its geometry field.
    for bytes_per_sector in (512, 1024, 2048, 4096):
        backup_offset = offset + BOOT_REGION_SECTORS * bytes_per_sector
        backup = _valid_boot_region(source, backup_offset, available_bytes)
        if backup and backup.bytes_per_sector == bytes_per_sector:
            # VolumeFlags is intentionally excluded from the boot checksum. The
            # specification defines the main sector as current and the backup's
            # copy as stale, even when backup geometry is needed for recovery.
            main_flags = (
                struct.unpack_from("<H", primary_sector, 0x6A)[0]
                if len(primary_sector) >= 0x6C
                else 0
            )
            _validate_number_of_fats_and_flags(backup.number_of_fats, main_flags)
            return replace(backup, flags=main_flags), "backup"
    return None


def _probe(
    source: ImageSource, offset: int, length: int, kind: str
) -> VolumeLocation | None:
    if offset < 0 or length < SECTOR_SIZE or offset + length > source.size:
        return None
    selected = _select_boot_region(source, offset, length)
    if not selected:
        return None
    _, boot_region = selected
    return VolumeLocation(offset, length, kind, boot_region)


def _one(candidates: list[VolumeLocation], kind: str) -> VolumeLocation:
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        raise FormatError(
            f"More than one exFAT volume was found in the {kind}; select a partition image instead."
        )
    raise FormatError(
        "No valid exFAT volume was found in this image or its supported partition tables."
    )


def discover_volume(source: ImageSource) -> VolumeLocation:
    direct = _probe(source, 0, source.size, "direct-image")
    if direct:
        return direct
    mbr = source.read_at(0, SECTOR_SIZE)
    if len(mbr) < SECTOR_SIZE or mbr[510:512] != b"\x55\xaa":
        raise FormatError(
            "No exFAT boot sector or valid MBR/GPT partition table was found."
        )
    entries = [
        struct.unpack_from("<B3sB3sII", mbr, 446 + index * 16) for index in range(4)
    ]
    if any(item[2] == 0xEE for item in entries):
        header = source.read_at(SECTOR_SIZE, SECTOR_SIZE)
        if len(header) < 92 or header[:8] != b"EFI PART":
            raise FormatError("The protective MBR has no valid GPT header.")
        header_size = struct.unpack_from("<I", header, 12)[0]
        entry_lba, count, entry_size = struct.unpack_from("<QII", header, 72)
        if (
            not 92 <= header_size <= SECTOR_SIZE
            or not 0 < count <= MAX_GPT_ENTRIES
            or not 128 <= entry_size <= MAX_GPT_ENTRY_SIZE
            or entry_size % 8
        ):
            raise FormatError(
                "The GPT partition-entry geometry is invalid or exceeds safe limits."
            )
        table_bytes, table_offset = count * entry_size, entry_lba * SECTOR_SIZE
        if table_offset < SECTOR_SIZE * 2 or table_offset + table_bytes > source.size:
            raise FormatError(
                "The GPT partition-entry table is truncated or outside the image."
            )
        table, candidates = source.read_at(table_offset, table_bytes), []
        stored_header_crc, stored_table_crc = (
            struct.unpack_from("<II", header, 16)[0],
            struct.unpack_from("<I", header, 88)[0],
        )
        crc_header = bytearray(header[:header_size])
        crc_header[16:20] = b"\0" * 4
        if (
            zlib.crc32(crc_header) & 0xFFFFFFFF != stored_header_crc
            or zlib.crc32(table) & 0xFFFFFFFF != stored_table_crc
        ):
            raise FormatError("The GPT header or partition-entry checksum is corrupt.")
        for index in range(count):
            entry = table[index * entry_size : (index + 1) * entry_size]
            if entry[:16] == b"\0" * 16:
                continue
            first, last = struct.unpack_from("<QQ", entry, 32)
            if first > last:
                continue
            candidate = _probe(
                source, first * SECTOR_SIZE, (last - first + 1) * SECTOR_SIZE, "gpt"
            )
            if candidate:
                candidates.append(candidate)
        return _one(candidates, "GPT")
    candidates = []
    for _, _, part_type, _, first, sectors in entries:
        if part_type == 0 or sectors == 0:
            continue
        candidate = _probe(source, first * SECTOR_SIZE, sectors * SECTOR_SIZE, "mbr")
        if candidate:
            candidates.append(candidate)
    return _one(candidates, "MBR")


class ExfatVolume:
    def __init__(self, source: ImageSource):
        self.source = source
        self.location = discover_volume(source)
        self.base_offset = self.location.base_offset
        selected = _select_boot_region(
            source, self.base_offset, self.location.available_bytes
        )
        if not selected:  # discovery and opening must agree, even if the file changed.
            raise FormatError("Neither exFAT boot region validates in this image.")
        self.boot, self.boot_region = selected
        self._system_metadata: SystemMetadata | None = None

    def valid_cluster(self, cluster: int) -> bool:
        return 2 <= cluster < self.boot.cluster_count + 2

    def cluster_offset(self, cluster: int) -> int:
        return (
            self.base_offset
            + self.boot.heap_offset * self.boot.bytes_per_sector
            + (cluster - 2) * self.boot.cluster_size
        )

    def read_cluster(self, cluster: int) -> bytes:
        if not self.valid_cluster(cluster):
            raise FormatError("Attempted to read a cluster outside the cluster heap.")
        data = self.source.read_at(self.cluster_offset(cluster), self.boot.cluster_size)
        if len(data) != self.boot.cluster_size:
            raise FormatError(
                "The exFAT cluster heap is truncated during a cluster read."
            )
        return data

    def read_clusters(self, first_cluster: int, count: int) -> bytes:
        """Read a bounded contiguous cluster run with one source operation."""
        if (
            type(count) is not int
            or count < 1
            or not self.valid_cluster(first_cluster)
            or first_cluster + count > self.boot.cluster_count + 2
        ):
            raise FormatError(
                "Attempted to read a cluster range outside the cluster heap."
            )
        length = count * self.boot.cluster_size
        data = self.source.read_at(self.cluster_offset(first_cluster), length)
        if len(data) != length:
            raise FormatError(
                "The exFAT cluster heap is truncated during a cluster-range read."
            )
        return data

    def fat_next(self, cluster: int, *, fat_index: int | None = None) -> int:
        if not self.valid_cluster(cluster):
            raise FormatError(
                "Attempted to read a FAT entry outside the cluster range."
            )
        selected_fat = self.boot.active_fat if fat_index is None else fat_index
        if not 0 <= selected_fat < self.boot.number_of_fats:
            raise FormatError("Attempted to select a FAT outside NumberOfFats.")
        data = self.source.read_at(
            self.base_offset
            + (self.boot.fat_offset + selected_fat * self.boot.fat_length)
            * self.boot.bytes_per_sector
            + cluster * 4,
            4,
        )
        if len(data) != 4:
            raise FormatError("The active FAT is truncated during a FAT entry read.")
        return struct.unpack("<I", data)[0]

    def cluster_chain(
        self,
        first: int,
        cap: int = 8192,
        forbidden: Collection[int] | None = None,
        *,
        expected_clusters: int | None = None,
        fat_index: int | None = None,
    ) -> ChainResult:
        """Walk the active FAT without treating reserved values as end-of-chain.

        If ``expected_clusters`` is supplied, the final link is checked as well: an
        exact chain has that many clusters and a literal ``0xffffffff`` terminator.
        This distinction matters for recovery because a broad FAT EOC range is not
        valid exFAT metadata.
        """
        if cap < 1:
            return ChainResult((), ChainStatus.WORK_LIMIT)
        if expected_clusters is not None and expected_clusters < 1:
            return ChainResult((), ChainStatus.SHORT)
        result: list[int] = []
        seen: set[int] = set()
        current = first
        while True:
            if len(result) >= cap:
                return ChainResult(tuple(result), ChainStatus.WORK_LIMIT)
            if not self.valid_cluster(current):
                return ChainResult(tuple(result), ChainStatus.INVALID_NEXT)
            if current in seen:
                return ChainResult(tuple(result), ChainStatus.CYCLE)
            if forbidden is not None and current in forbidden:
                return ChainResult(tuple(result), ChainStatus.FORBIDDEN)
            seen.add(current)
            result.append(current)
            try:
                following = (
                    self.fat_next(current)
                    if fat_index is None
                    else self.fat_next(current, fat_index=fat_index)
                )
            except FormatError:
                return ChainResult(tuple(result), ChainStatus.TRUNCATED_READ)
            if following == FAT_END_OF_CHAIN:
                if expected_clusters is not None and len(result) < expected_clusters:
                    return ChainResult(tuple(result), ChainStatus.SHORT)
                return ChainResult(tuple(result), ChainStatus.EXACT)
            if following == FAT_BAD_CLUSTER:
                return ChainResult(tuple(result), ChainStatus.BAD_CLUSTER)
            if following >= 0xFFFFFFF6:
                return ChainResult(tuple(result), ChainStatus.INVALID_NEXT)
            if expected_clusters is not None and len(result) == expected_clusters:
                return ChainResult(tuple(result), ChainStatus.OVERLONG)
            current = following

    def _read_chain_data(
        self, chain: ChainResult, data_length: int, *, max_bytes: int
    ) -> bytes:
        if not chain.exact:
            raise FormatError(
                f"System metadata chain is not exact: {chain.status.value}."
            )
        if data_length > max_bytes:
            raise FormatError(
                "System metadata exceeds the configured bounded byte limit."
            )
        expected = (data_length + self.boot.cluster_size - 1) // self.boot.cluster_size
        if len(chain.clusters) != expected:
            raise FormatError("System metadata chain length does not match DataLength.")
        data = b"".join(self.read_cluster(cluster) for cluster in chain.clusters)
        return data[:data_length]

    @staticmethod
    def _upcase_checksum(data: bytes) -> int:
        checksum = 0
        for byte in data:
            checksum = (((checksum << 31) | (checksum >> 1)) + byte) & 0xFFFFFFFF
        return checksum

    @staticmethod
    def _decompress_upcase(data: bytes) -> tuple[int, ...]:
        if len(data) % 2:
            raise FormatError(
                "The Up-case Table DataLength is not a UTF-16 word count."
            )
        words = struct.unpack(f"<{len(data) // 2}H", data)
        mapping: list[int] = []
        index = 0
        while index < len(words):
            value = words[index]
            index += 1
            if value != 0xFFFF:
                if len(mapping) >= 0x10000:
                    raise FormatError(
                        "The Up-case Table expands beyond all Unicode code units."
                    )
                mapping.append(value)
                continue
            # In an uncompressed full table, the final U+FFFF mapping is the
            # literal value FFFF. Everywhere else FFFF is the compression
            # marker and must be followed by an identity-run count.
            if len(mapping) == 0xFFFF and index == len(words):
                mapping.append(0xFFFF)
                continue
            if index == len(words):
                raise FormatError(
                    "The Up-case Table ends in an incomplete compression run."
                )
            count = words[index]
            index += 1
            if count == 0 or len(mapping) + count > 0x10000:
                raise FormatError("The Up-case Table compression run is invalid.")
            mapping.extend(range(len(mapping), len(mapping) + count))
        if len(mapping) != 0x10000:
            raise FormatError(
                "The Up-case Table does not expand to all Unicode code units."
            )
        mandatory_ascii = tuple(
            code_unit - 0x20 if 0x61 <= code_unit <= 0x7A else code_unit
            for code_unit in range(0x80)
        )
        if tuple(mapping[:0x80]) != mandatory_ascii:
            raise FormatError(
                "The Up-case Table does not contain the mandatory ASCII mappings."
            )
        return tuple(mapping)

    def _root_records(
        self, *, max_chain_clusters: int
    ) -> tuple[tuple[int, ...], tuple[bytes, ...]]:
        root = self.cluster_chain(
            self.boot.root_cluster,
            cap=min(self.boot.cluster_count, max_chain_clusters),
            expected_clusters=None,
        )
        if not root.exact:
            raise FormatError(
                f"The root directory chain is not exact: {root.status.value}."
            )
        records: list[bytes] = []
        for cluster in root.clusters:
            data = self.read_cluster(cluster)
            for offset in range(0, len(data), 32):
                record = data[offset : offset + 32]
                if record[0] == 0:
                    return root.clusters, tuple(records)
                if len(records) >= MAX_ROOT_METADATA_RECORDS:
                    raise FormatError(
                        "The root directory exceeds the bounded metadata record limit."
                    )
                records.append(record)
        raise FormatError("The root directory has no end-of-directory marker.")

    @staticmethod
    def _validate_root_entry_types(records: tuple[bytes, ...]) -> None:
        """Reject unknown critical records before trusting root metadata.

        File entry sets legitimately contain the critical Stream Extension and
        File Name secondaries.  All other unknown critical primaries or
        secondaries make the active metadata unknowable for RC recovery.
        """
        index = 0
        known_primaries = {
            ALLOCATION_BITMAP,
            UPCASE_TABLE,
            VOLUME_LABEL,
            FILE_DIRECTORY,
            VOLUME_GUID,
        }
        while index < len(records):
            entry_type = records[index][0]
            if entry_type == 0x80:
                raise FormatError(
                    "The root directory contains an invalid 0x80 entry type."
                )
            if entry_type < 0x80:
                index += 1
                continue
            if entry_type & 0x40:
                # A secondary entry is meaningful only after its File primary.
                # This loop reaches it only when it is standalone, because a
                # File set is consumed atomically below.  That is true for
                # benign secondaries too: silently skipping one could hide
                # ownership-affecting metadata from the root validator.
                raise FormatError(
                    "The root directory contains a standalone in-use secondary entry."
                )
            if entry_type == VOLUME_GUID:
                ExfatVolume._validate_volume_guid(records[index])
                index += 1
                continue
            if entry_type & 0x20 and entry_type not in known_primaries:
                secondary_count = records[index][1]
                end = index + secondary_count + 1
                if end > len(records) or any(
                    record[0] & 0xC0 != 0xC0 for record in records[index + 1 : end]
                ):
                    raise FormatError(
                        "The root directory contains a malformed benign primary entry set."
                    )
                # Generic benign sets are structurally skipped here so their
                # secondaries are never mistaken for detached entries. The
                # scanner sees the same set and marks ownership incomplete,
                # because this layer cannot establish whether unfamiliar
                # fields describe an allocation.
                index = end
                continue
            if entry_type not in known_primaries and not entry_type & 0x20:
                raise FormatError(
                    "The root directory contains unknown critical metadata."
                )
            if entry_type != FILE_DIRECTORY:
                index += 1
                continue
            secondary_count = records[index][1]
            if not 2 <= secondary_count <= 18 or index + secondary_count >= len(
                records
            ):
                raise FormatError(
                    "The root directory contains a truncated or invalid File entry set."
                )
            for secondary in records[index + 1 : index + secondary_count + 1]:
                secondary_type = secondary[0]
                if secondary_type < 0x80 or not secondary_type & 0x40:
                    raise FormatError(
                        "A root File entry set does not contain only secondary entries."
                    )
                if not secondary_type & 0x20 and secondary_type not in {
                    STREAM_EXTENSION,
                    FILE_NAME,
                }:
                    raise FormatError(
                        "The root File entry set contains an unknown critical secondary entry."
                    )
            index += secondary_count + 1

    @staticmethod
    def _validate_bitmap_padding(bitmap: AllocationBitmap, cluster_count: int) -> None:
        required_bytes = (cluster_count + 7) // 8
        if any(bitmap.data[required_bytes:]):
            raise FormatError(
                "The Allocation Bitmap has nonzero reserved trailing bytes."
            )
        remainder = cluster_count % 8
        if remainder and bitmap.data[required_bytes - 1] & ~((1 << remainder) - 1):
            raise FormatError(
                "The Allocation Bitmap has nonzero reserved trailing bits."
            )

    @staticmethod
    def _validate_volume_label(record: bytes) -> None:
        character_count = record[1]
        if character_count > 11 or any(record[24:32]):
            raise FormatError(
                "The Volume Label entry has an invalid character count or reserved fields."
            )
        try:
            label = record[2 : 2 + character_count * 2].decode("utf-16-le")
        except UnicodeDecodeError as exc:
            raise FormatError("The Volume Label contains invalid UTF-16.") from exc
        if any(
            ord(character) < 0x20 or character in _FORBIDDEN_VOLUME_LABEL_CHARACTERS
            for character in label
        ):
            raise FormatError("The Volume Label contains a forbidden character.")

    @staticmethod
    def _validate_volume_guid(record: bytes) -> None:
        checksum = 0
        for index, byte in enumerate(record):
            if index in (2, 3):
                continue
            if index == 0:
                byte |= 0x80
            checksum = (((checksum << 15) | (checksum >> 1)) + byte) & 0xFFFF
        if (
            record[1]
            or struct.unpack_from("<H", record, 2)[0] != checksum
            or any(record[4:6])
            or not any(record[6:22])
            or any(record[22:32])
        ):
            raise FormatError("The Volume GUID entry has invalid required fields.")

    def load_system_metadata(
        self,
        *,
        max_chain_clusters: int = MAX_SYSTEM_METADATA_CHAIN_CLUSTERS,
        max_bytes: int = MAX_SYSTEM_METADATA_BYTES,
    ) -> SystemMetadata:
        """Parse and validate the root's mandatory allocation and case metadata."""
        if max_chain_clusters < 1 or max_bytes < 1:
            raise FormatError("System metadata limits must be positive.")
        # This is a hard safety ceiling, including for callers of this lower
        # level method. System metadata is retained while it is validated, so a
        # user-provided scan limit must never lift this cap.
        max_chain_clusters = min(max_chain_clusters, MAX_SYSTEM_METADATA_CHAIN_CLUSTERS)
        # The root chain is retained while root records are interpreted. Bound
        # its byte work as well as its cluster count before walking it.
        max_chain_clusters = min(
            max_chain_clusters, max_bytes // self.boot.cluster_size
        )
        if max_chain_clusters < 1:
            raise FormatError("System metadata byte limit is below one cluster.")
        bitmaps: list[AllocationBitmap] = []
        upcase_records: list[tuple[int, int, int]] = []
        volume_labels = 0
        volume_guids = 0
        root_clusters, root_records = self._root_records(
            max_chain_clusters=max_chain_clusters
        )
        self._validate_root_entry_types(root_records)
        for record in root_records:
            entry_type = record[0]
            if entry_type == ALLOCATION_BITMAP:
                identifier = record[1]
                first, length = struct.unpack_from("<IQ", record, 20)
                if (
                    identifier & ~1
                    or any(record[2:20])
                    or not self.valid_cluster(first)
                ):
                    raise FormatError(
                        "The Allocation Bitmap entry has invalid reserved fields or geometry."
                    )
                expected = (
                    length + self.boot.cluster_size - 1
                ) // self.boot.cluster_size
                if length < (self.boot.cluster_count + 7) // 8 or expected == 0:
                    raise FormatError(
                        "The Allocation Bitmap is too short for the cluster heap."
                    )
                if expected > max_chain_clusters:
                    raise FormatError(
                        "The Allocation Bitmap chain exceeds the configured work limit."
                    )
                chain = self.cluster_chain(
                    first,
                    cap=expected,
                    expected_clusters=expected,
                    fat_index=identifier,
                )
                data = self._read_chain_data(chain, length, max_bytes=max_bytes)
                bitmaps.append(
                    AllocationBitmap(identifier, first, length, chain.clusters, data)
                )
            elif entry_type == UPCASE_TABLE:
                checksum = struct.unpack_from("<I", record, 4)[0]
                first, length = struct.unpack_from("<IQ", record, 20)
                if (
                    record[1]
                    or any(record[2:4])
                    or any(record[8:20])
                    or not self.valid_cluster(first)
                ):
                    raise FormatError(
                        "The Up-case Table entry has invalid reserved fields or geometry."
                    )
                upcase_records.append((checksum, first, length))
            elif entry_type == VOLUME_LABEL:
                self._validate_volume_label(record)
                volume_labels += 1
            elif entry_type == VOLUME_GUID:
                self._validate_volume_guid(record)
                volume_guids += 1
        expected_ids = set(range(self.boot.number_of_fats))
        if (
            len(bitmaps) != self.boot.number_of_fats
            or {item.identifier for item in bitmaps} != expected_ids
        ):
            raise FormatError(
                "The root directory must contain exactly one Allocation Bitmap for each FAT."
            )
        if len(upcase_records) != 1:
            raise FormatError(
                "The root directory must contain exactly one Up-case Table."
            )
        if volume_labels > 1:
            raise FormatError("The root directory contains more than one Volume Label.")
        if volume_guids > 1:
            raise FormatError("The root directory contains more than one Volume GUID.")
        checksum, first, length = upcase_records[0]
        if length > MAX_UPCASE_TABLE_BYTES:
            raise FormatError(
                "The Up-case Table DataLength exceeds the canonical UTF-16 table size."
            )
        expected = (length + self.boot.cluster_size - 1) // self.boot.cluster_size
        if expected == 0:
            raise FormatError("The Up-case Table is empty.")
        if expected > max_chain_clusters:
            raise FormatError(
                "The Up-case Table chain exceeds the configured work limit."
            )
        chain = self.cluster_chain(first, cap=expected, expected_clusters=expected)
        data = self._read_chain_data(chain, length, max_bytes=max_bytes)
        if self._upcase_checksum(data) != checksum:
            raise FormatError("The Up-case Table checksum is invalid.")
        table = UpcaseTable(
            first, length, checksum, chain.clusters, self._decompress_upcase(data)
        )
        by_identifier = {item.identifier: item for item in bitmaps}
        active_bitmap = by_identifier[self.boot.active_fat]
        for bitmap in bitmaps:
            self._validate_bitmap_padding(bitmap, self.boot.cluster_count)
        system_clusters = (
            *root_clusters,
            *(cluster for bitmap in bitmaps for cluster in bitmap.clusters),
            *table.clusters,
        )
        if len(set(system_clusters)) != len(system_clusters):
            raise FormatError("Root system metadata allocations overlap.")
        for cluster in system_clusters:
            if not active_bitmap.is_allocated(cluster):
                raise FormatError(
                    "The active Allocation Bitmap marks system metadata free."
                )
        return SystemMetadata(tuple(bitmaps), active_bitmap, table, root_clusters)

    def system_metadata(
        self, *, max_chain_clusters: int = MAX_SYSTEM_METADATA_CHAIN_CLUSTERS
    ) -> SystemMetadata:
        """Return the validated system metadata, parsing it once per volume."""
        if self._system_metadata is None:
            self._system_metadata = self.load_system_metadata(
                max_chain_clusters=min(
                    max_chain_clusters, MAX_SYSTEM_METADATA_CHAIN_CLUSTERS
                )
            )
        return self._system_metadata

    def cluster_is_allocated(self, cluster: int) -> bool:
        return self.system_metadata().active_bitmap.is_allocated(cluster)

    def active_system_owners(self) -> set[int]:
        metadata = self.system_metadata()
        return {
            *metadata.root_clusters,
            *(cluster for bitmap in metadata.bitmaps for cluster in bitmap.clusters),
            *metadata.upcase_table.clusters,
        }
