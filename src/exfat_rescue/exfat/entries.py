from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone
from typing import Any

from ..errors import FormatError
from .volume import ExfatVolume

FILE, DELETED_FILE, STREAM, DELETED_STREAM, NAME, DELETED_NAME = (
    0x85,
    0x05,
    0xC0,
    0x40,
    0xC1,
    0x41,
)
VENDOR_EXTENSION, DELETED_VENDOR_EXTENSION = 0xE0, 0x60
VENDOR_ALLOCATION, DELETED_VENDOR_ALLOCATION = 0xE1, 0x61
FILE_ATTRIBUTES_MASK = 0x0037
FORBIDDEN_NAME_CHARACTERS = frozenset('"*/:<>?\\|')


def entry_set_checksum(data: bytes) -> int:
    checksum = 0
    for index, byte in enumerate(data):
        if index in (2, 3):
            continue
        if index % 32 == 0:
            byte |= 0x80
        checksum = (((checksum << 15) | (checksum >> 1)) + byte) & 0xFFFF
    return checksum


def name_hash(name: str, upcase_mapping: tuple[int, ...]) -> int:
    """Return the exFAT NameHash for a UTF-16 filename and validated Up-case table."""
    encoded = name.encode("utf-16-le", "surrogatepass")
    checksum = 0
    for index in range(0, len(encoded), 2):
        code_unit = encoded[index] | (encoded[index + 1] << 8)
        upper = upcase_mapping[code_unit]
        for byte in (upper & 0xFF, upper >> 8):
            checksum = (((checksum << 15) | (checksum >> 1)) + byte) & 0xFFFF
    return checksum


def _utc_offset_minutes(value: int) -> int | None:
    if not value & 0x80:
        return None
    quarter_hours = value & 0x7F
    if quarter_hours & 0x40:
        quarter_hours -= 0x80
    return quarter_hours * 15


def _timestamp(value: int, utc_offset: int) -> tuple[str | None, int | None]:
    if not value:
        return None, None
    # The low five bits store two-second increments. Values 30 and 31 are
    # reserved; clamping them would turn malformed metadata into a fabricated
    # timestamp.
    if value & 31 > 29:
        return None, None
    try:
        # exFAT timestamps are local wall-clock values unless the optional UTC
        # offset byte is marked valid. Keeping this naive is intentional.
        parsed = datetime(  # noqa: DTZ001
            1980 + (value >> 25),
            (value >> 21) & 15,
            (value >> 16) & 31,
            (value >> 11) & 31,
            (value >> 5) & 63,
            (value & 31) * 2,
        )
    except ValueError:
        return None, None
    offset_minutes = _utc_offset_minutes(utc_offset)
    if offset_minutes is not None:
        parsed = parsed.replace(tzinfo=timezone(timedelta(minutes=offset_minutes)))
    return parsed.isoformat(), offset_minutes


def _valid_name(name: str) -> bool:
    return (
        bool(name)
        and name not in {".", ".."}
        and all(
            ord(character) >= 0x20 and character not in FORBIDDEN_NAME_CHARACTERS
            for character in name
        )
    )


def _valid_vendor_secondary(
    entry: bytes, *, deleted: bool, volume: ExfatVolume
) -> bool:
    """Validate a known benign secondary without assigning it file data.

    A Vendor Allocation can describe storage which scanner.py accounts for as
    active ownership.  It is deliberately not exposed here as part of the
    File stream's recoverable allocation.
    """
    expected_extension = DELETED_VENDOR_EXTENSION if deleted else VENDOR_EXTENSION
    expected_allocation = DELETED_VENDOR_ALLOCATION if deleted else VENDOR_ALLOCATION
    entry_type = entry[0]
    flags = entry[1]
    if not any(entry[2:18]):  # The null GUID is invalid for both entries.
        return False
    if entry_type == expected_extension:
        # Vendor Extension has no allocation and reserves every flag bit.
        return flags == 0
    if entry_type != expected_allocation:
        return False
    # Vendor Allocation requires AllocationPossible.  Only NoFatChain may be
    # set in addition; the remaining GeneralSecondaryFlags are reserved.
    if flags & ~0x03 or not flags & 1:
        return False
    first_cluster = struct.unpack_from("<I", entry, 20)[0]
    data_length = struct.unpack_from("<Q", entry, 24)[0]
    if data_length > volume.boot.volume_bytes:
        return False
    if first_cluster == 0:
        return data_length == 0 and not flags & 2
    if not volume.valid_cluster(first_cluster):
        return False
    # NoFatChain requires both a nonempty allocation and a valid first
    # cluster.  The latter is checked above, and the former here.
    if not flags & 2:
        return True
    if data_length == 0:
        return False
    clusters = (data_length + volume.boot.cluster_size - 1) // volume.boot.cluster_size
    return first_cluster + clusters <= volume.boot.cluster_count + 2


def parse_entry_set(
    data: bytes, offset: int, volume: ExfatVolume, absolute_offset: int
) -> dict[str, Any] | None:
    if offset + 64 > len(data) or data[offset] not in (FILE, DELETED_FILE):
        return None
    secondaries = data[offset + 1]
    if not 2 <= secondaries <= 18 or offset + (secondaries + 1) * 32 > len(data):
        return None
    item = data[offset : offset + (secondaries + 1) * 32]
    if entry_set_checksum(item) != struct.unpack_from("<H", item, 2)[0]:
        return None
    stream = item[32:64]
    deleted = item[0] == DELETED_FILE
    expected_stream = DELETED_STREAM if deleted else STREAM
    expected_name = DELETED_NAME if deleted else NAME
    if any(item[6:8]) or any(item[25:32]) or stream[0] != expected_stream:
        return None
    stream_flags = stream[1]
    if (
        not stream_flags & 1
        or stream_flags & ~0x03
        or stream[2] != 0
        or any(stream[6:8])
        or any(stream[16:20])
    ):
        return None
    name_length = stream[3]
    expected_names = (name_length + 14) // 15
    if not name_length or secondaries < 1 + expected_names:
        return None
    names = []
    for number in range(expected_names):
        name_entry = item[(2 + number) * 32 : (3 + number) * 32]
        if name_entry[0] != expected_name or name_entry[1] != 0:
            return None
        names.append(name_entry[2:32])
    encoded_name = b"".join(names)
    if any(encoded_name[name_length * 2 :]):
        return None
    for number in range(2 + expected_names, secondaries + 1):
        vendor_entry = item[number * 32 : (number + 1) * 32]
        if not _valid_vendor_secondary(vendor_entry, deleted=deleted, volume=volume):
            return None
    try:
        name = encoded_name[: name_length * 2].decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    if not _valid_name(name):
        return None
    if not deleted:
        try:
            expected_name_hash = name_hash(
                name, volume.system_metadata().upcase_table.mapping
            )
        except (FormatError, IndexError, ValueError):
            # The volume-level RC entrypoint validates mandatory system metadata
            # before accepting a recovery plan. Keep directory scanning able to
            # report a damaged entry rather than turning it into an unrelated
            # volume-open failure.
            expected_name_hash = struct.unpack_from("<H", stream, 4)[0]
        if expected_name_hash != struct.unpack_from("<H", stream, 4)[0]:
            return None
    attributes = struct.unpack_from("<H", item, 4)[0]
    if attributes & ~FILE_ATTRIBUTES_MASK:
        return None
    is_directory = bool(attributes & 0x10)
    first_cluster = struct.unpack_from("<I", stream, 20)[0]
    size, valid_size = (
        struct.unpack_from("<Q", stream, 24)[0],
        struct.unpack_from("<Q", stream, 8)[0],
    )
    no_fat_chain = bool(stream_flags & 2)
    contiguous_clusters = (
        (size + volume.boot.cluster_size - 1) // volume.boot.cluster_size
        if size and no_fat_chain
        else 0
    )
    if (
        size > volume.boot.volume_bytes
        or valid_size > size
        or (is_directory and size > 256 * 1024 * 1024)
        or (is_directory and size == 0)
        or (is_directory and valid_size != size)
        or (is_directory and size % volume.boot.cluster_size)
        or (size == 0 and first_cluster != 0)
        or (size and not volume.valid_cluster(first_cluster))
        or (no_fat_chain and size == 0)
        or (
            contiguous_clusters
            and first_cluster + contiguous_clusters > volume.boot.cluster_count + 2
        )
    ):
        return None
    modified_at, modified_utc_offset_minutes = _timestamp(
        struct.unpack_from("<I", item, 12)[0], item[23]
    )
    return {
        "entry_offset": absolute_offset,
        "name": name,
        "size_bytes": size,
        "valid_size_bytes": valid_size,
        "first_cluster": first_cluster,
        "no_fat_chain": no_fat_chain,
        "deleted": deleted,
        "is_directory": is_directory,
        "attributes": attributes,
        "modified_at": modified_at,
        "modified_utc_offset_minutes": modified_utc_offset_minutes,
        "entry_checksum": f"{struct.unpack_from('<H', item, 2)[0]:04x}",
    }
