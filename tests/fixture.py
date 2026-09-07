from __future__ import annotations

import struct
import zlib

from exfat_rescue.exfat.entries import entry_set_checksum


def _boot_checksum(region: bytes, bytes_per_sector: int = 512) -> int:
    checksum = 0
    for index, byte in enumerate(region[:-bytes_per_sector]):
        if index in (0x6A, 0x6B, 0x70):
            continue
        checksum = (((checksum << 31) | (checksum >> 1)) + byte) & 0xFFFFFFFF
    return checksum


def refresh_boot_checksums(data: bytearray) -> None:
    for start_sector in (0, 12):
        start = start_sector * 512
        region = bytes(data[start : start + 12 * 512])
        checksum = _boot_checksum(region)
        for offset in range(start + 11 * 512, start + 12 * 512, 4):
            struct.pack_into("<I", data, offset, checksum)


def entry(
    name: str,
    *,
    deleted: bool = False,
    first_cluster: int = 3,
    size: int = 10,
    valid_size: int | None = None,
    directory: bool = False,
    corrupt: bool = False,
    utc_offset_quarters: int | None = None,
    no_fat_chain: bool = True,
) -> bytes:
    encoded = name.encode("utf-16-le")
    names = (len(encoded) + 29) // 30
    records = bytearray((2 + names) * 32)
    records[0] = 0x05 if deleted else 0x85
    records[1] = 1 + names
    struct.pack_into("<H", records, 4, 0x10 if directory else 0)
    struct.pack_into("<I", records, 12, (46 << 25) | (1 << 21) | (2 << 16))
    if utc_offset_quarters is not None:
        if not -64 <= utc_offset_quarters <= 63:
            raise ValueError("UTC offset must fit the exFAT signed 7-bit field")
        records[23] = 0x80 | (utc_offset_quarters & 0x7F)
    records[32] = 0x40 if deleted else 0xC0
    records[33] = 3 if no_fat_chain else 1
    records[35] = len(name)
    struct.pack_into("<Q", records, 40, size if valid_size is None else valid_size)
    struct.pack_into("<I", records, 52, first_cluster)
    struct.pack_into("<Q", records, 56, size)
    # The compact fixture Up-case Table has the mandatory ASCII mappings and
    # uses identity mappings for the remaining UTF-16 code units.
    checksum = 0
    for index in range(0, len(encoded), 2):
        code_unit = encoded[index] | (encoded[index + 1] << 8)
        upper = code_unit - 0x20 if 0x61 <= code_unit <= 0x7A else code_unit
        for byte in (upper & 0xFF, upper >> 8):
            checksum = (((checksum << 15) | (checksum >> 1)) + byte) & 0xFFFF
    struct.pack_into("<H", records, 36, checksum)
    for index in range(names):
        begin = 64 + index * 32
        records[begin] = 0x41 if deleted else 0xC1
        records[begin + 2 : begin + 32] = encoded[index * 30 : (index + 1) * 30].ljust(
            30, b"\x00"
        )
    struct.pack_into("<H", records, 2, entry_set_checksum(records))
    if corrupt:
        records[2] ^= 1
    return bytes(records)


def allocation_bitmap_entry(
    identifier: int, first_cluster: int, data_length: int
) -> bytes:
    record = bytearray(32)
    record[0], record[1] = 0x81, identifier
    struct.pack_into("<I", record, 20, first_cluster)
    struct.pack_into("<Q", record, 24, data_length)
    return bytes(record)


def upcase_checksum(data: bytes) -> int:
    checksum = 0
    for byte in data:
        checksum = (((checksum << 31) | (checksum >> 1)) + byte) & 0xFFFFFFFF
    return checksum


def upcase_entry(first_cluster: int, data: bytes) -> bytes:
    record = bytearray(32)
    record[0] = 0x82
    struct.pack_into("<I", record, 4, upcase_checksum(data))
    struct.pack_into("<I", record, 20, first_cluster)
    struct.pack_into("<Q", record, 24, len(data))
    return bytes(record)


def set_active_bitmap_allocations(data: bytearray, allocated: set[int]) -> None:
    """Rewrite the default fixture's active Allocation Bitmap after a geometry edit.

    Directory-semantics tests sometimes enlarge the cluster heap.  Those tests
    remain valid exFAT volumes by rebuilding the required bitmap length rather
    than weakening system-metadata validation.
    """
    cluster_count = struct.unpack_from("<I", data, 0x5C)[0]
    heap_sector = struct.unpack_from("<I", data, 0x58)[0]
    bytes_per_sector = 1 << data[0x6C]
    sectors_per_cluster = 1 << data[0x6D]
    cluster_size = bytes_per_sector * sectors_per_cluster
    bitmap_length = (cluster_count + 7) // 8
    root = heap_sector * bytes_per_sector
    bitmap_cluster = struct.unpack_from("<I", data, root + 20)[0]
    bitmap = bytearray(bitmap_length)
    for cluster in allocated:
        if not 2 <= cluster < cluster_count + 2:
            raise ValueError("bitmap allocation is outside the fixture cluster heap")
        bitmap[(cluster - 2) // 8] |= 1 << ((cluster - 2) % 8)
    struct.pack_into("<Q", data, root + 24, bitmap_length)
    begin = heap_sector * bytes_per_sector + (bitmap_cluster - 2) * cluster_size
    data[begin : begin + bitmap_length] = bitmap


def image(
    *,
    corrupt_boot: bool = False,
    truncated: bool = False,
    number_of_fats: int = 1,
    active_second_fat: bool = False,
) -> bytes:
    sectors, cluster_count = 2048, 16
    fat_sector, heap_sector = 24, sectors - cluster_count
    data = bytearray(sectors * 512)
    data[:3] = b"\xeb\x76\x90"
    data[3:11] = b"EXFAT   "
    data[510:512] = b"\x55\xaa"
    struct.pack_into("<Q", data, 0x48, sectors)
    struct.pack_into("<I", data, 0x50, fat_sector)
    struct.pack_into("<I", data, 0x54, 1)
    struct.pack_into("<I", data, 0x58, heap_sector)
    struct.pack_into("<I", data, 0x5C, cluster_count)
    struct.pack_into("<I", data, 0x60, 2)
    struct.pack_into("<I", data, 0x64, 0x12345678)
    struct.pack_into("<H", data, 0x68, 0x0100)
    data[0x6C:0x70] = bytes((9, 0, number_of_fats, 0))
    if active_second_fat:
        if number_of_fats != 2:
            raise ValueError("active second FAT requires two FATs")
        struct.pack_into("<H", data, 0x6A, 1)
    for sector in range(1, 9):
        data[(sector + 1) * 512 - 4 : (sector + 1) * 512] = b"\x00\x00\x55\xaa"
    data[12 * 512 : 24 * 512] = data[: 12 * 512]
    fat = fat_sector * 512
    for cluster in range(2, cluster_count + 2):
        struct.pack_into("<I", data, fat + cluster * 4, 0xFFFFFFFF)
        if number_of_fats == 2:
            struct.pack_into("<I", data, fat + 512 + cluster * 4, 0xFFFFFFFF)
    if active_second_fat:
        struct.pack_into("<I", data, fat + 512 + 2 * 4, 0x12345678)
    root = heap_sector * 512
    bitmap_data_length = (cluster_count + 7) // 8
    bitmap_clusters = tuple(7 + index for index in range(number_of_fats))
    upcase_cluster = 7 + number_of_fats
    allocated = {2, 3, *bitmap_clusters, upcase_cluster}
    bitmap_data = bytearray(bitmap_data_length)
    for cluster in allocated:
        bitmap_data[(cluster - 2) // 8] |= 1 << ((cluster - 2) % 8)
    for index, cluster in enumerate(bitmap_clusters):
        begin = heap_sector * 512 + (cluster - 2) * 512
        data[begin : begin + bitmap_data_length] = bitmap_data
        record = allocation_bitmap_entry(index, cluster, bitmap_data_length)
        data[root + index * 32 : root + (index + 1) * 32] = record
    # Identity through U+0060, explicit ASCII upper-case mappings, then identity
    # for U+007B through U+FFFF.
    upcase_words = [0xFFFF, 0x0061, *range(0x0041, 0x005B), 0xFFFF, 0xFF85]
    upcase_data = struct.pack(f"<{len(upcase_words)}H", *upcase_words)
    begin = heap_sector * 512 + (upcase_cluster - 2) * 512
    data[begin : begin + len(upcase_data)] = upcase_data
    metadata_length = number_of_fats * 32
    data[root + metadata_length : root + metadata_length + 32] = upcase_entry(
        upcase_cluster, upcase_data
    )
    metadata_length += 32
    first = entry("Active.txt", first_cluster=3)
    second = entry("Deleted.txt", deleted=True, first_cluster=4)
    data[root + metadata_length : root + metadata_length + len(first)] = first
    data[
        root + metadata_length + len(first) : root
        + metadata_length
        + len(first)
        + len(second)
    ] = second
    orphan = entry("orphan.txt", deleted=True, first_cluster=5)
    data[root + 512 : root + 512 + len(orphan)] = orphan
    bad = entry("bad.txt", first_cluster=6, corrupt=True)
    data[root + 1024 : root + 1024 + len(bad)] = bad
    if corrupt_boot:
        data[3:11] = b"NOPE    "
        data[12 * 512 + 3 : 12 * 512 + 11] = b"NOPE    "
    refresh_boot_checksums(data)
    return bytes(data[:200] if truncated else data)


def mbr_image(*, ambiguous: bool = False) -> bytes:
    partition = image()
    partition_sectors = len(partition) // 512
    starts = [1, partition_sectors + 16] if ambiguous else [1]
    disk_sectors = starts[-1] + partition_sectors + 16
    data = bytearray(disk_sectors * 512)
    data[510:512] = b"\x55\xaa"
    for index, start in enumerate(starts):
        struct.pack_into(
            "<B3sB3sII",
            data,
            446 + index * 16,
            0,
            b"\0" * 3,
            0x07,
            b"\0" * 3,
            start,
            partition_sectors,
        )
        data[start * 512 : (start + partition_sectors) * 512] = partition
    return bytes(data)


def gpt_image(*, corrupt_table: bool = False, truncated_table: bool = False) -> bytes:
    partition, start = image(), 34
    sectors = len(partition) // 512
    disk_sectors = start + sectors + 34
    data = bytearray(disk_sectors * 512)
    data[510:512] = b"\x55\xaa"
    struct.pack_into(
        "<B3sB3sII",
        data,
        446,
        0,
        b"\0" * 3,
        0xEE,
        b"\0" * 3,
        1,
        disk_sectors - 1,
    )
    header = bytearray(512)
    header[:8] = b"EFI PART"
    struct.pack_into("<I", header, 8, 0x00010000)
    struct.pack_into("<I", header, 12, 92)
    struct.pack_into("<Q", header, 24, 1)
    struct.pack_into("<Q", header, 32, disk_sectors - 1)
    struct.pack_into("<Q", header, 40, 34)
    struct.pack_into("<Q", header, 48, disk_sectors - 2)
    struct.pack_into("<QII", header, 72, 2, 4, 128)
    table = bytearray(512)
    table[:16] = b"\x11" * 16
    struct.pack_into("<QQ", table, 32, start, start + sectors - 1)
    struct.pack_into("<I", header, 88, zlib.crc32(table) & 0xFFFFFFFF)
    crc_data = bytearray(header[:92])
    crc_data[16:20] = b"\0" * 4
    struct.pack_into("<I", header, 16, zlib.crc32(crc_data) & 0xFFFFFFFF)
    data[512:1024], data[1024:1536] = header, table
    data[start * 512 : (start + sectors) * 512] = partition
    if corrupt_table:
        data[1024] ^= 1
    if truncated_table:
        return bytes(data[:1200])
    return bytes(data)
