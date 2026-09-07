from __future__ import annotations

import copy
import hashlib
import importlib.resources
import json
import tempfile
import unittest
from pathlib import Path

from exfat_rescue.errors import ManifestError
from exfat_rescue.manifest import (
    DEFAULT_MAX_MANIFEST_RECORDS,
    parse_manifest_v2_bytes,
    read_manifest_v2,
    validate_manifest_plans,
    write_manifest_v2,
)
from exfat_rescue.planner import plan_recovery
from exfat_rescue.scanner import scan
from exfat_rescue.source import ImageSource
from tests.fixture import image


class ManifestV2Tests(unittest.TestCase):
    def _valid_bytes(self) -> bytes:
        with tempfile.TemporaryDirectory() as directory:
            source_path = Path(directory) / "source.img"
            manifest_path = Path(directory) / "manifest.jsonl"
            source_path.write_bytes(image())
            source = ImageSource.open(source_path)
            try:
                scanned = scan(source)
                planned = plan_recovery(
                    scanned.volume,
                    scanned.candidates,
                    active_owners=scanned.active_owners,
                    metadata_complete=scanned.metadata_complete,
                    ownership_complete=scanned.ownership_complete,
                )
                write_manifest_v2(
                    source,
                    manifest_path,
                    planned,
                    {
                        "orphan_scan": True,
                        "version": 2,
                        "volume_offset_bytes": scanned.volume.base_offset,
                        "source_kind": scanned.volume.location.source_kind,
                        "boot_region": scanned.volume.boot_region,
                        "max_candidates": 100,
                        "max_scan_clusters": 50_000_000,
                        "max_fat_steps": 10_000_000,
                    },
                )
                return manifest_path.read_bytes()
            finally:
                source.close()

    @staticmethod
    def _encode(records: list[dict]) -> bytes:
        content = b"".join(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            for record in records[:-1]
        )
        records[-1] = {
            "record_type": "complete",
            "candidate_count": len(records) - 2,
            "content_record_count": len(records) - 1,
            "content_sha256": hashlib.sha256(content).hexdigest(),
        }
        return (
            content
            + json.dumps(records[-1], sort_keys=True, separators=(",", ":")).encode()
            + b"\n"
        )

    def test_round_trip_and_tamper_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_path = Path(directory) / "source.img"
            manifest_path = Path(directory) / "manifest.jsonl"
            source_path.write_bytes(image())
            source = ImageSource.open(source_path)
            try:
                scanned = scan(source)
                planned = plan_recovery(
                    scanned.volume,
                    scanned.candidates,
                    active_owners=scanned.active_owners,
                    metadata_complete=scanned.metadata_complete,
                    ownership_complete=scanned.ownership_complete,
                )
                write_manifest_v2(
                    source,
                    manifest_path,
                    planned,
                    {
                        "orphan_scan": True,
                        "version": 2,
                        "volume_offset_bytes": scanned.volume.base_offset,
                        "source_kind": scanned.volume.location.source_kind,
                        "boot_region": scanned.volume.boot_region,
                        "max_candidates": 100,
                        "max_scan_clusters": 50_000_000,
                        "max_fat_steps": 10_000_000,
                    },
                )
                manifest = read_manifest_v2(manifest_path)
                validate_manifest_plans(manifest, planned)
            finally:
                source.close()
            content = manifest_path.read_text(encoding="utf-8")
            manifest_path.write_text(
                content.replace('"version":2', '"version":3', 1), encoding="utf-8"
            )
            with self.assertRaises(ManifestError):
                read_manifest_v2(manifest_path)

    def test_strict_parser_rejects_rehashed_semantic_tampering(self) -> None:
        records = [json.loads(line) for line in self._valid_bytes().splitlines()]

        def mutate(path: tuple[object, ...], value: object) -> bytes:
            changed = copy.deepcopy(records)
            target: object = changed
            for component in path[:-1]:
                target = target[component]  # type: ignore[index]
            target[path[-1]] = value  # type: ignore[index]
            return self._encode(changed)

        cases = {
            "wrong option set": mutate(
                (0, "scan_options"),
                {"orphan_scan": True},
            ),
            "orphan scan disabled": mutate((0, "scan_options", "orphan_scan"), False),
            "invalid source geometry": mutate((0, "source", "volume_length_bytes"), 0),
            "invalid extent cluster": mutate((1, "extents", 0, "first_cluster"), 1),
            "raw candidate mismatch": mutate(
                (1, "source_candidate", "name"), "different"
            ),
            "invalid warning": mutate((0, "warnings"), [""]),
            "max candidates above framing ceiling": mutate(
                (0, "scan_options", "max_candidates"),
                DEFAULT_MAX_MANIFEST_RECORDS - 1,
            ),
            "hostile allocation mode": mutate((1, "allocation_mode"), []),
            "hostile metadata location": mutate((1, "metadata_location"), {}),
            "hostile disposition": mutate((1, "disposition"), []),
            "hostile recovery basis": mutate((1, "recovery_basis"), {}),
            "hostile raw location": mutate((1, "source_candidate", "location"), []),
            "hostile source kind": mutate((0, "source", "source_kind"), {}),
            "hostile boot region": mutate((0, "source", "boot_region"), []),
        }
        for label, content in cases.items():
            with self.subTest(label=label), self.assertRaises(ManifestError):
                parse_manifest_v2_bytes(content)

    def test_strict_parser_enforces_framing_and_reader_limits(self) -> None:
        content = self._valid_bytes()
        for label, changed, arguments in (
            ("missing newline", content.rstrip(b"\n"), {}),
            ("byte limit", content, {"max_bytes": len(content) - 1}),
            ("record limit", content, {"max_records": 2}),
            ("invalid limits", content, {"max_records": 1}),
            ("invalid json", b"{}\nnot-json\n", {}),
            ("non-object", b"[]\n{}\n", {}),
        ):
            with self.subTest(label=label), self.assertRaises(ManifestError):
                parse_manifest_v2_bytes(changed, **arguments)

    def test_packaged_schema_rejects_undeclared_nested_recovery_data(self) -> None:
        import jsonschema

        schema_resource = importlib.resources.files("exfat_rescue.schemas").joinpath(
            "manifest-v2.json"
        )
        schema = json.loads(schema_resource.read_text(encoding="utf-8"))
        records = [json.loads(line) for line in self._valid_bytes().splitlines()]
        for record in records:
            jsonschema.validate(record, schema)

        invalid = copy.deepcopy(records[1])
        invalid["source_candidate"]["undeclared"] = True
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(invalid, schema)

        boundary = copy.deepcopy(records[0])
        boundary["scan_options"]["max_candidates"] = DEFAULT_MAX_MANIFEST_RECORDS - 2
        jsonschema.validate(boundary, schema)
        boundary["scan_options"]["max_candidates"] += 1
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(boundary, schema)

    def test_parser_accepts_manifest_framing_candidate_boundary(self) -> None:
        records = [json.loads(line) for line in self._valid_bytes().splitlines()]
        records[0]["scan_options"]["max_candidates"] = DEFAULT_MAX_MANIFEST_RECORDS - 2
        parse_manifest_v2_bytes(self._encode(records))
