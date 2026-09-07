from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import exfat_rescue.manifest as manifest_module
from exfat_rescue.errors import ManifestError, OutputError, SourceError
from exfat_rescue.manifest import (
    DEFAULT_MAX_MANIFEST_RECORDS,
    MAX_MANIFEST_LINE_BYTES,
    parse_manifest_v2_bytes,
    validate_manifest_plans,
    write_manifest_v2,
)
from exfat_rescue.planner import PlannerResult, plan_recovery
from exfat_rescue.scanner import scan
from exfat_rescue.source import ImageSource, preflight_output_path, refuse_output_path
from tests.fixture import image


class ManifestBoundaryExtraTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.source_path = Path(self.temp.name) / "source.img"
        self.source_path.write_bytes(image())

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _planned(self) -> tuple[ImageSource, PlannerResult, dict[str, object]]:
        source = ImageSource.open(self.source_path)
        scanned = scan(source)
        planned = plan_recovery(
            scanned.volume,
            scanned.candidates,
            active_owners=scanned.active_owners,
            metadata_complete=scanned.metadata_complete,
            ownership_complete=scanned.ownership_complete,
        )
        options: dict[str, object] = {
            "orphan_scan": True,
            "version": 2,
            "volume_offset_bytes": scanned.volume.base_offset,
            "source_kind": scanned.volume.location.source_kind,
            "boot_region": scanned.volume.boot_region,
            "max_candidates": 100,
            "max_scan_clusters": 50_000_000,
            "max_fat_steps": 10_000_000,
        }
        return source, planned, options

    @staticmethod
    def _encoded(records: list[dict[str, object]]) -> bytes:
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

    def _valid_records(self) -> list[dict[str, object]]:
        source, planned, options = self._planned()
        try:
            output = Path(self.temp.name) / "valid.jsonl"
            write_manifest_v2(source, output, planned, options)
            return [json.loads(line) for line in output.read_bytes().splitlines()]
        finally:
            source.close()

    def test_writer_rejects_duplicate_unsorted_and_missing_raw_candidates(self) -> None:
        source, planned, options = self._planned()
        try:
            duplicate = replace(planned, plans=(planned.plans[0], planned.plans[0]))
            unsorted = replace(planned, plans=tuple(reversed(planned.plans)))
            missing = replace(planned, source_candidates=planned.source_candidates[:-1])
            mismatched_raw = replace(
                planned,
                source_candidates=(
                    {**planned.source_candidates[0], "name": "not-the-plan"},
                    *planned.source_candidates[1:],
                ),
            )
            for label, result in (
                ("duplicate", duplicate),
                ("order", unsorted),
                ("missing-raw", missing),
                ("mismatched-raw", mismatched_raw),
            ):
                with self.subTest(label=label), self.assertRaises(ManifestError):
                    write_manifest_v2(
                        source, Path(self.temp.name) / f"{label}.jsonl", result, options
                    )
        finally:
            source.close()

    def test_writer_enforces_line_limit_and_leaves_partial_file(self) -> None:
        source, planned, _options = self._planned()
        try:
            oversized = replace(
                planned,
                source_candidates=tuple(
                    {**candidate, "name": "x" * MAX_MANIFEST_LINE_BYTES}
                    if index == 0
                    else candidate
                    for index, candidate in enumerate(planned.source_candidates)
                ),
            )
            # The semantic raw/plan name equality guard rejects this first; invoke the
            # low-level writer with an oversized otherwise opaque record instead.
            from exfat_rescue.manifest import _write_v2

            target = Path(self.temp.name) / "large.jsonl"
            with self.assertRaises(ManifestError):
                _write_v2(
                    source,
                    target,
                    [
                        {
                            "record_type": "manifest",
                            "blob": "x" * MAX_MANIFEST_LINE_BYTES,
                        }
                    ],
                )
            self.assertTrue(target.exists())
            self.assertEqual(target.read_bytes(), b"")
            self.assertNotEqual(oversized, planned)
        finally:
            source.close()

    def test_writer_enforces_cumulative_record_limit_including_completion(self) -> None:
        source, planned, options = self._planned()
        try:
            complete_records = len(planned.plans) + 2
            framing_options = {
                **options,
                "max_candidates": complete_records - 2,
            }
            with patch(
                "exfat_rescue.manifest.DEFAULT_MAX_MANIFEST_RECORDS",
                complete_records,
            ):
                write_manifest_v2(
                    source,
                    Path(self.temp.name) / "record-boundary.jsonl",
                    planned,
                    framing_options,
                )
            with (
                patch(
                    "exfat_rescue.manifest.DEFAULT_MAX_MANIFEST_RECORDS",
                    complete_records - 1,
                ),
                self.assertRaises(ManifestError),
            ):
                rejected = Path(self.temp.name) / "record-boundary-plus-one.jsonl"
                write_manifest_v2(
                    source,
                    rejected,
                    planned,
                    framing_options,
                )
            self.assertFalse(rejected.exists())
        finally:
            source.close()

    def test_public_writer_enforces_scan_candidate_framing_ceiling(self) -> None:
        source, planned, options = self._planned()
        try:
            boundary_options = {
                **options,
                "max_candidates": DEFAULT_MAX_MANIFEST_RECORDS - 2,
            }
            write_manifest_v2(
                source,
                Path(self.temp.name) / "scan-option-boundary.jsonl",
                planned,
                boundary_options,
            )
            rejected = Path(self.temp.name) / "scan-option-boundary-plus-one.jsonl"
            with self.assertRaises(ManifestError):
                write_manifest_v2(
                    source,
                    rejected,
                    planned,
                    {
                        **boundary_options,
                        "max_candidates": boundary_options["max_candidates"] + 1,
                    },
                )
            self.assertFalse(rejected.exists())
        finally:
            source.close()

    def test_writer_enforces_cumulative_byte_limit_including_completion(self) -> None:
        source, planned, options = self._planned()
        try:
            baseline = Path(self.temp.name) / "byte-baseline.jsonl"
            write_manifest_v2(source, baseline, planned, options)
            complete_bytes = baseline.stat().st_size
            with patch(
                "exfat_rescue.manifest.DEFAULT_MAX_MANIFEST_BYTES", complete_bytes
            ):
                write_manifest_v2(
                    source,
                    Path(self.temp.name) / "byte-boundary.jsonl",
                    planned,
                    options,
                )
            incomplete = Path(self.temp.name) / "byte-boundary-plus-one.jsonl"
            with (
                patch(
                    "exfat_rescue.manifest.DEFAULT_MAX_MANIFEST_BYTES",
                    complete_bytes - 1,
                ),
                self.assertRaises(ManifestError),
            ):
                write_manifest_v2(source, incomplete, planned, options)
            self.assertTrue(incomplete.exists())
            self.assertNotIn(b'"record_type":"complete"', incomplete.read_bytes())
        finally:
            source.close()

    def test_parser_rejects_duplicate_keys_inventory_and_completion_tampering(
        self,
    ) -> None:
        records = self._valid_records()
        duplicate_key = b'{"record_type":"manifest","record_type":"manifest"}\n'
        with self.assertRaises(ManifestError):
            parse_manifest_v2_bytes(duplicate_key)
        for label, mutate in (
            (
                "duplicate inventory",
                lambda values: values.__setitem__(2, copy.deepcopy(values[1])),
            ),
            (
                "candidate count",
                lambda values: values[0].__setitem__("candidate_count", 99),
            ),
        ):
            changed = copy.deepcopy(records)
            mutate(changed)
            with self.subTest(label=label), self.assertRaises(ManifestError):
                parse_manifest_v2_bytes(self._encoded(changed))
        content = self._encoded(copy.deepcopy(records)).replace(
            records[-1]["content_sha256"].encode(), b"0" * 64
        )
        with self.assertRaises(ManifestError):
            parse_manifest_v2_bytes(content)

    def test_parser_normalizes_decoder_limits_and_nonstandard_constants(self) -> None:
        too_many_digits = b'{"number":' + b"1" * 4_301 + b"}\n"
        with self.assertRaises(ManifestError):
            parse_manifest_v2_bytes(too_many_digits)
        for constant in (b"NaN", b"Infinity", b"-Infinity"):
            with (
                self.subTest(constant=constant),
                patch("exfat_rescue.manifest.json.loads", wraps=json.loads) as decoder,
                self.assertRaises(ManifestError),
            ):
                parse_manifest_v2_bytes(b'{"number":' + constant + b"}\n")
            self.assertIn("parse_constant", decoder.call_args.kwargs)

    def test_parser_rejects_mixed_type_deterministic_lists_as_manifest_errors(
        self,
    ) -> None:
        records = self._valid_records()
        for label, mutate in (
            (
                "header warnings",
                lambda values: values[0].__setitem__("warnings", ["warning", 1]),
            ),
            (
                "candidate reasons",
                lambda values: values[1].__setitem__("reasons", ["fat_cycle", 1]),
            ),
        ):
            changed = copy.deepcopy(records)
            mutate(changed)
            with self.subTest(label=label), self.assertRaises(ManifestError):
                parse_manifest_v2_bytes(self._encoded(changed))

    def test_parser_normalizes_excessive_json_nesting(self) -> None:
        depth = sys.getrecursionlimit() * 2
        nested = b"[" * depth + b"0" + b"]" * depth + b"\n"
        self.assertLess(len(nested), MAX_MANIFEST_LINE_BYTES)
        with self.assertRaises(ManifestError):
            parse_manifest_v2_bytes(nested)

    def test_parser_requires_exact_source_status_and_geometry_fields(self) -> None:
        records = self._valid_records()
        for label, key, value in (
            ("missing status", "volume_dirty", None),
            ("wrong status type", "media_failure", 1),
            (
                "invalid heap",
                "cluster_heap_offset_bytes",
                records[0]["source"]["volume_offset_bytes"] - 1,
            ),
        ):
            changed = copy.deepcopy(records)
            if value is None:
                del changed[0]["source"][key]
            else:
                changed[0]["source"][key] = value
            with self.subTest(label=label), self.assertRaises(ManifestError):
                parse_manifest_v2_bytes(self._encoded(changed))

    def test_validate_manifest_plans_rejects_source_and_plan_revalidation_mismatch(
        self,
    ) -> None:
        source, planned, options = self._planned()
        try:
            output = Path(self.temp.name) / "revalidate.jsonl"
            write_manifest_v2(source, output, planned, options)
            manifest = parse_manifest_v2_bytes(output.read_bytes())
            changed_source = replace(
                planned,
                source_binding={**planned.source_binding, "image_size_bytes": 1},
            )
            changed_plan = replace(planned, plans=planned.plans[1:])
            for result in (changed_source, changed_plan):
                with self.assertRaises(ManifestError):
                    validate_manifest_plans(manifest, result)
        finally:
            source.close()

    def test_source_range_chunk_and_short_read_errors(self) -> None:
        source = ImageSource.open(self.source_path)
        try:
            with self.assertRaises(SourceError):
                source.read_exact(source.size, 1)
            with self.assertRaises(SourceError):
                source.sha256_region(-1, 1)
            with self.assertRaises(ValueError):
                source.sha256_region(0, 1, chunk_size=0)
            with (
                patch.object(ImageSource, "read_at", return_value=b""),
                self.assertRaises(SourceError),
            ):
                source.read_exact(0, 1)
        finally:
            source.close()

    def test_source_fstat_and_fingerprint_mutation_errors(self) -> None:
        source = ImageSource.open(self.source_path)
        try:
            with (
                patch("exfat_rescue.source.os.fstat", side_effect=OSError(5, "bad fd")),
                self.assertRaises(SourceError),
            ):
                source.assert_unchanged()
            with (
                patch.object(
                    ImageSource, "fingerprint", return_value={"changed": True}
                ),
                self.assertRaises(SourceError),
            ):
                source.assert_unchanged({"expected": True})
        finally:
            source.close()

    def test_output_parent_preflight_and_identity_replacement_protections(self) -> None:
        source = ImageSource.open(self.source_path)
        try:
            missing = Path(self.temp.name) / "missing" / "manifest.jsonl"
            with self.assertRaises(OutputError):
                refuse_output_path(source, missing)
            target = Path(self.temp.name) / "preflight.jsonl"
            with (
                patch(
                    "exfat_rescue.source.tempfile.mkstemp",
                    side_effect=OSError(13, "denied"),
                ),
                self.assertRaises(OutputError),
            ):
                preflight_output_path(source, target)
            with (
                patch(
                    "exfat_rescue.source.os.stat",
                    return_value=SimpleNamespace(
                        st_dev=source.device, st_ino=source.inode
                    ),
                ),
                self.assertRaises(OutputError),
            ):
                refuse_output_path(source, target)
        finally:
            source.close()

    def test_writer_detects_mocked_path_identity_replacement(self) -> None:
        source, planned, options = self._planned()
        try:
            target = Path(self.temp.name) / "replacement.jsonl"
            with (
                patch("exfat_rescue.manifest._path_has_identity", return_value=False),
                self.assertRaises(OutputError),
            ):
                write_manifest_v2(source, target, planned, options)
            self.assertTrue(target.exists())
        finally:
            source.close()

    def test_v2_writer_rejects_mutation_during_final_source_check(self) -> None:
        source, planned, options = self._planned()
        try:
            target = Path(self.temp.name) / "mutated-during-source-check.jsonl"
            original_assert = ImageSource.assert_unchanged

            def mutate_output(
                instance: ImageSource, *args: object, **kwargs: object
            ) -> None:
                original_assert(instance, *args, **kwargs)
                if instance is source:
                    with target.open("r+b") as output:
                        output.seek(0)
                        output.write(b"X")
                        output.flush()
                        os.fsync(output.fileno())

            with (
                patch.object(ImageSource, "assert_unchanged", new=mutate_output),
                self.assertRaises(OutputError),
            ):
                write_manifest_v2(source, target, planned, options)
            self.assertTrue(target.exists())
            with self.assertRaises(ManifestError):
                parse_manifest_v2_bytes(target.read_bytes())
        finally:
            source.close()

    def test_v2_writer_rechecks_source_after_completion_write(self) -> None:
        source, planned, options = self._planned()
        try:
            target = Path(self.temp.name) / "source-mutated-after-completion.jsonl"
            original_line = manifest_module._line
            mutated = False

            def mutate_source(record: dict[str, object]) -> str:
                nonlocal mutated
                line = original_line(record)
                if record.get("record_type") == "complete" and not mutated:
                    mutated = True
                    with self.source_path.open("r+b") as image_file:
                        image_file.seek(-1, os.SEEK_END)
                        image_file.write(b"X")
                        image_file.flush()
                        os.fsync(image_file.fileno())
                return line

            with (
                patch("exfat_rescue.manifest._line", new=mutate_source),
                self.assertRaises(SourceError),
            ):
                write_manifest_v2(source, target, planned, options)
            self.assertTrue(target.exists())
        finally:
            source.close()

    def test_v2_writer_rejects_private_metadata_mutation_before_proof(self) -> None:
        source, planned, options = self._planned()
        try:
            target = Path(self.temp.name) / "metadata-mutated-before-proof.jsonl"
            original_prove = manifest_module._prove_written_manifest

            def mutate_then_prove(fd: int, **kwargs: object) -> None:
                os.chmod(target, 0o644)
                original_prove(fd, **kwargs)

            with (
                patch(
                    "exfat_rescue.manifest._prove_written_manifest",
                    new=mutate_then_prove,
                ),
                self.assertRaises(OutputError),
            ):
                write_manifest_v2(source, target, planned, options)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)
        finally:
            source.close()

    def test_v2_writer_rechecks_source_after_content_proof(self) -> None:
        source, planned, options = self._planned()
        try:
            target = Path(self.temp.name) / "source-mutated-during-proof.jsonl"
            original_prove = manifest_module._prove_written_manifest

            def prove_then_mutate(fd: int, **kwargs: object) -> os.stat_result:
                state = original_prove(fd, **kwargs)
                with self.source_path.open("r+b") as image_file:
                    image_file.seek(-1, os.SEEK_END)
                    image_file.write(b"X")
                    image_file.flush()
                    os.fsync(image_file.fileno())
                return state

            with (
                patch(
                    "exfat_rescue.manifest._prove_written_manifest",
                    new=prove_then_mutate,
                ),
                self.assertRaises(SourceError),
            ):
                write_manifest_v2(source, target, planned, options)
            self.assertTrue(target.exists())
        finally:
            source.close()

    def test_v2_writer_rechecks_source_after_final_manifest_state(self) -> None:
        source, planned, options = self._planned()
        try:
            target = Path(self.temp.name) / "source-mutated-during-state-proof.jsonl"
            original_assert = manifest_module._assert_final_manifest_state

            def assert_then_mutate(*args: object, **kwargs: object) -> None:
                original_assert(*args, **kwargs)
                with self.source_path.open("r+b") as image_file:
                    image_file.seek(-1, os.SEEK_END)
                    image_file.write(b"X")
                    image_file.flush()
                    os.fsync(image_file.fileno())

            with (
                patch(
                    "exfat_rescue.manifest._assert_final_manifest_state",
                    new=assert_then_mutate,
                ),
                self.assertRaises(SourceError),
            ):
                write_manifest_v2(source, target, planned, options)
            self.assertTrue(target.exists())
        finally:
            source.close()

    def test_writer_and_reader_require_raw_allocation_geometry(self) -> None:
        source, planned, options = self._planned()
        try:
            plan = planned.plans[0]
            raw = planned.source_candidates[0]
            contiguous_disjoint = replace(
                plan,
                extents=(plan.extents[0], replace(plan.extents[0], first_cluster=7)),
            )
            fat_chain = replace(plan, allocation_mode="fat_chain")
            partial_unrecoverable_fat_chain = replace(
                fat_chain,
                disposition="unrecoverable",
                recovery_basis=None,
                reasons=("fat_chain_cycle",),
            )
            empty = replace(
                plan,
                logical_size_bytes=0,
                valid_data_bytes=0,
                extents=(),
                allocation_mode="empty",
            )
            cases = (
                (
                    "contiguous-first-cluster",
                    plan,
                    {**raw, "first_cluster": raw["first_cluster"] + 1},
                ),
                (
                    "contiguous-disjoint-extents",
                    contiguous_disjoint,
                    raw,
                ),
                (
                    "fat-chain-first-cluster",
                    fat_chain,
                    {**raw, "no_fat_chain": False, "first_cluster": 6},
                ),
                (
                    "partial-fat-chain-first-cluster",
                    partial_unrecoverable_fat_chain,
                    {**raw, "no_fat_chain": False, "first_cluster": 6},
                ),
                (
                    "empty-raw-allocation",
                    empty,
                    {
                        **raw,
                        "size_bytes": 0,
                        "valid_size_bytes": 0,
                        "first_cluster": 5,
                        "no_fat_chain": True,
                    },
                ),
            )
            for label, changed_plan, changed_raw in cases:
                changed = replace(
                    planned,
                    plans=(changed_plan, *planned.plans[1:]),
                    source_candidates=(changed_raw, *planned.source_candidates[1:]),
                )
                with self.subTest(writer=label), self.assertRaises(ManifestError):
                    write_manifest_v2(
                        source,
                        Path(self.temp.name) / f"{label}.jsonl",
                        changed,
                        options,
                    )

                output = Path(self.temp.name) / f"reader-{label}.jsonl"
                write_manifest_v2(source, output, planned, options)
                records = [
                    json.loads(line) for line in output.read_bytes().splitlines()
                ]
                records[1] = {
                    **records[1],
                    "extents": [
                        {
                            "first_cluster": extent.first_cluster,
                            "cluster_count": extent.cluster_count,
                        }
                        for extent in changed_plan.extents
                    ],
                    "allocation_mode": changed_plan.allocation_mode,
                    "logical_size_bytes": changed_plan.logical_size_bytes,
                    "valid_data_bytes": changed_plan.valid_data_bytes,
                    "source_candidate": changed_raw,
                }
                with self.subTest(reader=label), self.assertRaises(ManifestError):
                    parse_manifest_v2_bytes(self._encoded(records))

            # A global safety failure can make a contiguous candidate
            # unrecoverable before the planner materializes its one extent.
            incomplete = replace(
                plan,
                extents=(),
                disposition="unrecoverable",
                recovery_basis=None,
                reasons=("incomplete_active_metadata",),
            )
            valid_unrecoverable = replace(
                planned,
                plans=(incomplete, *planned.plans[1:]),
            )
            output = Path(self.temp.name) / "valid-unrecoverable-contiguous.jsonl"
            write_manifest_v2(source, output, valid_unrecoverable, options)
            parsed = parse_manifest_v2_bytes(output.read_bytes())
            self.assertEqual(parsed.plans[0], incomplete)
        finally:
            source.close()

    def test_parser_rejects_boolean_completion_counts(self) -> None:
        records = self._valid_records()
        header = {**records[0], "candidate_count": 0}
        content = (
            json.dumps(header, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        )
        for key, value in (("candidate_count", False), ("content_record_count", True)):
            completion = {
                "record_type": "complete",
                "candidate_count": 0,
                "content_record_count": 1,
                "content_sha256": hashlib.sha256(content).hexdigest(),
            }
            completion[key] = value
            encoded = (
                content
                + json.dumps(completion, sort_keys=True, separators=(",", ":")).encode()
                + b"\n"
            )
            with self.subTest(zero_candidate=key), self.assertRaises(ManifestError):
                parse_manifest_v2_bytes(encoded)

        one = [records[0], records[1], records[-1]]
        one[0] = {**one[0], "candidate_count": 1}
        content = b"".join(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            for record in one[:-1]
        )
        completion = {
            "record_type": "complete",
            "candidate_count": True,
            "content_record_count": 2,
            "content_sha256": hashlib.sha256(content).hexdigest(),
        }
        with self.assertRaises(ManifestError):
            parse_manifest_v2_bytes(
                content
                + json.dumps(completion, sort_keys=True, separators=(",", ":")).encode()
                + b"\n"
            )


if __name__ == "__main__":
    unittest.main()
