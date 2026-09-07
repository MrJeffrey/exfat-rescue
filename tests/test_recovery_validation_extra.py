from __future__ import annotations

import errno
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from exfat_rescue import recovery, verification
from exfat_rescue.errors import ManifestError, OutputError, ResourceLimitError


class RecoveryValidationExtraTests(unittest.TestCase):
    @staticmethod
    def _plan(**changes: object) -> dict[str, object]:
        value: dict[str, object] = {
            "candidate_id": "a" * 64,
            "entry_offset": 1,
            "entry_set_sha256": "b" * 64,
            "name": "candidate",
            "logical_size_bytes": 0,
            "valid_data_bytes": 0,
            "extents": [],
            "allocation_mode": "empty",
            "metadata_location": "active_directory",
            "disposition": "recoverable",
            "recovery_basis": "active_empty",
            "reasons": [],
        }
        value.update(changes)
        return value

    def test_strict_json_and_plan_schema_validation(self) -> None:
        self.assertEqual(recovery._json_object(b'{"a":1}', "state"), {"a": 1})
        for payload in (b'{"a":1,"a":2}', b"[]", b"not-json"):
            with self.subTest(payload=payload), self.assertRaises(ManifestError):
                recovery._json_object(payload, "state")

        invalid_plans = [
            object(),
            {"candidate_id": "a" * 64},
            self._plan(candidate_id="short"),
            self._plan(logical_size_bytes=True),
            self._plan(disposition="unknown"),
            self._plan(name=1),
            self._plan(recovery_basis=None),
            self._plan(
                disposition="conflicted",
                recovery_basis="active_empty",
                reasons=["conflict"],
            ),
            self._plan(extents=[{"first_cluster": 1, "cluster_count": 1}]),
            self._plan(extents=[{"first_cluster": 2, "cluster_count": 1}] * 4097),
        ]
        for index, plan in enumerate(invalid_plans):
            with (
                self.subTest(index=index),
                self.assertRaises((ManifestError, ResourceLimitError)),
            ):
                recovery._validate_plan(plan)

        terminal = self._plan(
            disposition="conflicted",
            recovery_basis=None,
            reasons=("active_owner_conflict",),
        )
        self.assertEqual(
            recovery._validate_plan(terminal)["reasons"], ["active_owner_conflict"]
        )

    def test_state_parsers_normalize_excessive_json_nesting(self) -> None:
        depth = max(300_000, sys.getrecursionlimit() * 2)
        nested = b'{"value":' + b"[" * depth + b"0" + b"]" * depth + b"}"
        self.assertLess(len(nested), 1024 * 1024)
        for parser in (recovery._json_object, verification._json):
            with (
                self.subTest(parser=parser.__module__),
                self.assertRaises(ManifestError),
            ):
                parser(nested, "state")

    def test_plan_geometry_requires_exact_in_volume_cluster_coverage(self) -> None:
        binding = {
            "cluster_size_bytes": 512,
            "cluster_heap_offset_bytes": 1024,
            "volume_offset_bytes": 0,
            "volume_length_bytes": 4096,
        }
        plan = recovery._validate_plan(
            self._plan(
                logical_size_bytes=512,
                valid_data_bytes=512,
                allocation_mode="contiguous",
                recovery_basis="active_contiguous_allocated",
                extents=[{"first_cluster": 2, "cluster_count": 1}],
            )
        )
        recovery._validate_plan_geometry(plan, binding)
        for changed_plan, changed_binding in (
            (plan, {**binding, "cluster_size_bytes": True}),
            ({**plan, "logical_size_bytes": 1024}, binding),
            (
                {**plan, "extents": [{"first_cluster": 20, "cluster_count": 1}]},
                binding,
            ),
        ):
            with self.assertRaises(ManifestError):
                recovery._validate_plan_geometry(changed_plan, changed_binding)

    def test_descriptor_relative_state_helpers_refuse_existing_or_unsafe_objects(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                recovery._write_new_at(root_fd, "state.json", b"{}\n")
                with self.assertRaises(OutputError):
                    recovery._write_new_at(root_fd, "state.json", b"{}\n")
                with self.assertRaises(OutputError):
                    recovery._mkdir_at(root_fd, "state.json")

                large = root / "large"
                large.write_bytes(b"xx")
                os.chmod(large, 0o600)
                with self.assertRaises(ManifestError):
                    recovery._read_regular_at(root_fd, "large", max_bytes=1)
                with mock.patch.object(
                    recovery.os, "pread", wraps=os.pread
                ) as bounded_read:
                    self.assertEqual(
                        recovery._read_regular_at(root_fd, "large", max_bytes=2),
                        b"xx",
                    )
                bounded_read.assert_called_once_with(mock.ANY, 2, 0)
                with (
                    mock.patch.object(recovery.os, "pread", return_value=b"x"),
                    self.assertRaises(OutputError),
                ):
                    recovery._read_regular_at(root_fd, "large", max_bytes=2)

                public = root / "public"
                public.mkdir(mode=0o755)
                with self.assertRaises(OutputError):
                    recovery._open_dir_at(root_fd, "public")
                with self.assertRaises(FileNotFoundError):
                    recovery._open_dir_at(root_fd, "missing")
            finally:
                os.close(root_fd)

    def test_io_errors_are_stable_and_full_destination_is_distinct(self) -> None:
        with self.assertRaises(ResourceLimitError):
            recovery._raise_output_io("write failed", OSError(errno.ENOSPC, "full"))
        with self.assertRaises(OutputError):
            recovery._raise_output_io("write failed", OSError(errno.EIO, "io"))
        with (
            mock.patch.object(os, "fsync", side_effect=OSError(errno.EIO, "io")),
            self.assertRaises(OutputError),
        ):
            recovery._fsync(1, "state")

    def test_private_object_checks_reject_permissions_and_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private = root / "private"
            private.write_text(json.dumps({"ok": True}), encoding="utf-8")
            os.chmod(private, 0o644)
            with self.assertRaises(OutputError):
                recovery._private_file_state(private.stat(), "State")
            os.chmod(root, 0o755)
            with self.assertRaises(OutputError):
                recovery._private_dir_state(root.stat(), "Directory")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
