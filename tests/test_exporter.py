from __future__ import annotations

import errno
import hashlib
import io
import json
import os
import struct
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from exfat_rescue import exporter
from exfat_rescue.cli import main
from exfat_rescue.errors import OutputError, VerificationError
from exfat_rescue.exporter import (
    _detected_content,
    _extension_consistent,
    _safe_export_name,
)
from exfat_rescue.recovery import _canonical
from tests.fixture import entry, image


class ExporterTests(unittest.TestCase):
    def test_export_content_proofs_reject_bounded_read_failures(self) -> None:
        """Direct proofs reject short, long, invalid-tail, and hash-mismatched data."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for payload, logical_size, valid_size, message in (
                    (b"a", 2, 2, "ended before"),
                    (b"abc", 2, 2, "exceeds"),
                    (b"ax", 2, 1, "nonzero ValidDataLength tail"),
                    (b"ab", 2, 2, "differs from its recovery record"),
                ):
                    with self.subTest(message=message):
                        path = root / "data"
                        path.write_bytes(payload)
                        path.chmod(0o600)
                        fd = os.open(path, os.O_RDWR)
                        try:
                            with self.assertRaisesRegex(OutputError, message):
                                exporter._prove_exported_contents(
                                    fd,
                                    directory_fd=directory_fd,
                                    name="data",
                                    logical_size_bytes=logical_size,
                                    valid_data_bytes=valid_size,
                                    output_sha256=hashlib.sha256(
                                        payload[:logical_size]
                                    ).hexdigest(),
                                    source_data_sha256=(
                                        hashlib.sha256(payload[:valid_size]).hexdigest()
                                        if message != "differs from its recovery record"
                                        else "0" * 64
                                    ),
                                )
                        finally:
                            os.close(fd)
                            path.unlink()
            finally:
                os.close(directory_fd)

    def test_catalog_proof_rejects_bounded_read_failures_and_replacement(self) -> None:
        """Catalog proof shares the same exact-size and pathname requirements."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for payload, expected_size, expected_digest, message in (
                    (b"a", 2, hashlib.sha256(b"aa").hexdigest(), "ended before"),
                    (b"abc", 2, hashlib.sha256(b"ab").hexdigest(), "exceeds"),
                    (b"ab", 2, "0" * 64, "differs from its intended content"),
                ):
                    with self.subTest(message=message):
                        path = root / "catalog"
                        path.write_bytes(payload)
                        path.chmod(0o600)
                        fd = os.open(path, os.O_RDWR)
                        try:
                            with self.assertRaisesRegex(OutputError, message):
                                exporter._prove_catalog_contents(
                                    fd,
                                    directory_fd=directory_fd,
                                    name="catalog",
                                    expected_size=expected_size,
                                    expected_sha256=expected_digest,
                                )
                        finally:
                            os.close(fd)
                            path.unlink()

                path = root / "catalog"
                path.write_bytes(b"ok")
                path.chmod(0o600)
                fd = os.open(path, os.O_RDWR)
                try:
                    path.rename(root / "old-catalog")
                    path.write_bytes(b"ok")
                    path.chmod(0o600)
                    with self.assertRaisesRegex(OutputError, "replaced during"):
                        exporter._prove_catalog_contents(
                            fd,
                            directory_fd=directory_fd,
                            name="catalog",
                            expected_size=2,
                            expected_sha256=hashlib.sha256(b"ok").hexdigest(),
                        )
                finally:
                    os.close(fd)
            finally:
                os.close(directory_fd)

    def test_export_proof_rejects_data_name_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "data"
            path.write_bytes(b"ok")
            path.chmod(0o600)
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            fd = os.open(path, os.O_RDWR)
            try:
                path.rename(root / "old-data")
                path.write_bytes(b"ok")
                path.chmod(0o600)
                with self.assertRaisesRegex(OutputError, "replaced during"):
                    exporter._prove_exported_contents(
                        fd,
                        directory_fd=directory_fd,
                        name="data",
                        logical_size_bytes=2,
                        valid_data_bytes=2,
                        output_sha256=hashlib.sha256(b"ok").hexdigest(),
                        source_data_sha256=hashlib.sha256(b"ok").hexdigest(),
                    )
            finally:
                os.close(fd)
                os.close(directory_fd)

    def test_content_proofs_wrap_descriptor_io_errors(self) -> None:
        """Proof helpers turn every descriptor boundary failure into OutputError."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "state"
            path.write_bytes(b"ok")
            path.chmod(0o600)
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            fd = os.open(path, os.O_RDWR)
            error = OSError(errno.EIO, "injected")
            exported_kwargs = {
                "directory_fd": directory_fd,
                "name": "state",
                "logical_size_bytes": 2,
                "valid_data_bytes": 2,
                "output_sha256": hashlib.sha256(b"ok").hexdigest(),
                "source_data_sha256": hashlib.sha256(b"ok").hexdigest(),
            }
            catalog_kwargs = {
                "directory_fd": directory_fd,
                "name": "state",
                "expected_size": 2,
                "expected_sha256": hashlib.sha256(b"ok").hexdigest(),
            }
            try:
                for proof, kwargs, operation, message in (
                    (
                        exporter._prove_exported_contents,
                        exported_kwargs,
                        "fstat",
                        "inspect exported data",
                    ),
                    (
                        exporter._prove_exported_contents,
                        exported_kwargs,
                        "lseek",
                        "seek exported data",
                    ),
                    (
                        exporter._prove_exported_contents,
                        exported_kwargs,
                        "read",
                        "read exported data",
                    ),
                    (
                        exporter._prove_exported_contents,
                        exported_kwargs,
                        "stat",
                        "revalidate exported data",
                    ),
                    (
                        exporter._prove_catalog_contents,
                        catalog_kwargs,
                        "fstat",
                        "inspect export catalog",
                    ),
                    (
                        exporter._prove_catalog_contents,
                        catalog_kwargs,
                        "lseek",
                        "seek export catalog",
                    ),
                    (
                        exporter._prove_catalog_contents,
                        catalog_kwargs,
                        "read",
                        "read export catalog",
                    ),
                    (
                        exporter._prove_catalog_contents,
                        catalog_kwargs,
                        "stat",
                        "revalidate export catalog",
                    ),
                ):
                    with (
                        self.subTest(operation=operation, message=message),
                        mock.patch.object(exporter.os, operation, side_effect=error),
                        self.assertRaisesRegex(OutputError, message),
                    ):
                        proof(fd, **kwargs)
            finally:
                os.close(fd)
                os.close(directory_fd)

    def test_final_export_state_rejects_changed_inventory(self) -> None:
        with (
            mock.patch.object(exporter, "_assert_root_path"),
            mock.patch.object(
                exporter,
                "_listdir_at",
                side_effect=(("catalog.jsonl", "files"), ("unexpected",)),
            ),
            self.assertRaisesRegex(OutputError, "inventory changed"),
        ):
            exporter._assert_final_export_state(
                parent_fd=-1,
                staging_name="staging",
                destination_fd=-1,
                files_fd=-1,
                exported_names=set(),
                exported_file_proofs={},
                exported_sizes={},
                catalog_size=0,
                catalog_proof=(),
            )

    def test_export_parent_helpers_reject_path_identity_and_ancestry_changes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            recovery = root / "recovery"
            recovery.mkdir(mode=0o700)
            root_fd = os.open(recovery, os.O_RDONLY | os.O_DIRECTORY)
            parent = root / "export-parent"
            parent.mkdir(mode=0o700)
            parent_fd, ancestor_fd, parent_name = (
                exporter._open_export_parent_with_ancestor(parent)
            )
            self.assertIsNotNone(ancestor_fd)
            try:
                parent.rename(root / "old-parent")
                parent.mkdir(mode=0o700)
                with self.assertRaisesRegex(OutputError, "replaced"):
                    exporter._assert_export_parent_boundary(
                        parent_fd=parent_fd,
                        ancestor_fd=ancestor_fd,
                        parent_name=parent_name,
                        requested_parent=parent,
                        root_fd=root_fd,
                    )
            finally:
                os.close(parent_fd)
                os.close(ancestor_fd)

            inside = recovery / "inside"
            inside.mkdir(mode=0o700)
            inside_fd, inside_ancestor_fd, inside_name = (
                exporter._open_export_parent_with_ancestor(inside)
            )
            try:
                with self.assertRaisesRegex(OutputError, "moved inside"):
                    exporter._assert_export_parent_boundary(
                        parent_fd=inside_fd,
                        ancestor_fd=inside_ancestor_fd,
                        parent_name=inside_name,
                        requested_parent=inside,
                        root_fd=root_fd,
                    )
            finally:
                os.close(inside_fd)
                os.close(inside_ancestor_fd)
                os.close(root_fd)

    def test_export_parent_helpers_reject_non_directory_and_cover_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            not_directory = root / "not-directory"
            not_directory.write_text("x", encoding="utf-8")
            with self.assertRaisesRegex(OutputError, "not a directory"):
                exporter._open_export_parent_with_ancestor(not_directory)
            root_fd, ancestor_fd, name = exporter._open_export_parent_with_ancestor(
                Path("/")
            )
            try:
                self.assertIsNone(ancestor_fd)
                self.assertEqual(name, "")
            finally:
                os.close(root_fd)

    def test_export_parent_boundary_covers_root_and_invalid_descriptor_type(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            recovery = root / "recovery"
            recovery.mkdir(mode=0o700)
            recovery_fd = os.open(recovery, os.O_RDONLY | os.O_DIRECTORY)
            root_fd = os.open(Path("/"), os.O_RDONLY | os.O_DIRECTORY)
            file_fd = os.open(root / "file", os.O_RDWR | os.O_CREAT, 0o600)
            try:
                exporter._assert_export_parent_boundary(
                    parent_fd=root_fd,
                    ancestor_fd=None,
                    parent_name="",
                    requested_parent=Path("/"),
                    root_fd=recovery_fd,
                )
                with self.assertRaisesRegex(OutputError, "no longer a directory"):
                    exporter._assert_export_parent_boundary(
                        parent_fd=file_fd,
                        ancestor_fd=None,
                        parent_name="",
                        requested_parent=root,
                        root_fd=recovery_fd,
                    )
            finally:
                os.close(file_fd)
                os.close(root_fd)
                os.close(recovery_fd)

    def test_export_parent_open_wraps_open_and_identity_races(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            with (
                mock.patch.object(
                    exporter.os,
                    "open",
                    side_effect=OSError(errno.EIO, "injected"),
                ),
                self.assertRaisesRegex(
                    OutputError, "Could not safely open export parent"
                ),
            ):
                exporter._open_export_parent_with_ancestor(Path("/"))

            original_fstat = exporter.os.fstat
            actual = parent.stat()
            mismatched = mock.Mock(
                st_mode=actual.st_mode,
                st_dev=actual.st_dev,
                st_ino=actual.st_ino + 1,
            )
            with (
                mock.patch.object(exporter.os, "fstat", return_value=mismatched),
                self.assertRaisesRegex(OutputError, "replaced while opening"),
            ):
                exporter._open_export_parent_with_ancestor(parent)
            check_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.assertEqual(original_fstat(check_fd).st_ino, actual.st_ino)
            finally:
                os.close(check_fd)

    def test_export_proof_rejects_data_appended_after_expected_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "data"
            payload = b"expected"
            path.write_bytes(payload)
            path.chmod(0o600)
            directory_fd = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            fd = os.open(path, os.O_RDONLY)
            original_read = os.read
            requests: list[int] = []
            appended = False

            def append_after_expected(target: int, count: int) -> bytes:
                nonlocal appended
                requests.append(count)
                result = original_read(target, count)
                if result and not appended:
                    appended = True
                    with path.open("ab") as handle:
                        handle.write(b"x")
                return result

            try:
                with (
                    mock.patch("exfat_rescue.exporter.os.read", append_after_expected),
                    self.assertRaises(OutputError),
                ):
                    exporter._prove_exported_contents(
                        fd,
                        directory_fd=directory_fd,
                        name="data",
                        logical_size_bytes=len(payload),
                        valid_data_bytes=len(payload),
                        output_sha256=hashlib.sha256(payload).hexdigest(),
                        source_data_sha256=hashlib.sha256(payload).hexdigest(),
                    )
            finally:
                os.close(fd)
                os.close(directory_fd)
            self.assertEqual(requests, [len(payload), 1])

    def _call(self, *arguments: str) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(list(arguments))
        return code, stdout.getvalue(), stderr.getvalue()

    def _recovery(self, root: Path) -> tuple[Path, Path]:
        source = root / "source.img"
        output = root / "recovery"
        source.write_bytes(image())
        code, stdout, stderr = self._call(
            "recover", str(source), "--output", str(output), "--json"
        )
        self.assertEqual((code, stderr), (0, ""))
        self.assertTrue(json.loads(stdout)["complete"])
        return source, output

    def test_export_verifies_copies_and_publishes_hashed_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _source, output = self._recovery(root)
            destination = root / "export"

            with mock.patch.object(
                exporter,
                "_release_file_cache",
                wraps=exporter._release_file_cache,
            ) as cache_release:
                code, stdout, stderr = self._call(
                    "export",
                    str(output),
                    "--destination",
                    str(destination),
                    "--json",
                )

            self.assertEqual((code, stderr), (0, ""))
            result = json.loads(stdout)
            self.assertTrue(result["ok"])
            self.assertGreater(result["file_count"], 0)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
            self.assertEqual(
                (destination / "catalog.jsonl").stat().st_mode & 0o777, 0o600
            )
            self.assertFalse((destination / ".catalog.jsonl.partial").exists())

            raw_lines = (
                (destination / "catalog.jsonl").read_bytes().splitlines(keepends=True)
            )
            records = [json.loads(line) for line in raw_lines]
            self.assertEqual(records[0]["format"], "exfat-rescue.export-catalog")
            self.assertEqual(records[-1]["record_type"], "complete")
            self.assertEqual(records[-1]["file_count"], result["file_count"])
            self.assertEqual(
                records[-1]["content_sha256"],
                hashlib.sha256(b"".join(raw_lines[:-1])).hexdigest(),
            )
            files = [record for record in records if record["record_type"] == "file"]
            self.assertEqual(len(files), result["file_count"])
            self.assertEqual(cache_release.call_count, result["file_count"] * 2)
            for record in files:
                exported = destination / record["exported_path"]
                self.assertTrue(exported.is_file())
                self.assertEqual(exported.stat().st_mode & 0o777, 0o600)
                self.assertEqual(
                    hashlib.sha256(exported.read_bytes()).hexdigest(),
                    record["output_sha256"],
                )
                self.assertIn(record["candidate_id"], exported.name)

    def test_export_refuses_existing_nested_and_tampered_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _source, output = self._recovery(root)
            existing = root / "existing"
            existing.mkdir()
            marker = existing / "keep"
            marker.write_text("keep", encoding="utf-8")

            with mock.patch.object(
                exporter,
                "_run_descriptor",
                side_effect=AssertionError("source validation should not start"),
            ):
                code, _stdout, stderr = self._call(
                    "export",
                    str(output),
                    "--destination",
                    str(existing),
                    "--json",
                )
            self.assertEqual(code, 5)
            self.assertEqual(json.loads(stderr)["error_code"], "unsafe_output")
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")

            nested = output / "nested-export"
            with mock.patch.object(
                exporter,
                "_run_descriptor",
                side_effect=AssertionError("source validation should not start"),
            ):
                code, _stdout, stderr = self._call(
                    "export",
                    str(output),
                    "--destination",
                    str(nested),
                    "--json",
                )
            self.assertEqual(code, 5)
            self.assertFalse(nested.exists())

            unsafe_event_log = output / "events.jsonl"
            code, _stdout, stderr = self._call(
                "export",
                str(output),
                "--destination",
                str(root / "event-refused"),
                "--event-log",
                str(unsafe_event_log),
                "--json",
            )
            self.assertEqual(code, 5)
            self.assertFalse(unsafe_event_log.exists())

            report = next(
                json.loads(line)
                for line in (output / "report.jsonl").read_bytes().splitlines()
                if json.loads(line).get("disposition") == "recovered"
            )
            data = output / report["output_path"]
            data.chmod(0o600)
            with data.open("r+b") as handle:
                handle.write(b"tampered")
            refused = root / "refused"
            code, stdout, stderr = self._call(
                "export",
                str(output),
                "--destination",
                str(refused),
                "--json",
            )
            self.assertEqual((code, stderr), (8, ""))
            self.assertEqual(json.loads(stdout)["error_code"], "verification_failed")
            staging = refused.with_name(exporter._export_staging_name(refused.name))
            self.assertFalse(refused.exists())
            self.assertTrue(staging.is_dir())
            self.assertFalse((staging / "catalog.jsonl").exists())
            self.assertTrue((staging / ".catalog.jsonl.partial").is_file())

    def test_export_refuses_destination_file_mutated_before_success(self) -> None:
        """A catalog must never be reported successful after a copy-time race."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _source, output = self._recovery(root)
            destination = root / "export"
            staging = destination.with_name(
                exporter._export_staging_name(destination.name)
            )
            original_fsync = exporter._fsync
            mutated = False

            def mutate_after_catalog_publish(fd: int, label: str) -> None:
                nonlocal mutated
                original_fsync(fd, label)
                if label == "export staging directory" and not mutated:
                    mutated = True
                    exported = next((staging / "files").iterdir())
                    with exported.open("r+b") as handle:
                        first = handle.read(1)
                        handle.seek(0)
                        handle.write(bytes([first[0] ^ 1]))

            with (
                mock.patch.object(
                    exporter, "_fsync", side_effect=mutate_after_catalog_publish
                ),
                self.assertRaisesRegex(OutputError, "changed after its content proof"),
            ):
                exporter.export_recovery(output, destination)
            self.assertTrue(mutated)
            self.assertFalse(destination.exists())

    def test_export_refuses_destination_bytes_mutated_during_copy(self) -> None:
        """The destination readback must catch writes made during _write_all."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _source, output = self._recovery(root)
            destination = root / "export"
            staging = destination.with_name(
                exporter._export_staging_name(destination.name)
            )
            original = exporter._write_all
            mutated = False

            def mutate_first_export_write(fd: int, data: bytes, label: str) -> None:
                nonlocal mutated
                original(fd, data, label)
                if label == "exported data" and not mutated:
                    mutated = True
                    os.pwrite(fd, bytes([data[0] ^ 1]), 0)

            with (
                mock.patch.object(
                    exporter, "_write_all", side_effect=mutate_first_export_write
                ),
                self.assertRaisesRegex(OutputError, "differs from its recovery record"),
            ):
                exporter.export_recovery(output, destination)

            self.assertTrue(mutated)
            self.assertFalse(destination.exists())
            self.assertTrue(staging.is_dir())

    def test_export_refuses_data_mutated_immediately_after_content_proof(self) -> None:
        """The content-proof state, not a later baseline, anchors final checks."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _source, output = self._recovery(root)
            destination = root / "export"
            staging = destination.with_name(
                exporter._export_staging_name(destination.name)
            )
            original = exporter._prove_exported_contents
            mutated = False

            def mutate_after_proof(*args, **kwargs):
                nonlocal mutated
                proof = original(*args, **kwargs)
                if not mutated:
                    exported = next((staging / "files").iterdir())
                    with exported.open("r+b") as handle:
                        first = handle.read(1)
                        handle.seek(0)
                        handle.write(bytes([first[0] ^ 1]))
                        handle.flush()
                        os.fsync(handle.fileno())
                    mutated = True
                return proof

            with (
                mock.patch.object(
                    exporter, "_prove_exported_contents", side_effect=mutate_after_proof
                ),
                self.assertRaisesRegex(OutputError, "changed after its content proof"),
            ):
                exporter.export_recovery(output, destination)

            self.assertTrue(mutated)
            self.assertFalse(destination.exists())
            self.assertTrue(staging.is_dir())

    def test_export_refuses_catalog_bytes_mutated_during_write(self) -> None:
        """The held catalog descriptor must prove catalog bytes before publication."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _source, output = self._recovery(root)
            destination = root / "export"
            staging = destination.with_name(
                exporter._export_staging_name(destination.name)
            )
            original = exporter._write_all
            mutated = False

            def mutate_first_catalog_write(fd: int, data: bytes, label: str) -> None:
                nonlocal mutated
                original(fd, data, label)
                if label == "export catalog" and not mutated:
                    mutated = True
                    os.pwrite(fd, bytes([data[0] ^ 1]), 0)

            with (
                mock.patch.object(
                    exporter, "_write_all", side_effect=mutate_first_catalog_write
                ),
                self.assertRaisesRegex(OutputError, "catalog changed"),
            ):
                exporter.export_recovery(output, destination)

            self.assertTrue(mutated)
            self.assertFalse(destination.exists())
            self.assertTrue(staging.is_dir())

    def test_export_refuses_catalog_mutated_immediately_after_content_proof(
        self,
    ) -> None:
        """Catalog publication must use the proof-bound state without recapturing it."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _source, output = self._recovery(root)
            destination = root / "export"
            staging = destination.with_name(
                exporter._export_staging_name(destination.name)
            )
            original = exporter._prove_catalog_contents
            mutated = False

            def mutate_after_proof(*args, **kwargs):
                nonlocal mutated
                state, proof = original(*args, **kwargs)
                if not mutated:
                    catalog = staging / "catalog.jsonl"
                    with catalog.open("r+b") as handle:
                        first = handle.read(1)
                        handle.seek(0)
                        handle.write(bytes([first[0] ^ 1]))
                        handle.flush()
                        os.fsync(handle.fileno())
                    mutated = True
                return state, proof

            with (
                mock.patch.object(
                    exporter, "_prove_catalog_contents", side_effect=mutate_after_proof
                ),
                self.assertRaisesRegex(OutputError, "changed after its content proof"),
            ):
                exporter.export_recovery(output, destination)

            self.assertTrue(mutated)
            self.assertFalse(destination.exists())
            self.assertTrue(staging.is_dir())

    def test_export_refuses_catalog_mutated_during_final_data_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _source, output = self._recovery(root)
            destination = root / "export"
            staging = destination.with_name(
                exporter._export_staging_name(destination.name)
            )
            original = exporter._check_file_proof_at
            mutated = False

            def mutate_catalog_after_data_proof(fd: int, name: str, **kwargs):
                nonlocal mutated
                result = original(fd, name, **kwargs)
                catalog = staging / "catalog.jsonl"
                if name != "catalog.jsonl" and catalog.exists() and not mutated:
                    mutated = True
                    with catalog.open("r+b") as handle:
                        first = handle.read(1)
                        handle.seek(0)
                        handle.write(bytes([first[0] ^ 1]))
                return result

            with (
                mock.patch.object(
                    exporter,
                    "_check_file_proof_at",
                    side_effect=mutate_catalog_after_data_proof,
                ),
                self.assertRaisesRegex(OutputError, "changed after its content proof"),
            ):
                exporter.export_recovery(output, destination)

            self.assertTrue(mutated)
            self.assertFalse(destination.exists())
            self.assertTrue(staging.is_dir())

    def test_export_refuses_checkpoint_mutated_during_later_run_proof(self) -> None:
        """Export must receive the common closed metadata/namespace boundary."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _source, output = self._recovery(root)
            destination = root / "export"
            import exfat_rescue.recovery as recovery_module

            original = recovery_module._named_state_proof
            mutated = False

            def mutate_after_run_proof(fd: int, name: str, label: str):
                nonlocal mutated
                proof = original(fd, name, label)
                if label == "Recovery run descriptor" and not mutated:
                    checkpoint = next((output / "records").iterdir())
                    with checkpoint.open("r+b") as handle:
                        handle.seek(0)
                        handle.write(b"{}\n")
                        handle.truncate()
                        handle.flush()
                        os.fsync(handle.fileno())
                    mutated = True
                return proof

            with (
                mock.patch.object(
                    recovery_module,
                    "_named_state_proof",
                    side_effect=mutate_after_run_proof,
                ),
                self.assertRaisesRegex(
                    VerificationError, "Recovery state changed during export"
                ),
            ):
                exporter.export_recovery(output, destination)

            self.assertTrue(mutated)
            self.assertFalse(destination.exists())

    def test_export_refuses_work_artifact_inserted_during_later_run_proof(self) -> None:
        """The common export boundary must resnapshot recovery namespaces."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _source, output = self._recovery(root)
            destination = root / "export"
            import exfat_rescue.recovery as recovery_module

            original = recovery_module._named_state_proof
            mutated = False

            def insert_after_run_proof(fd: int, name: str, label: str):
                nonlocal mutated
                proof = original(fd, name, label)
                if label == "Recovery run descriptor" and not mutated:
                    (output / "work" / "late").write_bytes(b"unexpected")
                    mutated = True
                return proof

            with (
                mock.patch.object(
                    recovery_module,
                    "_named_state_proof",
                    side_effect=insert_after_run_proof,
                ),
                self.assertRaisesRegex(
                    VerificationError, "Recovery state changed during export"
                ),
            ):
                exporter.export_recovery(output, destination)

            self.assertTrue(mutated)
            self.assertFalse(destination.exists())

    def test_export_refuses_object_added_after_initial_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _source, output = self._recovery(root)
            destination = root / "export"
            staging = destination.with_name(
                exporter._export_staging_name(destination.name)
            )
            original = exporter._fsync
            mutated = False

            def add_late_object(fd: int, label: str) -> None:
                nonlocal mutated
                original(fd, label)
                if label == "export parent directory" and not mutated:
                    mutated = True
                    (staging / "files" / "unexpected").write_bytes(b"late")

            with (
                mock.patch.object(exporter, "_fsync", side_effect=add_late_object),
                self.assertRaisesRegex(OutputError, "entry limit|inventory changed"),
            ):
                exporter.export_recovery(output, destination)

            self.assertTrue(mutated)
            self.assertFalse(destination.exists())
            self.assertTrue(staging.is_dir())

    def test_export_refuses_late_files_directory_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _source, output = self._recovery(root)
            destination = root / "export"
            staging = destination.with_name(
                exporter._export_staging_name(destination.name)
            )
            detached = root / "detached-files"
            original = exporter._fsync
            mutated = False

            def replace_files_directory(fd: int, label: str) -> None:
                nonlocal mutated
                original(fd, label)
                if label == "export parent directory" and not mutated:
                    mutated = True
                    (staging / "files").rename(detached)
                    (staging / "files").mkdir(mode=0o700)
                    (staging / "files" / "foreign").write_bytes(b"late")

            with (
                mock.patch.object(
                    exporter, "_fsync", side_effect=replace_files_directory
                ),
                self.assertRaisesRegex(OutputError, "replaced|identity changed"),
            ):
                exporter.export_recovery(output, destination)

            self.assertTrue(mutated)
            self.assertFalse(destination.exists())
            self.assertTrue(staging.is_dir())
            self.assertTrue(detached.is_dir())

    def test_export_preserves_recovered_content_semantics_in_copy_pass(self) -> None:
        """One-pass export must still prove the recorded source-data prefix."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _source, output = self._recovery(root)
            report_path = output / "report.jsonl"
            records = [
                json.loads(line) for line in report_path.read_bytes().splitlines()
            ]
            recovered = next(
                record for record in records if record.get("disposition") == "recovered"
            )
            recovered["source_data_sha256"] = "0" * 64
            checkpoint = output / "records" / f"{recovered['candidate_id']}.json"
            checkpoint.write_bytes(_canonical(recovered) + b"\n")
            content = b"".join(_canonical(record) + b"\n" for record in records[:-1])
            records[-1]["content_sha256"] = hashlib.sha256(content).hexdigest()
            report_path.write_bytes(content + _canonical(records[-1]) + b"\n")

            destination = root / "export"
            with self.assertRaisesRegex(
                VerificationError, "Recovered data changed during export"
            ):
                exporter.export_recovery(output, destination)
            self.assertFalse((destination / "catalog.jsonl").exists())

    def test_export_refuses_a_nonzero_valid_data_tail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.img"
            raw = bytearray(image())
            heap = struct.unpack_from("<I", raw, 0x58)[0] * 512
            active = entry("Active.txt", first_cluster=3, size=10, valid_size=5)
            raw[heap + 64 : heap + 64 + len(active)] = active
            source.write_bytes(raw)
            output = root / "recovery"
            code, stdout, stderr = self._call(
                "recover", str(source), "--output", str(output), "--json"
            )
            self.assertEqual((code, stderr), (0, ""))
            self.assertTrue(json.loads(stdout)["complete"])

            report_path = output / "report.jsonl"
            records = [
                json.loads(line) for line in report_path.read_bytes().splitlines()
            ]
            recovered = next(
                record
                for record in records
                if record.get("disposition") == "recovered"
                and record["valid_data_bytes"] < record["logical_size_bytes"]
            )
            data = output / recovered["output_path"]
            with data.open("r+b") as handle:
                handle.seek(recovered["valid_data_bytes"])
                handle.write(b"x")
            recovered["output_sha256"] = hashlib.sha256(data.read_bytes()).hexdigest()
            checkpoint = output / "records" / f"{recovered['candidate_id']}.json"
            checkpoint.write_bytes(_canonical(recovered) + b"\n")
            content = b"".join(_canonical(record) + b"\n" for record in records[:-1])
            records[-1]["content_sha256"] = hashlib.sha256(content).hexdigest()
            report_path.write_bytes(content + _canonical(records[-1]) + b"\n")

            destination = root / "export"
            with self.assertRaisesRegex(
                VerificationError, "nonzero ValidDataLength tail"
            ):
                exporter.export_recovery(output, destination)
            self.assertFalse(destination.exists())

    def test_export_publishes_the_whole_directory_only_after_final_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _source, output = self._recovery(root)
            destination = root / "export"
            original = exporter._check_file_proof_at
            publication_states: list[bool] = []

            def observe_requested_path(*args, **kwargs):
                result = original(*args, **kwargs)
                publication_states.append(destination.exists())
                return result

            with mock.patch.object(
                exporter,
                "_check_file_proof_at",
                side_effect=observe_requested_path,
            ):
                result = exporter.export_recovery(output, destination)

            self.assertTrue(result["ok"])
            self.assertTrue(publication_states)
            first_public = publication_states.index(True)
            self.assertGreater(first_public, 0)
            self.assertFalse(any(publication_states[:first_public]))
            self.assertTrue(all(publication_states[first_public:]))
            self.assertTrue((destination / "catalog.jsonl").is_file())

    def test_export_refuses_data_mutated_during_final_directory_rename(self) -> None:
        """Publication must reprove held files after the final directory rename."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _source, output = self._recovery(root)
            destination = root / "export"
            staging = destination.with_name(
                exporter._export_staging_name(destination.name)
            )
            original = exporter._rename_noreplace
            mutated = False

            def mutate_before_final_rename(
                source_fd: int,
                source_name: str,
                destination_fd: int,
                destination_name: str,
            ) -> None:
                nonlocal mutated
                if source_name == staging.name and destination_name == destination.name:
                    exported = next((staging / "files").iterdir())
                    with exported.open("r+b") as handle:
                        first = handle.read(1)
                        handle.seek(0)
                        handle.write(bytes([first[0] ^ 1]))
                        handle.flush()
                        os.fsync(handle.fileno())
                    mutated = True
                original(source_fd, source_name, destination_fd, destination_name)

            with (
                mock.patch.object(
                    exporter,
                    "_rename_noreplace",
                    side_effect=mutate_before_final_rename,
                ),
                self.assertRaisesRegex(OutputError, "changed after its content proof"),
            ):
                exporter.export_recovery(output, destination)

            self.assertTrue(mutated)
            self.assertTrue(destination.is_dir())

    def test_export_refuses_parent_moved_into_recovery_after_final_staging_proof(
        self,
    ) -> None:
        """The requested destination parent cannot become a recovery descendant."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _source, output = self._recovery(root)
            export_parent = root / "export-parent"
            export_parent.mkdir(mode=0o700)
            destination = export_parent / "export"
            staging = export_parent / exporter._export_staging_name(destination.name)
            moved_parent = output / "moved-parent"
            original = exporter._assert_final_export_state
            calls = 0

            def move_parent_after_staging_proof(*args, **kwargs):
                nonlocal calls
                result = original(*args, **kwargs)
                calls += 1
                if calls == 1:
                    export_parent.rename(moved_parent)
                return result

            with (
                mock.patch.object(
                    exporter,
                    "_assert_final_export_state",
                    side_effect=move_parent_after_staging_proof,
                ),
                self.assertRaisesRegex(
                    OutputError, "revalidate export parent|replaced"
                ),
            ):
                exporter.export_recovery(output, destination)

            self.assertEqual(calls, 1)
            self.assertFalse(destination.exists())
            self.assertTrue((moved_parent / staging.name).is_dir())
            self.assertFalse((moved_parent / destination.name).exists())

    def test_export_refuses_requested_output_parent_renamed_before_publication(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            requested_parent = root / "requested-parent"
            requested_parent.mkdir()
            _source, output = self._recovery(requested_parent)
            destination = root / "export"
            moved_parent = root / "moved-parent"
            original = exporter._revalidate_completion_state
            moved = False

            def move_parent_after_recovery_proof(*args, **kwargs):
                nonlocal moved
                result = original(*args, **kwargs)
                if not moved:
                    requested_parent.rename(moved_parent)
                    moved = True
                return result

            with (
                mock.patch.object(
                    exporter,
                    "_revalidate_completion_state",
                    side_effect=move_parent_after_recovery_proof,
                ),
                self.assertRaisesRegex(OutputError, "recovery output parent"),
            ):
                exporter.export_recovery(output, destination)

            self.assertTrue(moved)
            self.assertFalse(destination.exists())
            self.assertTrue((moved_parent / "recovery" / "report.jsonl").is_file())

    def test_export_refuses_requested_output_parent_ancestor_symlink_retarget(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second"
            (first / "parent").mkdir(parents=True)
            (second / "parent").mkdir(parents=True)
            link = root / "link"
            link.symlink_to(first, target_is_directory=True)
            _source, output = self._recovery(link / "parent")
            destination = root / "export"
            original = exporter._revalidate_completion_state
            retargeted = False

            def retarget_after_recovery_proof(*args, **kwargs):
                nonlocal retargeted
                result = original(*args, **kwargs)
                if not retargeted:
                    link.unlink()
                    link.symlink_to(second, target_is_directory=True)
                    retargeted = True
                return result

            with (
                mock.patch.object(
                    exporter,
                    "_revalidate_completion_state",
                    side_effect=retarget_after_recovery_proof,
                ),
                self.assertRaisesRegex(OutputError, "recovery output parent"),
            ):
                exporter.export_recovery(output, destination)

            self.assertTrue(retargeted)
            self.assertFalse(destination.exists())
            self.assertTrue((first / "parent" / "recovery" / "report.jsonl").is_file())

    def test_export_refuses_first_file_mutated_after_second_final_proof(self) -> None:
        """The reverse final pass closes a forward A-B-A content-state race."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _source, output = self._recovery(root)
            destination = root / "export"
            original = exporter._check_file_proof_at
            final_file_checks = 0
            mutated = False

            def mutate_after_second_forward_proof(fd: int, name: str, **kwargs):
                nonlocal final_file_checks, mutated
                result = original(fd, name, **kwargs)
                if destination.exists() and name != "catalog.jsonl":
                    final_file_checks += 1
                    if final_file_checks == 2 and not mutated:
                        files = sorted((destination / "files").iterdir())
                        self.assertGreaterEqual(len(files), 2)
                        with files[0].open("r+b") as handle:
                            first = handle.read(1)
                            handle.seek(0)
                            handle.write(bytes([first[0] ^ 1]))
                            handle.flush()
                            os.fsync(handle.fileno())
                        mutated = True
                return result

            with (
                mock.patch.object(
                    exporter,
                    "_check_file_proof_at",
                    side_effect=mutate_after_second_forward_proof,
                ),
                self.assertRaisesRegex(OutputError, "changed after its content proof"),
            ):
                exporter.export_recovery(output, destination)

            self.assertTrue(mutated)
            self.assertTrue(destination.is_dir())

    def test_export_never_overwrites_a_racing_final_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _source, output = self._recovery(root)
            destination = root / "export"
            staging = destination.with_name(
                exporter._export_staging_name(destination.name)
            )
            original = exporter._rename_noreplace

            def race_final_publication(
                source_fd: int,
                source_name: str,
                destination_fd: int,
                destination_name: str,
            ) -> None:
                if source_name == staging.name and destination_name == destination.name:
                    destination.mkdir()
                    (destination / "foreign").write_text("keep", encoding="utf-8")
                original(source_fd, source_name, destination_fd, destination_name)

            with (
                mock.patch.object(
                    exporter,
                    "_rename_noreplace",
                    side_effect=race_final_publication,
                ),
                self.assertRaises(OutputError),
            ):
                exporter.export_recovery(output, destination)

            self.assertEqual(
                (destination / "foreign").read_text(encoding="utf-8"), "keep"
            )
            self.assertTrue((staging / "catalog.jsonl").is_file())

    def test_safe_names_and_content_signatures_are_deterministic(self) -> None:
        candidate_id = "a" * 64
        name = _safe_export_name("../../bad\\name?.jpg ", candidate_id)
        self.assertNotIn("/", name)
        self.assertNotIn("\\", name)
        self.assertTrue(name.endswith(candidate_id))
        self.assertLessEqual(len(os.fsencode(name)), 255)
        self.assertEqual(_detected_content(b"\xff\xd8\xffrest"), "image/jpeg")
        self.assertEqual(_detected_content(b"%PDF-1.7"), "application/pdf")
        self.assertEqual(_detected_content(b"hello\n"), "text/plain")
        self.assertTrue(_extension_consistent("photo.JPG", "image/jpeg"))
        self.assertFalse(_extension_consistent("photo.png", "image/jpeg"))
        self.assertIsNone(
            _extension_consistent("unknown.bin", "application/octet-stream")
        )

    def test_safe_name_and_detector_edge_forms_are_bounded(self) -> None:
        candidate_id = "b" * 64
        self.assertTrue(_safe_export_name(". ", candidate_id).startswith("recovered--"))
        self.assertLessEqual(
            len(os.fsencode(_safe_export_name("é" * 200, candidate_id))), 255
        )
        self.assertEqual(_detected_content(b""), "application/x-empty")
        self.assertEqual(_detected_content(b"RIFFxxxxWAVE"), "audio/wav")
        self.assertEqual(_detected_content(b"RIFFxxxxAVI "), "video/x-msvideo")
        self.assertEqual(_detected_content(b"RIFFxxxxWEBP"), "text/plain")
        self.assertEqual(_detected_content(b"0000ftypheic"), "image/heif")
        self.assertEqual(_detected_content(b"0000ftypisom"), "video/mp4")
        self.assertEqual(_detected_content(b"\xff"), "application/octet-stream")
        self.assertEqual(_detected_content(b"\x01\x02"), "application/octet-stream")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
