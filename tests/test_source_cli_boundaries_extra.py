from __future__ import annotations

import errno
import io
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from exfat_rescue import cli
from exfat_rescue import source as source_module
from exfat_rescue.errors import OutputError, SourceError, VerificationError
from exfat_rescue.source import ImageSource, preflight_output_path, refuse_output_path


class SourceAndCliBoundaryTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX named pipes")
    def test_expected_regular_file_races_never_block_on_named_pipes(self) -> None:
        probes = {
            "source-open-race": """
                import os
                import tempfile
                from pathlib import Path
                from unittest import mock
                from exfat_rescue import source as source_module
                from exfat_rescue.errors import SourceError
                from exfat_rescue.source import ImageSource

                with tempfile.TemporaryDirectory() as temporary:
                    path = Path(temporary) / "source.img"
                    path.write_bytes(b"source")
                    original_lstat = os.lstat

                    def replace_after_lstat(value):
                        state = original_lstat(value)
                        path.unlink()
                        os.mkfifo(path, 0o600)
                        return state

                    with mock.patch.object(
                        source_module.os, "lstat", side_effect=replace_after_lstat
                    ):
                        try:
                            ImageSource.open(path)
                        except SourceError:
                            pass
                        else:
                            raise AssertionError("FIFO replacement was accepted")
            """,
            "managed-state": """
                import os
                import tempfile
                from pathlib import Path
                from exfat_rescue.errors import OutputError
                from exfat_rescue.recovery import _read_regular_at

                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    fifo = root / "run.json"
                    os.mkfifo(fifo, 0o600)
                    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        try:
                            _read_regular_at(root_fd, fifo.name)
                        except OutputError:
                            pass
                        else:
                            raise AssertionError("FIFO recovery state was accepted")
                    finally:
                        os.close(root_fd)
            """,
            "external-manifest": """
                import os
                import tempfile
                from pathlib import Path
                from exfat_rescue.errors import ManifestError
                from exfat_rescue.manifest import read_manifest_v2

                with tempfile.TemporaryDirectory() as temporary:
                    fifo = Path(temporary) / "manifest.jsonl"
                    os.mkfifo(fifo, 0o600)
                    try:
                        read_manifest_v2(fifo)
                    except ManifestError:
                        pass
                    else:
                        raise AssertionError("FIFO manifest was accepted")
            """,
            "event-log-race": """
                import os
                import tempfile
                from pathlib import Path
                from unittest import mock
                from exfat_rescue import cli
                from exfat_rescue.cli import _EventLog
                from exfat_rescue.errors import OutputError

                with tempfile.TemporaryDirectory() as temporary:
                    path = Path(temporary) / "events.jsonl"
                    event_log = _EventLog(path)
                    original_stat = os.stat
                    replaced = False

                    def replace_after_stat(*args, **kwargs):
                        global replaced
                        state = original_stat(*args, **kwargs)
                        if not replaced:
                            path.unlink()
                            os.mkfifo(path, 0o600)
                            replaced = True
                        return state

                    with mock.patch.object(
                        cli.os, "stat", side_effect=replace_after_stat
                    ):
                        try:
                            event_log.append({"event": "probe"})
                        except OutputError:
                            pass
                        else:
                            raise AssertionError("FIFO event log was accepted")
            """,
        }
        for label, script in probes.items():
            with self.subTest(probe=label):
                try:
                    result = subprocess.run(
                        [sys.executable, "-c", textwrap.dedent(script)],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                except subprocess.TimeoutExpired:
                    self.fail(f"{label} blocked on a named pipe")
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_source_cache_release_is_bounded_and_best_effort(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "image.img"
            image.write_bytes(b"abcdefgh")
            source = ImageSource.open(image)
            try:
                with (
                    mock.patch.object(source_module, "_POSIX_FADVISE") as advise,
                    mock.patch.object(source_module, "_POSIX_FADV_DONTNEED", 4),
                ):
                    self.assertTrue(source.release_cache(1, 6))
                    advise.assert_called_once_with(source.fd, 1, 6, 4)
                    advise.reset_mock()
                    self.assertTrue(
                        source_module._release_file_cache(
                            source.fd, 0, source.size, through_eof=True
                        )
                    )
                    advise.assert_called_once_with(source.fd, 0, 0, 4)

                with mock.patch.object(source_module, "_POSIX_FADVISE", None):
                    self.assertFalse(source.release_cache(0, source.size))

                with (
                    mock.patch.object(
                        source_module,
                        "_POSIX_FADVISE",
                        side_effect=OSError(errno.EINVAL, "unsupported"),
                    ),
                    mock.patch.object(source_module, "_POSIX_FADV_DONTNEED", 4),
                ):
                    self.assertFalse(source.release_cache(0, source.size))

                self.assertTrue(source.release_cache(0, 0))
                for offset, length in ((-1, 1), (0, -1), (7, 2)):
                    with (
                        self.subTest(offset=offset, length=length),
                        self.assertRaises(ValueError),
                    ):
                        source.release_cache(offset, length)
            finally:
                source.close()

    def test_source_open_and_read_faults_are_structured(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(SourceError):
                ImageSource.open(root / "missing.img")

            directory = root / "directory"
            directory.mkdir()
            with self.assertRaises(SourceError):
                ImageSource.open(directory)

            image = root / "image.img"
            image.write_bytes(b"abcdef")
            link = root / "link.img"
            link.symlink_to(image)
            with self.assertRaises(SourceError):
                ImageSource.open(link)

            source = ImageSource.open(image)
            try:
                with (
                    mock.patch.object(
                        os, "pread", side_effect=OSError(errno.EIO, "io")
                    ),
                    self.assertRaises(SourceError),
                ):
                    source.read_at(0, 1)
                self.assertEqual(source.read_at(-1, 1), b"")
                with self.assertRaises(SourceError):
                    source.read_exact(5, 2)
                with self.assertRaises(SourceError):
                    source.sha256_region(0, 7)
                with self.assertRaises(ValueError):
                    source.sha256_region(0, 1, chunk_size=0)
            finally:
                source.close()

    def test_source_identity_and_manifest_preflight_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "image.img"
            image.write_bytes(b"source")
            source = ImageSource.open(image)
            try:
                with self.assertRaises(OutputError):
                    refuse_output_path(source, image)
                with self.assertRaises(OutputError):
                    refuse_output_path(source, root / "missing" / "manifest.jsonl")
                with (
                    mock.patch(
                        "exfat_rescue.source.tempfile.mkstemp",
                        side_effect=OSError(errno.EROFS, "read-only"),
                    ),
                    self.assertRaises(OutputError),
                ):
                    preflight_output_path(source, root / "manifest.jsonl")
                with (
                    mock.patch.object(
                        os, "fstat", side_effect=OSError(errno.EIO, "io")
                    ),
                    self.assertRaises(SourceError),
                ):
                    source.assert_unchanged()
            finally:
                source.close()

    def test_event_log_refuses_existing_replaced_and_hardlinked_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            existing = root / "existing.jsonl"
            existing.write_text("keep", encoding="utf-8")
            with self.assertRaises(OutputError):
                cli._EventLog(existing)
            self.assertEqual(existing.read_text(encoding="utf-8"), "keep")

            path = root / "events.jsonl"
            event_log = cli._EventLog(path)
            event_log.append({"event": "first"})
            moved = root / "moved.jsonl"
            path.rename(moved)
            path.write_text("replacement", encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaises(OutputError):
                event_log.append({"event": "second"})
            self.assertEqual(path.read_text(encoding="utf-8"), "replacement")

            linked_path = root / "linked-events.jsonl"
            linked_log = cli._EventLog(linked_path)
            os.link(linked_path, root / "extra-link.jsonl")
            with self.assertRaises(OutputError):
                linked_log.append({"event": "refused"})

    def test_progress_reporter_restarts_timing_for_a_repeated_phase(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            with mock.patch.object(
                cli.time,
                "monotonic",
                side_effect=[10.0, 20.0, 30.0, 40.0],
            ):
                reporter = cli._ProgressReporter(path, human=False)
                reporter("verify-output-candidates", 1, 2, "candidates")
                reporter("verify-output-candidates", 2, 2, "candidates")
                reporter("verify-output-candidates", 1, 2, "candidates")
                reporter("verify-output-candidates", 2, 2, "candidates")

            events = [json.loads(line) for line in path.read_bytes().splitlines()]
            self.assertEqual([event["completed"] for event in events], [1, 2, 1, 2])
            self.assertEqual(events[1]["elapsed_seconds"], 10.0)
            self.assertEqual(events[2]["elapsed_seconds"], 0.001)
            self.assertEqual(events[3]["elapsed_seconds"], 10.0)
            self.assertEqual(events[2]["eta_seconds"], 0.001)

    def test_progress_reporter_restarts_a_repeated_one_item_phase(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            with mock.patch.object(
                cli.time,
                "monotonic",
                side_effect=[10.0, 20.0],
            ):
                reporter = cli._ProgressReporter(path, human=False)
                reporter("verify-source-candidates", 1, 1, "candidates")
                reporter("verify-source-candidates", 1, 1, "candidates")

            events = [json.loads(line) for line in path.read_bytes().splitlines()]
            self.assertEqual(
                [event["elapsed_seconds"] for event in events],
                [0.001, 0.001],
            )

    def test_selected_volume_digest_is_reused_only_while_source_is_unchanged(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "image.img"
            image.write_bytes(b"abcdefgh")
            source = ImageSource.open(image)
            try:
                original = ImageSource.sha256_region
                calls = 0

                def counted_hash_region(
                    current: ImageSource,
                    offset: int,
                    length: int,
                    *,
                    chunk_size: int = 1024 * 1024,
                ) -> str:
                    nonlocal calls
                    calls += 1
                    return original(current, offset, length, chunk_size=chunk_size)

                with mock.patch.object(
                    ImageSource,
                    "sha256_region",
                    autospec=True,
                    side_effect=counted_hash_region,
                ):
                    first = source.selected_volume_sha256(0, source.size)
                    second = source.selected_volume_sha256(0, source.size)
                self.assertEqual(first, second)
                self.assertEqual(calls, 1)

                image.write_bytes(b"abcdEfgh")
                with self.assertRaises(SourceError):
                    source.selected_volume_sha256(0, source.size)
            finally:
                source.close()

    def test_scanned_volume_digest_rejects_invalid_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "image.img"
            image.write_bytes(b"abcdefgh")
            source = ImageSource.open(image)
            try:
                for offset, length, digest in (
                    (-1, 1, "0" * 64),
                    (0, source.size + 1, "0" * 64),
                    (0, source.size, "not-a-digest"),
                ):
                    with (
                        self.subTest(offset=offset, length=length, digest=digest),
                        self.assertRaises(SourceError),
                    ):
                        source.remember_selected_volume_digest(offset, length, digest)
            finally:
                source.close()

    def test_region_hash_reports_bounded_progress_from_zero_to_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "image.img"
            image.write_bytes(b"abcdefgh")
            events: list[tuple[str, int, int, str]] = []
            source = ImageSource.open(
                image, progress=lambda *event: events.append(event)
            )
            try:
                source.sha256_region(1, 6, chunk_size=2)
            finally:
                source.close()

            self.assertEqual(events[0], ("hash-volume", 0, 6, "bytes"))
            self.assertEqual(events[-1], ("hash-volume", 6, 6, "bytes"))
            self.assertTrue(all(0 <= event[1] <= event[2] for event in events))

    def test_cli_boundary_envelopes_for_cancel_verify_and_internal_errors(self) -> None:
        for arguments, json_mode, expected_stream, expected_code in (
            (["inspect", "source.img"], False, "stderr", 130),
            (["inspect", "source.img", "--json"], True, "stderr", 130),
        ):
            stdout, stderr = io.StringIO(), io.StringIO()
            with (
                mock.patch.object(
                    cli.ImageSource, "open", side_effect=KeyboardInterrupt
                ),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                self.assertEqual(cli.main(arguments), expected_code)
            rendered = (
                stderr.getvalue() if expected_stream == "stderr" else stdout.getvalue()
            )
            if json_mode:
                self.assertEqual(json.loads(rendered)["error_code"], "cancelled")
            else:
                self.assertIn("Operation cancelled", rendered)

        for arguments, json_mode in (
            (["verify", "output"], False),
            (["verify", "output", "--json"], True),
        ):
            stdout, stderr = io.StringIO(), io.StringIO()
            with (
                mock.patch(
                    "exfat_rescue.verification.verify_recovery",
                    side_effect=VerificationError("altered"),
                ),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                self.assertEqual(cli.main(arguments), 8)
            self.assertEqual(stderr.getvalue(), "")
            if json_mode:
                self.assertEqual(
                    json.loads(stdout.getvalue())["error_code"], "verification_failed"
                )
            else:
                self.assertIn("Verification failed", stdout.getvalue())

        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            mock.patch(
                "exfat_rescue.verification.verify_recovery_set",
                side_effect=VerificationError("altered set"),
            ),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            self.assertEqual(
                cli.main(
                    [
                        "verify-set",
                        "output-1",
                        "output-2",
                        "--image",
                        "source.img",
                        "--json",
                    ]
                ),
                8,
            )
        self.assertEqual(stderr.getvalue(), "")
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["command"], "verify-set")
        self.assertEqual(payload["error_code"], "verification_failed")

        for arguments, json_mode in (
            (["inspect", "source.img"], False),
            (["inspect", "source.img", "--json"], True),
        ):
            stderr = io.StringIO()
            with (
                mock.patch.object(
                    cli.ImageSource, "open", side_effect=RuntimeError("secret")
                ),
                redirect_stderr(stderr),
            ):
                self.assertEqual(cli.main(arguments), 1)
            rendered = stderr.getvalue()
            self.assertNotIn("secret", rendered)
            if json_mode:
                self.assertEqual(json.loads(rendered)["error_code"], "internal_error")
            else:
                self.assertIn("unexpected internal error", rendered)

    def test_internal_manifest_rejects_unknown_options_and_omitted_candidates(
        self,
    ) -> None:
        planned = mock.Mock(source_binding={}, plans=(), source_candidates=())
        with self.assertRaises(ValueError):
            cli._internal_manifest_bytes(planned, {"undeclared": 1}, ())
        planned = mock.Mock(
            source_binding={
                "volume_offset_bytes": 0,
                "source_kind": "direct-image",
                "boot_region": "primary",
            },
            plans=(object(),),
            source_candidates=(),
        )
        with self.assertRaises(ValueError):
            cli._internal_manifest_bytes(planned, {}, ())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
