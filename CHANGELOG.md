# Changelog

## 0.2.0rc1 (unreleased)

- Report recovered and refused totals in new and resumed recovery summaries; reject
  manifest-evident selection and output-limit errors before scanning the image.
- Keep help and version available on unsupported platforms and explain Linux/macOS
  requirements before operational commands access files.
- Provide one recovery quickstart, separate advanced workflows, and explicit output
  limits in command help.
- Add `inspect`, v2 `scan`, planner-validated `recover` and `--resume`, `verify`,
  `verify-set`, and `export`, with noninteractive JSON output and optional event logs.
- Bind recovery manifests and runs to a full SHA-256 of the selected exFAT volume; reparse
  and replan metadata before recovery, resume, and image-backed verification.
- Add immutable manifests, private output directories, candidate-ID paths, resumable
  checkpoints, integrity reports, and verified exports with hashed catalogs.
- Refuse mutable sources, ambiguous or unsafe plans, altered recovery state, output
  replacement, and configured work, output, or space-limit overruns.
- Improve full-volume scan performance through bounded sequential reads while preserving
  complete source and output integrity checks.
- License original project work and contributions under Apache-2.0.

## 0.1.0 (development milestone)

- Initial image-first inspection and deterministic metadata-manifest MVP.
- Validate primary and backup exFAT boot regions and active FAT selection.
- Refuse mutable sources and bound scan work and retained candidates.
- Correct contiguous-directory, end-of-directory, and cross-cluster entry handling.
- Add hostile-input, schema, packaging, coverage, and installed-wheel validation.
- Add a hashed completion record so interrupted manifests are detectably incomplete.
- Preserve concurrent replacement files and downgrade overlapping directory allocations.
