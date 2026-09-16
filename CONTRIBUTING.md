# Contributing

Use synthetic fixtures only, keep image access read-only, and run every test, compile,
lint, and formatting command in [`AGENTS.md`](AGENTS.md). Please file public issues with
sanitized metadata, never a real disk image or recovered file. Features that write
sources or operate live devices need a separate safety design and are outside this release.

Every pull request must explain its recovery-safety impact, add synthetic regression
coverage, and pass tests against the built wheel. See [SUPPORT.md](SUPPORT.md) for the
support boundary and [`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md) for release
gates. Routine CI runs the `quick` profile on Linux/Python 3.11. Before a release, run
`gh workflow run ci.yml --ref <release-branch-or-tag> -f profile=release` for the exact
candidate commit. Verify the run's `head_sha` before tagging; the release profile runs
the full cross-platform, native exFAT, and Windows refusal suite.

## License and contributions

The project is licensed under Apache-2.0. By submitting a
contribution for inclusion, you agree to license it under Apache-2.0 unless you clearly
state different terms in writing before it is accepted. Do not submit material you cannot
license this way. See [NOTICE](NOTICE) for third-party attributions.
