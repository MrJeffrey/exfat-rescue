# exfat-rescue contributor guide

This project is a pure-Python, image-first exFAT scanner and recovery tool. `source.py`
is the only source-I/O boundary; `exfat/` parses boot and entry records; `scanner.py`
produces deterministic candidates; `planner.py` proves recovery dispositions;
`manifest.py` owns immutable manifest publication; `recovery.py` owns private resumable
output state; `verification.py` validates completed output; and `cli.py` owns the public
contract. `exporter.py` copies only already-verified output to safe recognizable names and
publishes its content catalog. Preserve that separation.

Setup and checks:

```sh
python -m pip install -e '.[dev]'
python -m coverage run -m unittest discover -s tests -v
python -m coverage report
python -m coverage report --include='*/planner.py' --fail-under=83
python -m coverage report --include='*/recovery.py' --fail-under=80
python -m coverage report --include='*/verification.py' --fail-under=84
python -m compileall -q src tests
ruff check src tests
ruff format --check src tests
python -m build
python -m twine check --strict dist/*
```

Safety invariants: accept only regular image files; open sources through `os.open` with
read-only, close-on-exec, and no-follow flags where available; never add a writable source
open; refuse publication when a source changes during scanning or recovery; never
overwrite or alias a source with output; keep commands noninteractive and telemetry-free.
Recovery may only extract a completely validated plan to a brand-new, private output
directory or resume a directory created by this tool. It must never write live devices,
guess allocations, publish partial files, follow symlinks, trust manifest extents without
replanning them, use source names as filesystem paths, or overwrite an existing object.
Preserve boot-region checksums, bounded cumulative work/candidate limits,
whole-directory EOD behavior, and NoFatChain semantics.
Charge attempted directory allocations to the cumulative work budget even when overlap
or corruption causes rejection.
Never auto-delete a failed final-path output: another process may have replaced it. A
trusted manifest must end in a valid `complete` record whose counts and content hash match
every preceding line.

The binding RC recovery contract is `docs/RC_RECOVERY_CONTRACT.md`. Any change to its
dispositions, recovery bases, source binding, manifest/report formats, output state
machine, exit codes, or safety claims requires tests and an explicit contract update in
the same pull request.

Fixtures are generated synthetic exFAT byte arrays only, except for test-time disposable
images formatted by local or CI exFAT tooling. Never commit those runtime-generated images
or add real image captures, recovered filenames, serial numbers, logs, or personal data.
Make a feature branch before editing, keep changes reviewable, run the checks above, and do
not bypass the source-write proof tests.
