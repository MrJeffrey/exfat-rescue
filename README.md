# exfat-rescue

`exfat-rescue` is a calm, read-only tool for inspecting an exFAT disk image, planning
metadata-backed recovery, and restoring files with currently validated allocations. It
is for people trying to recover files from a formatted exFAT drive, including Mac
external drive recovery, Linux exFAT recovery, a USB hard drive, or an SD card after a
quick format. It does not modify the image, the original drive, or any files it finds.

> **RC scope:** this release recovers only files with a complete, currently validated
> metadata allocation plan. It refuses ambiguous data and never writes to the image.

If this tool recovered your files, leave a ⭐ for the machine. It read every byte so
you didn’t have to. Please also star the [original sd-recovery project][sd-recovery],
whose parser concepts informed this project.

## What ships today

Install with Python 3.11 or newer:

```sh
# From a Git checkout:
pipx install .

# Or directly from GitHub:
pipx install git+https://github.com/MrJeffrey/exfat-rescue.git

exfat-rescue inspect /path/to/drive.img
exfat-rescue scan /path/to/drive.img --manifest candidates.jsonl
exfat-rescue scan /path/to/drive.img --manifest candidates.jsonl --json
exfat-rescue recover /path/to/drive.img --output recovered
exfat-rescue recover /path/to/drive.img --output recovered-large \
  --max-candidates 500000 --max-selected-candidates 500000 \
  --event-log recovery.events.jsonl
exfat-rescue verify recovered --image /path/to/drive.img
exfat-rescue verify-set recovered-part-1 recovered-part-2 --image /path/to/drive.img
exfat-rescue export recovered --destination recovered-by-name
```

The project is not published on PyPI. Install from a Git checkout or directly from this
repository; PyPI publication may follow a future release review.

Only stable regular image files are accepted. Block devices, symlinks, live-device
imaging, signature carving, MP4 repair, and writes to a source image are deliberately
out of scope. The scanner validates the selected exFAT boot region and directory entry-set
checksums, walks active directories, and also makes a conservative allocation-area pass
for valid orphaned or deleted candidates. That sequential pass computes the complete
selected-volume SHA-256 from the same bytes, avoiding a second full-volume read. If the
image changes during a scan, publication is refused so the manifest cannot mix different
source states.
For deleted files, an exact current allocation plan cannot prove that the bytes are the
historical contents; metadata may also be destroyed by a format.

The intended workflow is **image → inspect → scan → recover**, with `verify` available
for a later independent audit. Recovery writes
only complete logical streams tied to exact plans. It uses candidate-ID output paths,
zero-fills the exFAT undefined region after `ValidDataLength`, and records hashes for
source data and output. For damaged or unsupported volumes,
[TestDisk/PhotoRec][photorec] and [ddrescue][ddrescue] are useful fallback tools; use
them against a copy where practical.

## Recovering files from a formatted exFAT drive

A quick format can replace filesystem bookkeeping without immediately overwriting every
data cluster. In that situation, exFAT directory-entry sets may still describe old files.
`exfat-rescue scan` records metadata that passes structural checks so a later recovery
stage can make explicit decisions about names, clusters, fragmentation, and collisions.

This is relevant to an external drive formatted on a Mac, an exFAT USB hard drive used
between macOS and Linux, and camera or drone SD cards. Stop writing to the affected media
first. Create a sector image on a different physical disk with an established imaging
tool such as ddrescue, then inspect the image. Do not install software or save manifests
onto the drive being recovered.

This project is not a replacement for every TestDisk or PhotoRec workflow. It is an
exFAT-metadata-first tool with a deliberately narrow safety boundary. PhotoRec-style file
carving remains a useful fallback when metadata is gone or a file was fragmented.

## Image formats

`inspect`, `scan`, and `recover` accept:

- an exFAT partition image beginning with an exFAT boot sector;
- an ordinary MBR whole-disk image containing one exFAT primary partition; or
- a 512-byte-sector GPT whole-disk image containing one exFAT partition.

The tool refuses ambiguous images containing multiple discoverable exFAT volumes. GPT
images with non-512-byte logical sectors and extended MBR partitions are not supported in
this release. Extract the desired partition to a separate image instead of asking the tool to
guess. Conservative orphan scanning reconstructs bounded entry sets across physically
adjacent allocation units only when every unit containing that metadata is free; use a
carving tool when metadata recovery is incomplete.

The primary exFAT boot region is checksum-validated. When it is invalid, a checksum-valid
backup may supply the geometry, and `boot_region` records that decision. The current
active-FAT bit still comes from the main boot sector, as required by the specification.
If a two-FAT volume needs backup geometry, the manifest includes
`backup_geometry_with_main_active_fat` because corruption may also make that current
main-sector bit less trustworthy. The parser supports exFAT revision 1.00 and one or two
FATs.

## Manifest

`scan` writes a strict v2 newline-delimited JSON recovery-plan manifest. Its header binds
the selected volume, including its offset, length, and a full SHA-256 of that selected
volume, to the scan limits and parser decision. Each candidate records only a re-plannable
metadata candidate and its current disposition: `recoverable`, `conflicted`, or
`unrecoverable`. A manifest is not extraction authority: recovery rereads the image,
requires the complete current candidate inventory to match the manifest, and replans
every candidate before it creates output. This prevents an omitted overlapping candidate
from making an otherwise conflicted extent appear recoverable.

Output is created exclusively with private permissions: an existing manifest is never
replaced and the output cannot be the source image. The destination is preflighted before
the full-image pass. A successful manifest ends with a `complete` record containing the
candidate count, `content_record_count` (the number of preceding records), and a SHA-256
of every preceding JSONL byte. An interrupted or failed write may leave an incomplete
file; it is deliberately never deleted automatically. Manifest v1 is not accepted for
recovery. The machine-readable v2 schema is shipped with the package and maintained at
[`src/exfat_rescue/schemas/manifest-v2.json`][manifest-v2].

exFAT timestamps are local-time values. The manifest includes a UTC offset only when the
source entry actually recorded one; it never invents UTC for an unknown timezone.

`inspect` and `scan` accept direct partition images plus ordinary MBR and 512-byte-sector
GPT whole-disk images. If more than one exFAT partition is found, they refuse to guess;
provide a partition image instead. Recovery and `verify --image` use the full SHA-256 of
the selected exFAT volume, not a sampled image fingerprint.

All commands are noninteractive and telemetry-free. `--json` emits exactly one successful
machine-readable result on stdout; expected invocation and operational errors emit exactly
one JSON object on stderr. `verify` reports a completed integrity mismatch on stdout and
exits nonzero. Stable exit codes are: `2` usage or invalid selection, `3` unsafe or changed
source, `4` exFAT validation, `5` unsafe output state or destination I/O, `6` configured
work/output/space limit, `7` untrusted manifest/run/report integrity, `8` verification
mismatch or incompleteness, and `130` cancellation. Human-mode progress is written to
stderr, leaving stdout suitable for the final result.

Long-running `scan`, `recover`, `verify`, `verify-set`, and `export` commands accept
`--event-log NEW_JSONL_FILE`. The tool creates that file with private mode `0600`, never
overwrites it, and writes bounded JSON phase, progress, completion, or failure records in
append mode. The log is an operational aid, not trusted recovery state.
Progress records include elapsed time, rate, and an ETA when one can be calculated. This
machine-readable side channel does not change the command's one-result `--json` stdout or
stderr contract.

The scan default is 100,000 retained candidates; its explicit hard ceiling is 500,000,
with manifest framing for 500,002 records and 1 GiB. By default it also permits
50,000,000 allocation units. These limits bound memory and work on hostile or implausible
images. `--max-candidates` can select any discovery limit through the hard ceiling after
the operator verifies that sufficient memory is available;
`--max-scan-clusters` can raise the allocation-unit budget after the operator reviews the
image geometry and available resources. The CLI enforces the numeric ceilings, not a
platform-specific free-memory estimate. The selected volume's complete hash work, including
format regions outside the cluster heap, is charged to that budget, and `ClusterCount`
must match the volume geometry required by the exFAT specification. The candidate limit also bounds tracked directory
references and allocation units, plus cumulative directory allocation units examined,
including rejected aliases.
A full orphan pass reads the entire cluster heap and may take about as long as a
sequential read of the volume. An interrupted manifest never writes a `complete` record.
Recovery caps selected candidate IDs at 100,000 and selected logical output at 100 GiB
by default. A reviewed large recovery can explicitly raise the selection ceiling to
500,000 with `--max-selected-candidates`; the final report-size and destination-space
bounds still apply. Recovery refuses an over-limit selection before
creating an output directory if the validated selected plans exceed that limit.
Checkpoint files remain per-candidate for precise resume and audit, but their directory
durability flush is batched every 256 candidates. Recovered data is made durable first;
after a crash, resume can safely reconstruct any lost tail checkpoints from exact output
bytes without repeating completed extraction.

`recover --output` requires a brand-new directory. It never writes partial files: each
recovered file is stored under a candidate-ID path, with the undefined range from
`ValidDataLength` through `DataLength` zero-filled. Refused candidates are recorded but
do not produce files. `recover --resume` only accepts a private directory created by this
tool, forbids replacement manifests, selections, and limits, then revalidates its immutable
run state. `verify OUTPUT_DIRECTORY` checks the completed output inventory and hashes;
adding `--image IMAGE` also revalidates the source binding, metadata plan, and source bytes.
When one recovery is split across multiple output directories, `verify-set` requires those
outputs to share one exact manifest and disjoint selections. It performs the expensive
whole-image inventory and replan once for the set while retaining every per-output and
per-source-byte integrity check. Every output's immutable metadata and bounded inventory,
the set-wide compatibility rules, and the supplied image size are preflighted before any
recovered-content hashing or whole-image scan begins.

`export OUTPUT_DIRECTORY --destination NEW_DIRECTORY` first performs strict structural
output preflight, then verifies and copies each recovered file to a recognizable flat name
in one content pass. Unsafe path
characters are replaced, every filename carries its full candidate ID to prevent
collisions, and existing destinations are never overwritten. A private, hashed
`catalog.jsonl` records the original metadata name, exported path, size, SHA-256,
detected content signature, and whether a known filename extension agrees with that
signature. Source state is proved while copying; each completed destination file is then
read back through its held descriptor to prove its SHA-256, source-data prefix, and
zero-filled tail before cataloging. The completed catalog is likewise read back through
its held descriptor before its publication proof; file and catalog state are revalidated
after the catalog is complete. The export is built under a deterministic private sibling
staging name, then the whole directory is atomically renamed without replacement to the
requested destination. Failure before that rename leaves the requested path absent and
may retain the hidden staging directory as evidence. A durability or identity failure
after the rename may leave a complete requested directory that a retry safely refuses;
the renamed directory is proved again through its held descriptors before success.
Neither case is reported complete. Signature agreement is a triage aid, not proof that
deleted bytes are the historical contents.

The mandatory sequential allocation-area scan computes the complete selected-volume
SHA-256 in flight, so scan, recovery, resume, and image-backed verification do not reread
the full volume solely to hash it. Later safety boundaries reuse that digest only while
the same open descriptor remains unchanged. `recover --resume` may additionally seed the
originating run's digest when the regular image has the exact same local device, inode,
mode, link count, owner, size, modification time, and change time; the new scan recomputes
and checks it at no extra read cost. Independent `verify --image` and `verify-set` commands
never consume that resume proof and recompute the complete digest during their own scan.
A successful recovery already replans the complete manifest, proves the source binding,
hashes each recovered output once after publication, and publishes its completion record
last. Completion carries that content-bound file proof forward and binds report publication
to exact file identity/stat state without reading every output byte again. Running
`verify --image` immediately afterward repeats that work; reserve it for a later audit or
use `verify-set` once when separately produced outputs need a shared image-backed audit.
The private output permissions and run lock exclude other users and cooperating commands,
but portable filesystems do not provide an atomic snapshot across every file in the tree.
A privileged or same-account process that deliberately rewrites and reverts different
files between final checks is outside the completion guarantee; run `verify` after any
custody boundary to detect persistent or post-completion tampering.

## Agent and automation interface

The CLI is noninteractive, has no network calls, and supports one-result JSON output.
Automation should check `ok`, `error_code`, and the process exit status rather than parse
human prose. `inspect --json` reports `source_kind`, `boot_region`, and
`volume_offset_bytes`; `scan --json` repeats that selection and points to a versioned
JSONL manifest. JSON recovery reports completion plus aggregate output counts and bytes;
per-candidate recoveries and safe refusals are recorded in the output `report.jsonl`.
JSON verification reports whether an image was additionally checked. Consumers
must require the final `complete` record, verify its counts, and hash the exact bytes of
every preceding line before trusting a manifest.

Repository agents should read
[`AGENTS.md`](https://github.com/MrJeffrey/exfat-rescue/blob/main/AGENTS.md) before
editing. It defines the
source read-only invariant, synthetic-fixture policy, module ownership, and exact local
checks. The JSON Schema deliberately rejects undeclared fields so an incompatible record
change requires a manifest-version change instead of silently surprising consumers.

## Architecture

- `source.py` is the only image descriptor boundary and opens sources read-only.
- `exfat/volume.py` discovers and bounds the exFAT volume and reads FAT/cluster geometry.
- `exfat/entries.py` validates and decodes directory entry sets.
- `scanner.py` walks known directories and performs a conservative orphan metadata scan.
- `manifest.py` exclusively publishes and strictly reads deterministic v2 JSONL manifests.
- `planner.py` proves bounded allocation plans and their safety dispositions.
- `recovery.py` owns descriptor-relative, resumable extraction into private new output.
- `verification.py` validates completed recovery outputs, optionally against an image.
- `exporter.py` copies verified outputs to safe recognizable names and writes the catalog.
- `cli.py` owns the human and JSON command contracts.

## Privacy and safety

There is no telemetry. Disk images and recovered names can be extremely sensitive: do
not upload real disk images, recovered files, or private metadata to public issues.
Please describe problems using a synthetic fixture or sanitized structure instead.

See
[SECURITY.md](https://github.com/MrJeffrey/exfat-rescue/blob/main/SECURITY.md),
[CONTRIBUTING.md](https://github.com/MrJeffrey/exfat-rescue/blob/main/CONTRIBUTING.md),
[`docs/PERFORMANCE.md`](docs/PERFORMANCE.md),
and [NOTICE](https://github.com/MrJeffrey/exfat-rescue/blob/main/NOTICE).
The parser implements the cited portions of the
[Microsoft exFAT specification][exfat-spec]
for boot regions, allocation geometry, FAT selection, and directory semantics.

## License

Licensed under [Apache-2.0](LICENSE). Third-party attributions are in [NOTICE](NOTICE).

[ddrescue]: https://www.gnu.org/software/ddrescue/
[exfat-spec]: https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification
[manifest-v2]: https://github.com/MrJeffrey/exfat-rescue/blob/main/src/exfat_rescue/schemas/manifest-v2.json
[photorec]: https://www.cgsecurity.org/
[sd-recovery]: https://github.com/desmondmanoj21-cmd/sd-recovery
