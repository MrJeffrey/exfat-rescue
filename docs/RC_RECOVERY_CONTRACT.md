# 0.2.0rc1 recovery contract

This document defines the recovery contract for the 0.2.0rc1 release candidate. The
source image remains strictly read-only.
Unsafe, ambiguous, unbounded, or unverifiable plans are refused rather than guessed.
The supported platforms are Linux and macOS with Python 3.11 or newer. Help and version
information remain available on other platforms; operational commands exit 2 with a
clear unsupported-platform error before opening sources or creating output.

## Public commands

```text
exfat-rescue inspect IMAGE [--json]
exfat-rescue scan IMAGE --manifest NEW_MANIFEST [scan limits] [--json]
                  [--event-log NEW_JSONL_FILE]
exfat-rescue recover IMAGE --output NEW_DIRECTORY
                    [--manifest MANIFEST]
                    [--candidate-id ID ...]
                    [scan/planner/output limits]
                    [--json] [--event-log NEW_JSONL_FILE]
exfat-rescue recover IMAGE --resume OUTPUT_DIRECTORY [--json]
                    [--event-log NEW_JSONL_FILE]
exfat-rescue verify OUTPUT_DIRECTORY [--image IMAGE] [--json]
                    [--event-log NEW_JSONL_FILE]
exfat-rescue verify-set OUTPUT_DIRECTORY [OUTPUT_DIRECTORY ...]
                        --image IMAGE [--json] [--event-log NEW_JSONL_FILE]
exfat-rescue export OUTPUT_DIRECTORY --destination NEW_DIRECTORY
                    [--json] [--event-log NEW_JSONL_FILE]
```

`--output` and `--resume` are mutually exclusive and exactly one is required. Resume
forbids a replacement manifest, candidate selection, or changed limits; the immutable
run descriptor supplies them. Without `--manifest`, recovery performs a v2 scan and
persists its manifest. Every requested candidate ID must exist exactly once. Duplicate
or unknown selections fail before output-directory creation. With a supplied, structurally
validated v2 manifest, malformed, duplicate, or unknown selections, excessive selected
candidate counts, and excessive selected recoverable byte totals fail before the image
scan. Passing this preflight never authorizes extraction: the complete current image
inventory must still be scanned, compared, and globally replanned.

All commands are noninteractive and telemetry-free. In JSON mode, a successful command
emits exactly one JSON object on stdout. Invocation and operational errors emit exactly
one JSON object on stderr. A completed verification with mismatches emits its one result
on stdout and exits nonzero.

Long-running commands may create one new `0600` event-log file. Existing paths are
refused. Each bounded JSONL record identifies its format and version and reports a phase,
throttled progress (including elapsed time, rate, and optional ETA), final completion, or
failure. The event log is an operational aid, not trusted recovery state, and does not
alter the one-result JSON contract.
Event logs must be outside every managed recovery or export directory named by the
command, so operational reporting can never alter an input inventory or pre-create an
output target.

## Stable exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Command completed. Recovery may include safe refusals. |
| 1 | Unexpected internal failure. |
| 2 | Usage error or invalid candidate selection. |
| 3 | Unsafe, mismatched, or observably mutated source. |
| 4 | Invalid or unsupported exFAT volume. |
| 5 | Unsafe output state or destination I/O failure. |
| 6 | Configured work/output/space limit, including `ENOSPC`. |
| 7 | Invalid or untrusted manifest/run/report integrity. |
| 8 | Verification completed and found mismatch or incompleteness. |
| 130 | Cancellation. |

## Recovery meanings

Planner dispositions are `recoverable`, `conflicted`, and `unrecoverable`. Terminal
report dispositions are `recovered`, `conflicted`, and `unrecoverable`.

Successful new and resumed recovery results retain `candidate_count` and `output_bytes`
and include `recovered_count`, `refused_count`, `conflicted_count`, `unrecoverable_count`,
and `failed_count`. These counts cover the run's selected candidates, including previously
completed candidates on resume. `refused_count` is the sum of conflicted and unrecoverable
candidates, and `candidate_count` equals recovered plus refused. Human output presents
the same outcomes immediately. `failed_count` is zero for a completed run: operational
failures abort the command with the existing nonzero error envelope, without a successful
completion result or inferred partial counts. There is no terminal `failed` disposition.

- `recovered` means the tool produced the complete logical byte stream dictated by one
  exact, currently validated metadata allocation plan. For deleted or orphaned metadata,
  it does not mean the bytes are historically authentic or were never overwritten.
- `conflicted` means an exact plan exists, but it conflicts with active/system ownership,
  active allocation state, another plausible recovery candidate, or an unsafe metadata
  host. No file is written.
- `unrecoverable` means no single exact bounded allocation plan can be established. No
  file is written.

RC never emits or publishes a partial file. Bytes from `ValidDataLength` through
`DataLength` are written as zeroes and count as a complete logical recovery. Reports
record source bytes and zero-filled bytes separately.

Recovery basis is a separate, factual enum:

- `active_contiguous_allocated`
- `active_fat_chain_allocated`
- `active_empty`
- `deleted_contiguous_unallocated`
- `deleted_fat_chain_unallocated`
- `deleted_empty`
- `orphan_contiguous_unallocated`
- `orphan_fat_chain_unallocated`
- `orphan_empty`

An in-use entry is active only when reached through the completely validated root
directory tree. An in-use-looking entry found only by the heap pass is an orphan and
uses orphan safety rules. Completely destroyed metadata cannot yield an individual
candidate. The user-facing result is: "No metadata candidate was discoverable. This
does not establish whether additional lost files exist; signature carving is outside RC
scope."

## Exact allocation rules

The active Allocation Bitmap determines whether a cluster is currently allocated. The
active FAT determines non-contiguous chains. `NoFatChain` allocations never consult FAT
entries for their data clusters.

An exact FAT plan contains exactly `ceil(DataLength / cluster_size)` clusters and the
last FAT entry is exactly `0xFFFFFFFF`. `0xFFFFFFF7` is bad. Short, overlong, cyclic,
reserved, invalid-next, truncated-read, overlapping, or work-limited chains are
unrecoverable. FAT cluster numbers need not be numerically ascending. Empty files have no
extents.

Recovery requires:

- an exact root-directory chain;
- exactly `NumberOfFats` valid Allocation Bitmap entries with matching identifiers;
- selection of only the current main-sector `ActiveFat` and its bitmap;
- a valid active bitmap chain, reserved fields, and sufficient `DataLength` for every
  cluster bit;
- exactly one valid Up-case Table, including its chain, checksum, compression, and full
  Unicode mapping;
- valid active filename hashes using that table; and
- no unknown critical root metadata or incomplete active-directory traversal.

Ownership and allocation are distinct. Active ownership accounts for the root,
subdirectories, all bitmap copies, Up-case Table, active file streams, and recognized
allocation-bearing entries including Vendor Allocation entries. Active files require
every planned cluster to be set in the active bitmap and uniquely owned by that file.
Deleted and orphan candidates require every data cluster to be free. Every cluster that
physically hosts an orphan entry set must also be free; metadata in a validated active
directory is exempt from that host rule. Overlap between any plausible deleted/orphan
plans conflicts every participant, whether or not all participants were selected.

`VolumeDirty` and `MediaFailure` are recorded. They never authorize fallback to an
inactive FAT/bitmap or speculative recovery.

## Source and manifest binding

Manifest v1 is never accepted for recovery. Manifest v2 is strict, bounded JSONL with:

- at most 500,000 candidate records, 500,002 total records, and 1 GiB total bytes;
- a maximum 1 MiB line;
- duplicate-key rejection;
- exactly one header and one final completion record;
- no trailing content;
- exact counts, deterministic record order, and a byte-level SHA-256 over all preceding
  lines; and
- no undeclared fields.

Extent arrays are capped at 4,096 extents per candidate. Exceeding that cap is an
unrecoverable plan before output creation.

The v2 source binding includes the regular-image locator, selected-volume byte offset
and length, and a full SHA-256 of the selected exFAT volume. Candidate IDs are full
SHA-256 identifiers derived from that binding, the physical entry offset, and the raw
entry-set SHA-256. Duplicate IDs are invalid.

A completion hash is an integrity check, not authentication. Recovery validates the
complete manifest before creating output. It then rereads the image, requires the exact
complete current candidate inventory to match the manifest, compares all
extraction-relevant metadata and raw entry-set digests, replans every candidate from the
current active FAT and bitmap, and requires an exact match before applying the selected-ID
filter. An omitted overlapping candidate therefore cannot make an extent appear safe.
Manifest extents are never extraction authority by themselves.

Before a manifest writer reports success, it writes and flushes the completion record,
revalidates the source state, then streams the completed manifest once through a held
descriptor to prove its exact emitted bytes and private file state. Publication refuses
a changed source, content, pathname, owner, mode, link count, or identity.

Recovery obtains the full selected-volume SHA-256 before creating output and checks the
same proof again before final completion. The mandatory sequential allocation-area scan
computes that digest from the same bytes in flight, including the bounded regions before
and after the cluster heap, so hashing adds no second full-volume I/O pass. Repeated
requests in one continuously open source session may reuse the in-memory digest only
after exact descriptor-state revalidation. Recovery also checks descriptor identity/stat
state after planning, before and after each candidate, before publishing candidate data,
and before completion. Each recovered record includes the SHA-256 of bytes read through
`ValidDataLength` and the SHA-256 of the complete logical output. Observed change exits 3
without completion.

## Frozen planner boundary

The planner owns these immutable concepts:

```python
@dataclass(frozen=True)
class Extent:
    first_cluster: int
    cluster_count: int


@dataclass(frozen=True)
class RecoveryPlan:
    candidate_id: str
    entry_offset: int
    entry_set_sha256: str
    name: str
    logical_size_bytes: int
    valid_data_bytes: int
    extents: tuple[Extent, ...]
    allocation_mode: Literal["empty", "contiguous", "fat_chain"]
    metadata_location: Literal["active_directory", "deleted_directory", "orphan"]
    disposition: Literal["recoverable", "conflicted", "unrecoverable"]
    recovery_basis: str | None
    reasons: tuple[str, ...]
```

Extraction accepts only `RecoveryPlan` values from the planner. It never consumes raw
manifest candidates or interprets FAT chains independently.

## Resource contract

Planning completes globally before output-directory creation. The implementation charges
every attempted candidate, FAT step, interval, extent, manifest byte/record, and ownership
operation to cumulative budgets before allocation.

Required finite limits include candidates, volume scan clusters, cumulative FAT steps,
extent count per candidate, manifest bytes/records/line bytes, and logical output bytes.
The exFAT `ClusterCount` must equal the specification-defined cluster capacity of the
declared volume (up to the format ceiling). Complete selected-volume hashing, including
the format regions outside the heap, is charged to the scan-cluster work budget after
allowing the mandatory rounded FAT copies, fixed minimum-format region, and final partial
allocation unit; successfully consumed hash chunks receive the same best-effort
cache-release treatment as heap batches.
The scan default is 100,000 candidates. The public discovery limit is configurable from
1 through the hard 500,000-candidate manifest ceiling; it cannot be raised beyond what
the default reader can accept. An operator raising it must explicitly check available
memory; the CLI does not rely on a platform-specific free-memory estimate. Recovery run
descriptors and reports default to a separate 100,000 selected-ID
limit. `--max-selected-candidates` can explicitly raise that limit through the same hard
500,000-candidate ceiling, subject to descriptor and report byte bounds; a manifest's
recorded discovery limit is used when recovery, resume, or image-backed verification
replans it.
The default `--max-output-bytes` is 100 GiB (107374182400 bytes), disclosed in command
help. It is the overflow-safe sum of `DataLength`
for all selected plans whose preflight disposition is recoverable, including zero-filled
bytes. Exceeding it exits 6 without creating output. With a supplied manifest, a total
already exceeding this limit is rejected before scanning; successful preflight is followed
by the same limit check on freshly validated plans. Refused candidates still count toward
the selected-candidate limit but contribute no recoverable output bytes. Disk-space
preflight is advisory; mid-run `ENOSPC` leaves a resumable incomplete run.

An expected regular input/state object is opened nonblocking until its type proof, so a
raced special-file replacement cannot stall the command. Recovered/exported content
readers consume exactly the validated logical size and one EOF probe; concurrent appends
cannot extend their I/O budget.

Planner memory is bounded by the volume bitmap/compact ownership structures and candidate
count, not recovered file size or the total materialized cluster list. Long FAT chains
use bounded algorithms and additional charged passes. Hostile repeated overlaps and
converging chains must terminate deterministically.

## Output durability state machine

New output must not exist. Recovery first creates a deterministic, bounded-name private
bootstrap sibling under the already-open output parent. It stages the exact immutable
manifest and run descriptor plus empty private `records`, `files`, and `work`
directories, then fsyncs and atomically renames that bootstrap directory to the absent
output name with platform no-replace semantics. An interruption before output publication
is retried only by repeating the identical `recover --output` invocation; after output
publication it is resumed only with `--resume`. A target and its bootstrap sibling at the
same time is unsafe ambiguity. A mismatching or unknown bootstrap object is never deleted
or overwritten.

The published output retains an open directory descriptor, and every managed operation is
descriptor-relative with no-follow and exclusive creation. Files are mode `0600`,
directories `0700`, source names never become filesystem path components, and every opened
object is validated for expected type, identity, owner, and link count. Creation and
resume each take a nonblocking exclusive advisory lock on the bootstrap or output
directory and fail closed when another recovery process owns that lock.

```text
OUTPUT/
  run.json
  manifest.jsonl
  records/<candidate-id>.json
  files/<candidate-id>/data
  work/<candidate-id>.partial  # only while an incomplete run is resumable
  report.jsonl                 # exists only after terminal completion
```

`run.json` and the internal manifest are immutable. Run format v2 records source binding,
the exact local source-file state at creation, selection, all effective limits, and format
versions. Format v1 runs remain readable and resumable but carry no reusable source proof.
Every descriptor, checkpoint, and
completion report is first written to a private state temporary, fsynced, and atomically
renamed to its absent final name with platform no-replace semantics. A matching incomplete
state prefix is append-resumable; a mismatching or replaced object is left untouched.

A candidate file is streamed to its fixed run-owned work temporary, hashed, and fsynced.
The source is revalidated, then the complete temporary is atomically renamed to the absent
candidate-ID data path with the same no-replace guarantee. Resume compares every existing
temporary byte with the current exact source plan before appending missing bytes. Atomic
rename consumes the work name without unlinking it; this state machine never deletes or
overwrites a temporary whose identity or contents are uncertain. The candidate and work
directories are fsynced before an immutable candidate checkpoint is published. Each
checkpoint file is individually fsynced; checkpoint-directory entries are flushed in
batches of at most 256. A crash may therefore discard only the latest checkpoint names,
whose already-durable candidate data is safely revalidated and adopted by resume.

A crash after data publication but before checkpoint publication is resumable. Resume
replans and hashes the existing regular file and adopts it only on an exact match. It
refuses changed descriptors, manifests, selections, limits, checkpoint order/content,
symlinks, special files, unknown hard links, or altered completed files. Completion is a
deterministic `report.jsonl`, ending with a hash/count record covering the immutable run,
manifest binding, and every candidate checkpoint. It is published last after all data,
records, and directories are durable. After completion, resume is a validating no-op.
Recovery performs one full content proof of each output after publishing or adopting it,
then carries the resulting exact file-state proof through completion. The pre-report and
post-publication boundaries reopen each output and require the exact same device, inode,
mode, link count, owner, size, modification time, and change time without redundantly
rereading its content. Any replacement or mutation fails completion when it remains
present at a subsequent state boundary.

These portable file-state checks do not claim an atomic snapshot of a directory tree.
Recovery directories are private (`0700` directories and `0600` files), and commands
hold the run lock to exclude cooperating writers. A privileged process or a
noncooperating process running as the same effective user can still rewrite and revert
different files between any finite sequence of checks; that actively adversarial writer
is outside the completion guarantee. Persistent changes, namespace moves, and mutations
at the tested content/state boundaries fail closed, and a later `verify` detects
post-completion content tampering.

Fault-injection tests cover every write, short write, flush, fsync, publish, checkpoint,
and completion boundary.

## Verification claims

`verify OUTPUT_DIRECTORY` validates run and manifest integrity, completion and report
order/count/hash, the exact expected inventory, every recovered file's regular/no-follow/
no-unknown-hardlink state, logical size, SHA-256, and zero-filled byte count. It claims
only internal/output integrity. An incomplete run is a completed verification failure
(exit 8), not malformed invocation.
Each output's bytes are read once for that hash/zero-tail proof. The final inventory
boundary reuses the exact held file-state proof and refuses a mutation or replacement
present at its subsequent state checks instead of performing a redundant second content
read. The same noncooperating-writer scope above applies.

`verify OUTPUT_DIRECTORY --image IMAGE` additionally opens the image read-only, validates
the full source/volume binding, requires the complete current candidate inventory to match
the manifest, and replans every manifest candidate before validating the selected recovery
records. It compares current source bytes through `ValidDataLength` to each recorded
source-data SHA-256 and proves output bytes from `ValidDataLength` through `DataLength` are
zero. It still does not constitute a digital signature against an attacker able to rewrite
both reports and files.

`verify-set OUTPUT_DIRECTORY ... --image IMAGE` applies the same image-backed claim to
multiple completed outputs that share byte-identical manifests and identical scan/planner
limits. Candidate selections must be disjoint. It performs the complete current image
inventory and global manifest replan once, then validates every output and compares each
selected recovery's current source bytes to its checkpoint. Reusing that immutable global
proof must not weaken any individual output inventory, hash, zero-tail, or source-byte
check. Before any recovered-content read or whole-image scan, it preflights every output's
run, manifest, completion report, exact checkpoint bytes, and bounded directory and file
shape, proves set compatibility and disjointness, and rejects an image whose size cannot
match the runs. The number of set outputs is bounded by the recovery-candidate ceiling;
after byte-comparing manifests, preflight retains only compact per-candidate facts.

`export OUTPUT_DIRECTORY --destination NEW_DIRECTORY` first applies strict structural
output preflight. It then copies each recovered stream through held no-follow descriptors,
using the copy pass to prove its SHA-256, source-data prefix, and mandatory zero-filled
tail against the recovery report. Before cataloging, it reads each completed destination
once through that held descriptor and proves the same full-output hash, source-data
prefix, and zero-filled tail. It also reads the completed catalog through its held
descriptor before its publication proof. Export names are sanitized basenames suffixed by the
full candidate ID, so source names are never interpreted as paths and collisions are
impossible. A final hashed `catalog.jsonl` binds the run, original metadata names,
exported paths, byte counts, output hashes, conservative content signatures, and
extension-consistency observations. The files and catalog are built in a deterministic
private sibling staging directory; exact file state is checked before a no-replace atomic
rename publishes the entire directory at the requested path, then checked again through
the held descriptors before success. An interrupted or failed
copy before that rename leaves the requested path absent and may preserve the hidden
staging directory, including a completed internal catalog when failure happened late. A
durability or identity failure after the rename may leave a complete requested directory
that a retry safely refuses. A pre-existing or racing foreign destination is left
untouched. Failed export is never reported complete. Content signatures do not establish
historical authenticity.

One continuously open `ImageSource` may retain the full selected-volume SHA-256 in memory
and reuse it at later internal safety boundaries only after revalidating descriptor state.
`recover --resume` may seed that digest from a private immutable v2 run only when device,
inode, file mode, link count, owner, size, modification time, and change time exactly
match the reopened regular image. The mandatory scan always recomputes the complete
digest and rejects a seeded conflict, so the state proof saves no content validation and
is not authentication. The complete metadata inventory is still rescanned and replanned.
Image-backed `verify` and `verify-set` always perform an independent full hash during
their own scan and never consume the resume proof.

## Release gates

Every recovery-basis class has an exact-byte positive test. Every refusal reason has a
negative test. Fault injection proves safe resume at every durability boundary. Peak RSS
is tested against substantially different logical file sizes with a fixed allowed delta.
Release requires passing Linux/macOS CI, version-recorded tests with native exFAT
formatters, including a populated image that is quick-formatted again and must yield the
exact known bytes of both a deleted file and a former active file. These cases use native
filesystem writes and formatting, without manually rewriting allocation metadata. The
release also requires reproducible wheel and sdist builds and the recovery validation
required for the exact release commit. A signed tag and release review are required before any public
package publication.
