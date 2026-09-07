# Performance contract

`exfat-rescue` treats whole-image reads and durable metadata operations as explicit
budgets. Wall-clock assertions are intentionally avoided because disk, filesystem, and
cache behavior varies; tests count the expensive operations directly.

## Full-volume pass budget

| Command | Additional full-volume I/O passes for SHA-256 | Notes |
| --- | ---: | --- |
| new `recover` | 0 | The mandatory sequential cluster scan hashes the same bytes in flight; no standalone full-volume reread occurs. |
| unchanged `recover --resume` (run v2) | 0 | Exact local file-state proof is checked against the digest recomputed by the mandatory scan. |
| changed or relocated `recover --resume` | 0 | The mandatory scan recomputes the digest from source content instead of trusting stale proof. |
| `verify --image` | 0 | Independent verification recomputes the digest during its mandatory scan. |
| `verify-set --image` | 0 for the entire set | Outputs share one scan/replan and must have disjoint selections. |

Every command above still performs one mandatory sequential pass over the allocation
area. That pass detects orphan entries and recomputes the selected-volume content proof
at the same time. Its 32-byte-aligned entry-type lane is searched in the C-backed regular
expression engine, so Python parsing runs only for actual File entry markers rather than
every possible metadata slot. Contiguous clusters are read in bounded runs of up to 4 MiB
while orphan parsing uses only a fixed 576-byte bridge across adjacent cluster boundaries,
preventing small-cluster images from turning the sequential pass into millions of
individual source operations. Reads of selected recovered extents are additional,
purposeful I/O. On platforms that support
`POSIX_FADV_DONTNEED`, each consumed heap batch and each completed non-heap hash chunk is
released from the page cache. The exFAT `ClusterCount` geometry invariant is enforced and
the complete selected-volume byte work is charged to the configured scan limit after
allowing the mandatory rounded FAT copies, minimum format region, and final partial
allocation unit, so extra alignment space cannot create an unbounded hidden hash pass. This
keeps one-pass image data from driving a memory-constrained process into direct reclaim;
the hint is best-effort and does not change source-validation semantics.

## Output and checkpoint budget

- Manifest publication reads the completed manifest once through its held descriptor to
  prove the exact emitted bytes after the final source-state check. This is bounded by the
  1 GiB manifest ceiling and does not reread the image.
- Candidate publication reads each new output once to prove the atomic publication and
  retains the resulting exact file-state proof. Resume likewise retains the proof from
  its required content validation of each checkpointed or adopted output.
- Recovery completion carries those content-bound proofs forward and checks exact device,
  inode, mode, link-count, owner, size, modification-time, and change-time state at its
  pre-report and post-report boundaries. It does not reread all bytes.
- Output verification checks each file's hash and zero tail once, then uses the same exact
  file-state proof for its final inventory boundary. Successfully consumed output ranges
  are released from the page cache where the platform supports it.
- Recovered/exported readers request exactly the validated logical length plus one EOF
  probe, so a concurrent append cannot turn any content proof into an unbounded pass.
- Export structurally preflights the recovery, then hashes each recovered input only while
  copying it; that same pass verifies the source-data prefix and mandatory zero tail. It
  reads each completed destination once through its held descriptor to prove the same
  full-output hash, prefix, and tail before cataloging. Exact file-state proofs are
  retained, and the completed staging directory is atomically published only after its
  final proof.
- Each checkpoint file is fsynced. The checkpoint directory is fsynced once per 256
  candidates and once for a nonempty tail. Candidate data is durable first, so resume can
  reconstruct tail checkpoints lost in a crash.
- Recovery, image-backed verification, and export release successfully consumed source
  and output ranges after hashing or durable copy. Advisory failure never weakens or
  prevents the corresponding integrity check.

## Large-image workflow

Prefer one adequately bounded `recover` command over many small batches. Use
`--max-selected-candidates` only after reviewing the candidate count and available space,
and use `--event-log` for persistent rate and ETA updates. A successful recovery already
performs source binding, complete metadata replan, extraction hashes, and output
completion checks. Run image-backed verification later as an independent audit; use
`verify-set` when existing work is necessarily split across compatible output runs.
`verify-set` rejects incompatible manifests, planner limits, overlapping selections,
malformed reports or checkpoints, invalid completed inventories or recovered-file shape,
and a wrong image size for the entire bounded set before its single expensive image scan
or any recovered-file content pass. It releases each compared raw manifest and retains
only compact per-candidate structural facts for this preflight.

The deterministic regression tests cover the pass counts above, unchanged-source resume,
shared set verification, output content-pass reuse, checkpoint flush batching, progress
events, and the 500,000-candidate framing ceiling.
