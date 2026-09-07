# Usage and alternative workflows

Complete the [safe prerequisites and installation](../README.md#before-you-begin) first.
The examples below are alternatives. Use fresh manifest, output, export, and event-log
paths for each new run; existing paths are never overwritten. Replace the image path
with your own and run from healthy storage away from the affected drive.

## Review a manifest before recovery

```sh
exfat-rescue scan /path/to/drive.img --manifest candidates.jsonl
exfat-rescue recover /path/to/drive.img --manifest candidates.jsonl --output recovered-from-manifest
```

Review the JSONL manifest between commands if you want to choose files. To recover
only selected candidates, add `--candidate-id FULL_ID` to the recovery command, repeating
the option for each full candidate ID from the manifest. Do not edit the manifest.
Recovery still scans and replans the complete image inventory before extracting a
selection. Selection and output-limit errors evident in a valid manifest are rejected
before that scan begins.

## Larger recovery

After checking available memory and destination space, this alternative permits up to
500,000 discovered and selected candidates, with a **1 TiB** logical output ceiling:

```sh
exfat-rescue recover /path/to/drive.img --output recovered-large \
  --max-candidates 500000 --max-selected-candidates 500000 \
  --max-output-bytes 1099511627776 --event-log recovery-large.events.jsonl
```

The default byte ceiling is **100 GiB (107374182400 bytes)**, independent of the candidate
limits. `--max-output-bytes` takes a positive integer in bytes. Raising a ceiling does
not allocate that amount in advance and does not guarantee that the destination has
enough space. Export needs space for another copy.

The default scan budget is 50,000,000 allocation units; inspect the image geometry and
available resources before raising `--max-scan-clusters`. Discovery and selection each
have a hard ceiling of 500,000 candidates. More details are in the
[reference](REFERENCE.md#manifests-limits-and-recovery-state).

## JSON and progress

Add `--json` to a command for one machine-readable result. For example, this is a
separate scan using its own new manifest:

```sh
exfat-rescue scan /path/to/drive.img --manifest candidates-json.jsonl --json
```

Successful results go to stdout. Invocation and operational errors go to stderr and
exit nonzero. A completed verification with mismatches reports its result on stdout
and exits nonzero. Check the process exit status and `ok`, rather than parsing human
messages. [Exit codes and format details](REFERENCE.md) describe the full contract.

Human progress goes to stderr. For persistent phase, rate, and ETA events, use
`--event-log NEW_FILE.jsonl` with `scan`, `recover`, `verify`, `verify-set`, or `export`.
Keep the event log outside managed recovery and export directories.

## Resume and verify

Resume uses the original run's immutable selection, manifest, and limits. Do not pass
replacement selections, manifests, or limits:

```sh
exfat-rescue recover /path/to/drive.img --resume recovered
```

A successful recovery includes source and output integrity checks. For a later audit,
`exfat-rescue verify recovered` checks the completed output; add
`--image /path/to/drive.img` to revalidate the source and metadata too.

If you have already created multiple runs from the same exact manifest with disjoint
candidate selections, verify them with one shared image scan:

```sh
exfat-rescue verify-set recovered-part-1 recovered-part-2 --image /path/to/drive.img
```

Those directories must already exist and satisfy the shared-manifest and disjoint-selection
requirements. Prefer one adequately bounded recovery over splitting a new job into
many small runs.
