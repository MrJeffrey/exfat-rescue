# exfat-rescue

`exfat-rescue` recovers files from exFAT disk images on **Linux and macOS**, using
surviving filesystem metadata to validate each file's allocation. It opens the image
read-only and writes recovered files to a new directory.

This release candidate supports active, deleted, and orphaned file metadata. A quick
format may leave enough metadata and data intact for recovery, but success depends on
what survived. Ambiguous allocations are refused. Recovered deleted or orphaned bytes
are not proof of the file's original contents; overwritten data cannot be restored.

## Before you begin

1. Stop writing to the affected drive. Do not install software or save output onto it.
2. Create a sector image on a different physical disk with an established imaging tool
   such as [GNU ddrescue](https://www.gnu.org/software/ddrescue/).
3. Work on that stable image. Keep manifests, logs, and recovered files on healthy
   storage, with enough free space for recovery and an additional copy if exporting.

Python **3.11 or newer** and Linux or macOS are required. Windows is unsupported.
Only regular image files are accepted; live devices and symlink sources are refused.
This tool does not image drives, carve file signatures, or repair file contents.

## Install

For the current development checkout, with
[pipx](https://pipx.pypa.io/stable/installation/) available:

```sh
git clone https://github.com/MrJeffrey/exfat-rescue.git
cd exfat-rescue
pipx install .
```

The package is not published on PyPI. Tagged source-install instructions are published
with an approved release.

## Recover and export

Run these commands from a directory on healthy storage. Replace `/path/to/drive.img`
with your image path. Both output directory names must be unused.

```sh
exfat-rescue inspect /path/to/drive.img
exfat-rescue recover /path/to/drive.img --output recovered
exfat-rescue export recovered --destination recovered-by-name
```

Recovery scans the image, validates the complete metadata inventory, and saves its
manifest and per-file report inside `recovered`. The completion message reports how
many files were recovered, refused, or failed. Refused candidates produce no file; their reasons
are recorded in `recovered/report.jsonl`. A completed command can include safe refusals.
Operational errors stop the run and exit nonzero instead of reporting completion.

Export creates a separate copy with recognizable, sanitized filenames and a catalog.
Keep the original recovery directory intact for verification or resume. To check it
later, including its source binding:

```sh
exfat-rescue verify recovered --image /path/to/drive.img
```

If recovery is interrupted, resume the same run with
`exfat-rescue recover /path/to/drive.img --resume recovered`.

Recovery defaults to **100,000 selected candidates and 100 GiB of logical output**.
A full scan reads the selected volume and can take substantial time on a large image.
See [alternative workflows](docs/USAGE.md) for a separate manifest, candidate selection,
larger limits, JSON output, and event logs. Each example is an alternative, not another
step in the workflow above.

## Supported images

- An exFAT partition image.
- An MBR whole-disk image containing one exFAT primary partition.
- A GPT whole-disk image with 512-byte logical sectors and one exFAT partition.

Images with multiple discoverable exFAT volumes are refused; provide a separate image
of the desired partition. When metadata is destroyed, tools such as
[TestDisk/PhotoRec](https://www.cgsecurity.org/) offer other recovery approaches.

## Documentation

- [Usage and alternative workflows](docs/USAGE.md)
- [Commands, manifests, limits, and architecture](docs/REFERENCE.md)
- [Recovery contract](docs/RC_RECOVERY_CONTRACT.md)
- [Performance](docs/PERFORMANCE.md)
- [Contributing](CONTRIBUTING.md) and [security](SECURITY.md)

There is no telemetry. Use synthetic examples when reporting problems; do not upload
disk images, recovered files, or private metadata to public issues.

## License

Licensed under [Apache-2.0](LICENSE). Third-party attributions are in [NOTICE](NOTICE).
