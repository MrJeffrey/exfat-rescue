#!/usr/bin/env bash
# Exercise the public CLI against a freshly tool-formatted, disposable exFAT image.
#
# This deliberately uses only a private temporary image and a temporary attachment.
# It never enumerates or touches physical block devices.
set -euo pipefail

umask 077
readonly SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
readonly REPOSITORY_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
readonly PYTHON_BIN="${PYTHON_BIN:-python3}"
readonly KEEP_ARTIFACTS="${EXFAT_RESCUE_INTEGRATION_KEEP:-0}"

scratch_root="$REPOSITORY_ROOT/.scratch/native-exfat-integration"
mkdir -p "$scratch_root"
tmp_root="$(TMPDIR="$scratch_root" mktemp -d "$scratch_root/exfat-rescue-real.XXXXXXXX")"
image="$tmp_root/disposable-exfat.img"
mount_root="$tmp_root/mount"
manifest="$tmp_root/candidates.jsonl"
output="$tmp_root/recovered"
resume_output="$tmp_root/resume-output"
reformat_manifest="$tmp_root/reformat-candidates.jsonl"
reformat_output="$tmp_root/reformat-recovered"
image_device=""
mounted=0

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    set +e
    if [ "$mounted" -eq 1 ]; then
        if [ "$(uname -s)" = "Darwin" ]; then
            /sbin/umount "$mount_root" >/dev/null 2>&1 || true
        else
            sudo umount "$mount_root" >/dev/null 2>&1 || true
        fi
    fi
    if [ -n "$image_device" ]; then
        if [ "$(uname -s)" = "Darwin" ]; then
            /usr/bin/hdiutil detach "$image_device" -force >/dev/null 2>&1 || true
        else
            sudo losetup --detach "$image_device" >/dev/null 2>&1 || true
        fi
    fi
    if [ "$KEEP_ARTIFACTS" = "1" ]; then
        printf 'Retained disposable integration artifacts: %s\n' "$tmp_root" >&2
    else
        rm -rf -- "$tmp_root"
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        printf 'Missing required integration command: %s\n' "$1" >&2
        exit 77
    }
}

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

native_formatter_evidence() {
    case "$(uname -s)" in
        Darwin)
            printf 'Native formatter: newfs_exfat (%s)\n' "$(sw_vers -productVersion)"
            ;;
        Linux)
            # exfatprogs 1.2.2 prints its version with status 1. Formatting below
            # remains a separate command whose failure always stops the test.
            local version_status=0
            mkfs.exfat -V >&2 || version_status=$?
            [ "$version_status" -le 1 ]
            ;;
    esac
}

settle_native_mount() {
    # macOS may create its private volume-event directory immediately after a new
    # filesystem is mounted.  Let that native bookkeeping allocate first, before the
    # proof files reserve their clusters.
    if [ "$(uname -s)" = "Darwin" ]; then
        sync
        sleep 1
    fi
}

attach_image() {
    case "$(uname -s)" in
        Darwin)
            require_command hdiutil
            require_command newfs_exfat
            # A raw image is attached explicitly as CRawDiskImage, so the image given
            # to exfat-rescue starts at the exFAT boot sector rather than a UDIF header.
            image_device="$(hdiutil attach -nobrowse -nomount \
                -imagekey diskimage-class=CRawDiskImage "$image" \
                | awk '/^\/dev\// {print $1; exit}')"
            [ -n "$image_device" ] || {
                printf 'Could not attach private raw integration image.\n' >&2
                exit 1
            }
            ;;
        Linux)
            require_command mkfs.exfat
            require_command mount.exfat-fuse
            require_command losetup
            require_command umount
            require_command sudo
            # GitHub's Linux runner kernel does not guarantee an exFAT module.  Use
            # the independently implemented userspace driver against a private loop
            # mapping, then release both in the trap.
            image_device="$(sudo losetup --find --show "$image")"
            ;;
        *)
            printf 'Unsupported integration platform: %s\n' "$(uname -s)" >&2
            exit 77
            ;;
    esac
}

format_mapped_image() {
    local label="$1"
    case "$(uname -s)" in
        Darwin)
            # Do not pass -R: newfs_exfat preserves the existing raw-image geometry,
            # while the default format resets only filesystem metadata.
            /sbin/newfs_exfat -v "$label" "/dev/r${image_device#/dev/}" >/dev/null
            ;;
        Linux)
            # mkfs.exfat defaults to a quick format, leaving non-metadata clusters
            # available for the reformat recovery case below.
            sudo mkfs.exfat -n "$label" "$image_device" >/dev/null
            ;;
    esac
}

mount_image() {
    case "$(uname -s)" in
        Darwin)
            /sbin/mount_exfat "$image_device" "$mount_root"
            ;;
        Linux)
            sudo mount.exfat-fuse "$image_device" "$mount_root"
            ;;
    esac
    mounted=1
}

create_format_and_mount() {
    mkdir "$mount_root"
    case "$(uname -s)" in
        Darwin) mkfile -n 64m "$image" ;;
        Linux) truncate -s 64M "$image" ;;
    esac
    attach_image
    native_formatter_evidence
    format_mapped_image EXFATRC
    mount_image
    settle_native_mount
}

unmount_image() {
    if [ "$mounted" -eq 1 ]; then
        if [ "$(uname -s)" = "Darwin" ]; then
            /sbin/umount "$mount_root"
        else
            sudo umount "$mount_root"
        fi
        mounted=0
    fi
    if [ -n "$image_device" ]; then
        if [ "$(uname -s)" = "Darwin" ]; then
            /usr/bin/hdiutil detach "$image_device" >/dev/null
        else
            sudo losetup --detach "$image_device"
        fi
        image_device=""
    fi
}

create_format_and_mount
printf 'active payload\nwith exact bytes\n' > "$mount_root/active.txt"
active_sha="$(hash_file "$mount_root/active.txt")"
# Place this directory and all proof data beyond quick-format metadata allocation.
# The tail keeps the deleted set before an EOD marker during the healthy-phase scan.
dd if=/dev/zero of="$mount_root/filler.bin" bs=1048576 count=8 status=none
mkdir "$mount_root/reformat-proof"
printf 'quick reformat payload\nwith exact bytes\n' > "$mount_root/reformat-proof/reformat-target.txt"
printf 'deleted payload\nwith exact bytes\n' > "$mount_root/reformat-proof/deleted.txt"
reformat_sha="$(hash_file "$mount_root/reformat-proof/reformat-target.txt")"
deleted_sha="$(hash_file "$mount_root/reformat-proof/deleted.txt")"
printf 'directory tail\n' > "$mount_root/reformat-proof/after-deletion.txt"
rm "$mount_root/reformat-proof/deleted.txt"
sync
unmount_image

image_sha_before="$(hash_file "$image")"
cd "$REPOSITORY_ROOT"
"$PYTHON_BIN" -m exfat_rescue.cli scan "$image" --manifest "$manifest" --json > "$tmp_root/scan.json"
"$PYTHON_BIN" -m exfat_rescue.cli recover "$image" --manifest "$manifest" --output "$output" --json > "$tmp_root/recover.json"
"$PYTHON_BIN" -m exfat_rescue.cli verify "$output" --image "$image" --json > "$tmp_root/verify.json"
image_sha_after="$(hash_file "$image")"
[ "$image_sha_before" = "$image_sha_after" ] || {
    printf 'Integration image changed during read-only CLI operations.\n' >&2
    exit 1
}

"$PYTHON_BIN" - "$manifest" "$output" active.txt "$active_sha" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

manifest_path = Path(sys.argv[1])
output_root = Path(sys.argv[2])
expected = dict(zip(sys.argv[3::2], sys.argv[4::2], strict=True))

manifest_records = [json.loads(line) for line in manifest_path.read_text().splitlines()]
names = {
    record["candidate_id"]: record["source_candidate"]["name"]
    for record in manifest_records
    if record.get("record_type") == "candidate"
}
report_records = [
    json.loads(line) for line in (output_root / "report.jsonl").read_text().splitlines()
]
recovered = {}
for record in report_records:
    if record.get("record_type") != "candidate" or record.get("disposition") != "recovered":
        continue
    candidate_id = record["candidate_id"]
    payload = output_root / "files" / candidate_id / "data"
    recovered[names[candidate_id]] = hashlib.sha256(payload.read_bytes()).hexdigest()

for name, expected_sha in expected.items():
    if name not in names.values():
        raise SystemExit(f"{name} was not discovered in the native image")
    if recovered.get(name) != expected_sha:
        raise SystemExit(f"{name} was not recovered with its exact SHA-256")
PY

# A copied completed run becomes detectably incomplete when only its final report is
# removed. Resume must validate its immutable state and republish that final record.
cp -R "$output" "$resume_output"
rm "$resume_output/report.jsonl"
"$PYTHON_BIN" -m exfat_rescue.cli recover "$image" --resume "$resume_output" --json > "$tmp_root/resume.json"
"$PYTHON_BIN" -m exfat_rescue.cli verify "$resume_output" --image "$image" --json > "$tmp_root/resume-verify.json"
image_sha_resume="$(hash_file "$image")"
[ "$image_sha_before" = "$image_sha_resume" ] || {
    printf 'Integration image changed during resume or verification.\n' >&2
    exit 1
}

# Reformat the populated private image using the same platform-native formatter.  The
# old proof directory lies after the filler allocation and is therefore discovered by
# the heap scan as orphaned metadata after the new root directory is initialized.
attach_image
format_mapped_image EXFATREFMT
unmount_image

reformat_image_sha_before="$(hash_file "$image")"
"$PYTHON_BIN" -m exfat_rescue.cli scan "$image" --manifest "$reformat_manifest" --json > "$tmp_root/reformat-scan.json"
"$PYTHON_BIN" -m exfat_rescue.cli recover "$image" --manifest "$reformat_manifest" --output "$reformat_output" --json > "$tmp_root/reformat-recover.json"
"$PYTHON_BIN" -m exfat_rescue.cli verify "$reformat_output" --image "$image" --json > "$tmp_root/reformat-verify.json"
reformat_image_sha_after="$(hash_file "$image")"
[ "$reformat_image_sha_before" = "$reformat_image_sha_after" ] || {
    printf 'Reformatted integration image changed during read-only CLI operations.\n' >&2
    exit 1
}

"$PYTHON_BIN" - "$reformat_manifest" "$reformat_output" reformat-target.txt "$reformat_sha" deleted.txt "$deleted_sha" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

manifest_path = Path(sys.argv[1])
output_root = Path(sys.argv[2])
expected = {
    sys.argv[3]: (sys.argv[4], False),
    sys.argv[5]: (sys.argv[6], True),
}

manifest_candidates = [
    record
    for record in (json.loads(line) for line in manifest_path.read_text().splitlines())
    if record.get("record_type") == "candidate"
]

report_records = [
    json.loads(line) for line in (output_root / "report.jsonl").read_text().splitlines()
]
reports = {
    record["candidate_id"]: record
    for record in report_records
    if record.get("record_type") == "candidate"
}
for name, (expected_sha, expected_deleted) in expected.items():
    candidates = [
        record for record in manifest_candidates
        if record["source_candidate"]["name"] == name
    ]
    if len(candidates) != 1:
        raise SystemExit(f"{name} was not uniquely discovered after native quick reformat")
    candidate = candidates[0]
    if candidate["source_candidate"]["deleted"] is not expected_deleted:
        raise SystemExit(f"{name} did not retain its expected deletion state")
    if candidate["recovery_basis"] != "orphan_contiguous_unallocated":
        raise SystemExit(f"{name} did not have an unallocated orphan recovery basis")
    report = reports.get(candidate["candidate_id"])
    if report is None or report.get("disposition") != "recovered":
        raise SystemExit(f"{name} was not recovered after native quick reformat")
    payload = output_root / "files" / candidate["candidate_id"] / "data"
    if hashlib.sha256(payload.read_bytes()).hexdigest() != expected_sha:
        raise SystemExit(f"{name} was not recovered with its exact SHA-256 after native quick reformat")
PY

printf 'Real exFAT integration passed (%s).\n' "$(uname -s)"
