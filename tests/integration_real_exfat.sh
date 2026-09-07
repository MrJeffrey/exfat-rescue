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

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/exfat-rescue-real.XXXXXXXX")"
image="$tmp_root/disposable-exfat.img"
mount_root="$tmp_root/mount"
manifest="$tmp_root/candidates.jsonl"
output="$tmp_root/recovered"
resume_output="$tmp_root/resume-output"
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

format_and_mount() {
    mkdir "$mount_root"
    case "$(uname -s)" in
        Darwin)
            require_command hdiutil
            require_command newfs_exfat
            # A raw image is attached explicitly as CRawDiskImage, so the image given
            # to exfat-rescue starts at the exFAT boot sector rather than a UDIF header.
            mkfile -n 64m "$image"
            image_device="$(hdiutil attach -nobrowse -nomount \
                -imagekey diskimage-class=CRawDiskImage "$image" \
                | awk '/^\/dev\// {print $1; exit}')"
            [ -n "$image_device" ] || {
                printf 'Could not attach private raw integration image.\n' >&2
                exit 1
            }
            /sbin/newfs_exfat -v EXFATRC "$image_device" >/dev/null
            /sbin/mount_exfat "$image_device" "$mount_root"
            ;;
        Linux)
            require_command mkfs.exfat
            require_command mount.exfat-fuse
            require_command losetup
            require_command umount
            require_command sudo
            truncate -s 64M "$image"
            mkfs.exfat -n EXFATRC "$image" >/dev/null
            # GitHub's Linux runner kernel does not guarantee an exFAT module.  Use
            # the independently implemented userspace driver against a private loop
            # mapping, then release both in the trap.
            image_device="$(sudo losetup --find --show "$image")"
            sudo mount.exfat-fuse "$image_device" "$mount_root"
            ;;
        *)
            printf 'Unsupported integration platform: %s\n' "$(uname -s)" >&2
            exit 77
            ;;
    esac
    mounted=1
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

format_and_mount
printf 'active payload\nwith exact bytes\n' > "$mount_root/active.txt"
printf 'deleted payload\nwith exact bytes\n' > "$mount_root/deleted.txt"
active_sha="$(hash_file "$mount_root/active.txt")"
deleted_sha="$(hash_file "$mount_root/deleted.txt")"
# Keep a later live entry so removal cannot turn the deleted entry's former slot into
# a terminal end-of-directory marker on implementations that compact directory tails.
printf 'directory tail\n' > "$mount_root/after-deletion.txt"
rm "$mount_root/deleted.txt"
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

"$PYTHON_BIN" - "$manifest" "$output" "$active_sha" "$deleted_sha" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

manifest_path = Path(sys.argv[1])
output_root = Path(sys.argv[2])
expected = {"active.txt": sys.argv[3], "deleted.txt": sys.argv[4]}

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

if recovered.get("active.txt") != expected["active.txt"]:
    raise SystemExit("active.txt was not recovered with its exact SHA-256")

# Native formatters differ in whether deletion retains a complete entry set.  If it
# survives and is recoverable, require an exact recovery; if it was erased or safely
# refused, report that outcome rather than making the host filesystem's deletion
# implementation a false product failure.
deleted_id = next(
    (candidate_id for candidate_id, name in names.items() if name == "deleted.txt"),
    None,
)
if deleted_id is None:
    print("deleted entry metadata was not retained by this formatter")
elif deleted_id in {
    record["candidate_id"]
    for record in report_records
    if record.get("record_type") == "candidate"
    and record.get("disposition") == "recovered"
}:
    if recovered.get("deleted.txt") != expected["deleted.txt"]:
        raise SystemExit("deleted.txt was not recovered with its exact SHA-256")
else:
    print("deleted entry was safely refused by the recovery planner")
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

printf 'Real exFAT integration passed (%s).\n' "$(uname -s)"
