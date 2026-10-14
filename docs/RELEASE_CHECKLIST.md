# 0.2.0rc1 source prerelease checklist

This release is a source-only GitHub prerelease. PyPI publication, uploaded build
artifacts, tag signing, and an additional large-media recovery trial are outside its
scope. Build and installed-wheel checks remain required because Git installation builds
the package.

1. Prepare the release notes and finalize the changelog and version before selecting the
   release commit. Confirm README commands and the recovery contract match the candidate.
   Check tracked files and reachable commit metadata for private data; keep recovery
   images, recovered files, logs, and private validation records out of the repository.
   Before changing visibility, also review retained Actions runs, logs and artifacts,
   issues, and pull requests for private data; resolve any exposure before proceeding.
2. Record the final candidate SHA after review and any merge. Manually run
   `gh workflow run ci.yml --ref <release-branch> -f profile=release` from a branch pointing
   at that SHA. Require all nine jobs to pass: six Linux/macOS Python jobs, the Windows
   unsupported-platform job, and two native exFAT integration jobs. Verify the completed
   run's `head_sha` matches. Any later commit requires validation of the new candidate.
3. Retain the workflow's reproducible builds, license and distribution inspection, and
   clean installed-wheel tests as validation. Do not attach those build artifacts to this
   source release. Routine `quick` CI does not satisfy the release gate.
4. Obtain explicit approval for the exact validated commit before making the repository
   public, creating the release tag, or publishing the GitHub prerelease. At the public
   transition, require the routine `ubuntu-latest / Python 3.11` check on `main` and enable
   private vulnerability reporting. Confirm the security-reporting link works.
5. Create an annotated `v0.2.0rc1` tag at the approved SHA and a GitHub prerelease without
   uploaded assets. Include this source-install command in the release notes:

   ```sh
   pipx install 'git+https://github.com/MrJeffrey/exfat-rescue.git@v0.2.0rc1'
   ```

6. Before announcing the release, verify anonymous repository access, cloning and
   installation from the tag, schema links, and the repository description and topics.
