# Release checklist

1. Confirm the default branch is protected and every required CI job is green.
2. Run the full hostile-input and synthetic-fixture suite on Linux and macOS.
3. Derive a numeric `SOURCE_DATE_EPOCH` from the release commit, build the sdist and
   wheel twice, and byte-compare each pair. Run `twine check --strict`, inspect their
   contents, and install the wheel in a clean environment outside the source tree.
4. Confirm README claims match the shipped commands and update `CHANGELOG.md`.
5. Confirm the wheel and sdist each contain the verbatim Apache-2.0 `LICENSE` and `NOTICE`
   preserving the sd-recovery MIT notice; confirm package metadata reports Apache-2.0.
   Confirm `SECURITY.md`, issue forms, and schemas are present and contain no private
   recovery data.
6. Confirm Dependabot, secret scanning, push protection, private vulnerability reporting,
   and required pull-request checks are enabled.
7. Complete the required recovery validation and approval for the exact release commit.
   Keep recovery images, recovered data, and other private material out of public release
   artifacts.
8. Create a signed release tag from the approved commit.
9. Verify the public clone URL, Git installation, schema URL, topics, description, and
   logged-out repository access before announcing source availability.
10. If publishing to PyPI, use trusted publishing after a separate release review; never
    store an API token in GitHub. Verify wheel installation from PyPI before announcing it.
