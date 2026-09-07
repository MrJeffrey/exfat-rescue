class RescueError(Exception):
    """A calm, actionable error expected at the command line."""

    exit_code = 1
    error_code = "internal_error"


class UsageError(RescueError):
    """A syntactically valid invocation contains an invalid selection or option mix."""

    exit_code = 2
    error_code = "usage_error"


class SourceError(RescueError):
    exit_code = 3
    error_code = "unsafe_source"


class FormatError(RescueError):
    exit_code = 4
    error_code = "invalid_exfat_image"


class OutputError(RescueError):
    exit_code = 5
    error_code = "unsafe_output"


class ResourceLimitError(RescueError):
    exit_code = 6
    error_code = "resource_limit"


class ManifestError(RescueError):
    """A manifest, descriptor, or report failed its integrity checks."""

    exit_code = 7
    error_code = "invalid_manifest"


class VerificationError(RescueError):
    """A completed verification found an incomplete or altered recovery run."""

    exit_code = 8
    error_code = "verification_failed"
