"""Exception types that map directly to CLI exit codes.

See .chief/milestone-1/_contract/01-cli-interface.md for the exit code table.
"""


class UsageError(Exception):
    """Bad CLI usage or missing/invalid configuration. Maps to exit code 3."""


class PreconditionError(Exception):
    """A precondition failed before any write happened. Maps to exit code 2."""
