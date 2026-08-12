"""Reads and validates the --idp-secrets file: JSON, alias -> secret.

See .chief/milestone-2/_contract/02-idp-mapping.md's "The secrets file".
Exit-code split confirmed against .chief/milestone-2/_contract/03-cli-and-report-extensions.md
and reconciled with 02's explicit statements: group/world-readable and
malformed content are usage errors an operator must fix (exit 3), while a
missing or otherwise unreadable file is a precondition failure (exit 2) --
see the amendment in 03 for the reconciliation.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

from kc2ak.errors import PreconditionError, UsageError
from kc2ak.redact import register_secret


def read_idp_secrets(path: Path) -> dict[str, str]:
    """Validates permissions and structure, then registers every value with
    redact() before returning -- so a secret is redactable before it can
    reach a log line, per the contract's "registered at read time" rule.
    No exception raised here ever embeds file contents or values, only the
    path, so a malformed file can never leak through its own error message.
    """
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise PreconditionError(f"--idp-secrets file {path} is not readable: {exc}") from None

    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise UsageError(f"--idp-secrets file {path} must not be group- or world-readable")

    try:
        raw = path.read_text()
    except OSError as exc:
        raise PreconditionError(f"--idp-secrets file {path} is not readable: {exc}") from None

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        raise UsageError(f"--idp-secrets file {path} is not valid JSON") from None

    if not isinstance(data, dict) or not all(isinstance(v, str) for v in data.values()):
        raise UsageError(f"--idp-secrets file {path} must be a JSON object of string values")

    register_secret(*data.values())
    return {str(k): v for k, v in data.items()}
