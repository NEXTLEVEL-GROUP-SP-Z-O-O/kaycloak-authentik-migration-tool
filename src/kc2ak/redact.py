"""Secret redaction, shared by every client and error path.

Tokens, client secrets and passwords are registered here as soon as they are
known, then stripped out of anything routed through redact() — request logs,
error messages, exception text. Every later task inherits this: nothing else
in the codebase should print a secret directly.
"""

from __future__ import annotations

_PLACEHOLDER = "[REDACTED]"
_secrets: list[str] = []


def register_secret(*values: str | None) -> None:
    """Record one or more secret values so redact() will strip them."""
    for value in values:
        if value and value not in _secrets:
            _secrets.append(value)


def redact(text: str) -> str:
    """Replace every registered secret value in text with a placeholder."""
    # Longest first, so a secret that happens to be a substring of another
    # registered secret doesn't leave a partial value exposed.
    for secret in sorted(_secrets, key=len, reverse=True):
        text = text.replace(secret, _PLACEHOLDER)
    return text
