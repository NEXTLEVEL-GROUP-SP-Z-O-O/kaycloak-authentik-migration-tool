"""read_idp_secrets: permission, structure, and redaction-at-read-time rules
from .chief/milestone-2/_contract/02-idp-mapping.md's "The secrets file".
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kc2ak import redact as redact_mod
from kc2ak.errors import PreconditionError, UsageError
from kc2ak.idp_secrets import read_idp_secrets
from kc2ak.redact import redact


def setup_function() -> None:
    redact_mod._secrets.clear()


def _write(tmp_path: Path, content: str, mode: int = 0o600) -> Path:
    path = tmp_path / "idp-secrets.json"
    path.write_text(content)
    path.chmod(mode)
    return path


def test_reads_valid_file_and_registers_secrets(tmp_path: Path) -> None:
    path = _write(tmp_path, '{"corporate-sso": "s3cr3t-value"}')
    result = read_idp_secrets(path)
    assert result == {"corporate-sso": "s3cr3t-value"}
    assert redact("the value is s3cr3t-value here") == "the value is [REDACTED] here"


def test_group_readable_file_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path, "{}", mode=0o640)
    with pytest.raises(UsageError):
        read_idp_secrets(path)


def test_world_readable_file_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path, "{}", mode=0o604)
    with pytest.raises(UsageError):
        read_idp_secrets(path)


def test_0644_file_is_refused(tmp_path: Path) -> None:
    # The contract's own example of what must be rejected.
    path = _write(tmp_path, "{}", mode=0o644)
    with pytest.raises(UsageError):
        read_idp_secrets(path)


def test_owner_only_file_is_accepted(tmp_path: Path) -> None:
    path = _write(tmp_path, '{"a": "b"}', mode=0o600)
    assert read_idp_secrets(path) == {"a": "b"}


def test_malformed_json_is_usage_error(tmp_path: Path) -> None:
    path = _write(tmp_path, "not json at all")
    with pytest.raises(UsageError):
        read_idp_secrets(path)


def test_non_object_json_is_usage_error(tmp_path: Path) -> None:
    path = _write(tmp_path, "[1, 2, 3]")
    with pytest.raises(UsageError):
        read_idp_secrets(path)


def test_non_string_value_is_usage_error(tmp_path: Path) -> None:
    path = _write(tmp_path, '{"a": 123}')
    with pytest.raises(UsageError):
        read_idp_secrets(path)


def test_missing_file_is_precondition_error(tmp_path: Path) -> None:
    with pytest.raises(PreconditionError):
        read_idp_secrets(tmp_path / "does-not-exist.json")
