from kc2ak import redact as redact_mod
from kc2ak.redact import redact, register_secret


def setup_function() -> None:
    # each test gets a clean secret registry
    redact_mod._secrets.clear()


def test_redact_replaces_registered_secret() -> None:
    register_secret("s3cr3t-token")
    assert redact("Authorization: Bearer s3cr3t-token") == "Authorization: Bearer [REDACTED]"


def test_redact_ignores_none_and_empty() -> None:
    register_secret(None, "", "abc")
    assert redact_mod._secrets == ["abc"]


def test_redact_no_secrets_registered_is_noop() -> None:
    assert redact("nothing to see here") == "nothing to see here"


def test_redact_longest_match_first_avoids_partial_leak() -> None:
    register_secret("abc", "abcdef")
    # if "abc" were replaced first, "def" would leak from "abcdef"
    assert redact("abcdef") == "[REDACTED]"


def test_redact_multiple_secrets_in_one_string() -> None:
    register_secret("password1", "token2")
    assert redact("password1 and token2") == "[REDACTED] and [REDACTED]"


def test_register_secret_is_idempotent() -> None:
    register_secret("dup")
    register_secret("dup")
    assert redact_mod._secrets.count("dup") == 1
