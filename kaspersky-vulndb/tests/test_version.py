import pytest

from vulndb.version import InvalidVersionError, branch_start, parse_version, version_key


def test_parse_strips_trailing_zeros():
    assert parse_version("128.0") == (128,)
    assert parse_version(" 1.2.0.0 ") == (1, 2)
    assert parse_version("0") == (0,)


@pytest.mark.parametrize("text", ["", "1.", ".1", "1..2", "1.x", "v1.2", "1.2-beta", "-1"])
def test_parse_rejects_non_numeric(text):
    with pytest.raises(InvalidVersionError):
        parse_version(text)


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("1.9", "1.10"),
        ("2", "2.0.1"),
        ("7.0.24", "7.1"),
        ("8.0.3210.7", "8.0.4310.10"),
        ("0", "0.0.1"),
        ("20.005.30574", "23.008.20533"),
    ],
)
def test_key_order_matches_version_order(lower, higher):
    assert version_key(lower) < version_key(higher)


def test_key_equal_for_trailing_zeros():
    assert version_key("128") == version_key("128.0.0")


def test_key_rejects_huge_segment():
    with pytest.raises(InvalidVersionError):
        version_key("1." + "9" * 11)


@pytest.mark.parametrize(
    ("lower_fixed", "fixed", "expected"),
    [
        ("12.21.1", "13.17.1", "13"),
        ("2.39.4", "2.40.2", "2.40"),
        ("7.6.7", "24.2.3.2", "24"),
        ("7.0.24", "7.1.6", "7.1"),
        ("7.1", "7.1.6", "7.1"),
    ],
)
def test_branch_start(lower_fixed, fixed, expected):
    assert branch_start(lower_fixed, fixed) == expected
