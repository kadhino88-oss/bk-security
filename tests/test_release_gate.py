import pytest

from scripts.release_gate import _dashboard_test_count


def test_release_gate_requires_a_positive_dashboard_test_count():
    assert _dashboard_test_count({"dashboard_tests_passed": 25}) == 25
    assert _dashboard_test_count({"dashboard_tests_passed": 26}) == 26


@pytest.mark.parametrize(
    "metadata",
    [
        {},
        {"dashboard_tests_passed": 0},
        {"dashboard_tests_passed": -1},
        {"dashboard_tests_passed": 24},
        {"dashboard_tests_passed": True},
        {"dashboard_tests_passed": "25"},
        {"dashboard_tests_passed": 2.5},
    ],
)
def test_release_gate_blocks_missing_or_invalid_dashboard_test_counts(metadata):
    with pytest.raises(ValueError, match="Dashboard Node test results are missing"):
        _dashboard_test_count(metadata)
