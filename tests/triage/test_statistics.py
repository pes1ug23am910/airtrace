import pytest

from triage.statistics import clopper_pearson, exact_mcnemar


def test_r7_clopper_pearson_matches_analytic_boundary_cases():
    assert clopper_pearson(0, 0) == [None, None]
    assert clopper_pearson(0, 10) == pytest.approx([0, 1 - 0.025 ** 0.1])
    assert clopper_pearson(10, 10) == pytest.approx([0.025 ** 0.1, 1])
    assert clopper_pearson(1, 1) == pytest.approx([0.025, 1])
    assert clopper_pearson(5, 10) == pytest.approx([0.18708602844739855, 0.8129139715526015])


def test_r7_exact_mcnemar_counts_and_two_sided_probability():
    assert exact_mcnemar(0, 0)["p_value"] == 1
    assert exact_mcnemar(6, 0)["p_value"] == 0.03125
    assert exact_mcnemar(0, 6)["p_value"] == 0.03125
    assert exact_mcnemar(1, 1)["p_value"] == 1
    result = exact_mcnemar(5, 1)
    assert result["b"] == 5 and result["c"] == 1
    assert result["p_value"] == 14 / 64
