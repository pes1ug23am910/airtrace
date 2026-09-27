"""Small exact binomial calculations; no asymptotic normal approximation."""

import math


def binomial_probability(first: int, last: int, n: int, p: float) -> float:
    if p == 0:
        return float(first <= 0 <= last)
    if p == 1:
        return float(first <= n <= last)
    logs = []
    for k in range(first, last + 1):
        logs.append(math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)
                    + k * math.log(p) + (n - k) * math.log1p(-p))
    if not logs:
        return 0.0
    largest = max(logs)
    return min(1.0, math.exp(largest) * math.fsum(math.exp(value - largest) for value in logs))


def clopper_pearson(successes: int, trials: int, alpha: float = 0.05) -> list:
    """Invert equal-tailed binomial tests, including the zero/all-success edges."""
    if not 0 <= successes <= trials or not 0 < alpha < 1:
        raise ValueError("Invalid binomial counts or alpha")
    if trials == 0:
        return [None, None]
    lower = 0.0
    upper = 1.0
    if successes:
        low, high = 0.0, 1.0
        for _ in range(70):
            middle = (low + high) / 2
            if binomial_probability(successes, trials, trials, middle) < alpha / 2:
                low = middle
            else:
                high = middle
        lower = (low + high) / 2
    if successes < trials:
        low, high = 0.0, 1.0
        for _ in range(70):
            middle = (low + high) / 2
            if binomial_probability(0, successes, trials, middle) > alpha / 2:
                low = middle
            else:
                high = middle
        upper = (low + high) / 2
    return [lower, upper]


def exact_mcnemar(b: int, c: int) -> dict:
    """b: left alone correct; c: right alone correct; two-sided exact p-value."""
    if type(b) is not int or type(c) is not int or min(b, c) < 0:
        raise ValueError("Discordant counts must be nonnegative integers")
    discordant = b + c
    if discordant == 0:
        p_value = 1.0
    else:
        tail = sum(math.comb(discordant, k) for k in range(min(b, c) + 1))
        p_value = min(1.0, 2 * tail / (2 ** discordant))
    return {"b": b, "c": c, "discordant": discordant, "p_value": p_value,
            "method": "two-sided exact binomial; no multiple-comparison adjustment"}
