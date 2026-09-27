"""Placeholder baseline: no signatures have been measured on a real dev split.

Add rules only after reviewing ``python -m lab.observe`` on the dev split.
Each future rule receives Toolbox outputs and returns a cited Diagnosis or None.
The first matching rule wins. Test-split observations must not inform this file.
"""

from triage.schema import Diagnosis, unknown
from triage.data import View
from triage.tools import Toolbox


PLACEHOLDER = True
RULES = ()


def diagnose(view: View) -> Diagnosis:
    """Use the same restricted view as the models; rules are still a skeleton."""
    toolbox = Toolbox(view)
    for rule in RULES:
        diagnosis = rule(toolbox)
        if diagnosis is not None:
            for evidence in diagnosis.evidence:
                evidence.auto = True
            return diagnosis
    return unknown(
        view,
        fix="No measured rule signatures are available. Inspect the dev observations before adding rules.",
    )
