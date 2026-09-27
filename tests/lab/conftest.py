import os
from pathlib import Path

import pytest


def pytest_addoption(parser):
    parser.addoption("--lab-dataset", help="Generated hwsim dataset directory (or AIRTRACE_DATASET)")


def pytest_generate_tests(metafunc):
    if "lab_bundle_path" not in metafunc.fixturenames:
        return
    directory = metafunc.config.getoption("--lab-dataset") or os.environ.get("AIRTRACE_DATASET")
    if not directory:
        metafunc.parametrize("lab_bundle_path", [pytest.param(None, marks=pytest.mark.skip(
            reason="No lab dataset: pass --lab-dataset DIR or set AIRTRACE_DATASET"))])
        return
    from lab.manifest import verify_manifest
    dataset = Path(directory)
    manifest = verify_manifest(dataset)
    if not manifest["bundles"]:
        raise pytest.UsageError("The supplied lab dataset has no bundles")
    metafunc.parametrize("lab_bundle_path", [dataset / entry["path"] for entry in manifest["bundles"]],
                         ids=[entry["id"] for entry in manifest["bundles"]])
