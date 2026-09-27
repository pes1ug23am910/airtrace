"""Keep optional pytest cache output inside the local scratch directory."""

import os
from pathlib import Path
import shutil

import pytest


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    # One place to find the parser: an explicit AIRTRACE_BIN wins, then PATH, then the
    # locally built binary the README describes (.local/airtrace[.exe]).
    if not os.environ.get("AIRTRACE_BIN") and not shutil.which("airtrace"):
        for name in ("airtrace.exe", "airtrace"):
            local = config.rootpath / ".local" / name
            if local.is_file():
                os.environ["AIRTRACE_BIN"] = str(local)
                break
    # pytest creates --basetemp itself but not its parent; .local/ is ignored by Git,
    # so a fresh checkout has no .local/ until something makes it.
    if config.option.basetemp:
        Path(config.option.basetemp).resolve().parent.mkdir(parents=True, exist_ok=True)
    if config.pluginmanager.hasplugin("cacheprovider"):
        config.inicfg["cache_dir"] = str(config.rootpath / ".local" / "pytest-cache")
