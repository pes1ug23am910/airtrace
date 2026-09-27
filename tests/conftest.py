"""Keep optional pytest cache output inside the local scratch directory."""

from pathlib import Path

import pytest


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    # pytest creates --basetemp itself but not its parent; .local/ is ignored by Git,
    # so a fresh checkout has no .local/ until something makes it.
    if config.option.basetemp:
        Path(config.option.basetemp).resolve().parent.mkdir(parents=True, exist_ok=True)
    if config.pluginmanager.hasplugin("cacheprovider"):
        config.inicfg["cache_dir"] = str(config.rootpath / ".local" / "pytest-cache")
