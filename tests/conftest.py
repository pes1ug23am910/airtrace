"""Keep optional pytest cache output inside the local scratch directory."""

import pytest


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    if config.pluginmanager.hasplugin("cacheprovider"):
        config.inicfg["cache_dir"] = str(config.rootpath / ".local" / "pytest-cache")
