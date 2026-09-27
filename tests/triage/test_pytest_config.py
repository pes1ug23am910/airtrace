from pathlib import Path
import subprocess
import sys

import pytest


def test_f9_cache_location(pytestconfig):
    if pytestconfig.pluginmanager.hasplugin("cacheprovider"):
        assert Path(pytestconfig.getini("cache_dir")).resolve() == (
            pytestconfig.rootpath / ".local" / "pytest-cache").resolve()


@pytest.mark.parametrize("disabled", [False, True])
def test_f9_pytest_config_warning_free_with_or_without_cacheprovider(tmp_path, disabled):
    root = Path(__file__).resolve().parents[2]
    argv = [sys.executable, "-m", "pytest", str(Path(__file__).resolve()), "-q",
            "-W", "error", "-k", "test_f9_cache_location", "--basetemp", str(tmp_path / "nested")]
    if disabled:
        argv.extend(["-p", "no:cacheprovider"])
    result = subprocess.run(argv, cwd=root, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "warning" not in (result.stdout + result.stderr).lower()
