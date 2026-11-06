"""Puts the package on the path and builds the real-Hermes rig the end-to-end tests share."""

import shutil
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import hermes_rig  # noqa: E402


@pytest.fixture(scope="session")
def rig(tmp_path_factory):
    home = hermes_rig.hermes_home()
    if hermes_rig.hermes_exe() is None or not hermes_rig.home_uses_stub(home):
        pytest.skip("needs Hermes installed and a home whose model points at the local stub")
    scratch = tmp_path_factory.mktemp("rig")
    workdir = scratch / "workdir"
    workdir.mkdir()
    backup = scratch / "config-before.yaml"
    shutil.copy2(home / "config.yaml", backup)
    bench = hermes_rig.Rig(home, workdir, scratch)
    # A plugin left in this home could log or act on every hook, so only the plugin under test runs.
    for plugin in sorted((home / "plugins").iterdir()):
        bench.hermes(["plugins", "disable", plugin.name])
    bench.stop_gateway()
    bench.start_stub()
    try:
        yield bench
    finally:
        bench.stop_gateway()
        bench.stop_stub()
        shutil.copy2(backup, home / "config.yaml")
