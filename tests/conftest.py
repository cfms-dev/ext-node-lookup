import os
import shutil
import sys
from pathlib import Path

import pytest


EXTENSION_ROOT = Path(__file__).resolve().parents[1]


def _find_server_root() -> Path:
    configured_root = os.environ.get("CFMS_SERVER_ROOT")
    candidates = []
    if configured_root:
        candidates.append(Path(configured_root))
    candidates.append(EXTENSION_ROOT.parent / "cfms_on_websocket")

    for candidate in candidates:
        resolved = candidate.resolve()
        if (resolved / "src/include/extensions/manager.py").is_file():
            return resolved
    raise RuntimeError(
        "CFMS server checkout not found; set CFMS_SERVER_ROOT to cfms_on_websocket"
    )


@pytest.fixture(scope="session")
def server_root() -> Path:
    return _find_server_root()


@pytest.fixture(scope="session", autouse=True)
def isolated_server_runtime(server_root: Path, tmp_path_factory):
    runtime_dir = tmp_path_factory.mktemp("cfms-node-lookup")
    shutil.copy(server_root / "src/config.toml.sample", runtime_dir / "config.toml")
    (runtime_dir / "init").touch()

    original_cwd = Path.cwd()
    server_src = str(server_root / "src")
    sys.path.insert(0, server_src)
    os.chdir(runtime_dir)
    try:
        yield runtime_dir
    finally:
        config_module = sys.modules.get("include.config.settings")
        if config_module is not None:
            config_module.global_config.stop()
        os.chdir(original_cwd)
        try:
            sys.path.remove(server_src)
        except ValueError:
            pass
