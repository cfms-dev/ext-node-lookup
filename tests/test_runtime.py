from pathlib import Path


def test_server_config_and_database_use_isolated_runtime(isolated_server_runtime):
    from include.config import paths
    from include.config.settings import global_config
    from include.database.session import engine

    runtime = isolated_server_runtime
    assert paths.EXECUTABLE_ABSPATH == runtime
    assert paths.PROJECT_ABSPATH == runtime.parent
    assert paths.EXTENSION_ROOT == runtime / "include" / "extensions"
    assert global_config._config_path == runtime / "config.toml"
    assert Path(engine.url.database).parent == runtime
