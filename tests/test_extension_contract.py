from pathlib import Path


def test_manifest_matches_server_extension_contract() -> None:
    from include.config.constants import CORE_VERSION
    from include.extensions.manager import parse_extension_manifest

    extension_root = Path(__file__).resolve().parents[1]
    manifest = parse_extension_manifest(extension_root / "manifest.toml")

    assert manifest.manifest_version == 2
    assert manifest.extension.identifier == "node_lookup"
    assert manifest.extension.version == "0.2.0"
    assert manifest.extension.license == "Apache-2.0"
    minimum_server_version = manifest.compatibility.minimum_server_version
    assert minimum_server_version is not None
    assert str(minimum_server_version) == "0.4.1.260811_alpha"
    assert minimum_server_version <= CORE_VERSION
