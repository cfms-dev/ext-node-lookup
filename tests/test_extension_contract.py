from pathlib import Path


def test_manifest_matches_server_extension_contract(server_root: Path) -> None:
    from include.extensions.manager import discover_extensions

    extension_root = Path(__file__).resolve().parents[1]
    discovered = discover_extensions(extension_root.parent)

    extension = discovered["node_lookup"]
    assert extension.directory == extension_root
    assert extension.manifest.version == "0.1.0"
    assert extension.manifest.license == "Apache-2.0"
