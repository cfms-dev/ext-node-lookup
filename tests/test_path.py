import pytest

from _path import NodePathError, parse_node_path


@pytest.mark.parametrize(
    ("path", "segments"),
    [
        ("/", ()),
        ("/projects/cfms_on_websocket", ("projects", "cfms_on_websocket")),
        ("/项目/机密 文档", ("项目", "机密 文档")),
        ("/name%2Fwith%2fslash", ("name/with/slash",)),
        ("/100%25", ("100%",)),
        ("/%252F", ("%2F",)),
        ("/quote%27%20OR%201%3D1", ("quote' OR 1=1",)),
    ],
)
def test_parse_node_path(path: str, segments: tuple[str, ...]) -> None:
    assert parse_node_path(path) == segments


@pytest.mark.parametrize(
    "path",
    [
        "",
        "relative/path",
        "//double",
        "/trailing/",
        "/empty//segment",
        "/.",
        "/a/..",
        "/%2E%2E",
        "/bad%",
        "/bad%2",
        "/bad%GG",
        "/%FF",
        "/nul%00byte",
    ],
)
def test_parse_node_path_rejects_invalid_syntax(path: str) -> None:
    with pytest.raises(NodePathError):
        parse_node_path(path)


def test_parse_node_path_enforces_decoded_segment_length() -> None:
    assert parse_node_path("/" + "a" * 255) == ("a" * 255,)
    with pytest.raises(NodePathError, match="segment is too long"):
        parse_node_path("/" + "a" * 256)


def test_parse_node_path_enforces_depth() -> None:
    maximum_path = "/" + "/".join("a" for _ in range(128))
    assert len(parse_node_path(maximum_path)) == 128

    with pytest.raises(NodePathError, match="too many segments"):
        parse_node_path(maximum_path + "/a")


def test_parse_node_path_enforces_encoded_path_length_before_decoding() -> None:
    oversized = "/" + "/".join("%41" * 255 for _ in range(6))
    assert len(oversized) > 4096
    with pytest.raises(NodePathError, match="Path is too long"):
        parse_node_path(oversized)
