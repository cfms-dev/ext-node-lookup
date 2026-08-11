"""Strict parsing for the node lookup path wire format."""

from urllib.parse import unquote_to_bytes

__all__ = ["NodePathError", "parse_node_path"]

MAX_PATH_LENGTH = 4096
MAX_PATH_SEGMENTS = 128
MAX_SEGMENT_LENGTH = 255
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


class NodePathError(ValueError):
    """Raised when a submitted node path is not in canonical wire form."""


def _validate_percent_escapes(segment: str) -> None:
    index = 0
    while index < len(segment):
        if segment[index] != "%":
            index += 1
            continue
        if (
            index + 2 >= len(segment)
            or segment[index + 1] not in _HEX_DIGITS
            or segment[index + 2] not in _HEX_DIGITS
        ):
            raise NodePathError("Path contains an invalid percent escape")
        index += 3


def _decode_segment(segment: str) -> str:
    _validate_percent_escapes(segment)
    try:
        decoded = unquote_to_bytes(segment).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise NodePathError("Path contains invalid UTF-8") from exc

    if not decoded:
        raise NodePathError("Path segments must not be empty")
    if len(decoded) > MAX_SEGMENT_LENGTH:
        raise NodePathError("Path segment is too long")
    if "\x00" in decoded:
        raise NodePathError("Path segments must not contain NUL")
    if decoded in {".", ".."}:
        raise NodePathError("Dot path segments are not supported")
    return decoded


def parse_node_path(path: str) -> tuple[str, ...]:
    """Parse one absolute path without normalizing or double-decoding it."""
    if not path.startswith("/"):
        raise NodePathError("Path must be absolute")
    if len(path) > MAX_PATH_LENGTH:
        raise NodePathError("Path is too long")
    if path == "/":
        return ()

    encoded_segments = path[1:].split("/")
    if any(not segment for segment in encoded_segments):
        raise NodePathError("Path segments must not be empty")
    if len(encoded_segments) > MAX_PATH_SEGMENTS:
        raise NodePathError("Path has too many segments")
    return tuple(_decode_segment(segment) for segment in encoded_segments)
