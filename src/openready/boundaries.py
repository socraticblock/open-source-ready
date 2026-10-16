"""Bounded, descriptor-relative I/O for untrusted artifact paths (POSIX).

Path validation is lexical; confinement is enforced again by opening each component
with O_NOFOLLOW. An open root descriptor pins the directory through rename races.
Captured bytes are immutable and are the only bytes scanners and writers consume.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Iterator

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_FILES = 10_000
MAX_METADATA_BYTES = 8 * 1024 * 1024


class BoundaryError(ValueError):
    """An input cannot safely cross the artifact boundary."""


def relative_parts(value: object) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise BoundaryError("expected a canonical relative POSIX path")
    parts = tuple(value.split("/"))
    if any(p in ("", ".", "..") or any(ord(c) < 32 or ord(c) == 127 for c in p) for p in parts):
        raise BoundaryError("noncanonical or traversing path")
    return parts


@contextmanager
def directory(path: Path) -> Iterator[int]:
    """Open an absolute directory without following any symlink component."""
    absolute = Path(os.path.abspath(path))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


@dataclass(frozen=True)
class FrozenFile:
    path: str
    data: bytes
    mode: int

    def record(self) -> dict[str, str | int]:
        return {
            "path": self.path,
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "bytes": len(self.data),
            "mode": f"{self.mode:04o}",
        }


def read_file(root_fd: int, relative: str, limit: int = MAX_FILE_BYTES) -> FrozenFile:
    parts = relative_parts(relative)
    parent = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise BoundaryError("expected a single-link regular file")
            if before.st_size > limit:
                raise BoundaryError("file exceeds the configured byte limit")
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = os.read(fd, min(1024 * 1024, limit + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > limit:
                    raise BoundaryError("file exceeds the configured byte limit")
            after = os.fstat(fd)
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise BoundaryError("file changed while being captured")
            return FrozenFile(relative, b"".join(chunks), stat.S_IMODE(before.st_mode) & 0o777)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def capture(root: Path, paths: list[str]) -> tuple[FrozenFile, ...]:
    if len(paths) > MAX_FILES or len(set(paths)) != len(paths):
        raise BoundaryError("too many or duplicate input paths")
    for path in paths:
        relative_parts(path)
    files: list[FrozenFile] = []
    total = 0
    with directory(root) as fd:
        for path in sorted(paths):
            item = read_file(fd, path)
            total += len(item.data)
            if total > MAX_TOTAL_BYTES:
                raise BoundaryError("snapshot exceeds the total byte limit")
            files.append(item)
    return tuple(files)


def manifest_entries(document: object) -> dict[str, dict[str, object]]:
    """Validate the entire file list before the first content read."""
    if not isinstance(document, dict) or not isinstance(document.get("files"), list):
        raise BoundaryError("manifest must contain a files array")
    entries = document["files"]
    if len(entries) > MAX_FILES:
        raise BoundaryError("manifest contains too many entries")
    result: dict[str, dict[str, object]] = {}
    total = 0
    folded: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise BoundaryError("manifest entry must be an object")
        path = entry.get("path")
        relative_parts(path)
        assert isinstance(path, str)
        size = entry.get("bytes")
        digest = entry.get("sha256")
        if type(size) is not int or size < 0 or size > MAX_FILE_BYTES:
            raise BoundaryError("invalid file byte count")
        if not isinstance(digest, str) or re.fullmatch("[0-9a-f]{64}", digest) is None:
            raise BoundaryError("invalid sha256")
        if path.casefold() in folded:
            raise BoundaryError("duplicate or case-colliding manifest path")
        folded.add(path.casefold())
        total += size
        result[path] = entry
    if total > MAX_TOTAL_BYTES:
        raise BoundaryError("manifest exceeds total byte limit")
    for path in result:
        parts = path.split("/")
        if any("/".join(parts[:i]).casefold() in folded for i in range(1, len(parts))):
            raise BoundaryError("file/directory collision")
    if "file_count" in document and (
        type(document["file_count"]) is not int or document["file_count"] != len(result)
    ):
        raise BoundaryError("manifest file count disagrees")
    if "total_bytes" in document and (
        type(document["total_bytes"]) is not int or document["total_bytes"] != total
    ):
        raise BoundaryError("manifest byte total disagrees")
    return result


def decode_object(data: bytes) -> dict[str, object]:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise BoundaryError("duplicate JSON key")
            result[key] = value
        return result

    def invalid_constant(value: str) -> object:
        raise BoundaryError(f"non-finite JSON number: {value}")

    try:
        document = json.loads(data, object_pairs_hook=unique, parse_constant=invalid_constant)
    except RecursionError as exc:
        raise BoundaryError("metadata nesting exceeds parser limit") from exc
    if not isinstance(document, dict):
        raise BoundaryError("metadata must be a JSON object")
    return document
