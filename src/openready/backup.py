"""Private backup, verified restore, and the migration-failure drill (OR-008).

Three properties, each of which is a check rather than a promise:

1. **The backup is written outside the project.** A backup inside the tree is a
   backup that gets published with it, and one that doubles on the next run.
2. **A backup is not a backup until a restore has been verified.** ``create``
   writes a per-file hash manifest; ``verify_restore`` extracts into a throwaway
   directory and recomputes every hash. Without that step the only evidence is that
   a command exited 0.
3. **A migration is not safe because it is written inside a transaction.** The
   drill applies a migration that is *designed to fail partway* against a synthetic
   database and then checks that the original rows and schema survived. SQLite
   rolls DDL back inside a transaction; that is worth demonstrating on this machine
   rather than assuming.

The drill's database is synthetic and lives in a temporary directory. Nothing here
touches real data, and no migration is ever run against a shared database.
"""

from __future__ import annotations

import io
import gzip
import hashlib
import json
import os
import re
import sqlite3
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from . import boundaries
from .capabilities import environment_label
from .private import private_home
from .status import FAIL, INFO, NEEDS_HUMAN, NOT_ENFORCED, NOT_RUN, PASS, REVIEW, STOP, Result

MANIFEST_SUFFIX = ".manifest.json"
# The manifest written *inside* each archive. It is the tool's own artefact, so restore
# verification must not report it as content the manifest failed to record.
ARCHIVE_MANIFEST_NAME = "BACKUP-MANIFEST.json"
SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    ".openready-candidate",
}

BACKUP_LIMITATION = (
    "A backup on the same machine and the same filesystem is not a disaster "
    "recovery plan: it does not survive the loss of this machine."
)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _walk_required(base: Path) -> List[str]:
    """Only documented directory exclusions; unreadable entries abort collection."""
    paths: List[str] = []

    def onerror(exc: OSError) -> None:
        raise exc

    for where, dirs, names in os.walk(base, topdown=True, onerror=onerror):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and d != "backups")
        for name in dirs:
            if (Path(where) / name).is_symlink():
                raise boundaries.BoundaryError("backup contains a directory symlink")
        paths.extend((Path(where) / name).relative_to(base).as_posix() for name in sorted(names))
    return paths


def collect(root: Path, private_dir: Optional[Path] = None) -> List[Tuple[str, bytes]]:
    """Capture all required files or raise; never return a partial backup."""
    items: List[Tuple[str, bytes]] = []
    for base, prefix in ((Path(root), ""), (private_dir, "private/")):
        if base is None:
            continue
        if not base.is_dir():
            raise boundaries.BoundaryError("backup source directory is missing")
        for item in boundaries.capture(base, _walk_required(base)):
            rel = prefix + item.path
            if rel == ARCHIVE_MANIFEST_NAME:
                raise boundaries.BoundaryError("source collides with reserved backup metadata")
            items.append((rel, item.data))
    # Validate the combined namespaces as well as each individual capture.
    boundaries.manifest_entries(
        {
            "files": [
                {"path": rel, "sha256": _digest(data), "bytes": len(data)} for rel, data in items
            ]
        }
    )
    return items


def _result(check: str, status: str, message: str) -> Result:
    return Result(
        check,
        status,
        STOP if status == FAIL else INFO,
        message,
        __version__,
        environment_label(),
        limitations=[BACKUP_LIMITATION],
    )


def create(
    root: Path,
    destination: Optional[Path] = None,
    private_dir: Optional[Path] = None,
    env: Optional[Dict[str, str]] = None,
) -> Tuple[List[Result], Optional[Path]]:
    root = Path(os.path.abspath(root))
    private_dir = (
        Path(private_dir)
        if private_dir
        else (private_home(env) if private_home(env).is_dir() else None)
    )
    if destination is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        destination = private_home(env) / "backups" / f"{root.name}-{stamp}.tar.gz"
    destination = Path(os.path.abspath(destination))
    if destination == root or root in destination.parents:
        return [
            _result("backup.outside-project", FAIL, "backup destination is inside the project")
        ], None
    sidecar = destination.with_name(destination.name + MANIFEST_SUFFIX)
    if destination.exists() or destination.is_symlink() or sidecar.exists() or sidecar.is_symlink():
        return [_result("backup.no-overwrite", FAIL, "backup or sidecar already exists")], None
    try:
        items = collect(root, private_dir)
        if not items:
            raise boundaries.BoundaryError("nothing found to back up")
        manifest = {
            "schema_version": "1.0",
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "project": root.name,
            "file_count": len(items),
            "total_bytes": sum(len(data) for _, data in items),
            "files": [
                {"path": rel, "sha256": _digest(data), "bytes": len(data)}
                for rel, data in sorted(items)
            ],
            "includes_private_data": private_dir is not None,
            "excluded_directories": sorted(SKIP_DIRS | {"backups"}),
        }
        destination.parent.mkdir(parents=True, exist_ok=True)
        with boundaries.directory(destination.parent) as parent_fd:
            with tempfile.TemporaryDirectory(
                prefix=".openready-backup-", dir=destination.parent
            ) as tmp:
                archive_path = Path(tmp) / "archive"
                with archive_path.open("xb") as output:
                    os.fchmod(output.fileno(), 0o600)
                    with tarfile.open(fileobj=output, mode="w:gz") as archive:
                        entries = items + [
                            (ARCHIVE_MANIFEST_NAME, json.dumps(manifest, sort_keys=True).encode())
                        ]
                        for rel, data in sorted(entries):
                            info = tarfile.TarInfo(rel)
                            info.size = len(data)
                            info.mode = 0o600
                            archive.addfile(info, io.BytesIO(data))
                    output.flush()
                    os.fsync(output.fileno())
                manifest["archive_sha256"] = "sha256:" + _digest(archive_path.read_bytes())
                side_path = Path(tmp) / "sidecar"
                side_path.write_text(
                    json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
                )
                side_path.chmod(0o600)
                # Exclusive links publish complete files. Archive is the commit marker;
                # a crash between links leaves only a sidecar, never a partial archive.
                os.link(side_path, sidecar.name, dst_dir_fd=parent_fd)
                try:
                    os.link(archive_path, destination.name, dst_dir_fd=parent_fd)
                except OSError:
                    os.unlink(sidecar.name, dir_fd=parent_fd)
                    raise
                os.fsync(parent_fd)
        return [
            _result("backup.created", PASS, f"{len(items)} files captured completely")
        ], destination
    except (OSError, ValueError, tarfile.TarError) as exc:
        return [_result("backup.content", FAIL, f"backup refused: {exc}")], None


def _members(tar: tarfile.TarFile) -> List[tarfile.TarInfo]:
    members: List[tarfile.TarInfo] = []
    seen: set[str] = set()
    total = 0
    for member in tar:
        boundaries.relative_parts(member.name)
        if not (member.isfile() or member.isdir()) or member.sparse is not None:
            raise boundaries.BoundaryError("archive contains a forbidden member type")
        name = member.name.casefold()
        if name in seen:
            raise boundaries.BoundaryError("archive contains duplicate or case-colliding paths")
        seen.add(name)
        if member.size < 0 or member.size > boundaries.MAX_FILE_BYTES:
            raise boundaries.BoundaryError("archive member exceeds byte limit")
        total += member.size
        members.append(member)
        if total > boundaries.MAX_TOTAL_BYTES or len(members) > boundaries.MAX_FILES + 1:
            raise boundaries.BoundaryError("archive exceeds extraction limits")
    return members


def _tar_bytes(raw: bytes) -> bytes:
    """Bound decompression including tar headers, PAX metadata and padding."""
    limit = boundaries.MAX_TOTAL_BYTES + boundaries.MAX_METADATA_BYTES
    chunks: List[bytes] = []
    total = 0
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
        while True:
            chunk = stream.read(min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise boundaries.BoundaryError("decompressed archive exceeds byte limit")
            chunks.append(chunk)
    return b"".join(chunks)


def _safe_members(archive: Path) -> Tuple[List[tarfile.TarInfo], Optional[str]]:
    try:
        with boundaries.directory(archive.absolute().parent) as fd:
            raw = boundaries.read_file(fd, archive.name, boundaries.MAX_TOTAL_BYTES).data
        with tarfile.open(fileobj=io.BytesIO(_tar_bytes(raw)), mode="r:") as tar:
            return _members(tar), None
    except (ValueError, OSError, tarfile.TarError, EOFError) as exc:
        return [], str(exc)


def _validated_backup(
    archive: Path, expected_manifest: Optional[Dict[str, Any]] = None
) -> Tuple[List[Result], Dict[str, Any], Dict[str, bytes]]:
    """Read once, validate once; restore writes these exact validated bytes.

    No tar extraction API is used: types, names and limits are checked before
    regular file streams are read. Archive permissions and ownership are ignored.
    """
    results: List[Result] = []
    report: Dict[str, Any] = {"restored": 0, "missing": [], "mismatched": [], "unexpected": []}
    payload: Dict[str, bytes] = {}
    try:
        archive = Path(archive).absolute()
        with boundaries.directory(archive.parent) as fd:
            raw = boundaries.read_file(fd, archive.name, boundaries.MAX_TOTAL_BYTES).data
            if expected_manifest is None:
                expected_manifest = boundaries.decode_object(
                    boundaries.read_file(
                        fd, archive.name + MANIFEST_SUFFIX, boundaries.MAX_METADATA_BYTES
                    ).data
                )
        recorded = boundaries.manifest_entries(expected_manifest)
        if expected_manifest.get("schema_version") != "1.0":
            raise boundaries.BoundaryError("unsupported backup schema")
        declared = expected_manifest.get("archive_sha256")
        if not isinstance(declared, str) or not re.fullmatch("sha256:[0-9a-f]{64}", declared):
            raise boundaries.BoundaryError("backup sidecar lacks a valid archive digest")
        if ARCHIVE_MANIFEST_NAME in recorded:
            raise boundaries.BoundaryError("manifest lists reserved backup metadata")
        with tarfile.open(fileobj=io.BytesIO(_tar_bytes(raw)), mode="r:") as tar:
            members = _members(tar)
            for member in members:
                if member.isdir():
                    continue
                handle = tar.extractfile(member)
                if handle is None:
                    raise boundaries.BoundaryError("regular member has no data")
                with handle:
                    data = handle.read(member.size + 1)
                if len(data) != member.size:
                    raise boundaries.BoundaryError("truncated archive member")
                if member.name != ARCHIVE_MANIFEST_NAME:
                    payload[member.name] = data
        declared = expected_manifest.get("archive_sha256")
        if declared and declared != "sha256:" + _digest(raw):
            results.append(
                _result("backup.archive-integrity", FAIL, "archive digest differs from sidecar")
            )
        report["unexpected"] = sorted(set(payload) - set(recorded))
        for rel, entry in recorded.items():
            if rel not in payload:
                report["missing"].append(rel)
            elif len(payload[rel]) != entry["bytes"] or _digest(payload[rel]) != entry["sha256"]:
                report["mismatched"].append(rel)
            else:
                report["restored"] += 1
        if report["unexpected"]:
            results.append(
                _result("backup.restore-unexpected", FAIL, "archive contains unrecorded files")
            )
        failed = bool(results or report["missing"] or report["mismatched"])
        results.append(
            _result(
                "backup.restore-integrity",
                FAIL if failed else PASS,
                "backup validation failed" if failed else "every recorded file and byte verified",
            )
        )
    except (OSError, ValueError, tarfile.TarError, EOFError) as exc:
        results.append(
            _result("backup.restore-readable", FAIL, f"archive could not be read safely: {exc}")
        )
    if any(result.status == FAIL for result in results):
        payload = {}
    return results, report, payload


def verify_restore(
    archive: Path, expected_manifest: Optional[Dict[str, Any]] = None
) -> Tuple[List[Result], Dict[str, Any]]:
    results, report, _ = _validated_backup(archive, expected_manifest)
    return results, report


def restore(
    archive: Path, destination: Path, env: Optional[Dict[str, str]] = None
) -> Tuple[List[Result], Optional[Path]]:
    destination = Path(os.path.abspath(destination))
    results, _, payload = _validated_backup(archive)
    if any(result.status == FAIL for result in results):
        return results, None
    try:
        if destination.is_symlink() or (
            destination.exists() and (not destination.is_dir() or any(destination.iterdir()))
        ):
            raise boundaries.BoundaryError("restore destination must be absent or empty")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with boundaries.directory(destination.parent) as parent_fd:
            identity = os.fstat(parent_fd)
            with tempfile.TemporaryDirectory(
                prefix=".openready-restore-", dir=destination.parent
            ) as tmp:
                staging = Path(tmp) / "tree"
                staging.mkdir(mode=0o700)
                for rel, data in payload.items():
                    target = staging / rel
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open("xb") as handle:
                        os.fchmod(handle.fileno(), 0o600)
                        handle.write(data)
                        handle.flush()
                        os.fsync(handle.fileno())
                current = destination.parent.stat()
                if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
                    raise boundaries.BoundaryError("restore parent changed")
                os.rename(staging, destination.name, dst_dir_fd=parent_fd)
                os.fsync(parent_fd)
    except (OSError, ValueError) as exc:
        results.append(_result("restore.no-overwrite", FAIL, str(exc)))
        return results, None
    results.append(_result("restore.completed", PASS, f"{len(payload)} verified files restored"))
    return results, destination


# --- migration drill ----------------------------------------------------------

_MIGRATION_OK = [
    "ALTER TABLE items ADD COLUMN stage TEXT",
    "UPDATE items SET stage = 'backfilled'",
]
_MIGRATION_FAILS_PARTWAY = [
    "ALTER TABLE items ADD COLUMN stage TEXT",
    "UPDATE items SET stage = 'backfilled'",
    # Not a syntax error: the statement is valid and fails at run time, mid-way.
    "INSERT INTO items (id, name) VALUES (1, 'duplicate primary key')",
]


def _seed_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL)")
        connection.executemany(
            "INSERT INTO items (id, name) VALUES (?, ?)", [(1, "alpha"), (2, "beta"), (3, "gamma")]
        )
        connection.commit()
    finally:
        connection.close()


def _apply(path: Path, statements: List[str], transactional: bool) -> Optional[str]:
    connection = sqlite3.connect(path)
    try:
        if transactional:
            connection.execute("BEGIN")
        for statement in statements:
            connection.execute(statement)
        if transactional:
            connection.commit()
        return None
    except sqlite3.Error as exc:
        if transactional:
            connection.rollback()
        return str(exc)
    finally:
        connection.close()


def _state(path: Path) -> Dict[str, Any]:
    connection = sqlite3.connect(path)
    try:
        rows = connection.execute("SELECT id, name FROM items ORDER BY id").fetchall()
        columns = [row[1] for row in connection.execute("PRAGMA table_info(items)")]
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        return {"rows": rows, "columns": columns, "integrity": integrity}
    finally:
        connection.close()


def migration_drill() -> List[Result]:
    """Prove the rollback story on synthetic databases, on this machine.

    Three independent databases, because the interesting claim is a contrast:

    - **A, transactional**: the migration fails at its *last* statement, so the
      rollback has real work to undo. The original rows must survive *and* the
      column added earlier in the same transaction must be gone again.
    - **B, success then reverse**: a migration that applies cleanly can be undone by
      an explicit reverse statement, with the rows intact.
    - **C, no transaction**: the same failing migration applied without a
      transaction leaves the half-applied state behind. That is the hazard the
      other two are protecting against, demonstrated rather than asserted.
    """
    expected_rows = [(1, "alpha"), (2, "beta"), (3, "gamma")]
    results: List[Result] = []

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)

        db_a = work / "a.sqlite"
        _seed_database(db_a)
        before_a = _state(db_a)
        failure_a = _apply(db_a, _MIGRATION_FAILS_PARTWAY, transactional=True)
        after_a = _state(db_a)

        db_b = work / "b.sqlite"
        _seed_database(db_b)
        forward_b = _apply(db_b, _MIGRATION_OK, transactional=True)
        migrated_b = _state(db_b)
        reverse_b = _apply(db_b, ["ALTER TABLE items DROP COLUMN stage"], transactional=True)
        after_b = _state(db_b)

        db_c = work / "c.sqlite"
        _seed_database(db_c)
        failure_c = _apply(db_c, _MIGRATION_FAILS_PARTWAY, transactional=False)
        after_c = _state(db_c)

    rolled_back = (
        bool(failure_a) and after_a["rows"] == expected_rows and "stage" not in after_a["columns"]
    )
    results.append(
        Result(
            "migration.transactional-rollback",
            PASS if rolled_back else FAIL,
            INFO if rolled_back else STOP,
            (
                f"a migration failing at its last statement ({failure_a}) rolled back completely: "
                f"{len(expected_rows)} original rows intact and the column added earlier in the same "
                f"transaction removed again"
            )
            if rolled_back
            else (
                f"no failure was induced ({failure_a!r})"
                if not failure_a
                else f"rollback was incomplete: columns={after_a['columns']} rows={after_a['rows']}"
            ),
            __version__,
            environment_label(),
            limitations=[
                "Demonstrated on a synthetic SQLite database in a temporary directory. SQLite "
                "rolls DDL back inside a transaction; other engines may not.",
            ],
        )
    )

    results.append(
        Result(
            "migration.initial-state-preserved",
            PASS if before_a["rows"] == expected_rows and before_a["integrity"] == "ok" else FAIL,
            INFO,
            f"seeded state verified before any migration: {len(before_a['rows'])} rows, "
            f"integrity {before_a['integrity']}",
            __version__,
            environment_label(),
        )
    )

    reverse_ok = (
        forward_b is None
        and reverse_b is None
        and "stage" in migrated_b["columns"]
        and after_b["rows"] == expected_rows
        and "stage" not in after_b["columns"]
    )
    results.append(
        Result(
            "migration.reverse-statement",
            PASS if reverse_ok else NEEDS_HUMAN,
            INFO if reverse_ok else REVIEW,
            (
                "the applied column was added by the forward migration and removed again by an explicit "
                "reverse statement, with every row intact"
            )
            if reverse_ok
            else f"reverse statement did not restore the prior schema (forward={forward_b!r}, reverse={reverse_b!r})",
            __version__,
            environment_label(),
            required=False,
            limitations=[
                "A reverse statement is only safe when the forward migration was additive."
            ],
        )
    )

    untransacted_partial = bool(failure_c) and "stage" in after_c["columns"]
    results.append(
        Result(
            "migration.untransacted-hazard",
            PASS if untransacted_partial else NOT_RUN,
            INFO if untransacted_partial else REVIEW,
            (
                "the same failing migration applied without a transaction leaves the half-applied "
                "column behind -- this is the state the transaction prevents"
            )
            if untransacted_partial
            else "the untransacted contrast could not be demonstrated on this engine",
            __version__,
            environment_label(),
            required=False,
            enforcement=None if untransacted_partial else NOT_ENFORCED,
        )
    )
    return results
