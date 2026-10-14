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

import hashlib
import json
import os
import shutil
import sqlite3
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from .capabilities import environment_label
from .private import private_home
from .status import FAIL, INFO, NEEDS_HUMAN, NOT_ENFORCED, NOT_RUN, PASS, REVIEW, STOP, Result

MANIFEST_SUFFIX = ".manifest.json"
# The manifest written *inside* each archive. It is the tool's own artefact, so restore
# verification must not report it as content the manifest failed to record.
ARCHIVE_MANIFEST_NAME = "BACKUP-MANIFEST.json"
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache",
             ".ruff_cache", ".pytest_cache", ".openready-candidate"}

BACKUP_LIMITATION = (
    "A backup on the same machine and the same filesystem is not a disaster "
    "recovery plan: it does not survive the loss of this machine."
)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def collect(root: Path, private_dir: Optional[Path] = None) -> List[Tuple[str, bytes]]:
    """Every file worth protecting: the project, and the private data beside it."""
    root = Path(root)
    items: List[Tuple[str, bytes]] = []
    for base, prefix in ((root, ""), (private_dir, "private/")):
        if base is None or not Path(base).is_dir():
            continue
        for where, dirs, names in os.walk(base, topdown=True):
            dirs[:] = sorted(d for d in dirs
                             if d not in SKIP_DIRS and d != "backups")
            for name in sorted(names):
                path = Path(where) / name
                try:
                    if not path.is_file() or path.is_symlink():
                        continue
                    if path.lstat().st_size > 64 * 1024 * 1024:
                        continue
                    data = path.read_bytes()
                except OSError:
                    continue
                rel = prefix + path.relative_to(base).as_posix()
                items.append((rel, data))
    return items


def create(root: Path, destination: Optional[Path] = None,
           private_dir: Optional[Path] = None,
           env: Optional[Dict[str, str]] = None) -> Tuple[List[Result], Optional[Path]]:
    """Write a backup outside the project, with a per-file hash manifest."""
    root = Path(root).resolve()
    private_dir = Path(private_dir).resolve() if private_dir else (
        private_home(env) if private_home(env).is_dir() else None)
    if destination is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        destination = private_home(env) / "backups" / f"{root.name}-{stamp}.tar.gz"
    destination = Path(destination).resolve()

    results: List[Result] = []
    if destination == root or root in destination.parents:
        results.append(Result(
            "backup.outside-project", FAIL, STOP,
            f"{destination} is inside the project; a backup there is published with it",
            __version__, environment_label(),
        ))
        return results, None
    if destination.exists():
        results.append(Result(
            "backup.no-overwrite", FAIL, STOP,
            f"{destination} already exists; refusing to overwrite an existing backup",
            __version__, environment_label(),
        ))
        return results, None

    items = collect(root, private_dir)
    if not items:
        results.append(Result(
            "backup.content", FAIL, STOP, "nothing found to back up",
            __version__, environment_label(),
        ))
        return results, None

    manifest = {
        "schema_version": "1.0",
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "project": root.name,
        "file_count": len(items),
        "total_bytes": sum(len(data) for _, data in items),
        "files": [{"path": rel, "sha256": _digest(data), "bytes": len(data)}
                  for rel, data in sorted(items)],
        "includes_private_data": private_dir is not None,
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(destination, "w:gz") as archive:
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp)
            for rel, data in items:
                target = staging / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            manifest_path = staging / ARCHIVE_MANIFEST_NAME
            manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                                     encoding="utf-8")
            for entry in sorted(staging.rglob("*")):
                if entry.is_file():
                    archive.add(entry, arcname=entry.relative_to(staging).as_posix(),
                                recursive=False)

    sidecar = destination.with_name(destination.name + MANIFEST_SUFFIX)
    # The archive's own digest is recorded before the sidecar is written, so a doctored
    # archive can be detected. Hashing the archive does not change it, and the sidecar
    # is a separate file.
    archive_digest = _digest(destination.read_bytes())
    manifest["archive_sha256"] = "sha256:" + archive_digest
    sidecar.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    results.append(Result(
        "backup.created", PASS, INFO,
        f"{len(items)} file(s), {manifest['total_bytes']} bytes -> {destination.name} "
        f"(sha256:{archive_digest[:16]}...)",
        __version__, environment_label(), limitations=[BACKUP_LIMITATION],
    ))
    return results, destination


def verify_restore(archive: Path, expected_manifest: Optional[Dict[str, Any]] = None
                   ) -> Tuple[List[Result], Dict[str, Any]]:
    """Extract into a throwaway directory and recompute every recorded hash."""
    archive = Path(archive)
    results: List[Result] = []
    report: Dict[str, Any] = {"restored": 0, "missing": [], "mismatched": [], "unexpected": []}
    if not archive.is_file():
        results.append(Result(
            "backup.restore-readable", FAIL, STOP, f"{archive} does not exist",
            __version__, environment_label(),
        ))
        return results, report
    if expected_manifest is None:
        sidecar = archive.with_name(archive.name + MANIFEST_SUFFIX)
        if not sidecar.is_file():
            results.append(Result(
                "backup.restore-readable", NOT_RUN, REVIEW,
                "no manifest sidecar accompanies this archive, so a restorable content list "
                "cannot be checked item by item",
                __version__, environment_label(), enforcement=NOT_ENFORCED,
                limitations=[BACKUP_LIMITATION],
            ))
            return results, report
        expected_manifest = json.loads(sidecar.read_text(encoding="utf-8"))

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "restore"
        work.mkdir()
        try:
            with tarfile.open(archive, "r:gz") as tar:
                for member in tar.getmembers():
                    name = member.name
                    if member.issym() or member.islnk() or name.startswith("/") or ".." in name.split("/"):
                        results.append(Result(
                            "backup.restore-safe", FAIL, STOP,
                            f"archive member {name!r} escapes the restore root",
                            __version__, environment_label(),
                        ))
                        return results, report
                tar.extractall(work)
            extracted = sorted(p.relative_to(work).as_posix()
                               for p in work.rglob("*") if p.is_file())
        except (tarfile.TarError, OSError) as exc:
            results.append(Result(
                "backup.restore-readable", FAIL, STOP, f"archive could not be read: {exc}",
                __version__, environment_label(),
            ))
            return results, report

        recorded_archive = str(expected_manifest.get("archive_sha256") or "")
        if recorded_archive:
            actual = "sha256:" + _digest(archive.read_bytes())
            if actual != recorded_archive:
                results.append(Result(
                    "backup.archive-integrity", FAIL, STOP,
                    (f"this archive hashes to {actual}, but its manifest records "
                     f"{recorded_archive}; the archive is not the one that was verified"),
                    __version__, environment_label(),
                ))

        for entry in expected_manifest.get("files", []):
            target = work / entry["path"]
            if not target.is_file():
                report["missing"].append(entry["path"])
                continue
            if _digest(target.read_bytes()) != entry["sha256"]:
                report["mismatched"].append(entry["path"])
                continue
            report["restored"] += 1

        # Both directions. Checking only that recorded files are present lets an
        # injected file ride along in an archive that "restores cleanly". The
        # manifest the tool writes *into* the archive is its own artefact, not
        # backed-up content, so it is not counted as unexpected.
        recorded_paths = {entry["path"] for entry in expected_manifest.get("files", [])}
        report["unexpected"] = [
            name for name in extracted
            if name not in recorded_paths and name != ARCHIVE_MANIFEST_NAME]

    expected = len(expected_manifest.get("files", []))
    if report["unexpected"]:
        results.append(Result(
            "backup.restore-unexpected", FAIL, STOP,
            (f"{len(report['unexpected'])} file(s) were restored that the manifest does not "
             f"record: {', '.join(report['unexpected'][:4])}"),
            __version__, environment_label(),
        ))
    if report["missing"] or report["mismatched"]:
        results.append(Result(
            "backup.restore-integrity", FAIL, STOP,
            f"{len(report['missing'])} missing and {len(report['mismatched'])} mismatched of "
            f"{expected} recorded file(s); this backup does NOT restore cleanly",
            __version__, environment_label(),
        ))
    else:
        results.append(Result(
            "backup.restore-integrity", PASS, INFO,
            f"all {expected} recorded file(s) restored with matching hashes",
            __version__, environment_label(), limitations=[BACKUP_LIMITATION],
        ))
    return results, report


# --- restore to a location the operator names ---------------------------------


def _safe_members(archive: Path) -> Tuple[List[tarfile.TarInfo], Optional[str]]:
    """Every member, or the name of the first one that escapes the restore root.

    A backup that restores a symlink, a hardlink, an absolute path or a ``..``
    component can write anywhere on the machine. The archive is an input file, so it
    is treated as untrusted even though this tool wrote it.
    """
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
    for member in members:
        name = member.name
        if member.issym() or member.islnk() or name.startswith("/") or ".." in name.split("/"):
            return members, name
    return members, None


def restore(archive: Path, destination: Path, env: Optional[Dict[str, str]] = None
            ) -> Tuple[List[Result], Optional[Path]]:
    """Restore an archive to a location the operator names, verified first.

    The order is the point (acceptance test A07): the archive is extracted into a
    throwaway directory, every recorded hash is recomputed **there**, and only after
    that does anything reach ``destination``. A restore that fails verification
    writes nothing, so it cannot destroy the very data it was meant to recover.

    Nothing is overwritten: a non-empty destination is refused. Recovery of an
    existing tree is a decision an operator makes, not something a restore should
    infer.
    """
    archive = Path(archive)
    destination = Path(destination)
    results: List[Result] = []

    if not archive.is_file():
        results.append(Result(
            "restore.archive-readable", FAIL, STOP, f"{archive} does not exist",
            __version__, environment_label(),
        ))
        return results, None

    sidecar = archive.with_name(archive.name + MANIFEST_SUFFIX)
    if not sidecar.is_file():
        results.append(Result(
            "restore.manifest", FAIL, STOP,
            f"no manifest sidecar ({sidecar.name}) accompanies this archive, so the restore "
            f"cannot be verified item by item and was not attempted",
            __version__, environment_label(),
            limitations=["A restore that cannot be verified is not a restore. Use `backup` to "
                         "produce an archive that carries one."],
        ))
        return results, None
    try:
        manifest = json.loads(sidecar.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        results.append(Result(
            "restore.manifest", FAIL, STOP, f"the manifest sidecar is unreadable ({exc})",
            __version__, environment_label(),
        ))
        return results, None

    if destination.exists() and any(destination.iterdir()):
        results.append(Result(
            "restore.no-overwrite", FAIL, STOP,
            f"{destination} already exists and is not empty; refusing to restore over it, "
            f"because a recovery that overwrites newer data is worse than no recovery",
            __version__, environment_label(),
        ))
        return results, None

    recorded_archive = str(manifest.get("archive_sha256") or "")
    if recorded_archive:
        actual = "sha256:" + _digest(archive.read_bytes())
        if actual != recorded_archive:
            results.append(Result(
                "restore.archive-integrity", FAIL, STOP,
                f"this archive hashes to {actual} but its manifest records {recorded_archive}; "
                f"it is not the archive that was verified, so nothing was restored",
                __version__, environment_label(),
            ))
            return results, None

    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".openready-restore-", dir=str(destination.parent)))
    try:
        _, escape = _safe_members(archive)
        if escape:
            results.append(Result(
                "restore.safe-extract", FAIL, STOP,
                f"archive member {escape!r} escapes the restore root; nothing was extracted",
                __version__, environment_label(),
            ))
            return results, None

        with tarfile.open(archive, "r:gz") as tar:
            tar.extractall(staging)

        recorded = {entry["path"]: entry for entry in manifest.get("files", [])}
        missing: List[str] = []
        mismatched: List[str] = []
        for rel, entry in sorted(recorded.items()):
            target = staging / rel
            if not target.is_file():
                missing.append(rel)
            elif _digest(target.read_bytes()) != entry.get("sha256"):
                mismatched.append(rel)
        extracted = sorted(p.relative_to(staging).as_posix()
                           for p in staging.rglob("*") if p.is_file())
        unexpected = [name for name in extracted
                      if name not in recorded and name != ARCHIVE_MANIFEST_NAME]

        if missing or mismatched or unexpected:
            results.append(Result(
                "restore.verified-before-recovery", FAIL, STOP,
                f"verification failed before anything was written: {len(missing)} missing, "
                f"{len(mismatched)} mismatched, {len(unexpected)} unexpected file(s)",
                __version__, environment_label(),
                limitations=["Nothing reached the destination. The archive is not restorable as "
                             "it stands.", BACKUP_LIMITATION],
            ))
            return results, None

        # Only now does anything reach the destination.
        if destination.exists():
            destination.rmdir()
        shutil.move(str(staging), str(destination))
        staging = None  # type: ignore[assignment]
    finally:
        if staging is not None and Path(staging).exists():
            shutil.rmtree(staging, ignore_errors=True)

    results.append(Result(
        "restore.completed", PASS, INFO,
        f"{len(recorded)} file(s) restored to {destination} with every recorded hash recomputed "
        f"and matching before anything was written",
        __version__, environment_label(), evidence_path=str(destination),
        limitations=["Restoring to a location the operator names is deliberate: this never "
                     "overwrites the project it came from.", BACKUP_LIMITATION],
    ))
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
        connection.executemany("INSERT INTO items (id, name) VALUES (?, ?)",
                               [(1, "alpha"), (2, "beta"), (3, "gamma")])
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

    rolled_back = (bool(failure_a) and after_a["rows"] == expected_rows
                   and "stage" not in after_a["columns"])
    results.append(Result(
        "migration.transactional-rollback",
        PASS if rolled_back else FAIL, INFO if rolled_back else STOP,
        (f"a migration failing at its last statement ({failure_a}) rolled back completely: "
         f"{len(expected_rows)} original rows intact and the column added earlier in the same "
         f"transaction removed again")
        if rolled_back else
        (f"no failure was induced ({failure_a!r})" if not failure_a else
         f"rollback was incomplete: columns={after_a['columns']} rows={after_a['rows']}"),
        __version__, environment_label(),
        limitations=[
            "Demonstrated on a synthetic SQLite database in a temporary directory. SQLite "
            "rolls DDL back inside a transaction; other engines may not.",
        ],
    ))

    results.append(Result(
        "migration.initial-state-preserved",
        PASS if before_a["rows"] == expected_rows and before_a["integrity"] == "ok" else FAIL,
        INFO,
        f"seeded state verified before any migration: {len(before_a['rows'])} rows, "
        f"integrity {before_a['integrity']}",
        __version__, environment_label(),
    ))

    reverse_ok = (forward_b is None and reverse_b is None and "stage" in migrated_b["columns"]
                  and after_b["rows"] == expected_rows and "stage" not in after_b["columns"])
    results.append(Result(
        "migration.reverse-statement",
        PASS if reverse_ok else NEEDS_HUMAN, INFO if reverse_ok else REVIEW,
        ("the applied column was added by the forward migration and removed again by an explicit "
         "reverse statement, with every row intact")
        if reverse_ok else
        f"reverse statement did not restore the prior schema (forward={forward_b!r}, reverse={reverse_b!r})",
        __version__, environment_label(), required=False,
        limitations=["A reverse statement is only safe when the forward migration was additive."],
    ))

    untransacted_partial = bool(failure_c) and "stage" in after_c["columns"]
    results.append(Result(
        "migration.untransacted-hazard",
        PASS if untransacted_partial else NOT_RUN, INFO if untransacted_partial else REVIEW,
        ("the same failing migration applied without a transaction leaves the half-applied "
         "column behind -- this is the state the transaction prevents")
        if untransacted_partial else
        "the untransacted contrast could not be demonstrated on this engine",
        __version__, environment_label(), required=False,
        enforcement=None if untransacted_partial else NOT_ENFORCED,
    ))
    return results
