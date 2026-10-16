"""Candidate-tree checks: the file, path and content controls.

This module exists because the inherited v0.2 prototype (`reference/openready.py`
in the handoff) failed four checks that the specification requires of it. Each
lesson is encoded here as a control rather than as advice:

===========================  ==================================================
Prototype defect             Control here
===========================  ==================================================
Exported ``docs/`` content   :func:`scan_host_paths` -- absolute home paths are a
verbatim, host paths and     blocker, not a warning, because they both disclose a
private prose included,      username and break portability. Private *prose*
then printed "NO KNOWN       remains undetectable by construction and is reported
BLOCKERS DETECTED"           as ``NOT_RUN`` (:data:`PROSE_LIMITATION`), never PASS.
Casefold collisions passed   :func:`scan_casefold_collisions` and
                             :func:`scan_reserved_names`
Hardlink alias exported as   :func:`scan_links` -- symlinks AND hardlinks
an independent file          (``st_nlink > 1``)
LFS pointer exported as      :func:`scan_lfs_and_submodules`
ordinary text
===========================  ==================================================

Every scanner here is a **deny-list**: it can prove it found something, never
that nothing exists. Callers must surface that, and :data:`PROSE_LIMITATION` is
the mandatory wording for the one category no scanner can cover.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Optional, Tuple

MAX_SCAN_BYTES = 4 * 1024 * 1024
SKIP_DIR_NAMES = {".git", "__pycache__", ".mypy_cache", ".ruff_cache", ".pytest_cache"}

DENY_COMPONENTS = {
    ".git", ".env", ".ssh", ".aws", ".npmrc", ".pypirc", ".netrc", ".git-credentials",
    "id_rsa", "id_ed25519", "id_ecdsa", "credentials", "secrets", "private",
    "private-data", "personal", "userdata", "node_modules", "__pycache__",
    ".DS_Store", "dist", "build", ".next", ".cache", ".venv", "venv", ".openready-private",
}
DENY_SUFFIXES = (
    ".pem", ".key", ".p12", ".pfx", ".sqlite", ".sqlite3", ".db", ".log", ".pyc", ".kdbx",
)

# Explicit exceptions to the deny rules above. A deny-list that also blocks the
# artefacts the specification *requires* is a defect: the specification mandates a
# committed placeholder config (``.env.example`` / ``.example.env``) so a stranger
# can run the project. Blocking it would force callers to weaken the rule.
ALLOWED_EXCEPTIONS = {".env.example", ".example.env"}

# Windows-reserved device names. A candidate that contains one cannot be checked
# out on Windows at all, and silently differs there.
RESERVED_STEMS = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}
INVALID_NAME_CHARS = set('<>:"|?*\\')

# Deny-list content signatures. Absence here is not proof of absence.
#
# The patterns deliberately do NOT require a closing quote or a trailing slash.
# Requiring a trailing slash on a home path misses the same path at end of line,
# which is the same disclosure; requiring a quoted value misses an unquoted
# assignment. False positives are absorbed by the acknowledgement path, which is
# named and visible, whereas a missed disclosure is silent.
#
# Neither this comment nor the pattern table below may *contain* a shaped example
# of the shapes they describe. The scanner scans its own source like any other
# file, so a literal example here becomes a deny-list hit in this repository's own
# object store -- an unexportable file in the tool that exists to make exports
# clean. Describe the shape; never write one.
#
# The assignment pattern is bounded in two ways, both of which were review finds:
#
# * `[ \t]*` rather than `\s*` between the key and the separator. `\s*` reaches a
#   newline, so a dictionary dispatch such as
#   `client_secret:\n        store_client_secret(args.client_secret)` matched and
#   blocked the export of a file with no credential in it at all.
# * a negative lookahead for `(` before any whitespace or quote, so an assignment
#   whose value is a *call* (`secret = artifactFor(...)`) is not read as a
#   credential. A credential is a literal value, not an expression.
SECRET_SIGNATURES: Tuple[Tuple[str, "re.Pattern[bytes]"], ...] = (
    # `\s*`, not `\s+`, between the tokens of the header. The whitespace-stripped
    # copy this module also scans has no whitespace in it at all, so a pattern
    # demanding whitespace could never match there -- which left a header split
    # *inside* a word (`...BEGI<newline>N RSA...`) undetected in both passes. It was
    # found by probing the redaction path, not by reading this line.
    ("PEM private key", re.compile(b"-" * 5 + rb"BEGIN(?:\s*[A-Z]+)?\s*PRIVATE\s*KEY" + b"-" * 5)),
    ("AWS access key id", re.compile(rb"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")),
    ("GitHub token", re.compile(rb"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b")),
    ("GitHub fine-grained PAT", re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("OpenAI-style key", re.compile(rb"\bsk-[A-Za-z0-9]{20,}\b")),
    # The current OpenAI format is hyphen-separated (`sk-proj-...`) and Anthropic's keys are
    # `sk-ant-...`; the pattern above reaches neither, because its character class stops at the
    # first hyphen. A signature named "OpenAI-style key" that misses OpenAI's present-day keys
    # is worse than no signature at all: it reads as coverage. Found by probing the list with
    # the shapes it claimed, not by reading it.
    ("vendor-segmented API key", re.compile(rb"\bsk-(?:ant|proj|live|test)-[A-Za-z0-9_-]{16,}\b")),
    # Stripe separates its segments with underscores, so no hyphen-based pattern reaches these
    # either. `pk_` is deliberately **absent**: publishable keys are designed to be published in
    # front ends, and refusing them would be a false refusal -- the kind this tool cannot afford,
    # because every one costs an acknowledgement and teaches the operator to ignore the list.
    ("Stripe-style key", re.compile(
        rb"\b(?:(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|whsec_[A-Za-z0-9]{16,})\b")),
    ("Google API key", re.compile(rb"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("Slack token", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Telegram bot token", re.compile(rb"\b\d{9,10}:AA[A-Za-z0-9_-]{30,}\b")),
    ("JWT", re.compile(rb"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("credential assignment", re.compile(
        rb"(?i)(?:password|passwd|api[_-]?key|secret|client[_-]?secret|access[_-]?token)"
        rb"[\"']?[ \t]*[:=][ \t]*[\"']?(?![^ \t\"'\r\n]*\()[^\s\"']{8,}")),
    # Assembled from fragments on purpose: written whole, this line would itself be
    # the OpenSSH literal it looks for, and every commit of this file would carry a
    # deny-list hit. Adjacent literals concatenate at compile time, so the runtime
    # pattern is byte-for-byte the same as a single literal.
    ("OpenSSH private key", re.compile(b"-" * 5 + b"BEGIN OPENSSH PRIVATE KEY" + b"-" * 5)),
)

# A database is not source, and its rows are never content-scanned. The name rules
# below deny a database by extension, but an extension is a rename away: a copy at
# `data/records.db.bak-161134` was exported with every row intact because only the
# *final* extension was compared. These signatures close the rename case for the
# formats whose magic number is unambiguous.
DATABASE_SIGNATURES: Tuple[Tuple[str, bytes], ...] = (
    ("SQLite database", b"SQLite format 3\x00"),
)

# SQLite's write-ahead log does not begin with the database magic, so a renamed copy
# (`dump.dat`) defeated the signature table as well as the extension rule. The header
# is 32 bytes and fixed: magic, format version, page size. Checking those three fields
# is specific enough to report; a bare four-byte magic would not be.
SQLITE_WAL_MAGICS = (b"\x37\x7f\x06\x82", b"\x37\x7f\x06\x83")
SQLITE_WAL_FORMAT_VERSION = 3007000
SQLITE_PAGE_SIZES = frozenset((512, 1024, 2048, 4096, 8192, 16384, 32768, 65536))
_SQLITE_SIDECARS = ("-wal", "-shm", "-journal")


def _sqlite_sidecar_signature(data: bytes) -> Optional[str]:
    """Name the SQLite sidecar format this blob uses, or None.

    A write-ahead log holds committed pages that exist in no other file, which makes it
    a database for the purposes of this check.
    """
    if len(data) < 32 or data[:4] not in SQLITE_WAL_MAGICS:
        return None
    version = int.from_bytes(data[4:8], "big")
    page_size = int.from_bytes(data[8:12], "big")
    if version != SQLITE_WAL_FORMAT_VERSION or page_size not in SQLITE_PAGE_SIZES:
        return None
    return "SQLite write-ahead log"


DATABASE_LIMITATION = (
    "A database is refused by content, not inspected: its rows are not scanned, so "
    "this check says nothing about what the file contains."
)

HOST_PATH_PATTERNS: Tuple[Tuple[str, "re.Pattern[bytes]"], ...] = (
    ("POSIX home path", re.compile(rb"/home/[A-Za-z0-9._-]+(?![A-Za-z0-9._-])")),
    ("macOS home path", re.compile(rb"/Users/[A-Za-z0-9._-]+(?![A-Za-z0-9._-])")),
    ("Windows user path", re.compile(rb"[A-Za-z]:\\\\?Users\\\\?[A-Za-z0-9._-]+", re.I)),
    ("WSL Windows mount", re.compile(rb"/mnt/[a-z]/Users/[A-Za-z0-9._-]+", re.I)),
)

LFS_POINTER = b"version https://git-lfs.github.com/spec/v1"

#: What a redacted home path becomes. `~` keeps the record readable on the machine
#: that produced it and discloses nothing on any other.
EVIDENCE_PATH_PLACEHOLDER = b"~"
EVIDENCE_REDACTION_MARKER = b"<redacted>"
CROSS_LINE_PASS_LIMIT = 32


def _joined_without_indentation(data: bytes) -> bytes:
    """Lines joined with their indentation removed, intra-line spacing kept.

    This is the copy that closes the split-across-a-newline evasion. Removing *all*
    whitespace (the previous behaviour) also manufactured matches across the spaces of
    ordinary code: a binding whose name ends in `Secret` and whose value is a long object
    literal became one unbroken assignment as far as the pattern was concerned, and the
    scanner reported a credential in a line that has none. Newlines and the indentation
    that follows them are what an evasion uses; the spaces inside a line are what
    ordinary code uses, so only the former are removed.

    Writing *this* paragraph is how the trap was found a second time: put the compacted
    form of such a line in a docstring and the docstring becomes the false positive.
    """
    return b"".join(line.lstrip() for line in data.split(b"\n"))


def _joined_with_map(data: bytes) -> Tuple[bytes, List[int]]:
    """`_joined_without_indentation`, plus each kept byte's offset in ``data``.

    Redaction has to work on the same text the scanner scans, and then map a hit back to
    the original span, because that is the only place it exists.
    """
    kept = bytearray()
    offsets: List[int] = []
    position = 0
    for line in data.split(b"\n"):
        current = position
        position += len(line) + 1  # + the newline that split() consumed
        stripped = line.lstrip()
        start = current + (len(line) - len(stripped))
        for offset, byte in enumerate(stripped):
            kept.append(byte)
            offsets.append(start + offset)
    return bytes(kept), offsets


def _joined_hit(joined: bytes) -> Optional[Tuple[int, int]]:
    """First match span in the indentation-stripped, line-joined copy."""
    best: Optional[Tuple[int, int]] = None
    for _name, pattern in (*HOST_PATH_PATTERNS, *SECRET_SIGNATURES):
        match = pattern.search(joined)
        if match and (best is None or match.start() < best[0]):
            best = (match.start(), match.end())
    return best


def redact_for_evidence(data: bytes) -> bytes:
    """Strip machine paths and credential shapes from text written to a record.

    Why this is a control and not a courtesy: the tool refuses to export a tree
    that contains a home path or a credential shape, and its own acceptance record
    contains both -- the sandbox paths the run happened in, and the deliberately
    credential-shaped fixtures the run measured. Written verbatim, the record makes
    this repository unexportable by its own gate, and it publishes a username the
    moment the repository is opened. So redaction happens at the point of writing,
    and the record can never be the file that blocks the export.

    Two passes, because the scanner makes two: the raw text, and the
    whitespace-stripped copy. A hit found only in the stripped copy is blanked by
    span in the original, since that is the only place it exists.

    Callers must still verify: :func:`scan_content` over the returned bytes is the
    check that this did what it says, and the acceptance runner fails rather than
    write a record that does not pass it.
    """
    text = data
    for _name, pattern in HOST_PATH_PATTERNS:
        text = pattern.sub(EVIDENCE_PATH_PLACEHOLDER, text)
    for _name, pattern in SECRET_SIGNATURES:
        text = pattern.sub(EVIDENCE_REDACTION_MARKER, text)
    for _ in range(CROSS_LINE_PASS_LIMIT):
        joined, offsets = _joined_with_map(text)
        hit = _joined_hit(joined)
        if hit is None:
            return text
        start, end = hit
        span_start = offsets[start]
        span_end = offsets[end - 1] + 1
        text = text[:span_start] + EVIDENCE_REDACTION_MARKER + text[span_end:]
    return text

PROSE_LIMITATION = (
    "Arbitrary confidential prose cannot be detected by pattern scanning. This "
    "check can never report that a document is free of private content."
)
DENYLIST_LIMITATION = (
    "Deny-list scan: it can report a match, never the absence of one. It cannot "
    "see unusual credential formats or content inside an unread binary."
)


@dataclass
class Finding:
    """One problem found in the candidate tree."""

    check_id: str
    message: str
    path: str = ""
    limitation: str = ""
    status: str = "FAIL"
    severity: str = "STOP"
    #: Set when the finding comes from the object store rather than the working tree:
    #: the blob it was found in. An acknowledgement can bind to it, so an exception
    #: names the exact bytes it covers instead of every shape in that path forever.
    object_id: str = ""


@dataclass
class TreeReport:
    files: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return any(f.status == "FAIL" for f in self.findings)


def _denied_suffix(component: str) -> Optional[str]:
    """The denied extension inside a component, if it names one at all.

    Comparing only the *final* extension let a rotated copy of a denied artefact
    through: `records.db` was refused, but `records.db.bak-161134` and
    `records.db.20261013` were exported with every row intact. Any dotted token
    that names a denied extension denies the component, so a backup suffix, a
    rotation stamp or an archive extension cannot hide the original type.
    """
    name = component.lower()
    # SQLite keeps committed-but-uncheckpointed rows in sidecar files beside the
    # database. `records.db-wal` was allowed -- one dotted token, `db-wal`, matches no
    # denied extension -- and its header is not the database magic, so the content
    # check missed it too: it was exported at exit 0 with the row inside it. A sidecar
    # is the database.
    for sidecar in _SQLITE_SIDECARS:
        if name.endswith(sidecar):
            name = name[: -len(sidecar)]
            break
    for token in name.split(".")[1:]:
        if f".{token}" in DENY_SUFFIXES:
            return f".{token}"
    return None


def _safe_component(component: str) -> bool:
    """True when a single path component is publishable and portable."""
    low = component.lower()
    if low in ALLOWED_EXCEPTIONS:
        return True
    stem = low.split(".")[0]
    if component in DENY_COMPONENTS or low in DENY_COMPONENTS:
        return False
    if low.startswith(".env."):
        return False
    if _denied_suffix(component):
        return False
    if any(ord(c) < 32 for c in component):
        return False
    if stem in RESERVED_STEMS:
        return False
    if any(c in INVALID_NAME_CHARS for c in component):
        return False
    if component != component.rstrip(". "):
        return False
    return True


def safe_relative(raw: str) -> Path:
    """Validate a candidate-relative path. Raises ValueError when unsafe."""
    if not isinstance(raw, str) or not raw or "\x00" in raw or "\\" in raw:
        raise ValueError(f"unsafe path: {raw!r}")
    pure = PurePosixPath(raw)
    if pure.is_absolute():
        raise ValueError(f"absolute path not allowed: {raw!r}")
    parts = raw.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise ValueError(f"unsafe path traversal: {raw!r}")
    if ":" in parts[0]:
        raise ValueError(f"drive-qualified path not allowed: {raw!r}")
    for component in parts:
        if not _safe_component(component):
            raise ValueError(f"private or non-portable path component: {raw!r}")
    return Path(*parts)


def scan_links(root: Path, rel: str) -> List[Finding]:
    """Symlinks and hardlinks both escape the candidate's own guarantee."""
    findings: List[Finding] = []
    current = Path(root)
    for part in PurePosixPath(rel).parts:
        current = current / part
        try:
            st = current.lstat()
        except OSError as exc:
            findings.append(Finding("candidate.path-unreadable", f"cannot stat: {exc}", rel))
            return findings
        if stat.S_ISLNK(st.st_mode):
            findings.append(Finding(
                "candidate.symlink", "symlink inside the candidate tree", rel,
                "A symlink can point outside the tree; its target is not exported.",
            ))
            return findings
    st = current.lstat()
    if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
        findings.append(Finding(
            "candidate.hardlink",
            f"file has {st.st_nlink} hard links; editing one changes the others",
            rel,
            "A hardlink alias is indistinguishable from an ordinary file by content.",
        ))
    return findings


def scan_paths(paths: Iterable[str]) -> List[Finding]:
    """Reserved names and casefold collisions across the whole candidate.

    Collisions are detected per path *component*, not per whole path. Folding the
    whole path misses ``src/Lib/a.txt`` against ``src/lib/b.txt``, which is the same
    defect as ``Notes.md`` against ``notes.md``: on a case-insensitive filesystem the
    two trees collapse into one, silently losing a file.
    """
    findings: List[Finding] = []
    folded: Dict[str, str] = {}
    folded_dirs: Dict[tuple, tuple] = {}
    for rel in paths:
        parts = PurePosixPath(rel).parts
        # A collision can be in a *directory* component, not just the filename:
        # ``src/Lib/a.txt`` and ``src/lib/b.txt`` have distinct filenames and collapse
        # into one tree on a case-insensitive filesystem. Comparing whole folded paths
        # cannot see that, so compare folded directory prefixes as well.
        for depth in range(1, len(parts)):
            folded_dir = tuple(part.casefold() for part in parts[:depth])
            actual_dir = tuple(parts[:depth])
            previous = folded_dirs.get(folded_dir)
            if previous is not None and previous != actual_dir:
                findings.append(Finding(
                    "candidate.casefold-collision",
                    f"{'/'.join(actual_dir)}/ and {'/'.join(previous)}/ differ only by case",
                    rel,
                    "On a case-insensitive filesystem the two directories are one, "
                    "silently merging their contents.",
                ))
                break
            folded_dirs[folded_dir] = actual_dir
        for component in parts:
            stem = component.lower().split(".")[0]
            if stem in RESERVED_STEMS:
                findings.append(Finding(
                    "candidate.reserved-name",
                    f"{component!r} is a reserved device name on Windows", rel,
                    "Cannot be checked out on Windows; fails there rather than here.",
                ))
            if component != component.rstrip(". "):
                findings.append(Finding(
                    "candidate.trailing-dot-or-space",
                    f"{component!r} ends with a dot or space", rel,
                    "Windows silently strips it, so two different trees result.",
                ))
        key = "/".join(part.casefold() for part in parts)
        if key in folded and folded[key] != rel:
            findings.append(Finding(
                "candidate.casefold-collision",
                f"{rel!r} and {folded[key]!r} differ only by case in some path component",
                rel,
                "They collide on case-insensitive filesystems, silently losing one.",
            ))
        else:
            folded[key] = rel
    return findings


def scan_content(rel: str, data: bytes) -> List[Finding]:
    """Secret shapes, host paths, LFS and submodule pointers in one blob."""
    findings: List[Finding] = []
    joined = _joined_without_indentation(data) if b"\n" in data or b"\r" in data else data
    for description, pattern in SECRET_SIGNATURES:
        if pattern.search(data) or (joined is not data and pattern.search(joined)):
            findings.append(Finding(
                "privacy.secret-shape", f"possible {description} in {rel}", rel,
                DENYLIST_LIMITATION,
            ))
    for description, pattern in HOST_PATH_PATTERNS:
        if pattern.search(data):
            findings.append(Finding(
                "candidate.host-path",
                f"{description} in {rel} -- discloses a username and breaks portability",
                rel,
            ))
    if data.lstrip()[:64].startswith(LFS_POINTER):
        findings.append(Finding(
            "candidate.lfs-pointer",
            f"{rel} is a Git LFS pointer, not the asset itself", rel,
            "A stranger receives a 130-byte pointer and no file.",
        ))
    # The check is on content, not on the name: a database is a database whatever it
    # is called, and the extension rules above are a rename away from being useless.
    for description, signature in DATABASE_SIGNATURES:
        if data[:len(signature)] == signature:
            findings.append(Finding(
                "candidate.database-file",
                f"{rel} is a {description}; its rows are not scanned and it is not part "
                f"of a source release",
                rel, DATABASE_LIMITATION,
            ))
            break
    sidecar = _sqlite_sidecar_signature(data)
    if sidecar:
        findings.append(Finding(
            "candidate.database-file",
            f"{rel} is a {sidecar}; it holds pages that are in no other file and is not "
            f"part of a source release",
            rel, DATABASE_LIMITATION,
        ))
    return findings


def content_object_id(data: bytes) -> str:
    """The git object id of a blob with this content, as a 12-character prefix.

    Git's blob id is ``sha1("blob <size>\\0" + content)``, and it is the one identifier
    a working-tree file and an object-store blob can both carry: if the bytes are the
    same, the id is the same. That is what lets an acknowledgement name the *content*
    it covers -- `git rev-parse HEAD:path` prints the same value -- instead of the path,
    which would cover whatever is written there next.

    Verified against `git hash-object` in `tests/test_scan.py`.
    """
    header = b"blob " + str(len(data)).encode("ascii") + b"\x00"
    # Git object identifier compatibility, not candidate integrity (which uses SHA-256).
    return hashlib.sha1(header + data, usedforsecurity=False).hexdigest()[:12]


def scan_file(rel: str, data: bytes) -> List[Finding]:
    """`scan_content` plus the id of the bytes, so an acknowledgement can bind to them.

    Every finding about a file carries the same id, and a finding about the same bytes
    in the object store carries the same id too: one entry, one decision, both places.
    """
    findings = scan_content(rel, data)
    object_id = content_object_id(data)
    for finding in findings:
        finding.object_id = object_id
    return findings


def scan_structure(root: Path) -> List[Finding]:
    """Repository-level structural conditions, for every path that produces a candidate.

    ``scan_tree`` is only used by ``doctor``. Leaving the submodule check inside it
    meant the export path never ran it: ``.gitmodules`` was reported as a STOP by
    ``doctor`` and shipped by ``candidate`` in the same breath.
    """
    root = Path(root)
    findings: List[Finding] = []
    if (root / ".gitmodules").is_file():
        findings.append(Finding(
            "candidate.submodule",
            ".gitmodules present: a submodule is a pointer to another repository",
            ".gitmodules",
            "The submodule's own contents and licence are not part of the candidate.",
        ))
    for name in (".env", ".env.local", ".env.production"):
        if (root / name).is_file():
            findings.append(Finding(
                "candidate.env-file",
                f"{name} exists in the tree; it is not exported and its contents were not "
                f"scanned",
                name,
                "Excluded by name, never inspected. If it holds real values, rotating them "
                "is the only remedy.",
                status="NEEDS_HUMAN", severity="REVIEW",
            ))
    return findings


def scan_tree(root: Path) -> TreeReport:
    """Walk a candidate root and report every problem found, with limitations."""
    root = Path(root)
    report = TreeReport()
    try:
        walker = os.walk(root, topdown=True, followlinks=False)
    except OSError as exc:
        report.findings.append(Finding("candidate.unreadable", str(exc)))
        return report

    # os.walk only prunes when the ``dirs`` list is mutated *during* iteration.
    # Materialising the walk (e.g. sorted(os.walk(...))) silently disables the
    # skip list, which is how generated directories leak into a candidate.
    for where, dirs, names in walker:
        base = Path(where)
        keep: List[str] = []
        for d in sorted(dirs):
            if d in SKIP_DIR_NAMES:
                report.skipped.append((base / d).relative_to(root).as_posix())
            else:
                keep.append(d)
        dirs[:] = keep
        for name in sorted(names):
            rel = (base / name).relative_to(root).as_posix()
            if not _safe_component(name):
                report.findings.append(Finding(
                    "candidate.unsafe-name",
                    f"{rel} is a private, generated or non-portable path",
                    rel,
                ))
                continue
            report.findings.extend(scan_links(root, rel))
            path = root / rel
            try:
                size = path.lstat().st_size
            except OSError as exc:
                report.findings.append(Finding("candidate.unreadable", str(exc), rel))
                continue
            if size > MAX_SCAN_BYTES:
                report.findings.append(Finding(
                    "candidate.unscanned-large-file",
                    f"{rel} is {size} bytes and was not content-scanned",
                    rel, DENYLIST_LIMITATION, status="NOT_RUN", severity="REVIEW",
                ))
                report.files.append(rel)
                continue
            try:
                data = path.read_bytes()
            except OSError as exc:
                report.findings.append(Finding("candidate.unreadable", str(exc), rel))
                continue
            report.findings.extend(scan_file(rel, data))
            report.files.append(rel)

    if (root / ".gitmodules").is_file():
        report.findings.append(Finding(
            "candidate.submodule",
            ".gitmodules present: a submodule is a pointer to another repository",
            ".gitmodules",
            "The submodule's own contents and licence are not part of the candidate.",
        ))
    report.findings.extend(scan_paths(report.files))
    return report
