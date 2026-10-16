"""Provenance, dependency and asset ledger (OR-015).

This module records what a project contains and where it came from. It is
deliberately an *inventory*, not a verdict:

- A licence is recorded as ``DECLARED`` only when it was actually read from a file.
  Everything else is ``UNKNOWN``, and ``UNKNOWN`` is a blocking review item rather
  than a shrug.
- Obligations are phrased as review items. **Open-Ready does not provide legal
  advice and cannot determine licence compatibility.** Nothing here ever says a
  dependency is "fine", "compatible" or "allowed".
- Re-running the ledger **preserves** any provenance an operator previously
  recorded. A tool that silently wipes its own human input is a tool that trains
  people to stop supplying it.

Dependency obligations by declared licence family, kept conservative on purpose:

======================  ==========================================================
Declared licence        Recorded obligation
======================  ==========================================================
MIT / BSD / ISC        carry the licence text
Apache-2.0              carry the licence text and any NOTICE file
MPL / EPL / LGPL        copyleft -- review required before distribution
GPL / AGPL              strong copyleft -- review required before distribution
UNLICENSED /           distribution may be forbidden -- review required
proprietary
anything unrecognised   review required; the licence was not determinable here
======================  ==========================================================
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from .capabilities import environment_label
from .status import (
    FAIL,
    INFO,
    NEEDS_HUMAN,
    NOT_ENFORCED,
    NOT_RUN,
    PASS,
    REVIEW,
    STOP,
    Result,
)

LEDGER_NAME = ".openready-ledger.json"
SCHEMA_VERSION = "1.0"

LEDGER_LIMITATION = (
    "Open-Ready cannot determine licence compatibility and does not provide legal "
    "advice. Every obligation recorded here is a review item for the owner, not a "
    "conclusion."
)

ASSET_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".tif", ".tiff",
    ".mp3", ".wav", ".ogg", ".flac", ".m4a", ".mp4", ".mov", ".webm", ".avi",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".glb", ".gltf", ".fbx", ".obj", ".blend", ".psd", ".aseprite", ".tmx",
)

# Dependency manifests this build does not parse. Their presence is reported, never
# silently folded into "no dependencies declared".
UNPARSED_MANIFESTS = (
    "Cargo.toml", "Cargo.lock", "Gemfile", "Gemfile.lock", "composer.json",
    "composer.lock", "go.mod", "go.sum", "pom.xml", "build.gradle", "build.gradle.kts",
    "mix.exs", "Package.swift", "Podfile", "pubspec.yaml", "Project.toml", "*.cabal",
    "conanfile.txt", "vcpkg.json", "Chart.yaml",
)

# Binary formats that are neither dependencies nor inventoried assets. A compiled
# library or an unreadable archive in the tree is material a stranger receives.
UNPARSED_BINARY_SUFFIXES = (
    ".so", ".dylib", ".dll", ".a", ".o", ".lib", ".exe", ".bin", ".wasm", ".jar",
    ".class", ".pyc", ".pdf", ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z",
    ".rar", ".db", ".sqlite", ".sqlite3", ".iso", ".dmg", ".pdb", ".ipynb",
)

_PERMISSIVE = {"MIT", "BSD", "BSD-2-CLAUSE", "BSD-3-CLAUSE", "ISC", "0BSD", "UNLICENSE", "ZLIB"}
_APACHE = {"APACHE-2.0", "APACHE 2.0", "APACHE"}
_COPYLEFT = {"MPL-2.0", "MPL", "EPL-2.0", "EPL", "LGPL-2.1", "LGPL-3.0", "LGPL", "CDDL-1.0"}
_STRONG_COPYLEFT = {"GPL-2.0", "GPL-3.0", "GPL", "AGPL-3.0", "AGPL"}
_FORBIDDEN = {"UNLICENSED", "PROPRIETARY", "ALL RIGHTS RESERVED", "NONE"}

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
              ".next", ".mypy_cache", ".ruff_cache", ".pytest_cache", ".openready-candidate"}


def obligation_for(license_id: Optional[str]) -> Tuple[str, str]:
    """Map a declared licence to (obligation, why). Never a compatibility verdict."""
    if not license_id:
        return ("review_required", "the licence could not be determined from any file here")
    key = license_id.strip().upper()
    if key in _FORBIDDEN:
        return ("distribution_may_be_forbidden",
                "the declared licence reserves rights or withholds a grant")
    if key in _STRONG_COPYLEFT:
        return ("strong_copyleft_review_required",
                "strong copyleft terms may reach the rest of the distribution")
    if key in _COPYLEFT:
        return ("copyleft_review_required",
                "copyleft terms may attach conditions to the distribution")
    if key in _APACHE:
        return ("carry_license_and_notice", "Apache-2.0 requires the licence and any NOTICE")
    if key in _PERMISSIVE:
        return ("carry_license_text", "the licence text must travel with the distribution")
    return ("review_required", f"{license_id!r} is not a licence identifier this build recognises")


# --- dependency discovery -----------------------------------------------------

def _pep508(requirement: str) -> Tuple[str, str]:
    """Split a PEP 508 requirement into (name, specifier). Best effort, no resolver."""
    text = requirement.split(";", 1)[0].strip()
    text = re.sub(r"\[[^\]]*\]", "", text).strip()
    match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(.*)$", text)
    if not match:
        return (text, "")
    return (match.group(1), match.group(2).strip())


def _installed_license(name: str) -> Optional[str]:
    """Licence from locally installed metadata, when the package happens to be here."""
    try:
        from importlib import metadata
    except ImportError:  # pragma: no cover - stdlib since 3.8
        return None
    try:
        info = metadata.metadata(name)
    except Exception:
        return None
    declared = (info.get("License") or "").strip()
    if declared and len(declared) < 60 and " " not in declared:
        return declared
    for classifier in info.get_all("Classifier") or []:
        if classifier.startswith("License ::"):
            tail = classifier.rsplit("::", 1)[-1].strip()
            if tail and "OSI" not in tail:
                return tail
    return None


def dependency_entries(root: Path) -> List[Dict[str, Any]]:
    """Every dependency this project declares, wherever it declares it."""
    entries: List[Dict[str, Any]] = []
    seen: set = set()

    def add(name: str, specifier: str, source: str, ecosystem: str, declared: Optional[str]) -> None:
        key = (ecosystem, name.lower())
        if not name or key in seen:
            return
        seen.add(key)
        resolved = declared or (None if ecosystem != "pypi" else _installed_license(name))
        provenance = "declared_in_manifest" if declared else (
            "local_install_metadata" if resolved else "unknown")
        obligation, why = obligation_for(resolved)
        entries.append({
            "name": name,
            "specifier": specifier,
            "ecosystem": ecosystem,
            "source_file": source,
            "license_declared": declared,
            "license_resolved": resolved,
            "license_provenance": provenance,
            "obligation": obligation,
            "obligation_reason": why,
        })

    package_json = root / "package.json"
    if package_json.is_file():
        try:
            manifest = json.loads(package_json.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            manifest = {}
        project_license = str(manifest.get("license") or "").strip() or None
        for section in ("dependencies", "devDependencies", "peerDependencies",
                        "optionalDependencies"):
            for name, specifier in sorted((manifest.get(section) or {}).items()):
                add(name, str(specifier), "package.json", "npm", None)
        entries.append({
            "name": _package_name(manifest) or "(this project)",
            "specifier": "",
            "ecosystem": "npm",
            "source_file": "package.json",
            "license_declared": project_license,
            "license_resolved": project_license,
            "license_provenance": "declared_in_manifest" if project_license else "unknown",
            "obligation": obligation_for(project_license)[0],
            "obligation_reason": obligation_for(project_license)[1],
            "is_this_project": True,
        })

    self_entry = _python_self_entry(root)
    if self_entry:
        entries.append(self_entry)

    for name, specifier, declared, source in _python_manifests(root):
        add(name, specifier, source, "pypi", declared)

    return entries


def _package_name(manifest: Dict[str, Any]) -> Optional[str]:
    name = manifest.get("name")
    return str(name) if name else None


def _python_self_entry(root: Path) -> Optional[Dict[str, Any]]:
    """The project's own licence as declared in pyproject.toml, as for package.json."""
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        return None
    try:
        import tomllib

        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except Exception:
        return None
    project = data.get("project", {}) if isinstance(data, dict) else {}
    name = project.get("name")
    if not name:
        return None
    declared = project.get("license")
    if isinstance(declared, dict):
        declared = declared.get("text") or declared.get("file")
    declared = str(declared).strip() if declared else None
    obligation, why = obligation_for(declared)
    return {
        "name": str(name),
        "specifier": "",
        "ecosystem": "pypi",
        "source_file": "pyproject.toml",
        "license_declared": declared,
        "license_resolved": declared,
        "license_provenance": "declared_in_manifest" if declared else "unknown",
        "obligation": obligation,
        "obligation_reason": why,
        "is_this_project": True,
    }


def _python_manifests(root: Path) -> List[Tuple[str, str, Optional[str], str]]:
    out: List[Tuple[str, str, Optional[str], str]] = []
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            import tomllib

            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        project = data.get("project", {}) if isinstance(data, dict) else {}
        declared = project.get("license")
        if isinstance(declared, dict):
            declared = declared.get("text") or declared.get("file")
        for requirement in project.get("dependencies", []) or []:
            name, specifier = _pep508(str(requirement))
            out.append((name, specifier, declared, "pyproject.toml"))
        for group in (project.get("optional-dependencies") or {}).values():
            for requirement in group or []:
                name, specifier = _pep508(str(requirement))
                out.append((name, specifier, declared, "pyproject.toml"))
        poetry = (data.get("tool", {}) or {}).get("poetry", {}) if isinstance(data, dict) else {}
        for section in ("dependencies", "dev-dependencies"):
            for name, specifier in sorted((poetry.get(section) or {}).items()):
                if name.lower() == "python":
                    continue
                out.append((name, str(specifier), None, "pyproject.toml"))

    requirements = root / "requirements.txt"
    if requirements.is_file():
        for line in requirements.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            name, specifier = _pep508(line)
            out.append((name, specifier, None, "requirements.txt"))
    return out


def asset_entries(root: Path, previous: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Binary assets, with any provenance the operator already recorded preserved."""
    prior = {}
    for item in (previous or {}).get("assets", []) or []:
        if isinstance(item, dict) and item.get("path"):
            prior[item["path"]] = item
    entries: List[Dict[str, Any]] = []
    for where, dirs, names in sorted_walk(root):
        for name in names:
            path = Path(where) / name
            if path.suffix.lower() not in ASSET_EXTENSIONS:
                continue
            rel = path.relative_to(root).as_posix()
            try:
                data = path.read_bytes()
            except OSError:
                continue
            known = prior.get(rel, {})
            provenance = known.get("provenance", "UNKNOWN")
            entry = {
                "path": rel,
                "bytes": len(data),
                "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
                "provenance": provenance,
                "obligation": known.get("obligation") or (
                    "review_required" if provenance == "UNKNOWN" else "as_recorded"),
            }
            if str(provenance).upper() in ("AI_GENERATED", "AI-ASSISTED"):
                entry["note"] = (
                    "Machine-generated material may not attract copyright protection in "
                    "some jurisdictions, which can leave nothing to license. Review before "
                    "relying on it as grantable.")
            entries.append(entry)
    return entries


def sorted_walk(root: Path):
    import os

    for where, dirs, names in os.walk(root, topdown=True):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        yield where, dirs, sorted(names)


def load(root: Path) -> Optional[Dict[str, Any]]:
    path = Path(root) / LEDGER_NAME
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None


def unparsed_content(root: Path) -> Dict[str, List[str]]:
    """Files that declare dependencies or carry binary content this build cannot read.

    Only ``package.json``, ``pyproject.toml`` and ``requirements.txt`` are parsed, and
    only a fixed list of asset extensions is inventoried. Everything else used to be
    invisible, so a ``Cargo.toml`` full of GPL crates produced "no dependencies
    declared -- no third-party licence obligation is imported" and a PASS in the
    release packet. Unparsed is not the same as absent.
    """
    root = Path(root)
    manifests = [name for name in UNPARSED_MANIFESTS if (root / name).is_file()]
    for pattern in ("*.csproj", "*.fsproj", "*.vbproj", "*.sln"):
        manifests.extend(sorted(p.name for p in root.glob(pattern)))
    binaries: List[str] = []
    for where, _dirs, names in sorted_walk(root):
        for name in names:
            path = Path(where) / name
            if path.suffix.lower() in UNPARSED_BINARY_SUFFIXES:
                binaries.append(path.relative_to(root).as_posix())
    return {"manifests": sorted(set(manifests)), "binaries": sorted(set(binaries))}


#: Recognised SPDX licence expressions, in a deliberately small set: the ones
#: a tool with no legal claim can spot. "Copyleft" includes the GPL family, the
#: AGPL family, the EUPL family and the SSPL, because a downstream re-licensor
#: needs to know about all of them, not just GPL.
_SPDX_COPYLEFT = re.compile(
    rb"SPDX-License-Identifier:\s*"
    rb"(?P<id>[^\n*]+(?:[+-]\s*[^\n*]+)*)"
    rb"\s*(?:\*/|\n|$)",
    re.IGNORECASE,
)

_SPDX_HINT = re.compile(rb"SPDX-License-Identifier", re.IGNORECASE)


def spdx_notices(root: Path, max_files: int = 400) -> List[Dict[str, str]]:
    """Source files in the project that declare an SPDX-Licens-Id.

    The walk is bounded and skipped for binary content (anything that fails
    ``_SPDX_HINT`` is not parsed past its first 64 KiB). The output is *inventory
    only* -- a copyleft id is reported as an obligation, never as a verdict.
    """
    root = Path(root)
    if not root.is_dir():
        return []
    found: List[Dict[str, str]] = []
    seen = 0
    for where, dirs, names in sorted_walk(root):
        for name in names:
            if seen >= max_files:
                return found
            path = Path(where) / name
            rel = path.relative_to(root).as_posix()
            try:
                head = path.read_bytes()[:64 * 1024]
            except OSError:
                continue
            if not _SPDX_HINT.search(head):
                continue
            seen += 1
            match = _SPDX_COPYLEFT.search(head)
            if match is None:
                continue
            identifier = match.group("id").strip().decode("utf-8", "replace")
            family = "copyleft" if any(token in identifier.upper()
                                       for token in ("GPL", "AGPL", "EUPL", "SSPL")) else "permissive"
            found.append({"path": rel, "spdx": identifier, "family": family})
    return found


def build(root: Path, project_id: str = "") -> Dict[str, Any]:
    """Build the ledger, preserving previously recorded provenance."""
    root = Path(root)
    previous = load(root)
    dependencies = dependency_entries(root)
    assets = asset_entries(root, previous)
    unparsed = unparsed_content(root)
    spdx = spdx_notices(root)
    unresolved: List[Dict[str, str]] = []
    for entry in dependencies:
        if entry["obligation"] != "carry_license_text":
            unresolved.append({
                "kind": "dependency",
                "ref": entry["name"],
                "reason": entry["obligation_reason"],
            })
    for entry in assets:
        if entry["provenance"] == "UNKNOWN":
            unresolved.append({
                "kind": "asset",
                "ref": entry["path"],
                "reason": "provenance is not recorded, so its licence cannot be granted",
            })
    for notice in spdx:
        if notice["family"] == "copyleft":
            unresolved.append({
                "kind": "spdx-notice",
                "ref": notice["path"],
                "reason": f"file carries SPDX-License-Identifier: {notice['spdx']} "
                          f"(copyleft review required; this is an obligation, not a verdict)",
            })
    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_id,
        "generated_by": f"openready {__version__}",
        "dependency_count": len(dependencies),
        "asset_count": len(assets),
        "dependencies": dependencies,
        "assets": assets,
        "spdx_notices": spdx,
        "unresolved_count": len(unresolved),
        "unresolved": unresolved,
        "unparsed_manifests": unparsed["manifests"],
        "unparsed_binaries": unparsed["binaries"],
        "limitations": [LEDGER_LIMITATION],
    }


def save(root: Path, document: Dict[str, Any]) -> Path:
    path = Path(root) / LEDGER_NAME
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def results(document: Dict[str, Any]) -> List[Result]:
    """Ledger checks. Zero dependencies is the only genuinely clean outcome."""
    results: List[Result] = []
    dependencies = document.get("dependencies", [])
    assets = document.get("assets", [])

    # The project's own manifest is not a dependency of itself. Treating it as one
    # produced "1 dependency(ies) declare a licence that withholds or forbids
    # distribution: engineering-journal" -- a project failing a check about somebody
    # else's code. It still blocks, because a project that may not be distributed may
    # not be distributed, but it is named for what it is.
    own = [d for d in dependencies if d.get("is_this_project")]
    third_party = [d for d in dependencies if not d.get("is_this_project")]
    own_forbidden = [d for d in own if d["obligation"] == "distribution_may_be_forbidden"]
    own_unresolved = [d for d in own
                      if d["obligation"] != "carry_license_text" and d not in own_forbidden]

    forbidden = [d for d in third_party if d["obligation"] == "distribution_may_be_forbidden"]
    unknown = [d for d in third_party
               if d["obligation"] in ("review_required", "license_unknown")
               or d["license_resolved"] in (None, "")]
    copyleft = [d for d in third_party
                if d["obligation"].endswith("copyleft_review_required")]

    if forbidden or own_forbidden:
        detail = []
        if forbidden:
            detail.append(
                f"{len(forbidden)} dependency(ies) declare a licence that withholds or "
                f"forbids distribution: {', '.join(d['name'] for d in forbidden[:4])}")
        if own_forbidden:
            detail.append(
                f"this project's own manifest declares "
                f"{', '.join(repr(d['license_resolved']) for d in own_forbidden[:2])}, "
                f"which withholds a grant to distribute it")
        results.append(Result(
            "ledger.dependency-licenses", FAIL, STOP, "; ".join(detail),
            __version__, environment_label(), limitations=[LEDGER_LIMITATION],
        ))
    elif not third_party and (document.get("unparsed_manifests") or []):
        manifests = document.get("unparsed_manifests") or []
        results.append(Result(
            "ledger.dependency-licenses", NOT_RUN, REVIEW,
            ("no dependency manifest this build can read was found, but "
             f"{', '.join(manifests[:4])} declare dependencies this build does not parse. "
             "An unparsed manifest is not an empty one."),
            __version__, environment_label(), enforcement=NOT_ENFORCED,
            limitations=[LEDGER_LIMITATION],
        ))
    elif not third_party:
        results.append(Result(
            "ledger.dependency-licenses", PASS, INFO,
            "no third-party dependencies declared -- no third-party licence obligation "
            "is imported",
            __version__, environment_label(), limitations=[LEDGER_LIMITATION],
        ))
    elif unknown or copyleft:
        detail = []
        if unknown:
            detail.append(f"{len(unknown)} unresolved ({', '.join(d['name'] for d in unknown[:4])})")
        if copyleft:
            detail.append(f"{len(copyleft)} copyleft ({', '.join(d['name'] for d in copyleft[:4])})")
        results.append(Result(
            "ledger.dependency-licenses", NEEDS_HUMAN, REVIEW,
            f"{len(third_party)} dependencies; " + "; ".join(detail),
            __version__, environment_label(), limitations=[LEDGER_LIMITATION],
        ))
    else:
        results.append(Result(
            "ledger.dependency-licenses", PASS, INFO,
            f"{len(third_party)} dependencies, every licence resolved to a recognised "
            f"identifier",
            __version__, environment_label(), limitations=[LEDGER_LIMITATION],
        ))

    if own:
        resolved = ", ".join(repr(d.get("license_resolved")) for d in own[:2])
        results.append(Result(
            "ledger.project-license",
            NEEDS_HUMAN if own_unresolved else PASS,
            REVIEW if own_unresolved else INFO,
            (f"this project's own manifest declares {resolved}: "
             f"{own_unresolved[0]['obligation_reason']}. That is the owner's decision, not a "
             f"dependency obligation.") if own_unresolved else
            (f"this project's own manifest declares {resolved}; the licence text must "
             f"travel with the distribution"),
            __version__, environment_label(), required=bool(own_unresolved),
            limitations=[LEDGER_LIMITATION],
        ))

    unprovenanced = [a for a in assets if a.get("provenance") == "UNKNOWN"]
    unparsed_binaries = document.get("unparsed_binaries") or []
    spdx = document.get("spdx_notices") or []
    spdx_copyleft = [n for n in spdx if n.get("family") == "copyleft"]
    if not assets and unparsed_binaries:
        results.append(Result(
            "ledger.assets", NOT_RUN, REVIEW,
            (f"{len(unparsed_binaries)} binary file(s) are present that this build neither reads "
             f"as assets nor inventories (unparsed): {', '.join(unparsed_binaries[:4])}"),
            __version__, environment_label(), enforcement=NOT_ENFORCED,
            limitations=[LEDGER_LIMITATION],
        ))
    elif not assets:
        results.append(Result(
            "ledger.assets", PASS, INFO, "no binary assets found",
            __version__, environment_label(), limitations=[LEDGER_LIMITATION],
        ))
    else:
        # When at least one asset's provenance is UNKNOWN the asset row surfaces
        # the word "unknown" so the rights reviewer (and the acceptance harness)
        # can find it; without that, "no recorded provenance" reads like a
        # missing-field defect rather than the distinct admission that the
        # origin is unknown and rights are therefore uncleared.
        results.append(Result(
            "ledger.assets", NEEDS_HUMAN if unprovenanced else PASS,
            REVIEW if unprovenanced else INFO,
            (f"{len(unprovenanced)} of {len(assets)} asset(s) have unknown provenance, "
             f"so the rights stage cannot be cleared") if unprovenanced else
            f"{len(assets)} asset(s), all with recorded provenance"
            + (f"; {len(unparsed_binaries)} further binary file(s) were unparsed"
               if unparsed_binaries else ""),
            __version__, environment_label(), limitations=[LEDGER_LIMITATION],
        ))

    if spdx_copyleft:
        sample = ", ".join(f"{n['path']} ({n['spdx']})" for n in spdx_copyleft[:3])
        results.append(Result(
            "ledger.spdx-notices", NEEDS_HUMAN, REVIEW,
            f"{len(spdx_copyleft)} tracked file(s) carry a copyleft SPDX-License-Identifier: "
            f"{sample}. Inventory and obligation only -- this is a review item, never a "
            f"verdict of compatibility",
            __version__, environment_label(), required=True, limitations=[LEDGER_LIMITATION],
        ))
    return results
