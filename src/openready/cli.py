"""Open-Ready command line.

There is deliberately **no** ``publish`` command, and this module contains no
implementation of one. Publication is an owner action bound to an exact artifact
digest, destination and licence, performed through a principal the builder cannot
write to (ADR-002). A builder-side command that published would defeat the only
control that matters, so its absence is a design decision, not a gap.

Exit codes, from ``docs/10-CLI-CONTRACT.md``:

====  =========================================================================
0     operation succeeded; does NOT mean a project is safe to publish
1     actionable failure or STOP
2     completed, but a required human review or permission blocks the next step
3     a required check was unavailable, unsupported, unenforceable or not run
64    CLI usage error
====  =========================================================================

Recorded deviations from the command list in that contract, none of them hidden:

* ``status``, ``backup`` and ``worth`` still accept ``--path``; ``status`` and
  ``backup`` now also honour ``--project ID`` through the private registry
  (``registry.py``), ``worth`` does not yet. ``--path`` is kept deliberately: the
  registry is an index that can be deleted, so addressing a project by path must
  always work.
* ``new`` is not in that contract. The contract's creation command is
  ``init --path PATH --language NAME``, and it produces a bare scaffold: no baseline
  commit, no synthetic fixture, no private runtime data root, no registration. ``new``
  composes those four steps, so that one command produces a project that can actually
  run, be named and be recovered. ``init`` keeps exactly its documented behaviour --
  including for ``--adopt``, which must never commit inside somebody's existing tree.
* ``acknowledge`` is not in that contract. Adopting a repository that already has history
  is the first wall a real user meets: the export refuses a candidate while the object
  store holds what the working tree no longer does, and there was no way to record that a
  blob had been looked at except by hand-writing the acknowledgement file. The command
  proposes one entry per blob, writes nothing without ``--write``, and proposes nothing at
  all for a finding in the working tree -- an exception at a path is wider than the reason
  for it, and editing the file costs less.
* ``packet`` is not a separate command -- ``verify --packet`` writes it, since emitting
  evidence is what ``verify`` is permitted to do.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import POLICY_VERSION, __version__
from . import acknowledge as acknowledge_mod
from . import advisory as advisory_mod
from . import backup as backup_mod
from . import candidate as candidate_mod
from . import doctor as doctor_mod
from . import external as external_mod
from . import feature as feature_mod
from . import history as history_mod
from . import limits as limits_mod
from . import intake as intake_mod
from . import ledger as ledger_mod
from . import migrate as migrate_mod
from . import policy as policy_mod
from . import private as private_mod
from . import project as project_mod
from . import promote as promote_mod
from . import providers as providers_mod
from . import registry as registry_mod
from . import staged as staged_mod
from . import templates as templates_mod
from . import verify as verify_mod
from .capabilities import detect
from .contracts import tool_root
from .status import (
    EXIT_FAIL,
    EXIT_OK,
    EXIT_USAGE,
    FAIL,
    INFO,
    NOT_ENFORCED,
    NOT_RUN,
    PASS,
    REVIEW,
    Result,
    exit_code_for,
    summarize,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openready",
        description=(
            "Open-Ready -- private-first project care and release-candidate "
            "preparation. No publish command exists."
        ),
    )
    parser.add_argument("--version", action="version",
                        version=f"openready {__version__} (policy {POLICY_VERSION})")
    sub = parser.add_subparsers(dest="command", required=True)

    p_new = sub.add_parser("new", help="create a complete private project in one step "
                                       "(scaffold, synthetic fixture, git baseline, "
                                       "private data root, registration)")
    p_new.add_argument("--path", required=True)
    p_new.add_argument("--project-id", dest="project_id", default=None,
                       help="defaults to the directory name")
    p_new.add_argument("--language", action="append", dest="languages")
    p_new.add_argument("--tier", default="T1", choices=list(project_mod.TIERS))
    p_new.add_argument("--allow-inside-checkout", dest="allow_inside_checkout",
                       action="store_true", help="override the enclosing-checkout refusal")
    p_new.add_argument("--backup", action="store_true",
                       help="also take a first backup outside the project and verify it")
    p_new.add_argument("--json", action="store_true")

    p_init = sub.add_parser("init", help="create a private project skeleton")
    p_init.add_argument("--path", required=True)
    p_init.add_argument("--project-id", dest="project_id", default=None,
                        help="defaults to the directory name")
    p_init.add_argument("--language", action="append", dest="languages")
    p_init.add_argument("--tier", default="T1", choices=list(project_mod.TIERS))
    p_init.add_argument("--git", action="store_true",
                        help="create a local git repo (no remote, no licence)")
    p_init.add_argument("--allow-inside-checkout", action="store_true",
                        help="override the enclosing-checkout refusal")
    p_init.add_argument("--adopt", action="store_true",
                        help="scaffold into an existing directory, creating only what is "
                             "missing and overwriting nothing")
    p_init.add_argument("--register", action="store_true",
                        help="also record the project in the private registry (metadata only)")
    p_init.add_argument("--json", action="store_true")

    p_doc = sub.add_parser("doctor", help="report findings and what was not checked")
    p_doc.add_argument("--path", required=True)
    p_doc.add_argument("--json", action="store_true")

    p_cap = sub.add_parser("capabilities",
                           help="detect host and fleet capabilities (no network)")
    p_cap.add_argument("--path")
    p_cap.add_argument("--json", action="store_true")

    p_st = sub.add_parser("status", help="report project metadata, or the private "
                                         "registry when given neither --path nor --project")
    p_st.add_argument("--path")
    p_st.add_argument("--project", default=None,
                      help="project id from the private registry")
    p_st.add_argument("--json", action="store_true")

    p_fix = sub.add_parser("fixture", help="write the deterministic synthetic corpus")
    p_fix.add_argument("--path", required=True)
    p_fix.add_argument("--json", action="store_true")

    p_led = sub.add_parser("ledger", help="build or report the provenance ledger")
    p_led.add_argument("--path", required=True)
    p_led.add_argument("--write", action="store_true")
    p_led.add_argument("--json", action="store_true")

    p_cand = sub.add_parser("candidate", help="export an UNAPPROVED candidate")
    p_cand.add_argument("--path", required=True)
    p_cand.add_argument("--out")
    p_cand.add_argument("--history", default="none", choices=("none", "squash", "preserve"))
    p_cand.add_argument("--json", action="store_true")

    p_ver = sub.add_parser("verify", help="verify a frozen candidate and emit a packet")
    p_ver.add_argument("--candidate", required=True)
    p_ver.add_argument("--packet")
    p_ver.add_argument("--no-build", action="store_true")
    p_ver.add_argument("--expected-digest", dest="expected_digest", default=None,
                       help="the digest recorded when this artifact was reviewed; "
                            "without it, verification only proves self-consistency")
    p_ver.add_argument("--json", action="store_true")

    p_bak = sub.add_parser("backup", help="private backup with a verified restore")
    p_bak.add_argument("--path")
    p_bak.add_argument("--project", default=None,
                       help="project id from the private registry")
    p_bak.add_argument("--out")
    p_bak.add_argument("--verify", action="store_true")
    p_bak.add_argument("--json", action="store_true")

    p_test = sub.add_parser("test", help="run the project's tests in a scrubbed environment")
    p_test.add_argument("--path", required=True)
    p_test.add_argument("--json", action="store_true")

    p_worth = sub.add_parser("worth", help="write a private recommendation memo")
    p_worth.add_argument("--path", required=True)
    p_worth.add_argument("--no-write", action="store_true")
    p_worth.add_argument("--json", action="store_true")

    p_upd = sub.add_parser("update", help="check policy and contract drift (changes nothing)")
    p_upd.add_argument("--path")
    p_upd.add_argument("--dry-run", action="store_true")
    p_upd.add_argument("--json", action="store_true")

    p_pre = sub.add_parser("precommit", help="check the STAGED content of a commit; "
                                             "advisory -- `git commit --no-verify` skips it")
    p_pre.add_argument("--path", default=".")
    p_pre.add_argument("--json", action="store_true")

    p_ack = sub.add_parser(
        "acknowledge",
        help="propose acknowledgements for the residue in the object store; writes "
             "nothing without --write",
        description=(
            "Adopting a repository that already has history. Its working tree can be "
            "cleaned by editing, but the object store still holds what was cleaned, and "
            "the export refuses a candidate while any of that is unacknowledged. This "
            "command proposes one entry per blob -- the exact bytes, not the path forever "
            "-- and records them only when asked. It proposes nothing for a finding in "
            "the working tree: a path-wide exception there is wider than its reason, and "
            "editing the file costs less."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_ack.add_argument("--path", default=".", help="project root (default: .)")
    p_ack.add_argument("--reason", default="",
                       help="the operator's statement about why these are safe to "
                            "acknowledge (required with --write)")
    p_ack.add_argument("--by", default="", help="who is acknowledging (default: you@host)")
    p_ack.add_argument("--expires", default="",
                       help="ISO date after which the entry stops applying")
    p_ack.add_argument("--write", action="store_true",
                       help="record the proposal in .openready-allow.json")
    p_ack.add_argument("--include-tree", action="store_true", dest="include_tree",
                       help="also acknowledge findings in the working tree (wider entries)")
    p_ack.add_argument("--json", action="store_true")

    # --- new work-order commands ---
    p_promote = sub.add_parser("promote",
                                help="record a `live_checked` stage after a loopback health probe")
    p_promote.add_argument("--path", required=True)
    p_promote.add_argument("--url", default=None,
                           help="loopback-only health URL; refused for any other host")
    p_promote.add_argument("--timeout", type=float, default=5.0)
    p_promote.add_argument("--json", action="store_true")

    p_rollback = sub.add_parser("rollback",
                                 help="move the code back, never the private data")
    p_rollback.add_argument("--path", required=True)
    p_rollback.add_argument("--to", required=True, help="the revision to roll back to")
    p_rollback.add_argument("--json", action="store_true")

    p_feat = sub.add_parser("feature",
                             help="worktree-per-feature and risk-tiered tests (read mostly)")
    feat_sub = p_feat.add_subparsers(dest="feature_command", required=True)
    p_feat_start = feat_sub.add_parser("start",
                                       help="create a worktree; the serving checkout is untouched")
    p_feat_start.add_argument("--path", required=True)
    p_feat_start.add_argument("--name", required=True)
    p_feat_start.add_argument("--base", default=None)
    p_feat_start.add_argument("--json", action="store_true")
    p_feat_test = feat_sub.add_parser("test",
                                      help="run the project's own suite + the tier's checks")
    p_feat_test.add_argument("--path", required=True)
    p_feat_test.add_argument("--name", required=True)
    p_feat_test.add_argument("--tier", default=None)
    p_feat_test.add_argument("--json", action="store_true")

    p_intake = sub.add_parser("intake", help="propose unadopted projects (never silently adopts)")
    p_intake.add_argument("--parent", required=True)
    p_intake.add_argument("--json", action="store_true")
    p_intake_propose = sub.add_parser("propose", parents=[p_intake], add_help=False)

    p_mig = sub.add_parser("migrate", help="run a synthetic migration drill (no real data touched)")
    p_mig.add_argument("--path", default=None)
    p_mig.add_argument("--drill", action="store_true")
    p_mig.add_argument("--migrate", action="store_true")
    p_mig.add_argument("--policy", default=None)
    p_mig.add_argument("--json", action="store_true")

    p_tpl = sub.add_parser("templates",
                            help="generate public-release artifacts on demand (NO licence file)")
    p_tpl.add_argument("--to", required=True)
    p_tpl.add_argument("--project-id", dest="project_id", default="")
    p_tpl.add_argument("--licence-recommendation", dest="licence_recommendation", default="MIT")
    p_tpl.add_argument("--overwrite", action="store_true")
    p_tpl.add_argument("--json", action="store_true")

    p_prov = sub.add_parser("providers", help="host-provider adapters (read-only)")
    prov_sub = p_prov.add_subparsers(dest="providers_command", required=True)
    p_prov_list = prov_sub.add_parser("list", help="list the supported adapters")
    p_prov_list.add_argument("--json", action="store_true")
    p_prov_pre = prov_sub.add_parser("preflight",
                                      help="read-only preflight of one provider")
    p_prov_pre.add_argument("--target", required=True)
    p_prov_pre.add_argument("--json", action="store_true")

    p_ext = sub.add_parser("external",
                            help="external-action profiles for high-risk integrations")
    p_ext.add_argument("--profile", required=True)
    p_ext.add_argument("--destination", default=None)
    p_ext.add_argument("--json", action="store_true")

    p_pol = sub.add_parser("policy", help="scoped owner approvals for external services")
    pol_sub = p_pol.add_subparsers(dest="policy_command", required=True)
    p_pol_check = pol_sub.add_parser("check", help="is this (destination, data-class) approved?")
    p_pol_check.add_argument("--destination", required=True)
    p_pol_check.add_argument("--data-class", dest="data_class", required=True)
    p_pol_check.add_argument("--json", action="store_true")
    p_pol_grant = pol_sub.add_parser("grant", help="OWNER act: record a scoped approval")
    p_pol_grant.add_argument("--service-id", dest="service_id", required=True)
    p_pol_grant.add_argument("--destination", required=True)
    p_pol_grant.add_argument("--data-class", dest="data_class", required=True)
    p_pol_grant.add_argument("--expires", required=True)
    p_pol_grant.add_argument("--actor", required=True)
    p_pol_grant.add_argument("--note", default="")
    p_pol_grant.add_argument("--json", action="store_true")
    p_pol_revoke = pol_sub.add_parser("revoke", help="OWNER act: revoke a scoped approval")
    p_pol_revoke.add_argument("--service-id", dest="service_id", required=True)
    p_pol_revoke.add_argument("--actor", required=True)
    p_pol_revoke.add_argument("--json", action="store_true")
    p_pol_list = pol_sub.add_parser("list", help="list approvals (redacted)")
    p_pol_list.add_argument("--json", action="store_true")

    p_restore = sub.add_parser("restore",
                                help="restore a backup archive to a location the operator names")
    p_restore.add_argument("--archive", required=True)
    p_restore.add_argument("--to", required=True)
    p_restore.add_argument("--json", action="store_true")

    p_history = sub.add_parser("history", help="bounded git history scan")
    p_history.add_argument("--path", required=True)
    p_history.add_argument("--json", action="store_true")

    p_limits = sub.add_parser("limits",
                              help="the one-command honesty view: every unverified "
                                   "control, with its requirement id, why it is "
                                   "unverified, and what would verify it")
    p_limits.add_argument("--path", default=None,
                          help="project root; defaults to the current directory")
    p_limits.add_argument("--json", action="store_true")

    return parser


def _emit(results: List[Result], as_json: bool, label: str,
          extra: Optional[Dict[str, Any]] = None) -> int:
    code = exit_code_for(results)
    if as_json:
        payload: Dict[str, Any] = {
            "tool_version": __version__,
            "policy_version": POLICY_VERSION,
            "command": label,
            "exit_code": code,
            "summary": summarize(results),
            "results": [r.to_dict() for r in results],
        }
        if extra:
            payload.update(extra)
        print(json.dumps(payload, indent=2, default=str))
    else:
        counts = summarize(results)
        for result in results:
            tag = "ok  " if result.status == PASS else _tag(result.status)
            extra_text = f" [{result.enforcement}]" if result.enforcement else ""
            print(f"  {tag} {result.check_id}: {result.message}{extra_text}")
            for limitation in result.limitations:
                print(f"        limitation: {limitation}")
        print(f"  -> exit {code} (failed {counts[FAIL]}, human {counts['NEEDS_HUMAN']}, "
              f"unrun {counts[NOT_RUN]})")
    return code


def _tag(status: str) -> str:
    return {"FAIL": "STOP", "NEEDS_HUMAN": "HUMAN", "NOT_RUN": "UNRUN",
            "NOT_APPLICABLE": "n/a "}.get(status, "PROB")


def _project_id_from_path(target: Path) -> str:
    """Derive a project id from the directory name when none was supplied.

    The contract's invocation is ``init --path PATH --language NAME``; ``project_id``
    appears in the project schema but the specification never says where it comes
    from, so requiring it as a flag made the documented invocation fail.
    """
    name = Path(target).resolve().name.strip().lower()
    cleaned = re.sub(r"[^a-z0-9-]+", "-", name).strip("-")
    return cleaned or "project"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse exits 2 for a usage error. This contract reserves 2 for
        # "completed, but a required human review blocks release", so a usage error
        # must not be indistinguishable from it.
        code = exc.code
        if code in (2, None):
            return EXIT_USAGE if code == 2 else EXIT_OK
        return int(code)
    command = args.command

    if command == "new":
        target = Path(args.path).expanduser()
        project_id = args.project_id or _project_id_from_path(target)
        results = project_mod.create(
            target, project_id, languages=args.languages or ["python"], tier=args.tier,
            force=args.allow_inside_checkout, backup=args.backup,
        )
        return _emit(results, args.json, "new")

    if command == "init":
        target = Path(args.path).expanduser()
        project_id = args.project_id or _project_id_from_path(target)
        results = project_mod.init(
            target, project_id,
            languages=args.languages or ["python"], tier=args.tier,
            git=args.git, force=args.allow_inside_checkout, adopt=args.adopt,
            register=args.register,
        )
        return _emit(results, args.json, "init")

    if command == "doctor":
        try:
            return doctor_mod.run(Path(args.path).expanduser(), json_output=args.json)
        except NotADirectoryError as exc:
            print(f"BLOCKED: {exc}", file=sys.stderr)
            return EXIT_FAIL

    if command == "capabilities":
        report = detect(Path(args.path).expanduser() if args.path else None)
        payload = report.as_dict()
        if args.json:
            print(json.dumps(payload, indent=2))
            return EXIT_OK
        print("OPEN-READY CAPABILITIES  (detected, never assumed; no network used)")
        for cap in report.capabilities:
            value = json.dumps(cap.value) if not isinstance(cap.value, str) else cap.value
            print(f"  {cap.capability_id:<32} {cap.enforcement:<12} {value}")
            if cap.note:
                print(f"      {cap.note}")
        return EXIT_OK

    if command == "status":
        if args.project:
            root, resolution = registry_mod.resolve(args.project)
            if root is None:
                return _emit(resolution, args.json, "status")
            return _status(root, args.json, registry_notes=resolution)
        if args.path:
            return _status(Path(args.path).expanduser(), args.json)
        return _registry_overview(args.json)

    if command == "fixture":
        root = Path(args.path).expanduser()
        root.mkdir(parents=True, exist_ok=True)
        written = private_mod.synthetic_corpus(root)
        found = private_mod.boundary_results(root)
        results = [Result(
            "fixture.written", PASS, INFO,
            f"wrote {len(written)} deterministic synthetic file(s) under {root}",
            __version__, "", limitations=[
                "Synthetic by construction: no operator content is copied into a fixture.",
            ],
        )] + found
        return _emit(results, args.json, "fixture", {"written": written})

    if command == "ledger":
        root = Path(args.path).expanduser()
        document = ledger_mod.build(root)
        if args.write:
            ledger_mod.save(root, document)
        results = ledger_mod.results(document)
        return _emit(results, args.json, "ledger", {
            "ledger": {
                "dependency_count": document["dependency_count"],
                "asset_count": document["asset_count"],
                "unresolved_count": document["unresolved_count"],
            },
            "unresolved": document["unresolved"][:20],
        })

    if command == "candidate":
        return _candidate(args)

    if command == "verify":
        results, packet = verify_mod.verify(
            Path(args.candidate).expanduser(),
            Path(args.packet).expanduser() if args.packet else None,
            run_build=not args.no_build,
            expected_digest=args.expected_digest,
        )
        return _emit(results, args.json, "verify", {"packet": packet})

    if command == "backup":
        return _backup(args)

    if command == "test":
        results = verify_mod.restricted_build(Path(args.path).expanduser())
        return _emit(results, args.json, "test")

    if command == "worth":
        root = Path(args.path).expanduser()
        results, memo = advisory_mod.worth(
            root, doctor_results_for(root), ledger_mod.build(root),
            write=not args.no_write,
        )
        if not args.json:
            print(memo)
        return _emit(results, args.json, "worth", {"memo": memo})

    if command == "update":
        results = advisory_mod.update_dry_run(
            Path(args.path).expanduser() if args.path else None)
        return _emit(results, args.json, "update")

    if command == "acknowledge":
        results, extra = acknowledge_mod.run(
            Path(args.path).expanduser(), reason=args.reason, by=args.by,
            expires=args.expires, write_it=args.write, include_tree=args.include_tree,
        )
        return _emit(results, args.json, "acknowledge", extra)

    if command == "precommit":
        results = staged_mod.run(Path(args.path).expanduser())
        return _emit(results, args.json, "precommit")

    if command == "promote":
        return _promote(args)

    if command == "rollback":
        return _rollback(args)

    if command == "feature":
        return _feature(args)

    if command == "intake":
        return _intake(args)

    if command == "migrate":
        return _migrate(args)

    if command == "templates":
        return _templates(args)

    if command == "providers":
        return _providers(args)

    if command == "external":
        return _external(args)

    if command == "policy":
        return _policy(args)

    if command == "restore":
        return _restore(args)

    if command == "history":
        return _history(args)

    if command == "limits":
        return _limits(args)

    print("usage error", file=sys.stderr)
    return EXIT_USAGE


def _status(root: Path, as_json: bool,
            registry_notes: Optional[List[Result]] = None) -> int:
    config_path = root / project_mod.CONFIG_NAME
    if not config_path.is_file():
        print(f"BLOCKED: no {project_mod.CONFIG_NAME} at {root}", file=sys.stderr)
        return EXIT_FAIL
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        print(f"BLOCKED: config unreadable: {exc}", file=sys.stderr)
        return EXIT_FAIL
    notes = registry_notes or []
    # Metadata only: never product contents, never private documents.
    if as_json:
        payload = dict(config)
        if notes:
            payload["registry"] = {
                "results": [r.to_dict() for r in notes],
                "exit_code": exit_code_for(notes),
            }
        print(json.dumps(payload, indent=2))
        return exit_code_for(notes)
    print(f"  project_id : {config.get('project_id')}")
    print(f"  visibility : {config.get('visibility')}")
    print(f"  risk_tier  : {config.get('risk_tier')}")
    print(f"  languages  : {', '.join(config.get('languages', []))}")
    print(f"  licence    : {config.get('license_intent')} (staged decision)")
    for note in notes:
        tag = "ok  " if note.status == PASS else _tag(note.status)
        print(f"  {tag} {note.check_id}: {note.message}")
    return exit_code_for(notes)


def _registry_overview(as_json: bool) -> int:
    """What ``status`` reports with neither --path nor --project: the portfolio index."""
    rows, problems = registry_mod.entries()
    results = problems or registry_mod.summary_results()
    code = exit_code_for(results)
    if as_json:
        print(json.dumps({
            "tool_version": __version__,
            "policy_version": POLICY_VERSION,
            "command": "status",
            "exit_code": code,
            "summary": summarize(results),
            "results": [r.to_dict() for r in results],
            "registry": str(registry_mod.registry_file()),
            "projects": rows,
        }, indent=2, default=str))
        return code
    print(f"OPEN-READY PROJECTS  (private registry metadata only, no project contents)")
    print(f"  registry: {registry_mod.registry_file()}")
    if not rows:
        print("  no projects registered")
    for entry in rows:
        baseline = "baseline commit" if entry.get("baseline_commit") else "NO baseline commit"
        print(f"  {str(entry.get('project_id')):<24} {str(entry.get('risk_tier')):<3} "
              f"{baseline:<16} {entry.get('path')}")
    return _emit(results, False, "status")


def doctor_results_for(root: Path) -> List[Result]:
    """Run doctor's checks without printing, for commands that consume them."""
    import contextlib
    import io

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        doctor_mod.run(root, json_output=True)
    try:
        return _results_from_payload(json.loads(buffer.getvalue()))
    except (ValueError, KeyError):
        return []


def _results_from_payload(payload: Dict[str, Any]) -> List[Result]:
    out: List[Result] = []
    for record in payload.get("results", []):
        out.append(Result(
            record["check_id"], record["status"], record["severity"], record["message"],
            record["tool_version"], record["environment"],
            required=record["status"] != NOT_RUN,
            enforcement=record.get("enforcement"),
            limitations=list(record.get("limitations", [])),
        ))
    return out


def _candidate(args: argparse.Namespace) -> int:
    root = Path(args.path).expanduser().resolve()
    out = Path(args.out).expanduser().resolve() if args.out else root / candidate_mod.CANDIDATE_DIRNAME
    if not (root / project_mod.CONFIG_NAME).is_file():
        print(f"BLOCKED: no {project_mod.CONFIG_NAME} at {root}", file=sys.stderr)
        return EXIT_FAIL

    plan = candidate_mod.plan(root, root.name)
    history_report = None
    if history_mod.is_repository(root):
        history_report = history_mod.scan(root)

    results, meta = candidate_mod.export(
        root, out, root.name, history_mode=args.history, history_report=history_report,
    )
    return _emit(results, args.json, "candidate", {
        "plan": {"allowlist": plan["allowlist"], "included": len(plan["included"]),
                 "excluded": plan["excluded"][:20]},
        "candidate": meta,
    })


def _backup(args: argparse.Namespace) -> int:
    if args.project:
        root, resolution = registry_mod.resolve(args.project)
        if root is None:
            return _emit(resolution, args.json, "backup")
    elif args.path:
        root = Path(args.path).expanduser().resolve()
    else:
        print("usage error: backup needs --path or --project ID", file=sys.stderr)
        return EXIT_USAGE
    results, archive = backup_mod.create(
        root, Path(args.out).expanduser() if args.out else None)
    extra: Dict[str, Any] = {"archive": str(archive) if archive else None}
    if archive is not None and args.verify:
        restore_results, report = backup_mod.verify_restore(archive)
        results = results + restore_results + backup_mod.migration_drill()
        extra["restore_report"] = report
    return _emit(results, args.json, "backup", extra)


def _promote(args: argparse.Namespace) -> int:
    results = promote_mod.promote(
        Path(args.path).expanduser().resolve(), url=args.url, timeout=args.timeout)
    return _emit(results, args.json, "promote")


def _rollback(args: argparse.Namespace) -> int:
    results = promote_mod.rollback(
        Path(args.path).expanduser().resolve(), to_revision=args.to)
    return _emit(results, args.json, "rollback")


def _feature(args: argparse.Namespace) -> int:
    if args.feature_command == "start":
        results, target = feature_mod.start(
            Path(args.path).expanduser().resolve(), args.name, base=args.base)
        return _emit(results, args.json, "feature-start", {"worktree": str(target) if target else None})
    if args.feature_command == "test":
        results = feature_mod.test(
            Path(args.path).expanduser().resolve(), args.name, tier=args.tier)
        return _emit(results, args.json, "feature-test")
    print("usage error: feature needs a subcommand (start|test)", file=sys.stderr)
    return EXIT_USAGE


def _intake(args: argparse.Namespace) -> int:
    parent = Path(args.parent).expanduser().resolve()
    results = intake_mod.propose(parent)
    return _emit(results, args.json, "intake", {"candidates":
        [c["name"] for c in intake_mod.candidates(parent)[0]]})


def _migrate(args: argparse.Namespace) -> int:
    if args.drill:
        return _emit(backup_mod.migration_drill(), args.json, "migrate")
    if args.migrate:
        target = Path(args.policy).expanduser().resolve() if args.policy else None
        if target is None:
            print("usage error: --migrate needs --policy FILE", file=sys.stderr)
            return EXIT_USAGE
        results = migrate_mod.apply(target, Path(args.path).expanduser().resolve() if args.path else None)
        return _emit(results, args.json, "migrate")
    print("usage error: migrate needs --drill or --migrate --policy FILE", file=sys.stderr)
    return EXIT_USAGE


def _templates(args: argparse.Namespace) -> int:
    written, results = templates_mod.generate(
        Path(args.to).expanduser().resolve(), args.project_id,
        licence_recommendation=args.licence_recommendation, overwrite=args.overwrite)
    return _emit(results, args.json, "templates", {"written": written})


def _providers(args: argparse.Namespace) -> int:
    if args.providers_command == "list":
        results = providers_mod.detect(None)
        return _emit(results, args.json, "providers", {"adapters": providers_mod.list_adapters()})
    if args.providers_command == "preflight":
        results = providers_mod.preflight(args.target)
        return _emit(results, args.json, "providers-preflight")
    print("usage error: providers needs list or preflight", file=sys.stderr)
    return EXIT_USAGE


def _external(args: argparse.Namespace) -> int:
    results = external_mod.results(args.profile, destination=args.destination)
    return _emit(results, args.json, "external")


def _policy(args: argparse.Namespace) -> int:
    if args.policy_command == "check":
        results = policy_mod.check(args.destination, args.data_class)
        return _emit(results, args.json, "policy-check")
    if args.policy_command == "grant":
        results = policy_mod.grant(args.service_id, args.destination, args.data_class,
                                   args.expires, args.actor, note=args.note)
        return _emit(results, args.json, "policy-grant")
    if args.policy_command == "revoke":
        results = policy_mod.revoke(args.service_id, args.actor)
        return _emit(results, args.json, "policy-revoke")
    if args.policy_command == "list":
        results = policy_mod.summary_results()
        return _emit(results, args.json, "policy-list", {"rows": policy_mod.rows()})
    print("usage error: policy needs check|grant|revoke|list", file=sys.stderr)
    return EXIT_USAGE


def _restore(args: argparse.Namespace) -> int:
    results, path = backup_mod.restore(
        Path(args.archive).expanduser().resolve(),
        Path(args.to).expanduser().resolve())
    return _emit(results, args.json, "restore", {"destination": str(path) if path else None})


def _history(args: argparse.Namespace) -> int:
    root = Path(args.path).expanduser().resolve()
    if not history_mod.is_repository(root):
        return _emit([Result(
            "history.not-a-repository", FAIL, STOP,
            f"{root} is not a git working tree", __version__, environment_label())],
            args.json, "history")
    report = history_mod.scan(root)
    choice = history_mod.history_choice(report)
    results = history_mod.results(report, choice=choice)
    if not results:
        results = [Result(
            "history.scan", NOT_RUN, REVIEW,
            "the history scan returned no findings; this is NOT a clean-history claim",
            __version__, environment_label(), required=True, enforcement=NOT_ENFORCED,
        )]
    return _emit(results, args.json, "history", {"report": report, "choice": choice})


def _limits(args: argparse.Namespace) -> int:
    """The one-command honesty view.

    Every unverified control, with its requirement id, why it is unverified,
    and what would verify it. ``limits`` is intentionally not a safety claim:
    a count of unverified controls is never PASS, and the exit code carries
    that fact to the operator.
    """
    root: Optional[Path] = Path(args.path).resolve() if args.path else None
    results = limits_mod.collect(root)
    return _emit(results, args.json, "limits",
                 extra={"rows": limits_mod.rows(root)})


if __name__ == "__main__":
    raise SystemExit(main())
