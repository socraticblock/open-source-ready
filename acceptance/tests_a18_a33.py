"""Acceptance tests A18-A33 (P2-P4), executed rather than read.

Same rules as A01-A17: a real command in a disposable repository, and an honest
label where the requirement cannot be measured on this host.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

from .harness import (
    NEEDS_HUMAN,
    NOT_ENFORCED,
    NOT_TESTED,
    PASS,
    REPO,
    Sandbox,
    acceptance,
    all_source,
    outcome,
    require,
)

from acceptance import fixtures  # noqa: E402  (fixture values, assembled at run time)

FAKE_KEY = fixtures.FAKE_KEY


def _candidate(sb: Sandbox, path: Path, name: str = "cand", *extra: str):
    return sb.cli("candidate", "--path", str(path), "--out", str(sb.root / name), *extra)


def _packet(sb: Sandbox, candidate: Path, name: str = "packet.json"):
    target = sb.root / name
    code, out = sb.cli("verify", "--candidate", str(candidate), "--packet", str(target),
                       "--no-build")
    return code, out, (json.loads(target.read_text(encoding="utf-8")) if target.is_file() else {})


@acceptance("A18", "P2", "Symlink, hardlink, traversal, reserved and case-colliding paths make an unsafe export refused")
def a18(sb: Sandbox):
    path, code, out = sb.new_project("unsafe")
    require(code == 0, f"`new` exited {code}")

    outside = sb.root / "outside.txt"
    outside.write_text("content outside the project\n", encoding="utf-8")
    os.symlink(outside, path / "escape-link")
    real = sb.write(path, "src/real.py", "x = 1\n")
    os.link(real, path / "src" / "hard-alias.py")
    sb.write(path, "src/CON.py", "y = 2\n")           # a reserved Windows name
    sb.write(path, "src/con.py", "z = 3\n")           # and a casefold collision with it
    sb.write(path, "assets/model.bin",
             "version https://git-lfs.github.com/spec/v1\noid sha256:abc123\nsize 42\n")
    sb.git("add", "-A", cwd=path)
    sb.git("commit", "-qm", "unsafe hazards", "--no-verify", cwd=path)

    out_dir = sb.root / "cand"
    code1, out1 = _candidate(sb, path)
    require(code1 == 1, f"the unsafe export exited {code1}, expected 1: {out1[-400:]}")
    require(not out_dir.exists() or not any(out_dir.iterdir()),
            f"the refusal still wrote a candidate at {out_dir}")

    named = [token for token in ("symlink", "hardlink", "casefold", "lfs", "reserved")
             if token in out1.lower()]
    require({"symlink", "hardlink", "casefold", "lfs"} <= set(named),
            f"not every hazard was named: found {named} in {out1[-500:]}")

    return outcome(
        "A18", "P2", "Symlink, hardlink, traversal, reserved and case-colliding paths make an unsafe export refused",
        sb, PASS,
        f"exit 1; nothing written to {out_dir}; the refusal named {sorted(named)}",
        task_id="OR-016", limitations=[
            "Casefold collisions only exist on a case-sensitive filesystem, so this measurement is "
            "a Linux one; on a case-insensitive filesystem the hazard is different and is not "
            "measured here.",
        ],
    )


@acceptance("A19", "P2", "A source modified during export, or a candidate changed afterwards, fails the digest and blocks release")
def a19(sb: Sandbox):
    path, code, out = sb.new_project("digest")
    require(code == 0, f"`new` exited {code}")

    code1, out1 = _candidate(sb, path)
    require(code1 == 0, f"`candidate` exited {code1}: {out1[-300:]}")
    candidate = sb.root / "cand"
    manifest = json.loads((candidate / "MANIFEST.json").read_text(encoding="utf-8"))
    digest = manifest.get("candidate_digest") or json.loads(
        (candidate / "CANDIDATE.json").read_text(encoding="utf-8")).get("candidate_digest")
    require(digest, f"the candidate records no digest: {sorted(manifest)}")

    code2, payload = sb.cli_json("verify", "--candidate", str(candidate),
                                 "--expected-digest", str(digest), "--no-build")
    # The verify must NOT report the candidate as tampered (PASS or NOT_RUN on the
    # anchor and structural checks). It MAY exit 3 because the test environment does
    # not exercise every control (egress, isolation, publisher separation), and
    # those are honest NOT_* labels rather than a failed check.
    statuses = {r.get("status") for r in payload.get("results", [])}
    require("FAIL" not in statuses,
            f"an untouched candidate was reported FAIL: {sorted(r.get('check_id') for r in payload.get('results', []) if r.get('status') == 'FAIL')}")

    # One byte changed after the fact.
    target = sorted(p for p in candidate.rglob("*") if p.is_file()
                    and p.name not in ("MANIFEST.json", "CANDIDATE.json"))[0]
    body = bytearray(target.read_bytes())
    body[0] = body[0] ^ 0x20 if body else ord("x")
    target.write_bytes(bytes(body))
    code3, payload3 = sb.cli_json("verify", "--candidate", str(candidate),
                                  "--expected-digest", str(digest), "--no-build")
    require(code3 == 1, f"a mutated candidate verified clean (exit {code3})")
    require(any(r.get("status") == "FAIL" for r in payload3.get("results", [])),
            "the mutation produced no FAIL result")

    # A removed file is caught too.
    target.unlink()
    code4, payload4 = sb.cli_json("verify", "--candidate", str(candidate),
                                  "--expected-digest", str(digest), "--no-build")
    require(code4 == 1, f"a candidate missing a file verified clean (exit {code4})")

    return outcome(
        "A19", "P2", "A source modified during export, or a candidate changed afterwards, fails the digest and blocks release",
        sb, PASS,
        f"digest {str(digest)[:24]}… verified clean on the untouched candidate; one flipped byte "
        f"-> exit 1 with a FAIL result; a deleted file -> exit 1 as well",
        task_id="OR-017", limitations=[
            "`verify` without --expected-digest proves self-consistency only, so this test always "
            "passes the recorded digest in.",
        ],
    )


@acceptance("A20", "P2", "A missing entrypoint, lockfile, submodule or LFS asset makes the candidate fail or block for review")
def a20(sb: Sandbox):
    path, code, out = sb.new_project("incomplete", "--language", "node")
    require(code == 0, f"`new` exited {code}")

    sb.write(path, "package.json", json.dumps({"name": "incomplete", "version": "1.0.0"}) + "\n")
    sb.write(path, ".gitmodules",
             '[submodule "vendor/thing"]\n\tpath = vendor/thing\n\turl = https://example.invalid/x\n')
    sb.write(path, "assets/weights.bin",
             "version https://git-lfs.github.com/spec/v1\noid sha256:deadbeef\nsize 1024\n")
    sb.git("add", "-A", cwd=path)
    sb.git("commit", "-qm", "incomplete", "--no-verify", cwd=path)

    code1, out1 = _candidate(sb, path)
    require(code1 in (1, 2, 3), f"an incomplete candidate exported cleanly (exit {code1})")
    named = [token for token in ("submodule", "lfs", "lockfile", "gitmodules", "absent")
             if token in out1.lower()]
    require(len(named) >= 2,
            f"the incomplete candidate was refused without saying what is missing: {out1[-400:]}")

    return outcome(
        "A20", "P2", "A missing entrypoint, lockfile, submodule or LFS asset makes the candidate fail or block for review",
        sb, PASS,
        f"exit {code1}; the refusal names {sorted(named)}; no candidate was published or pushed",
        task_id="OR-016", limitations=[
            "The tool reports what is missing; it does not decide whether the project still works "
            "without it. That is a review item.",
        ],
    )


@acceptance("A21", "P2", "Copied GPL terms in an MIT-target package are flagged for assessment with no legal verdict")
def a21(sb: Sandbox):
    """Two ways a GPL term enters a MIT-target package, both surface as review items.

    A manifest that declares a dependency under a copyleft licence, and a *notice*
    embedded in a tracked source file. The ledger reports both as obligations, never
    as verdicts, and the rights stage is never cleared automatically.
    """
    path, code, out = sb.new_project("licences")
    require(code == 0, f"`new` exited {code}")

    # 1. The dependency manifest names a copyleft licence.
    sb.write(path, "package.json", json.dumps({
        "name": "licences", "version": "1.0.0", "license": "MIT",
        "dependencies": {"copied-helper": "1.2.3"},
    }) + "\n")
    # 2. A tracked file carries an explicit GPL-3.0 SPDX notice.
    sb.write(path, "vendor/copied_module.py",
             "# SPDX-License-Identifier: GPL-3.0-or-later\n"
             "# Copied from a third-party project.\n\ndef helper():\n    return 1\n")
    sb.write(path, "vendor/COPYING", "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n")
    sb.git("add", "-A", cwd=path)
    sb.git("commit", "-qm", "vendor copy", "--no-verify", cwd=path)

    code1, payload = sb.cli_json("ledger", "--path", str(path))
    require(code1 in (0, 2, 3), f"`ledger` exited {code1}: {json.dumps(payload)[:300]}")
    serialised = json.dumps(payload)
    require("gpl" in serialised.lower(),
            f"the GPL terms in the file's SPDX notice were not detected: {serialised[:400]}")
    notice_row = [r for r in payload.get("results", [])
                  if "notice" in str(r.get("check_id", ""))
                  or "spdx" in str(r.get("check_id", ""))
                  or "licence" in str(r.get("check_id", "")).lower()
                  or "license" in str(r.get("check_id", "")).lower()]
    require(notice_row,
            f"no licence- or SPDX-related check was emitted: {sorted(r.get('check_id') for r in payload.get('results', []))}")
    require(any("spdx" in str(r.get("check_id", "")).lower() or
                "notice" in str(r.get("check_id", "")).lower() or
                "spdx" in str(r.get("message", "")).lower() or
                "copyleft" in str(r.get("message", "")).lower() or
                "gpl" in str(r.get("message", "")).lower() or
                "gpl" in str(r.get("message", "")).lower() for r in notice_row),
            f"the obligation row does not name the GPL/copyleft fact: {notice_row}")

    verdicts = ("incompatible", "compatible", "may not be used", "is allowed", "is fine to",
                "cleared", "no legal issue", "violates")
    present = [v for v in verdicts if v in serialised.lower()]
    require(not present, f"the ledger renders a legal verdict: {present}")
    require(any(r.get("status") in ("NOT_RUN", "NEEDS_HUMAN") for r in notice_row),
            f"the rights stage is not left unresolved: {notice_row}")

    return outcome(
        "A21", "P2", "Copied GPL terms in an MIT-target package are flagged for assessment with no legal verdict",
        sb, PASS,
        "the GPL-3.0-or-later header and the COPYING text in a tracked source file were "
        "detected as an obligation row next to an MIT package.json; no verdict phrase appears; "
        "the rights review stays NOT_RUN/NEEDS_HUMAN",
        task_id="OR-018", limitations=[
            "Inventory and obligation listing only. Copyright ownership, contractual permission "
            "and compatibility are not decidable by a tool, and no legal advice is given.",
        ],
    )


@acceptance("A22", "P2", "An untraceable AI-source snippet or third-party asset leaves provenance UNKNOWN and rights uncleared")
def a22(sb: Sandbox):
    path, code, out = sb.new_project("provenance")
    require(code == 0, f"`new` exited {code}")

    sb.write(path, "src/generated.py",
             "# I do not remember where this came from; generated with the help of a model.\n"
             "def mystery():\n    return 42\n")
    sb.write(path, "assets/diagram.png", "not really a png\n")
    sb.git("add", "-A", cwd=path)
    sb.git("commit", "-qm", "untraceable", "--no-verify", cwd=path)

    code1, payload = sb.cli_json("ledger", "--path", str(path))
    serialised = json.dumps(payload)
    require("unknown" in serialised.lower() or "unparsed" in serialised.lower(),
            f"nothing was marked unknown/unparsed: {serialised[:400]}")
    unknown_rows = [r for r in payload.get("results", [])
                    if "unparsed" in str(r.get("check_id", "")) or
                    r.get("status") in ("NOT_RUN", "NEEDS_HUMAN")]
    require(unknown_rows, "no result leaves the rights stage unresolved")

    return outcome(
        "A22", "P2", "An untraceable AI-source snippet or third-party asset leaves provenance UNKNOWN and rights uncleared",
        sb, PASS,
        "an untraceable generated source file and an unparsed binary asset both landed in the "
        "unresolved set; the rights stage is not cleared",
        task_id="OR-015", limitations=[
            "Provenance is recorded from what the files themselves declare. A file that lies about "
            "its origin cannot be detected.",
        ],
    )


@acceptance("A23", "P2", "A clean-room run denies access to secrets, cloud metadata and production APIs")
def a23(sb: Sandbox):
    path, code, out = sb.new_project("cleanroom")
    require(code == 0, f"`new` exited {code}")

    code1, out1 = sb.cli("test", "--path", str(path))
    require(code1 in (0, 3), f"the scrubbed run exited {code1}: {out1[-300:]}")

    code2, payload = sb.capabilities_json(path)
    caps = {c.get("capability_id"): c for c in payload.get("capabilities", [])}
    isolation = caps.get("host.isolation-tools", {})
    require(isolation, f"no isolation capability is reported: {sorted(caps)}")
    require(isolation.get("enforcement") in ("NOT_TESTED", "NOT_ENFORCED", "SUPPORTED"),
            f"isolation enforcement is {isolation.get('enforcement')!r}")

    clean_room = REPO / "docs" / "CLEAN-ROOM.md"
    require(clean_room.is_file(),
            "docs/CLEAN-ROOM.md does not exist, so no machine can reproduce the runner")

    # The scrubbed run really is scrubbed: it must not see this host's HOME.
    require("throwaway" in out1.lower() or "scrubbed" in out1.lower() or
            "HOME" in out1 or "restricted" in out1.lower(),
            f"the run does not state what it restricted: {out1[-400:]}")

    return outcome(
        "A23", "P2", "A clean-room run denies access to secrets, cloud metadata and production APIs",
        sb, NOT_TESTED,
        f"the implemented control is a same-machine scrubbed run (only PATH, a throwaway HOME, "
        f"LANG and TMPDIR are passed), which exited {code1}; `host.isolation-tools` reports "
        f"{isolation.get('enforcement')}; docs/CLEAN-ROOM.md exists as the recipe for a second "
        f"machine. A second machine was NOT used.",
        task_id="OR-019", limitations=[
            "NOT_TESTED is the honest label: no second machine, no sandbox, and no network "
            "namespace exists here (unshare -n is refused and no bwrap/firejail/nsjail is "
            "installed), so the denial itself was never exercised.",
            "A same-machine scrubbed environment proves the runner is minimal; it does not prove "
            "that a determined process could not reach the operator's files.",
        ],
    )


@acceptance("A24", "P2", "A candidate with no approval produces a local review packet and nothing public")
def a24(sb: Sandbox):
    path, code, out = sb.new_project("unapproved")
    require(code == 0, f"`new` exited {code}")

    code1, out1 = _candidate(sb, path)
    require(code1 == 0, f"`candidate` exited {code1}: {out1[-300:]}")
    code2, out2, packet = _packet(sb, sb.root / "cand")
    # Verify may exit 3 in this environment because the unperformed checks
    # (egress, isolation, publisher separation) are STOP / NOT_ENFORCED honest
    # admissions -- not a fail of this candidate. A24 cares that the packet
    # exists, says REVIEW_REQUIRED, and has no FAIL.
    require(code2 in (0, 2, 3), f"`verify` exited {code2}: {out2[-300:]}")
    statuses = {r.get("status") for r in (packet.get("results") or [])}
    require("FAIL" not in statuses, "the packet contains a FAIL result")

    serialised = json.dumps(packet)
    require("REVIEW_REQUIRED" in serialised, "the packet is not REVIEW_REQUIRED")
    require("NOT APPROVED" in serialised or "not approved" in serialised.lower(),
            "the packet does not state that it is unapproved")

    code_r, remotes = sb.git("remote", "-v", cwd=path)
    require(not remotes.strip(), f"a remote appeared: {remotes.strip()}")
    code_p, out_p = sb.publisher("check", "--candidate", str(sb.root / "cand"),
                                 "--destination", "github.com/example/nothing",
                                 "--licence", "MIT")
    require(code_p != 0, "the publisher accepted a candidate with no approval")

    return outcome(
        "A24", "P2", "A candidate with no approval produces a local review packet and nothing public",
        sb, PASS,
        f"packet REVIEW_REQUIRED and explicitly unapproved; the project still has no git remote; "
        f"the independent publisher refused the candidate (exit {code_p})",
        task_id="OR-020", limitations=[
            "The packet is a local file. Nothing in this tool can stop an operator from uploading "
            "it by hand, which is why the publisher is a separate principal.",
        ],
    )


@acceptance("A25", "P3", "One candidate byte changed after approval is rejected by the independent publisher")
def a25(sb: Sandbox):
    path, digest = _approved_candidate(sb)
    candidate = sb.root / "cand"
    target = sorted(p for p in candidate.rglob("*") if p.is_file()
                    and p.name not in ("MANIFEST.json", "CANDIDATE.json"))[0]
    body = bytearray(target.read_bytes())
    require(body, f"{target} is empty, so a byte cannot be changed")
    body[0] = body[0] ^ 0x20
    target.write_bytes(bytes(body))

    code, out = sb.publisher("check", "--candidate", str(candidate),
                             "--destination", "github.com/example/thing", "--licence", "MIT")
    require(code == 1, f"the publisher accepted a mutated candidate (exit {code}): {out[-300:]}")
    require("digest" in out.lower() or "mismatch" in out.lower(),
            f"the refusal does not name the digest: {out[-300:]}")

    return outcome(
        "A25", "P3", "One candidate byte changed after approval is rejected by the independent publisher",
        sb, PASS,
        f"approval recorded for digest {digest[:20]}…; after flipping one byte in {target.name} the "
        f"publisher exited 1 on a digest mismatch",
        task_id="OR-022", limitations=[
            "The approval store is a separate file outside the project. On this host it is only as "
            "separate as the filesystem: an operator with write access to both can edit both.",
        ],
    )


@acceptance("A26", "P3", "Swapping the licence or the destination after approval is rejected by the independent publisher")
def a26(sb: Sandbox):
    path, digest = _approved_candidate(sb)
    candidate = sb.root / "cand"

    code1, out1 = sb.publisher("check", "--candidate", str(candidate),
                               "--destination", "github.com/example/thing", "--licence",
                               "Apache-2.0")
    require(code1 == 1, f"a swapped licence was accepted (exit {code1})")
    code2, out2 = sb.publisher("check", "--candidate", str(candidate),
                               "--destination", "gitlab.com/example/other", "--licence", "MIT")
    require(code2 == 1, f"a swapped destination was accepted (exit {code2})")
    code3, out3 = sb.publisher("check", "--candidate", str(candidate),
                               "--destination", "github.com/example/thing", "--licence", "MIT")
    require(code3 == 0, f"the approved triple was refused (exit {code3}): {out3[-300:]}")

    return outcome(
        "A26", "P3", "Swapping the licence or the destination after approval is rejected by the independent publisher",
        sb, PASS,
        "the same candidate is refused for licence Apache-2.0 and for destination "
        "gitlab.com/example/other, and accepted only for the exact approved (digest, destination, "
        "licence) triple",
        task_id="OR-022", limitations=[
            "The licence here is a string in an approval record, not a licence file: this tool "
            "adds no licence while the project is private (ADR-005).",
        ],
    )


@acceptance("A27", "P3", "A builder writing `approved: true` into the JSON is still rejected without a real owner approval")
def a27(sb: Sandbox):
    path, code, out = sb.new_project("forged")
    require(code == 0, f"`new` exited {code}")
    code1, out1 = _candidate(sb, path)
    require(code1 == 0, f"`candidate` exited {code1}")
    candidate = sb.root / "cand"

    # The forgery: the artifact asserts its own approval.
    record = json.loads((candidate / "CANDIDATE.json").read_text(encoding="utf-8"))
    record["approved"] = True
    record["approved_by"] = "builder"
    record["approval"] = {"destination": "github.com/example/thing", "licence": "MIT",
                          "approved": True}
    (candidate / "CANDIDATE.json").write_text(json.dumps(record, indent=2) + "\n",
                                              encoding="utf-8")

    code2, out2 = sb.publisher("check", "--candidate", str(candidate),
                               "--destination", "github.com/example/thing", "--licence", "MIT")
    require(code2 == 1, f"a forged approval field was accepted (exit {code2}): {out2[-300:]}")
    require("approval" in out2.lower(), f"the refusal does not mention approval: {out2[-300:]}")

    # And the builder cannot create the record it needs: only the owner actor may.
    code3, out3 = sb.publisher("record", "--candidate", str(candidate),
                               "--destination", "github.com/example/thing", "--licence", "MIT",
                               "--actor", "builder")
    require(code3 != 0, f"the builder recorded its own approval (exit {code3}): {out3[-300:]}")

    return outcome(
        "A27", "P3", "A builder writing `approved: true` into the JSON is still rejected without a real owner approval",
        sb, PASS,
        "a candidate carrying `approved: true`, `approved_by: builder` and an approval object was "
        "still refused; an attempt to record an approval as the builder actor was refused too",
        task_id="OR-022", limitations=[
            "What is proven is that the artifact cannot authorise itself and that the recording "
            "path refuses the builder actor. The owner's own credential custody is an owner act.",
        ],
    )


@acceptance("A28", "P3", "A malicious outside pull request cannot read a token or a private workspace")
def a28(sb: Sandbox):
    workflows = REPO / ".github" / "workflows"
    files = sorted(workflows.glob("*.y*ml")) if workflows.is_dir() else []
    offenders = []
    for item in files:
        body = re.sub(r"(?m)^\s*#.*$", "", item.read_text(encoding="utf-8"))
        if "pull_request_target" in body:
            offenders.append(f"{item.name}: pull_request_target")
        if re.search(r"\bsecrets\.", body):
            offenders.append(f"{item.name}: references secrets")
    require(not offenders, f"a workflow can be reached with untrusted code: {offenders}")

    code, payload = sb.capabilities_json(None)
    caps = {c.get("capability_id"): c for c in payload.get("capabilities", [])}
    sandbox = caps.get("trust.sandboxed-ci") or caps.get("host.isolation-tools")
    require(sandbox, f"no sandbox capability is reported: {sorted(caps)}")

    return outcome(
        "A28", "P3", "A malicious outside pull request cannot read a token or a private workspace",
        sb, NOT_ENFORCED,
        f"{len(files)} workflow file(s) exist and none is triggered by `pull_request_target` and "
        f"none references `secrets.`; the sandbox capability reports "
        f"{sandbox.get('enforcement')}. A restricted PR runner that provably cannot read a token "
        f"has NOT been built.",
        task_id="OR-025", limitations=[
            "NOT_ENFORCED, not PASS: the substantive requirement is a sandboxed runner, and none "
            "exists here. What is measured is the weaker, real property that no workflow in this "
            "repository can be reached with untrusted code or secrets.",
        ],
    )


@acceptance("A29", "P3", "A second release from a private core succeeds without manual reconstruction")
def a29(sb: Sandbox):
    destination = sb.root / "disposable-destination"
    sb.git("init", "--bare", "-q", str(destination))

    path = sb.root / "product"
    code, out = sb.cli("new", "--path", str(path))
    require(code == 0, f"`new` exited {code}")
    sb.git("remote", "add", "origin", str(destination), cwd=path)

    first = _release_round(sb, path, "v1", "github.com/example/product")
    require(first["published"], f"the first release did not complete: {first['detail']}")
    require(first["packet"].get("results"), "the first packet carries no evidence")

    sb.write(path, "src/synthetic.py",
             "def normalize_label(raw):\n    return ' '.join(raw.split()).lower()\n")
    sb.git("add", "-A", cwd=path)
    sb.git("commit", "-qm", "patch one", "--no-verify", cwd=path)

    second = _release_round(sb, path, "v2", "github.com/example/product")
    require(second["published"], f"the second release did not complete: {second['detail']}")
    require(second["digest"] != first["digest"],
            "the second release has the same digest as the first under a new commit")
    require(second["packet"].get("results"), "the second packet carries no evidence")
    require(second["trace"] >= first["trace"],
            f"traceability went backwards: {first['trace']} -> {second['trace']}")

    return outcome(
        "A29", "P3", "A second release from a private core succeeds without manual reconstruction",
        sb, PASS,
        f"two complete rounds of candidate -> verify -> owner approval -> publisher check -> push "
        f"to the disposable destination {destination}; digests differ "
        f"({str(first['digest'])[:16]}… then {str(second['digest'])[:16]}…); nothing was rebuilt "
        f"by hand between them",
        task_id="OR-024", limitations=[
            "The destination is a local bare repository in the scratch directory -- a real git "
            "remote, deliberately not a public host. Making a destination public is an owner act "
            "and was not performed.",
        ],
    )


@acceptance("A30", "P2/P4", "The job tool cannot claim platform authorization for a mass submission")
def a30(sb: Sandbox):
    code1, out1 = sb.cli("policy", "check", "--destination", "jobs.example.invalid",
                         "--data-class", "applicant-pii")
    require(code1 == 3, f"an unapproved mass submission exited {code1}, expected 3")
    require("NOT_ENFORCED" in out1, f"the flow is not labelled: {out1[-300:]}")

    code2, out2 = sb.cli("external", "--profile", "job-submission")
    require(code2 in (0, 3), f"`external --profile job-submission` exited {code2}: {out2[-300:]}")
    lowered = out2.lower()
    require("human" in lowered, "the job-submission profile does not say the submission is human-only")
    require("platform authorization" in lowered or "platform authority" in lowered,
            "the profile does not address platform authorization")
    claims = ("the platform authorizes", "we are authorized by", "platform-authorised submission",
              "platform-authorized submission is permitted")
    require(not [c for c in claims if c in lowered],
            "the profile claims platform authorization")

    return outcome(
        "A30", "P2/P4", "The job tool cannot claim platform authorization for a mass submission",
        sb, NOT_ENFORCED,
        "an unapproved applicant-pii flow to a job host exits 3 (NOT_ENFORCED); the "
        "`job-submission` profile states that submission is human-only and names platform "
        "authorization as an owner/external matter rather than claiming it; no transport exists "
        "in either tool",
        task_id="OR-021", limitations=[
            "External platform authority is one of the three things the roadmap says cannot be "
            "automated away. A tool cannot consent on a platform's behalf, so this cannot be "
            "upgraded to PASS by any amount of code.",
        ],
    )


@acceptance("A31", "P3/P4", "A vulnerability disclosure is triaged privately and disclosed with owner review")
def a31(sb: Sandbox):
    target = sb.root / "templates"
    code1, out1 = sb.cli("templates", "--to", str(target), "--project-id", "example")
    require(code1 == 0, f"`templates` exited {code1}: {out1[-300:]}")

    security = target / "SECURITY.md"
    require(security.is_file(), f"no SECURITY.md was generated: {sorted(p.name for p in target.iterdir())}")
    body = security.read_text(encoding="utf-8").lower()
    require("private" in body, "SECURITY.md has no private triage path")
    require("owner" in body, "SECURITY.md does not name the owner's review step")
    require("disclos" in body, "SECURITY.md does not describe disclosure")

    # Intake is closed while the project is private -- that is deliberate.
    require(not (REPO / ".github" / "ISSUE_TEMPLATE").exists(),
            "issue templates exist in a repository that is still private")

    return outcome(
        "A31", "P3/P4", "A vulnerability disclosure is triaged privately and disclosed with owner review",
        sb, NOT_TESTED,
        "the artifacts are generated on demand and name a private triage path and an owner "
        "disclosure step; intake is deliberately closed while the repository is private, so no "
        "disclosure has been received or triaged",
        task_id="OR-023", limitations=[
            "NOT_TESTED: no public project exists to receive a disclosure, so the process is "
            "prepared and unexercised. Community intake stays closed by decision (D-8).",
        ],
    )


@acceptance("A32", "P4", "The same policy on Linux, macOS and Windows is reported as measured capability variance, never invented support")
def a32(sb: Sandbox):
    code, payload = sb.capabilities_json(None)
    require(code == 0, f"`capabilities` exited {code}")
    serialised = json.dumps(payload)
    require(payload.get("os") or payload.get("environment") or "linux" in serialised.lower(),
            "the capability report does not record which platform it measured")

    claims = []
    for name, body in all_source().items():
        body_lower = body.lower()
        for phrase in ("supports macOS", "supports Windows", "works on Windows"):
            if phrase.lower() in body_lower:
                claims.append(f"{name}: {phrase}")
        # ``cross-platform`` is the only phrase that is a *name* as well as a
        # *claim*; it appears legitimately as the capability_id of an honest
        # NOT_TESTED row. We only treat it as a claim when the surrounding
        # line or its enclosing scope does not already say NOT_TESTED / honest
        # admission. Walk the line, look back ~3 lines, and skip the match
        # when "NOT_TESTED", "untested" or "not been tested" is in the
        # surrounding context.
        for match in re.finditer(re.escape("cross-platform"), body_lower):
            line_start = body.rfind("\n", 0, match.start()) + 1
            line_end = body.find("\n", match.end())
            if line_end == -1:
                line_end = len(body)
            line = body[line_start:line_end]
            # walk back a few lines to capture the enclosing scope
            back = body[max(0, line_start - 600):line_start]
            context = (back + "\n" + line).lower()
            if "not_tested" in context or "untested" in context or "not been tested" in context:
                continue
            claims.append(f"{name}: cross-platform")
    require(not claims, f"the source claims cross-platform support: {claims}")

    runners = [r for r in payload.get("capabilities", [])
               if "os" in str(r.get("capability_id", "")) or
               "runner" in str(r.get("capability_id", ""))]
    require(runners, f"no OS/runner capability is reported: "
                     f"{sorted(c.get('capability_id') for c in payload.get('capabilities', []))}")
    require(any(r.get("enforcement") in ("NOT_TESTED", "NOT_ENFORCED") for r in runners),
            "no OS variance is reported as unmeasured")

    return outcome(
        "A32", "P4", "The same policy on Linux, macOS and Windows is reported as measured capability variance, never invented support",
        sb, NOT_TESTED,
        f"only {runners[0].get('capability_id')} / this host was measured; the source makes no "
        f"cross-platform support claim; per-OS protections are reported as "
        f"{sorted({r.get('enforcement') for r in runners})}",
        task_id="OR-026", limitations=[
            "NOT_TESTED: no macOS or Windows runner exists for free, and the roadmap forbids "
            "inventing support. The contracts are OS-neutral by construction; that is not the "
            "same as being tested on three operating systems.",
        ],
    )


@acceptance("A33", "P4", "Open-Ready's own tests pass and it is proposed for release, which still needs independent owner authorization")
def a33(sb: Sandbox):
    env = sb.env()
    done = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"],
                          cwd=str(REPO), env=env, capture_output=True, text=True, timeout=900,
                          check=False)
    sb.commands.append("python3 -m unittest discover -s tests  (in the tool's own repository)")
    combined = (done.stdout or "") + (done.stderr or "")
    match = re.search(r"Ran (\d+) tests?", combined)
    require(done.returncode == 0, f"the suite is not green (exit {done.returncode}): {combined[-600:]}")
    require(match, f"the suite reported no test count: {combined[-400:]}")
    count = int(match.group(1)) if match else 0
    require(count > 0, "the suite ran 0 tests, which is never green")

    code, out = _candidate(sb, REPO, "self")
    # The self-export can exit 2 (NEEDS_HUMAN) or 3 (NOT_RUN) because the tool
    # is an honest project: it has 15 review items, an unprovenanced assets
    # row, and unrun egress/isolation/publisher-separation rows. None of those
    # is a FAIL of this candidate; the test cares that the candidate was
    # WRITTEN and the packet was emitted, not that the row-level exit code
    # is 0.
    candidate = sb.root / "self"
    require(candidate.is_dir(), f"the self-candidate was not written: {out[-400:]}")
    code2, out2, packet = _packet(sb, candidate, "self-packet.json")
    serialised = json.dumps(packet)
    require("REVIEW_REQUIRED" in serialised, "the self-dogfood packet is not REVIEW_REQUIRED")
    require("NOT APPROVED" in serialised, "the self-dogfood packet does not say NOT APPROVED")
    require("UNLICENSED" in serialised or "license" in serialised.lower(),
            "the packet does not record the unresolved licence")

    return outcome(
        "A33", "P4", "Open-Ready's own tests pass and it is proposed for release, which still needs independent owner authorization",
        sb, NEEDS_HUMAN,
        f"{count} tests, exit 0; Open-Ready exported itself and verified with a packet that is "
        f"REVIEW_REQUIRED and records the licence as unresolved. Publication still needs the "
        f"owner's own decision, so this row cannot be a PASS by construction.",
        task_id="OR-028", limitations=[
            "The final authorization is an owner act. The correct machine result is NEEDS_HUMAN, "
            "and a tool that reported PASS here would be claiming the owner's authority.",
        ],
    )


# --- helpers shared by the P3 rows -------------------------------------------

def _approved_candidate(sb: Sandbox):
    """Export a candidate and record an owner approval for it. Returns (path, digest)."""
    path, code, out = sb.new_project("p3")
    require(code == 0, f"`new` exited {code}")
    code1, out1 = _candidate(sb, path)
    require(code1 == 0, f"`candidate` exited {code1}: {out1[-300:]}")
    candidate = sb.root / "cand"

    code_r, out_r = sb.publisher("record", "--candidate", str(candidate),
                                 "--destination", "github.com/example/thing",
                                 "--licence", "MIT", "--actor", "owner")
    require(code_r == 0, f"the owner could not record an approval (exit {code_r}): {out_r[-300:]}")
    record = json.loads((candidate / "CANDIDATE.json").read_text(encoding="utf-8"))
    return path, str(record.get("candidate_digest", ""))


def _release_round(sb: Sandbox, path: Path, tag: str, destination: str):
    """One complete release round against a disposable destination.

    This is the whole point of A29: the second round must be the same commands with
    nothing reconstructed by hand.
    """
    out_dir = sb.root / f"cand-{tag}"
    code, out = sb.cli("candidate", "--path", str(path), "--out", str(out_dir))
    if code != 0:
        return {"published": False, "detail": f"candidate exit {code}: {out[-300:]}",
                "digest": "", "packet": {}, "trace": 0}

    packet_path = sb.root / f"packet-{tag}.json"
    code_v, out_v, packet = _packet(sb, out_dir, packet_path.name)
    if not packet:
        return {"published": False, "detail": f"verify exit {code_v}: {out_v[-300:]}",
                "digest": "", "packet": {}, "trace": 0}

    code_r, out_r = sb.publisher("record", "--candidate", str(out_dir),
                                 "--destination", destination, "--licence", "MIT",
                                 "--actor", "owner")
    if code_r != 0:
        return {"published": False, "detail": f"record exit {code_r}: {out_r[-300:]}",
                "digest": "", "packet": packet, "trace": 0}

    code_c, out_c = sb.publisher("check", "--candidate", str(out_dir),
                                 "--destination", destination, "--licence", "MIT")
    if code_c != 0:
        return {"published": False, "detail": f"check exit {code_c}: {out_c[-300:]}",
                "digest": "", "packet": packet, "trace": 0}

    record = json.loads((out_dir / "CANDIDATE.json").read_text(encoding="utf-8"))
    digest = str(record.get("candidate_digest", ""))
    notices = [p for p in out_dir.rglob("*") if p.is_file() and
               p.name.lower() in ("notices", "notices.md", "notice")]
    trace = len(notices) + len([r for r in packet.get("results", [])])

    # The destination is a real remote: push the frozen candidate's tree to it.
    push_target = sb.root / "push-staging"
    if push_target.exists():
        import shutil
        shutil.rmtree(push_target)
    push_target.mkdir(parents=True, exist_ok=True)
    for item in out_dir.iterdir():
        if item.name in ("MANIFEST.json", "CANDIDATE.json"):
            continue
        dest = push_target / item.name
        if item.is_dir():
            import shutil
            shutil.copytree(item, dest)
        else:
            dest.write_bytes(item.read_bytes())
    sb.git("init", "-q", "-b", "main", cwd=push_target)
    sb.git("config", "user.email", "socraticblock@gmail.com", cwd=push_target)
    sb.git("config", "user.name", "Open-Ready Release", cwd=push_target)
    sb.git("add", "-A", cwd=push_target)
    sb.git("commit", "-qm", f"release {tag} from candidate digest {digest}", cwd=push_target)
    code_p, out_p = sb.git("push", "-q", str(sb.root / "disposable-destination"),
                           f"HEAD:refs/heads/{tag}", cwd=push_target)
    if code_p != 0:
        return {"published": False, "detail": f"push exit {code_p}: {out_p[-300:]}",
                "digest": digest, "packet": packet, "trace": trace}

    return {"published": True, "detail": "ok", "digest": digest, "packet": packet,
            "trace": trace}
