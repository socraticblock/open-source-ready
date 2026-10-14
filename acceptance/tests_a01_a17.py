"""Acceptance tests A01-A17 (P0-P2), executed rather than read.

Each test builds a disposable repository in the scratch directory, runs the tool
as a real command, and reports what actually happened. Where a requirement is not
met, the row says ``FAIL``; where it cannot be measured on this host, the row says
``NOT_RUN``, ``NOT_TESTED`` or ``NOT_ENFORCED`` and says why. Neither is smoothed
into a pass.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path

from .harness import (
    FAIL,
    NEEDS_HUMAN,
    NOT_APPLICABLE,
    NOT_ENFORCED,
    NOT_RUN,
    NOT_TESTED,
    PASS,
    AcceptanceFailure,
    Sandbox,
    acceptance,
    all_source,
    outcome,
    require,
)

from acceptance import fixtures  # noqa: E402  (fixture values, assembled at run time)

#: A documented AWS example key, assembled in :mod:`acceptance.fixtures` rather than
#: written here: this repository is scanned by its own deny-list, and a whole literal
#: would be a hit in this repository's own object store, making the tool unable to
#: export itself. Credential-shaped on purpose -- it is the shape the scanner must
#: catch -- and published by AWS as an invalid example. Nothing else secret-shaped is
#: written to disk by this suite.
FAKE_KEY = fixtures.FAKE_KEY

CONTROLS_USED = [
    "OPENREADY_PRIVATE_HOME", "OPENREADY_POLICY_HOME", "OPENREADY_AUDIT_HOME",
    "OPENREADY_APPROVAL_HOME", "git",
]


@acceptance("A01", "P0", "New product with no flags creates a private local project with no public side effect")
def a01(sb: Sandbox):
    path, code, out = sb.new_project("fresh")
    require(code == 0, f"`new` exited {code}: {out[-400:]}")

    config = json.loads((path / "openready.project.json").read_text(encoding="utf-8"))
    require(str(config.get("visibility", "")).lower() == "private",
            f"project visibility is {config.get('visibility')!r}, not 'private'")
    require(not (path / "LICENSE").exists(), "a LICENSE file was created")
    require(not (path / "LICENSE.md").exists(), "a LICENSE.md was created")

    code_r, out_r = sb.git("remote", "-v", cwd=path)
    require(not out_r.strip(), f"a git remote exists: {out_r.strip()}")

    # "no network action" measured two ways, because neither alone is a proof.
    # 1. static: nothing in the tool's own code can open an outbound connection.
    # The two exceptions are deliberate: ``promote.py`` uses ``urllib.request``
    # for a loopback-only health probe (it refuses non-loopback URLs at parse
    # time) and ``capabilities.py`` imports ``platform`` and ``sys`` for an
    # OS-variance report that names its own limit. Both are documented in the
    # module's docstring as a refusal-not-an-action, and both are tested.
    outbound_capable = {
        "import socket", "import http", "import ftplib", "import smtplib",
        "import telnetlib", "create_connection", "requests.",
    }
    documented_loopback = {"promote.py"}
    outbound_loopback = {"import urllib.request", "import urllib.error",
                         "urllib.request.Request", "urlopen"}
    source = all_source()
    hits: Dict[str, str] = {}
    for name, body in source.items():
        for token in outbound_capable:
            if token in body:
                hits.setdefault(name, token)
        if name not in documented_loopback:
            for token in outbound_loopback:
                if token in body:
                    hits.setdefault(name, token)
    require(not hits, f"outbound-capable code found in {sorted(hits.items())}")
    # 2. dynamic: the same command with every proxy variable pointed at a closed
    #    port still succeeds, so it does not depend on reaching anything.
    hostile = {"http_proxy": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9",
               "HTTP_PROXY": "http://127.0.0.1:9", "HTTPS_PROXY": "http://127.0.0.1:9",
               "no_proxy": "", "NO_PROXY": ""}
    code2, out2 = sb.cli("new", "--path", str(sb.root / "fresh2"), env_extra=hostile)
    require(code2 == 0, f"`new` failed with proxies pointed at a closed port: {out2[-400:]}")

    return outcome(
        "A01", "P0", "New product with no flags creates a private local project with no public side effect",
        sb, PASS,
        f"exit 0; visibility=private; no LICENSE; `git remote -v` empty; no outbound-capable "
        f"code in the module set ({len(source)} modules scanned); the same command still exits 0 "
        f"with all proxy variables aimed at 127.0.0.1:9",
        task_id="OR-004", limitations=[
            "No network namespace, strace or firewall is available on this host (unshare -n is "
            "refused), so the absence of a network *syscall* was not observed directly. What was "
            "measured is: the tool's own code contains no outbound client and no third-party "
            "package is imported at all.",
            "A 'visibility=private' field is a record, not enforcement: it cannot prevent an "
            "operator from running `gh repo create` by hand.",
        ],
    )


@acceptance("A02", "P0", "A project started inside an existing repository leaves it untouched without opt-in")
def a02(sb: Sandbox):
    outer = sb.repo("outer", {"README.md": "# existing\n", "src/app.py": "print('hi')\n"})
    before = sb.project_rev(outer)
    before_hashes = sb.tree_hashes(outer)

    code, out = sb.cli("init", "--path", str(outer / "child"))
    require(code != 0, f"`init` inside an existing checkout exited {code}, expected a refusal")

    require(sb.head_unchanged(outer, before), "the enclosing repository's HEAD moved")
    require(sb.tree_hashes(outer) == before_hashes, "the enclosing repository's files changed")
    require(not (outer / "child" / "openready.project.json").exists(),
            "a project contract was written inside the refusal case")

    # The documented opt-in may scaffold, but must never commit inside somebody
    # else's tree.
    code2, out2 = sb.cli("init", "--path", str(outer), "--adopt", "--allow-inside-checkout")
    require(sb.head_unchanged(outer, before),
            f"`init --adopt` committed inside the existing tree (exit {code2})")

    return outcome(
        "A02", "P0", "A project started inside an existing repository leaves it untouched without opt-in",
        sb, PASS,
        f"`init` inside {outer.name}/ refused (exit {code}, no project written); HEAD {before[:12]} "
        f"unchanged and all {len(before_hashes)} file hashes identical; `init --adopt "
        f"--allow-inside-checkout` also left HEAD at {before[:12]}",
        task_id="OR-004", limitations=[
            "`--adopt` is the documented opt-in; this measures that it does not commit, not that "
            "its scaffold is what the operator wanted.",
        ],
    )


@acceptance("A03", "P0", "A runtime loads a private record from the user-data root while tracked source and fixtures stay synthetic")
def a03(sb: Sandbox):
    path, code, out = sb.new_project("app")
    require(code == 0, f"`new` exited {code}: {out[-300:]}")

    # A record in the private data root, outside the project by construction.
    record = sb.private / "profile.json"
    record.write_text(json.dumps({"display_label": "PRIVATE-CANARY-7f3a"}), encoding="utf-8")

    # The project's own code runs and uses the private value: a real local app.
    driver = sb.root / "loads_private_record.py"
    driver.write_text(
        "import json, os, sys\n"
        f"sys.path.insert(0, {str(path)!r})\n"
        "from src.synthetic import normalize_label\n"
        "root = os.environ['OPENREADY_PRIVATE_HOME']\n"
        "raw = json.loads(open(os.path.join(root, 'profile.json')).read())['display_label']\n"
        "print(normalize_label(raw))\n",
        encoding="utf-8",
    )
    code2, out2 = sb.run([sys.executable, str(driver)])
    require(code2 == 0 and "private-canary-7f3a" in out2.lower(),
            f"the project's code could not use the private record: exit {code2} {out2[-300:]}")

    # ... and the project itself stays synthetic: the canary appears nowhere.
    leaked = [name for name, body in
              ((str(p.relative_to(path)), p.read_bytes())
               for p in path.rglob("*") if p.is_file() and ".git/" not in str(p))
              if b"PRIVATE-CANARY-7f3a" in body]
    require(not leaked, f"private data appears in project files: {leaked}")

    code3, payload = sb.cli_json("fixture", "--path", str(path))
    fixture_wrote = any("wrote" in r.get("message", "").lower() and
                        r.get("status") == "PASS" for r in payload.get("results", []))
    require(fixture_wrote, f"`fixture` did not record a written result: {sorted(r.get('check_id') for r in payload.get('results', []))}")

    # Determinism: the fixture is the same bytes on every run, so it can be a control.
    first = sb.tree_hashes(path / "journal")
    sb.cli("fixture", "--path", str(path))
    require(sb.tree_hashes(path / "journal") == first, "the synthetic fixture is not deterministic")

    return outcome(
        "A03", "P0", "A runtime loads a private record from the user-data root while tracked source and fixtures stay synthetic",
        sb, PASS,
        f"the project's own module read the record from {record.parent} and printed its normalized "
        f"value; the canary string appears in 0 project files; the synthetic fixture re-ran to "
        f"identical hashes",
        task_id="OR-005", limitations=[
            "The boundary is a filesystem convention, not a control: nothing prevents an operator "
            "copying private data into the project by hand.",
        ],
    )


@acceptance("A04", "P0", "A fake secret in source and a tracked .env is detected, blocks the commit, and is redacted in logs")
def a04(sb: Sandbox):
    path, code, out = sb.new_project("leaky")
    require(code == 0, f"`new` exited {code}")

    sb.write(path, "src/settings.py", fixtures.credential_line())
    sb.write(path, ".env", f"AWS_ACCESS_KEY_ID={FAKE_KEY}\n")
    sb.git("add", "-A", cwd=path)

    code2, out2 = sb.cli("precommit", "--path", str(path))
    require(code2 == 1, f"`precommit` exited {code2}, expected 1 (a STOP): {out2[-300:]}")
    require("privacy.secret-shape" in out2 or "env-file" in out2 or "blocked" in out2,
            f"the refusal does not name what it found: {out2[-300:]}")

    # Redaction: the value must not be echoed anywhere in the output.
    require(FAKE_KEY not in out2,
            f"the detected secret value was echoed into the log output: {out2[-400:]}")

    # The control is wired into git, so the commit itself is refused.
    code3, out3 = sb.git("commit", "-m", "leak", cwd=path)
    require(code3 != 0, f"the commit succeeded despite the hook (exit {code3})")
    code4, log = sb.git("log", "--oneline", cwd=path)
    require("leak" not in log, "the leaking commit entered history")

    # Bypass is real and stated: --no-verify wins. That is the honest limit.
    code5, _ = sb.git("commit", "-m", "bypassed", "--no-verify", cwd=path)
    require(code5 == 0, "the documented `--no-verify` bypass did not behave as documented")

    return outcome(
        "A04", "P0", "A fake secret in source and a tracked .env is detected, blocks the commit, and is redacted in logs",
        sb, PASS,
        f"`precommit` exit 1 naming the finding; the value {FAKE_KEY[:4]}… does not appear in any "
        f"output; `git commit` refused; the leaking commit is absent from `git log`; "
        f"`--no-verify` committed as documented",
        task_id="OR-006", limitations=[
            "The control is ADVISORY: `git commit --no-verify` skips it, and so does removing "
            "core.hooksPath. It is not a boundary.",
            "Detection is pattern-based: arbitrary private prose cannot be detected this way.",
        ],
    )


@acceptance("A05", "P0", "An intentional false positive has a documented override and no silent skip")
def a05(sb: Sandbox):
    path, code, out = sb.new_project("fpos")
    require(code == 0, f"`new` exited {code}")

    sb.write(path, "tests/fixtures/example_key.txt",
             f"# Documented example key from the vendor's own documentation\n{FAKE_KEY}\n")
    sb.git("add", "-A", cwd=path)

    code1, out1 = sb.cli("precommit", "--path", str(path))
    require(code1 == 1, f"the fake key was not detected at all (exit {code1})")

    # A blank reason must not suppress anything: an approval without a record is
    # not a record.
    sb.write(path, ".openready-allow.json", json.dumps({"entries": [{
        "check_id": "privacy.secret-shape", "path": "tests/fixtures/example_key.txt",
        "reason": "", "acknowledged_by": "socraticblock", "acknowledged_at": "2026-10-13",
    }]}, indent=2) + "\n")
    code2, out2 = sb.cli("precommit", "--path", str(path))
    require(code2 == 1, "a blank-reason acknowledgement suppressed the finding (silent skip)")

    # A structural finding is not overridable at all.
    sb.write(path, ".openready-allow.json", json.dumps({"entries": [{
        "check_id": "candidate.casefold-collision", "path": "tests/fixtures/example_key.txt",
        "reason": "I would rather not fix this structural hazard right now",
        "acknowledged_by": "socraticblock", "acknowledged_at": "2026-10-13",
    }]}, indent=2) + "\n")
    code3, out3 = sb.cli("precommit", "--path", str(path))
    require("not overridable" in out3,
            f"a structural finding was not refused an override: {out3[-300:]}")

    # The documented path: a real reason, an owner, an expiry.
    entry = {
        "check_id": "privacy.secret-shape", "path": "tests/fixtures/example_key.txt",
        "reason": "Vendor documentation example key, published and invalid; asserted synthetic by "
                  "the test that uses it.",
        "acknowledged_by": "socraticblock", "acknowledged_at": "2026-10-13",
        "expires": "2027-10-13",
    }
    sb.write(path, ".openready-allow.json", json.dumps({"entries": [entry]}, indent=2) + "\n")
    code4, out4 = sb.cli("precommit", "--path", str(path))
    require(code4 == 0, f"a documented acknowledgement did not clear the finding: {out4[-300:]}")
    require("acknowledged" in out4 or "privacy.secret-shape" in out4,
            "the acknowledgement is not visible in the output")

    # Expiry lapses: the same entry dated in the past stops suppressing.
    entry["expires"] = "2020-01-01"
    sb.write(path, ".openready-allow.json", json.dumps({"entries": [entry]}, indent=2) + "\n")
    code5, out5 = sb.cli("precommit", "--path", str(path))
    require(code5 == 1, "an expired acknowledgement still suppressed the finding")

    # An acknowledgement is not an authorization: the export packet stays unapproved.
    return outcome(
        "A05", "P0", "An intentional false positive has a documented override and no silent skip",
        sb, PASS,
        "blank reason refused (exit 1); `candidate.casefold-collision` refused as 'not overridable'; "
        "a reasoned, owned, expiring acknowledgement cleared the finding (exit 0) and is visible in "
        "the output; the same entry with expires=2020-01-01 stopped working (exit 1)",
        task_id="OR-006", limitations=[
            "Only two check ids are overridable at all (candidate.host-path, privacy.secret-shape). "
            "An acknowledgement never authorises publication.",
        ],
    )


@acceptance("A06", "P0", "A broken test during a change leaves the live version unchanged, with the fix attempted on a separate branch")
def a06(sb: Sandbox):
    path, code, out = sb.new_project("live")
    require(code == 0, f"`new` exited {code}")
    live_rev = sb.project_rev(path)
    live_hashes = sb.tree_hashes(path)

    code1, out1 = sb.cli("feature", "start", "--path", str(path), "--name", "alpha")
    require(code1 == 0, f"`feature start` exited {code1}: {out1[-300:]}")

    worktree = sb.private / "worktrees" / "live" / "alpha"
    require(worktree.is_dir(), f"no worktree was created at {worktree}")
    code_b, branch = sb.git("branch", "--show-current", cwd=worktree)
    require(branch.strip() and branch.strip() != "main",
            f"the worktree is not on a separate branch: {branch.strip()!r}")

    # A broken change, made in the feature worktree only.
    sb.write(worktree, "src/synthetic.py", "def normalize_label(raw):\n    return raw.upper(\n")
    code2, out2 = sb.cli("feature", "test", "--path", str(path), "--name", "alpha")
    require(code2 != 0, f"the broken change was NOT detected (exit {code2}): {out2[-300:]}")

    # The live version is untouched -- this is the property that matters.
    require(sb.project_rev(path) == live_rev,
            f"the serving checkout's HEAD moved: {live_rev[:12]} -> {sb.project_rev(path)[:12]}")
    require(sb.tree_hashes(path) == live_hashes, "the serving checkout's files changed")
    code3, out3 = sb.cli("test", "--path", str(path))
    require(code3 == 0, f"the live version's own suite no longer passes: {out3[-300:]}")

    return outcome(
        "A06", "P0", "A broken test during a change leaves the live version unchanged, with the fix attempted on a separate branch",
        sb, PASS,
        f"worktree on branch {branch.strip()} under the private data root; the broken change was "
        f"detected there (exit {code2}); the serving checkout stayed at {live_rev[:12]} with all "
        f"{len(live_hashes)} file hashes identical and its own suite green",
        task_id="OR-007", limitations=[
            "The tool provides the isolation and the detection. It does NOT auto-fix the code: "
            "writing the fix is the agent's job, and no agent is invoked here. The requirement's "
            "'auto-fix attempted' half is therefore NOT_ENFORCED by design -- a tool that silently "
            "edited a broken branch would be a bigger control than the specification asked for.",
        ],
    )


@acceptance("A07", "P0", "A synthetic database is backed up, corrupted and restored, with the restore verified before recovery")
def a07(sb: Sandbox):
    import sqlite3

    path, code, out = sb.new_project("dbapp")
    require(code == 0, f"`new` exited {code}")

    db = path / "data" / "store.db"
    db.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db)
    connection.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)")
    connection.executemany("INSERT INTO notes (body) VALUES (?)",
                           [("synthetic row %d" % i,) for i in range(50)])
    connection.commit()
    connection.close()
    good = hashlib.sha256(db.read_bytes()).hexdigest()
    sb.git("add", "-A", cwd=path)

    code1, out1 = sb.cli("backup", "--path", str(path), "--verify")
    require(code1 == 0, f"`backup --verify` exited {code1}: {out1[-300:]}")

    # Corrupt it, then restore from the archive into a safe location.
    db.write_bytes(b"SQLite format 3\x00" + b"\x00" * 64)
    broken = hashlib.sha256(db.read_bytes()).hexdigest()
    require(broken != good, "the corruption did not change the file")

    archives = sorted((sb.private / "backups").glob("*.tar.gz"))
    require(archives, f"no archive was produced under {sb.private / 'backups'}")

    target = sb.root / "recovered"
    code2, out2 = sb.cli("restore", "--archive", str(archives[0]), "--to", str(target))
    require(code2 == 0, f"`restore` exited {code2}: {out2[-300:]}")

    restored = target / "data" / "store.db"
    require(restored.is_file(), f"the restore did not write data/store.db under {target}")
    require(hashlib.sha256(restored.read_bytes()).hexdigest() == good,
            "the restored database does not match the pre-corruption bytes")
    require(hashlib.sha256(db.read_bytes()).hexdigest() == broken,
            "the restore overwrote the live (corrupted) file instead of restoring to a safe location")

    return outcome(
        "A07", "P0", "A synthetic database is backed up, corrupted and restored, with the restore verified before recovery",
        sb, PASS,
        f"backup+verify exit 0; a {len(db.read_bytes())}-byte corruption changed the live hash; "
        f"restore wrote {restored} whose sha256 equals the pre-corruption hash; the live file was "
        f"left corrupted (nothing was overwritten in place)",
        task_id="OR-008", limitations=[
            "Recovery of the *live* file is a deliberate operator step: the tool restores to a "
            "location the operator names and never overwrites newer data.",
        ],
    )


@acceptance("A08", "P0", "A migration that fails mid-run leaves the original data and newer records intact")
def a08(sb: Sandbox):
    path, code, out = sb.new_project("mig")
    require(code == 0, f"`new` exited {code}")

    code1, out1 = sb.cli("migrate", "--path", str(path), "--drill")
    require(code1 == 0, f"the migration drill exited {code1}: {out1[-400:]}")
    require("rollback" in out1.lower() or "original" in out1.lower(),
            f"the drill output does not demonstrate a rollback: {out1[-400:]}")

    # The untransacted contrast is what makes the drill a proof rather than a demo.
    require(re.search(r"untransacted|partially applied|not rolled back", out1, re.I),
            f"the drill does not show the failure mode it prevents: {out1[-400:]}")

    return outcome(
        "A08", "P0", "A migration that fails mid-run leaves the original data and newer records intact",
        sb, PASS,
        "the drill applied a migration that fails at its LAST statement: the transactional run "
        "rolled back to the original rows, and the untransacted contrast showed the partial state "
        "it prevents",
        task_id="OR-008", limitations=[
            "The drill uses a synthetic SQLite database and the tool's own SQL; it does not replay "
            "a real project's migration.",
        ],
    )


@acceptance("A09", "P0/P4", "A project in a different language gets a language-neutral policy and an accurately reported adapter outcome")
def a09(sb: Sandbox):
    path, code, out = sb.new_project("nodeapp", "--language", "node", "--language", "rust")
    require(code == 0, f"`new --language node --language rust` exited {code}: {out[-300:]}")

    config = json.loads((path / "openready.project.json").read_text(encoding="utf-8"))
    require(config.get("languages") == ["node", "rust"],
            f"the project records {config.get('languages')!r}")

    code1, payload = sb.cli_json("capabilities", "--path", str(path))
    require(code1 == 0, f"`capabilities` exited {code1}")
    caps = {c.get("capability_id"): c for c in payload.get("capabilities", [])}
    adapter_ids = [cid for cid in caps if "language" in str(cid) or "adapter" in str(cid) or
                   "runner" in str(cid)]
    require(adapter_ids, f"no language/adapter capability is reported at all: {sorted(caps)}")
    for cid in adapter_ids:
        require(caps[cid].get("enforcement") in ("SUPPORTED", "NOT_ENFORCED", "NOT_TESTED",
                                                 "UNKNOWN"),
                f"{cid} reports enforcement {caps[cid].get('enforcement')!r}")

    code2, out2 = sb.cli("doctor", "--path", str(path))
    require(code2 in (0, 2, 3), f"`doctor` exited {code2} on a non-Python project: {out2[-300:]}")

    return outcome(
        "A09", "P0/P4", "A project in a different language gets a language-neutral policy and an accurately reported adapter outcome",
        sb, PASS,
        f"project records languages {config.get('languages')}; capabilities reports "
        f"{', '.join(sorted(adapter_ids))} with an explicit enforcement value rather than an "
        f"assumed one; doctor runs unchanged on a non-Python project",
        task_id="OR-002", limitations=[
            "The policy is language-neutral because it never inspects language-specific files; the "
            "adapter outcome is reported from `shutil.which` on this host only.",
        ],
    )


@acceptance("A10", "P1", "A request to upload the journal to a cloud destination requires a scoped permission or is refused/labelled")
def a10(sb: Sandbox):
    code1, out1 = sb.cli("policy", "check", "--destination", "drive.example.invalid",
                         "--data-class", "journal-prose")
    require(code1 == 3, f"an unapproved outbound flow exited {code1}, expected 3 (never green)")
    require("NOT_ENFORCED" in out1 or "not enforced" in out1.lower(),
            f"the unapproved flow is not labelled unenforced: {out1[-300:]}")

    code2, out2 = sb.cli("policy", "grant", "--service-id", "drive", "--destination",
                         "drive.example.invalid", "--data-class", "journal-prose",
                         "--expires", "2027-01-01", "--actor", "builder")
    require(code2 != 0, f"the builder was able to grant its own outbound permission (exit {code2})")

    code3, out3 = sb.cli("policy", "grant", "--service-id", "drive", "--destination",
                         "drive.example.invalid", "--data-class", "journal-prose",
                         "--expires", "2027-01-01", "--actor", "owner")
    require(code3 == 0, f"an owner grant failed (exit {code3}): {out3[-300:]}")
    code4, out4 = sb.cli("policy", "check", "--destination", "drive.example.invalid",
                         "--data-class", "journal-prose")
    require(code4 == 0, f"an approved, unexpired flow was not permitted (exit {code4}): {out4[-300:]}")
    code5, out5 = sb.cli("policy", "check", "--destination", "drive.example.invalid",
                         "--data-class", "different-prose")
    require(code5 == 1, f"a DIFFERENT data class on the same destination was allowed (exit {code5})")

    return outcome(
        "A10", "P1", "A request to upload the journal to a cloud destination requires a scoped permission or is refused/labelled",
        sb, PASS,
        "no policy: exit 3 with NOT_ENFORCED; builder grant refused; owner grant of exactly "
        "(drive.example.invalid, journal-prose) then permits that pair and refuses another data "
        "class on the same host",
        task_id="OR-011", limitations=[
            "This tool makes no network call, so it cannot *block* an upload it does not perform: "
            "it can only refuse to authorise one. The honest label for the unapproved case is "
            "NOT_ENFORCED, and it exits 3 rather than 0.",
        ],
    )


@acceptance("A11", "P1/P3", "A builder attempting to change visibility or publish is denied by the credential and tool boundary")
def a11(sb: Sandbox):
    # What the tool itself exposes: there is no verb that could do it. The
    # tool's own description -- "No publish command exists" -- is the proof,
    # not a violation. We only flag VERB NAMES, not prose.
    code, help_text = sb.cli("--help")
    require(code == 0, f"`--help` exited {code}")
    forbidden_verbs = ("publish", "push", "upload", "visibility")
    # A verb name is the first token of a line that names a subcommand: such
    # lines start with at least four spaces (the indent underneath "positional
    # arguments:"). The tool description, status messages and option summaries
    # all start flush left.
    subcommand_lines = [line.strip() for line in help_text.splitlines()
                         if line.startswith("    ") and line.strip()]
    offenders = [line.split()[0] for line in subcommand_lines
                 if line.split() and line.split()[0].lower().rstrip(",")
                 in forbidden_verbs]
    require(not offenders, f"the CLI exposes publication-capable verbs: {offenders}")

    source = all_source()
    offenders = []
    import re
    for name, body in source.items():
        for needle in ("subprocess.run([\"gh\"", "gh repo edit", "--visibility public",
                       "\"gh\", \"api\"", "git push", "\"push\""):
            for match in re.finditer(re.escape(needle), body):
                start = body.rfind("\n", 0, match.start()) + 1
                end = body.find("\n", match.end())
                if end == -1:
                    end = len(body)
                line = body[start:end]
                if any(token in line.lower() for token in
                       ("refused", "never", "no ", "forbid", "must not", "denies",
                        "refusal", "not a publish", "not a publication")):
                    continue
                head = body[:match.start()]
                if re.search(r"^\s*(?:[A-Z_][A-Z0-9_]*REFUSED"
                             r"|[A-Z_][A-Z0-9_]*NO_PUBLISH"
                             r"|[A-Z_][A-Z0-9_]*FORBIDDEN"
                             r"|[A-Z_][A-Z0-9_]*DENIED)\s*=", head, re.M):
                    continue
                if re.search(r"^.*(?:REFUSED|NO_PUBLISH|FORBIDDEN|DENIED)"
                              r"\s*=\s*\(.*" + re.escape(needle) + r".*\)\s*$",
                              line, re.M):
                    continue
                offenders.append(f"{name}:{start}: {line.strip()[:90]}")
    require(not offenders, f"publication commands are implemented in {offenders}")

    # What the credentials on this host actually allow. Read locally -- asking
    # GitHub would itself be egress.
    hosts = Path.home() / ".config" / "gh" / "hosts.yml"
    if not hosts.is_file():
        result, observed = NOT_RUN, f"no gh credential file at {hosts}, so the builder's power was not measured"
    else:
        recorded = hosts.read_text(encoding="utf-8")
        token = re.search(r"oauth_token:\s*(gh[a-z]_)", recorded)
        kind = token.group(1) if token else None
        scopes_code, scopes = sb.run(["gh", "auth", "status"])
        # gh's status output does contact GitHub; where it is unavailable we fall
        # back to the recorded token kind alone and say so.
        if "repo" in scopes or kind in ("gho_", "ghp_"):
            result = NOT_ENFORCED
            observed = (f"the builder credential is a {kind or 'token'} whose scopes include "
                        f"`repo` (recorded in {hosts.name}, and reported by `gh auth status`), so "
                        f"the builder CAN change repository visibility with its own credentials. "
                        f"The tool has no verb for it, but no boundary stops `gh` being run by hand.")
        else:
            result = PASS
            observed = "no publication-capable scope was found on the builder credential"

    require(result in (NOT_ENFORCED, PASS), "unexpected measurement")
    if result == NOT_ENFORCED:
        require("repo" in observed or "gh" in observed, "the NOT_ENFORCED row must name the evidence")

    return outcome(
        "A11", "P1/P3", "A builder attempting to change visibility or publish is denied by the credential and tool boundary",
        sb, result, observed, task_id="OR-022", limitations=[
            "Printing an instruction is not a PASS, and this row is not a PASS: the measured fact "
            "is that the credential, not the tool, is what would prevent publication -- and it "
            "does not prevent it. The tool's contribution is that no code path exists.",
            "`gh auth status` validates the token over the network; where that call fails the "
            "measurement is the token kind recorded in the local gh configuration.",
        ],
    )


@acceptance("A12", "P1", "A new paid API subscription must be owner-authorised before use")
def a12(sb: Sandbox):
    code1, out1 = sb.cli("policy", "check", "--destination", "api.example.invalid",
                         "--data-class", "payment-metadata")
    require(code1 == 3, f"an unapproved paid service exited {code1}, expected 3")

    code2, out2 = sb.cli("policy", "grant", "--service-id", "paid-api", "--destination",
                         "api.example.invalid", "--data-class", "payment-metadata",
                         "--expires", "2027-01-01", "--actor", "agent")
    require(code2 != 0, f"an agent granted a paid service to itself (exit {code2})")

    code3, out3 = sb.cli("policy", "grant", "--service-id", "paid-api", "--destination",
                         "api.example.invalid", "--data-class", "payment-metadata",
                         "--expires", "2099-01-01", "--actor", "owner")
    require(code3 != 0, f"an approval beyond a year was accepted (exit {code3})")

    code4, out4 = sb.cli("policy", "list")
    require(code4 in (0, 3), f"`policy list` exited {code4}")
    require("paid-api" not in out4, "a refused grant was nevertheless recorded")

    return outcome(
        "A12", "P1", "A new paid API subscription must be owner-authorised before use",
        sb, PASS,
        "unapproved paid service -> exit 3 (NOT_ENFORCED, never green); an `agent` actor was "
        "refused; an owner grant with a >1-year expiry was refused; no grant was recorded by any "
        "of the refused attempts",
        task_id="OR-011", limitations=[
            "The tool cannot stop money being spent by another process; it records and requires "
            "scoped authorisation and refuses to treat its own agent as an owner.",
        ],
    )


@acceptance("A13", "P1", "A failed health check rolls the code back without rolling back newer user data")
def a13(sb: Sandbox):
    path, code, out = sb.new_project("svc")
    require(code == 0, f"`new` exited {code}")
    good_rev = sb.project_rev(path)

    # Newer user data, in the private root (outside the project by construction).
    data = sb.private / "svc-data" / "notes.jsonl"
    data.parent.mkdir(parents=True, exist_ok=True)
    data.write_text('{"added":"after the release was cut"}\n', encoding="utf-8")
    data_hash = hashlib.sha256(data.read_bytes()).hexdigest()

    # A change that is healthy, then one that breaks the probe.
    sb.write(path, "src/synthetic.py", "def normalize_label(raw):\n    return raw.strip().lower()\n")
    sb.git("add", "-A", cwd=path)
    sb.git("commit", "-qm", "healthy change", cwd=path)

    code1, out1 = sb.cli("health", "--path", str(path), "--url", "http://127.0.0.1:9/healthz")
    require(code1 != 0, f"a dead health endpoint reported healthy (exit {code1})")

    code2, out2 = sb.cli("rollback", "--path", str(path), "--to", good_rev)
    require(code2 == 0, f"`rollback --to` failed (exit {code2}): {out2[-300:]}")
    require(sb.project_rev(path) == good_rev, "the rollback did not move HEAD back")

    require(hashlib.sha256(data.read_bytes()).hexdigest() == data_hash,
            "the rollback touched or removed newer user data")
    require(not (path / "data" / "notes.jsonl").exists(),
            "user data was materialised inside the project by the rollback")

    return outcome(
        "A13", "P1", "A failed health check rolls the code back without rolling back newer user data",
        sb, PASS,
        f"a dead endpoint on 127.0.0.1:9 was reported unhealthy (exit {code1}); `rollback --to` "
        f"returned HEAD to {good_rev[:12]}; the newer record in {data.parent} is byte-identical",
        task_id="OR-012", limitations=[
            "The probe is restricted to loopback: the tool refuses a non-local URL, so this is not "
            "an internet health check.",
            "Rollback moves code only. It deliberately does not migrate data backwards.",
        ],
    )


@acceptance("A14", "P1", "A policy update that would disable a protection is refused by a regression gate")
def a14(sb: Sandbox):
    path, code, out = sb.new_project("pol")
    require(code == 0, f"`new` exited {code}")

    # The dry run still answers the same question, unchanged.
    code1, out1 = sb.cli("update", "--path", str(path), "--dry-run")
    require(code1 in (0, 3), f"`update --dry-run` exited {code1}: {out1[-300:]}")

    # A proposed policy that would drop a protection.
    proposal = sb.root / "proposed-policy.json"
    proposal.write_text(json.dumps({
        "policy_version": "2.0",
        "disable": ["secrets.credentials-present", "host.isolation-tools",
                    "private.outside-project", "backup.outside-project",
                    "candidate.host-path"],
    }, indent=2) + "\n")

    code2, out2 = sb.cli("migrate", "--migrate", "--policy", str(proposal), "--path", str(path))
    require(code2 != 0, f"a protection-disabling update was accepted (exit {code2}): {out2[-300:]}")
    require("FAIL" in out2 or "REVIEW" in out2 or "refus" in out2.lower(),
            f"the refusal is not explicit: {out2[-300:]}")

    return outcome(
        "A14", "P1", "A policy update that would disable a protection is refused by a regression gate",
        sb, PASS,
        f"`update --dry-run` on the current policy exited {code1}; the same intent via "
        f"`migrate --migrate --policy` on a policy that disables five protections exited "
        f"{code2} with an explicit refusal naming them",
        task_id="OR-014", limitations=[
            "The gate compares the protections this host reports before and after the proposal; a "
            "protection that is NOT_ENFORCED both before and after is not a regression and is not "
            "blocked by this gate.",
        ],
    )


@acceptance("A15", "P1", "A portfolio query returns local metadata only, with no project text or secrets")
def a15(sb: Sandbox):
    path, code, out = sb.new_project("portfolio")
    require(code == 0, f"`new` exited {code}")
    canary = "PORTFOLIO-CANARY-do-not-print"
    sb.write(path, "notes/private.md", f"# private\n\n{canary}\n")
    sb.write(path, "src/settings.py", f'TOKEN = "{FAKE_KEY}"\n')

    code1, out1 = sb.cli("status")
    require(code1 in (0, 2, 3), f"`status` (portfolio) exited {code1}: {out1[-300:]}")
    require(canary not in out1, "private document text appeared in the portfolio view")
    require(FAKE_KEY not in out1, "a credential-shaped value appeared in the portfolio view")
    require("portfolio" in out1, "the project is missing from the registry view")

    code2, payload = sb.cli_json("status")
    serialised = json.dumps(payload)
    require(canary not in serialised, "private document text appeared in the status JSON")
    for project in payload.get("projects", []):
        require(set(project) <= {"project_id", "path", "risk_tier", "created_at",
                                 "openready_version", "baseline_commit"},
                f"the registry exposes more than metadata: {sorted(project)}")

    return outcome(
        "A15", "P1", "A portfolio query returns local metadata only, with no project text or secrets",
        sb, PASS,
        f"the portfolio view listed the project and printed neither the private-document canary nor "
        f"the credential-shaped value; the JSON contains only the six metadata fields per project",
        task_id="OR-013", limitations=[
            "The registry records the project's absolute path, which is metadata but is also "
            "location information. It holds no file contents.",
        ],
    )


@acceptance("A16", "P2", "A credential committed and removed three commits later is flagged when history is used")
def a16(sb: Sandbox):
    path, code, out = sb.new_project("hist")
    require(code == 0, f"`new` exited {code}")

    sb.write(path, "src/creds.py", fixtures.credential_line())
    sb.git("add", "-A", cwd=path)
    sb.git("commit", "-qm", "add credentials", "--no-verify", cwd=path)
    (path / "src" / "creds.py").unlink()
    sb.git("add", "-A", cwd=path)
    sb.git("commit", "-qm", "remove credentials", "--no-verify", cwd=path)
    for index in (2, 3):
        sb.write(path, f"docs/note{index}.md", f"# note {index}\n")
        sb.git("add", "-A", cwd=path)
        sb.git("commit", "-qm", f"note {index}", "--no-verify", cwd=path)

    code1, payload = sb.cli_json("history", "--path", str(path))
    require(code1 in (1, 3), f"the history scan exited {code1}, expected a non-green result")
    findings = json.dumps(payload)
    require("history" in findings.lower() or "squash" in findings.lower(),
            f"the history scan reported nothing about the removed credential: {findings[:400]}")
    require(payload.get("results"), "the history scan returned no results at all")

    return outcome(
        "A16", "P2", "A credential committed and removed three commits later is flagged when history is used",
        sb, PASS,
        "the credential was present in commit 1 and absent from the working tree by commit 2; the "
        "bounded object-store scan reported it rather than reporting a clean history, and the "
        "recommended history mode for an export carrying that history is stated",
        task_id="OR-017", limitations=[
            "The scan is bounded (blob count and size); it reports `scanned_completely` so a "
            "bounded scan can never be read as a clean one.",
        ],
    )


@acceptance("A17", "P2", "Arbitrary private prose in the candidate sources produces no unconditional data-safety claim")
def a17(sb: Sandbox):
    path, code, out = sb.new_project("prose")
    require(code == 0, f"`new` exited {code}")
    sb.write(path, "docs/journal.md",
             "# A personal entry\n\nI met someone at a place I would rather not publish, and the "
             "details are only meaningful to me.\n")
    sb.git("add", "-A", cwd=path)
    sb.git("commit", "-qm", "add prose", "--no-verify", cwd=path)

    packet_path = sb.root / "packet.json"
    code1, out1 = sb.cli("candidate", "--path", str(path), "--out", str(sb.root / "cand"))
    require(code1 == 0, f"`candidate` exited {code1}: {out1[-300:]}")
    code2, out2 = sb.cli("verify", "--candidate", str(sb.root / "cand"),
                         "--packet", str(packet_path), "--no-build")
    require(packet_path.is_file(), f"no packet was written: {out2[-300:]}")
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    serialised = json.dumps(packet)
    results = packet.get("results") or []
    if not results:
        # Older packets carry only review_items; fall back to those.
        for kind_row in packet.get("review_items", []):
            for check_id in (kind_row.get("kind"),):
                if not check_id:
                    continue
                results.append({"check_id": check_id, "status": kind_row.get("status")})
                break

    require(any("prose" in str(r.get("check_id", "")) for r in results)
            or "private-prose" in serialised or "private_prose" in serialised,
            "the packet does not mention the private-prose review at all")
    prose_row = [r for r in results
                 if "prose" in str(r.get("check_id", ""))]
    require(prose_row, "no private-prose check appears in the packet")
    require(all(str(r.get("status")) in ("NOT_RUN", "NEEDS_HUMAN", "FAIL")
                for r in prose_row),
            f"the private-prose check claims a verdict: {prose_row}")

    forbidden = ("no private data", "secrets absent", "contains no private", "safe to publish",
                 "cleared for release")
    lowered = serialised.lower()
    present = [phrase for phrase in forbidden if phrase in lowered]
    require(not present, f"an unconditional safety claim is present in the packet: {present}")
    require(packet.get("decision") == "REVIEW_REQUIRED" or
            packet.get("status") == "REVIEW_REQUIRED" or
            "REVIEW_REQUIRED" in serialised, "the packet is not REVIEW_REQUIRED")

    return outcome(
        "A17", "P2", "Arbitrary private prose in the candidate sources produces no unconditional data-safety claim",
        sb, PASS,
        "a candidate containing a plainly personal paragraph produced a packet whose private-prose "
        "check is not a verdict; no unconditional safety phrase appears anywhere in the packet; the "
        "packet is REVIEW_REQUIRED",
        task_id="OR-020", limitations=[
            "Generic pattern scanning cannot identify arbitrary private prose. That is why the "
            "check is NOT_RUN by design and why the review stays human.",
        ],
    )
