"""On-demand public-release artifact templates (work order OR-023, decisions D-2/D-8).

The public-release paperwork -- a security policy, a contributing guide, a code of
conduct, a support note, third-party notices, a contribution policy, a public
README and an owner-act licence note -- is **generated on demand into a
candidate**, never committed as if the project were already open. Two properties
are structural, not decorative, and the code enforces both:

1. **Nothing here is a release and nothing here goes into tracked source.** The
   files are written into a destination the caller names (the candidate), and
   every result says so. A committed ``CONTRIBUTING.md`` that reads "contributions
   welcome" is a false statement about a private repository; a generated one that
   says contributions are not yet accepted is not.
2. **No licence is chosen and no licence grant is emitted.** This module *never*
   writes a file named ``LICENSE``, ``LICENCE`` or ``COPYING``, and it refuses --
   writing nothing at all -- if the destination already holds a real one. The
   recommendation that MIT be considered, with Apache-2.0 as the patent-grant
   alternative, lives in an ``OWNER-ACT-LICENCE.md`` placeholder that is
   deliberately **not** named ``LICENSE`` and explicitly states it grants nothing.
   Choosing and adding a licence is the owner's legal act (ADR-005 / decision
   D-2); a tool that picked one, or wrote the grant, would be doing the owner's
   legal act for them.

Governing rules copied from the rest of the package: every result carries
``limitations``; a refusal is ``FAIL``/``STOP`` and leaves the destination byte for
byte unchanged; and no result ever claims the project is ready to release.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from . import __version__
from .capabilities import environment_label
from .status import FAIL, INFO, PASS, STOP, Result

# The complete artifact set, in the order they are written.
TEMPLATE_FILES: Tuple[str, ...] = (
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SUPPORT.md",
    "NOTICES.md",
    "CONTRIBUTING-POLICY.md",
    "README.public.md",
    "OWNER-ACT-LICENCE.md",
)

DEFAULT_LICENCE_RECOMMENDATION = "MIT"
PATENT_GRANT_ALTERNATIVE = "Apache-2.0"

# Filenames (after stripping a common document extension) that mean a real licence
# or copying file already exists. ``OWNER-ACT-LICENCE.md`` does not match: it is a
# note *about* the owner's licence decision, not the decision itself.
_REAL_LICENCE_STEMS = frozenset({"license", "licence", "copying", "copyright"})

ON_DEMAND_RULE = (
    "Generated on demand into a candidate: never committed as if the project were "
    "already open, and never part of the project's tracked source."
)

NO_GRANT_RULE = (
    "Not a licence and not a release: this file grants no rights, and no licence has "
    "been chosen or added. Adding one is the owner's act, outside this tool."
)

# A generated file must never be mistaken for the grant.
if any(_name_for_stem in _REAL_LICENCE_STEMS for _name_for_stem in
       (n.lower().rsplit(".", 1)[0] for n in TEMPLATE_FILES)):  # pragma: no cover
    raise RuntimeError("a generated template must never be named like a licence file")

# check_id suffix and a one-line description per artifact.
_FILE_KINDS: Dict[str, Tuple[str, str]] = {
    "SECURITY.md": (
        "security",
        "security policy: a PRIVATE triage path and an OWNER review step before any "
        "disclosure",
    ),
    "CONTRIBUTING.md": (
        "contributing",
        "contributing guide: contributions are NOT accepted while the repository is private",
    ),
    "CODE_OF_CONDUCT.md": (
        "code-of-conduct",
        "code of conduct for any future public participation",
    ),
    "SUPPORT.md": (
        "support",
        "support and help policy",
    ),
    "NOTICES.md": (
        "notices",
        "third-party notices drawn from the provenance ledger as review items, never "
        "legal conclusions",
    ),
    "CONTRIBUTING-POLICY.md": (
        "contributing-policy",
        "contribution policy: DCO-style intent, no CLA machinery, relicensing becomes "
        "irreversible at the first outside contribution",
    ),
    "README.public.md": (
        "readme-public",
        "public-facing README draft with an installation section and a synthetic example",
    ),
    "OWNER-ACT-LICENCE.md": (
        "owner-act-licence",
        "owner-act placeholder recording a licence recommendation; grants nothing and is "
        "not named LICENSE",
    ),
}


def _is_real_licence_file(name: str) -> bool:
    """True for a LICENSE / LICENCE / COPYING (or COPYRIGHT) file, any common extension."""
    lowered = name.lower()
    for suffix in (".md", ".txt", ".rst", ".markdown"):
        if lowered.endswith(suffix):
            lowered = lowered[: -len(suffix)]
            break
    return lowered in _REAL_LICENCE_STEMS


def _env_label(env: Optional[Mapping[str, str]]) -> str:
    """Environment label for a result, with an optional offline override.

    ``env`` is accepted so a caller (and a test) can supply a deterministic
    environment label without touching the host; absent that, ``environment_label``
    is used exactly as elsewhere in the package.
    """
    if isinstance(env, Mapping):
        override = env.get("environment") or env.get("OPENREADY_ENVIRONMENT")
        if override:
            return str(override)
    return environment_label()


def generate(destination: Path, project_id: str, *,
             licence_recommendation: str = DEFAULT_LICENCE_RECOMMENDATION,
             overwrite: bool = False,
             env: Optional[Mapping[str, str]] = None) -> Tuple[List[str], List[Result]]:
    """Write the public-release templates into ``destination``.

    Returns ``(relative paths written, results)``.

    Refuses -- ``FAIL``/``STOP`` with **nothing written at all** -- when:

    - ``destination`` already holds a real ``LICENSE``/``LICENCE``/``COPYING`` file,
      regardless of ``overwrite``: this tool never competes with a real licence; or
    - a template that would be generated already exists and ``overwrite`` is False.

    No file written by this function is ever named ``LICENSE``, ``LICENCE`` or
    ``COPYING``.
    """
    dest = Path(destination)
    label = _env_label(env)

    if dest.exists() and not dest.is_dir():
        return [], [Result(
            "templates.destination", FAIL, STOP,
            f"{dest} exists and is not a directory; refusing to write templates",
            __version__, label,
        )]

    existing: List[str] = []
    if dest.is_dir():
        existing = sorted(p.name for p in dest.iterdir() if p.is_file())

    real = [name for name in existing if _is_real_licence_file(name)]
    if real:
        return [], [Result(
            "templates.existing-licence", FAIL, STOP,
            (f"{dest} already contains {', '.join(real)}. This tool never writes, "
             f"overwrites or competes with a real licence, and it refuses to place its "
             f"templates next to one. Nothing was written."),
            __version__, label,
            limitations=[NO_GRANT_RULE],
        )]

    collisions = [name for name in TEMPLATE_FILES if name in existing]
    if collisions and not overwrite:
        return [], [Result(
            "templates.exists", FAIL, STOP,
            (f"{dest} already contains generated template(s) "
             f"{', '.join(collisions)}; refusing to overwrite without overwrite=True. "
             f"Nothing was written."),
            __version__, label,
            limitations=[ON_DEMAND_RULE],
        )]

    created = not dest.exists()
    dest.mkdir(parents=True, exist_ok=True)
    written: List[str] = []
    try:
        for name in TEMPLATE_FILES:
            (dest / name).write_text(
                _render(name, project_id, licence_recommendation), encoding="utf-8")
            written.append(name)
    except Exception:
        # A half-written set is worse than none: leave no partial artifact set behind
        # that could be mistaken for a complete one.
        for name in written:
            (dest / name).unlink(missing_ok=True)
        if created:
            try:
                dest.rmdir()
            except OSError:
                pass
        raise

    return written, _results_for(written, dest, project_id, label)


def results_for(paths: List[str], destination: Path, project_id: str) -> List[Result]:
    """One summary result plus one result per generated file kind.

    Each result states the on-demand rule. A file that is named but absent is a
    ``FAIL`` for that kind and fails the summary -- there is no fake ``PASS`` for a
    template that is not on disk.
    """
    return _results_for(paths, Path(destination), project_id, environment_label())


def _results_for(paths: List[str], dest: Path, project_id: str, label: str) -> List[Result]:
    results: List[Result] = []
    missing: List[str] = []
    for name in paths:
        slug, description = _FILE_KINDS.get(name, (name.lower(), "generated template"))
        present = (dest / name).is_file()
        if not present:
            missing.append(name)
        results.append(Result(
            f"templates.{slug}",
            PASS if present else FAIL,
            INFO if present else STOP,
            ((f"{name} written to a candidate: {description}. {ON_DEMAND_RULE}")
             if present else
             (f"{name} is not present in {dest}; a named-but-absent template is not a "
              f"generated one and is not reported as present")),
            __version__, label, required=False,
            evidence_path=str(dest),
            limitations=[ON_DEMAND_RULE, NO_GRANT_RULE],
        ))

    where = f" for project {project_id!r}" if project_id else ""
    if missing:
        results.insert(0, Result(
            "templates.generated", FAIL, STOP,
            (f"{len(missing)} of {len(paths)} template(s){where} are missing from {dest}: "
             f"{', '.join(missing)}. A partial artifact set is not a generated one."),
            __version__, label,
            limitations=[ON_DEMAND_RULE],
        ))
    else:
        results.insert(0, Result(
            "templates.generated", PASS, INFO,
            (f"generated {len(paths)} on demand template(s){where} into {dest}. These are "
             f"drafts for a candidate: not a release, not tracked source, and containing "
             f"no licence grant."),
            __version__, label, required=False,
            evidence_path=str(dest),
            limitations=[ON_DEMAND_RULE, NO_GRANT_RULE],
        ))
    return results


# --- content ------------------------------------------------------------------

def _render(name: str, project_id: str, licence_recommendation: str) -> str:
    return _RENDERERS[name](project_id, licence_recommendation)


def _security_md(project_id: str, _licence: str) -> str:
    return f"""# Security Policy

Generated on demand by Open-Ready for the project `{project_id or "(this project)"}`.
This is a draft: review and edit it before it is ever published.

## Reporting a vulnerability

Do **not** open a public issue, a public discussion or a chat thread for a security
problem, and do not disclose publicly until the owner has reviewed the report.
Disclosure is coordinated with the owner, not decided by the reporter alone.

Please report privately, through one of these private channels:

- Email: `<PRIVATE-SECURITY-CONTACT>` -- replace this with a real, private address
  before any publication.
- A private, access-controlled tracker owned by the maintainer.

Both channels are **private**: a report received this way is visible only to the
maintainer and the reporter.

## Triage and the owner review step

1. The report arrives through a **private** channel above. Nothing about it is posted
   to a public surface.
2. The **owner** reviews the report *before any disclosure* and decides what, when and
   how anything is published. No disclosure happens without that owner review step.
3. A fix and a coordinated disclosure date are agreed between the reporter and the
   owner. Credit is offered but never assumed.

## Scope

This policy covers the source in this repository and any artifact built from it. It
does not cover third-party dependencies -- report those to their own projects, and
record what you find in the provenance ledger.

## Limitations

Generated on demand: this file is not committed as part of the project's source, and
it is not a claim that the project has run a security review. Open-Ready performed no
security assessment of the code.
"""


def _contributing_md(project_id: str, _licence: str) -> str:
    return f"""# Contributing

Generated on demand by Open-Ready for the project `{project_id or "(this project)"}`.
This is a draft for a release candidate, not part of the project's tracked source.

## Contributions are not accepted while this repository is private

This repository is **private**. While it is private, contributions are **not
accepted**: do not send patches, pull requests or code, and do not assume that
anything you send will be read or used. Do not open issues proposing work.

## The first outside contribution is the irreversible moment

Accepting the first contribution from someone **outside** the project is the moment
the relicensing position becomes irreversible. Once an outside contribution is merged,
the project can no longer be relicensed by the owner alone: every later licence choice
needs that contributor's agreement too. That is why contributions open only after the
owner has chosen and added a licence -- and why the first outside contribution is
treated as a one-way door.

## Before contributions can be accepted

- The owner must choose and add a licence. This tool does not choose, recommend as a
  decision, or add a licence -- see `OWNER-ACT-LICENCE.md`.
- A contribution policy must be in place (see `CONTRIBUTING-POLICY.md`).
- The code of conduct must be reviewed for a public audience (see
  `CODE_OF_CONDUCT.md`).

## Limitations

This guide is generated on demand and is not a promise that any contribution channel
exists. Until the repository is public and the owner has added a licence, there is no
open contribution process.
"""


def _code_of_conduct_md(project_id: str, _licence: str) -> str:
    return f"""# Code of Conduct

Generated on demand by Open-Ready for the project `{project_id or "(this project)"}`.
This is a draft; adopt a full, reviewed text before any public participation.

## Our pledge

We pledge to make participation in `{project_id or "this project"}` a harassment-free
experience for everyone, regardless of age, body size, visible or invisible
disability, ethnicity, sex characteristics, gender identity and expression, level of
experience, education, socio-economic status, nationality, personal appearance, race,
religion, or sexual identity and orientation.

## Our standards

Examples of behaviour that contributes to a positive environment:

- Showing empathy and kindness toward other people.
- Being respectful of differing opinions, viewpoints and experiences.
- Giving and gracefully accepting constructive feedback.
- Accepting responsibility, apologising to those affected by mistakes, and learning.

Examples of unacceptable behaviour:

- Sexualised language or imagery, and unwelcome sexual attention.
- Trolling, insulting or derogatory comments, and personal or political attacks.
- Public or private harassment.
- Publishing others' private information without explicit permission.

## Enforcement

Instances of abusive, harassing or otherwise unacceptable behaviour may be reported to
the maintainer responsible for enforcement at `<PRIVATE-CONDUCT-CONTACT>`. All
complaints will be reviewed and investigated promptly and fairly. The maintainer is
obliged to respect the privacy and security of the reporter of any incident.

## Limitations

Generated on demand: this text is a starting point, not legal advice, and it is not
committed as part of the project's source. Review it against a full code of conduct
before adoption.
"""


def _support_md(project_id: str, _licence: str) -> str:
    return f"""# Support

Generated on demand by Open-Ready for the project `{project_id or "(this project)"}`.
This is a draft; it is not part of the project's tracked source.

## How to get help

This project is not released and offers no support commitment yet. When a support
channel is opened, this file should say exactly where to ask and what response -- if
any -- to expect.

Answer these before publishing:

- Where do questions go (issue tracker, discussion forum, mailing list)?
- What is the expected response time, if any?
- What is explicitly out of scope?

## What is out of scope

- No support is provided for modifications you make yourself.
- No security reports go here -- use the private channel in `SECURITY.md`.
- No support commitment exists while the repository is private.

## Limitations

Generated on demand: this file makes no support promise and is not a service-level
agreement.
"""


def _notices_md(project_id: str, _licence: str) -> str:
    return f"""# Notices

Generated on demand by Open-Ready for the project `{project_id or "(this project)"}`.
This is a draft, not part of the project's tracked source.

This file is where third-party notices and attribution belong. It is populated from
the project's provenance ledger, not invented here.

## Where the obligations come from

The obligations for third-party dependencies and assets come from the **provenance
ledger** (`.openready-ledger.json`) that Open-Ready builds for this project. Each
entry in that ledger records what a dependency declares and what it may require of a
distribution.

## These are review items, never legal conclusions

Open-Ready does **not** provide legal advice and **cannot** determine licence
compatibility. Nothing here -- and nothing in the ledger -- says a dependency is
"fine", "compatible" or "allowed". Every recorded obligation is a **review item for
the owner**: a thing to check, not a verdict that has been reached. A licence marked
`UNKNOWN` is a blocking review item, not a shrug.

## What to fill in before publication

For each third-party component that requires it, record:

- the component name and version;
- the licence text that must travel with the distribution; and
- any NOTICE file the component's licence requires to be carried.

## Limitations

Generated on demand. This file is not legal advice and does not resolve any
obligation; it is a place to record them so the owner can review them.
"""


def _contributing_policy_md(project_id: str, _licence: str) -> str:
    return f"""# Contribution Policy

Generated on demand by Open-Ready for the project `{project_id or "(this project)"}`.
This is a draft, not part of the project's tracked source.

## Contributions are not accepted while this repository is private

This repository is **private**. While it is private, no contributions are accepted.
There is no open channel, and code sent to the project should be assumed unread.

## No CLA machinery

There is **no CLA** (Contributor Licence Agreement) here, and none is planned. This
project deliberately does not use CLA machinery: a contributor is **not** asked to
assign copyright, and a contributor is **not** asked to grant a relicensing right to
the project. The intent, if and when contributions open, is a DCO-style sign-off --
you certify that you have the right to submit the work, and you **keep** your
copyright.

No CLA bot, no copyright assignment form and no relicensing grant is part of this
project, because there is no CLA machinery at all.

## The first outside contribution is the irreversible moment

Accepting the **first outside contribution** is the irreversible point. After it, the
licence is no longer the owner's alone to choose: relicensing requires every
contributor's agreement. Because of that one-way door:

- contributions open **only after** the owner has chosen and added a licence;
- the contribution terms are fixed **before** the first outside pull request is
  merged, not adjusted afterwards; and
- the sign-off a contributor gives is recorded per commit, so the set of people whose
  agreement a relicensing would need is always known.

## Limitations

Generated on demand. This policy states an intent; it is not itself a contract, and it
grants nothing. See `OWNER-ACT-LICENCE.md` -- the licence decision is the owner's act.
"""


def _readme_public_md(project_id: str, _licence: str) -> str:
    name = project_id or "this project"
    return f"""# {name}

Generated on demand by Open-Ready. This is a **draft** public README for a release
candidate. **{name} is not released.** Nothing here says the project is available,
supported or ready to use.

## What this is

A one-paragraph, plain description of what `{name}` does and who it is for. Replace
this sentence: it should describe the project, not the tool that drafted the file.

## Installation

Once the project is released, install it from the channel it actually ships through.
Replace the placeholders below with the real instructions before publication.

From a source checkout:

```sh
git clone <REPOSITORY-URL>
cd {name}
python3 -m pip install .
```

Or from a published package (placeholder -- only if such a package exists):

```sh
python3 -m pip install {name}
```

Requirements and supported platforms go here. State what is **not** supported as
plainly as what is.

## Example (synthetic)

The example below is **synthetic**: the project name, the values and the paths are
invented for illustration and contain **no real data**. It is not a record of any real
run.

```python
import {name.replace("-", "_") or "example"} as example

# All values here are fabricated for this illustration.
config = example.Config(
    name="synthetic-demo",            # invented
    region="example-region-1",        # invented
    retries=3,
)
print(example.run(config))
```

## Status

**Not released.** This README is a draft generated on demand for a candidate; it is not
part of the project's tracked source, and its presence is not evidence that the project
is ready or open.

## Limitations

Generated on demand. Do not publish this file until every placeholder is replaced and
the owner has reviewed it; it makes no release, support or licence claim.
"""


def _owner_act_licence_md(project_id: str, licence_recommendation: str) -> str:
    recommended = (licence_recommendation or DEFAULT_LICENCE_RECOMMENDATION).strip()
    alternative = (PATENT_GRANT_ALTERNATIVE
                   if recommended.lower() != PATENT_GRANT_ALTERNATIVE.lower()
                   else DEFAULT_LICENCE_RECOMMENDATION)
    return f"""# Owner act: choosing and adding a licence

Generated on demand by Open-Ready for the project `{project_id or "(this project)"}`.

**This file is NOT a licence.** It grants no rights to anyone, it is not a legal
document, and it is deliberately **not** named `LICENSE`, `LICENCE` or `COPYING`. It is
a placeholder that records a recommendation and nothing more.

## Why this file exists

Choosing and adding a licence is an **owner act**. It is the owner's decision and the
owner's action, taken outside this tool. Open-Ready never chooses a licence, never
writes a licence file, and never records a licence as granted. A tool that picked a
licence on the owner's behalf would be performing the owner's legal act for them.

## Recommendation

- **{recommended}** -- recommended. A short, permissive licence that lets others use,
  change and share the work provided the copyright notice and the licence text travel
  with it. It is easy to read and widely understood.
- **{alternative}** -- the alternative to consider when a **patent grant** matters. It
  adds an express grant of patent rights from contributors and includes a notice
  requirement; it is longer, and it imposes more conditions on redistribution.

Neither is "the right" choice: both are permissive, and the difference that usually
decides it is whether you want the explicit patent grant the alternative provides.

## What the owner must do

1. **Decide.** Read the full text of the recommended licence and the alternative, and
   choose the one that fits the project's intent.
2. **Act.** Add the chosen licence **yourself**, as a file named `LICENSE` (or
   `COPYING`). That file, added by you, is the grant. **This file is not.**
3. **Record the choice** wherever the project records owner decisions, so the decision
   has an owner and a date.

## Limitations

This is not legal advice and not a licence. Open-Ready cannot determine licence
compatibility and does not provide legal advice. The names above are recommendations
for the owner to consider, not a decision made here and not a grant by this tool.
"""


_RENDERERS = {
    "SECURITY.md": _security_md,
    "CONTRIBUTING.md": _contributing_md,
    "CODE_OF_CONDUCT.md": _code_of_conduct_md,
    "SUPPORT.md": _support_md,
    "NOTICES.md": _notices_md,
    "CONTRIBUTING-POLICY.md": _contributing_policy_md,
    "README.public.md": _readme_public_md,
    "OWNER-ACT-LICENCE.md": _owner_act_licence_md,
}
