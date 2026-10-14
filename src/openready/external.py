"""External-action profiles for high-risk integrations (OR-021, A30).

The job-submission profile is the test case the work order names. Its failure
mode is a tool that *claims* it has the operator's consent to submit a job
application on their behalf. The tool cannot consent on a platform's behalf
either -- "external authority" is one of the three things the roadmap says
cannot be automated away. So the profile is what an honest answer looks like:

* **API permission** is required, scoped and owner-approved. The mechanism
  lives in ``policy``; this profile states what it asks for.
* **PII flow** is named: what categories of personal data cross the wire, in
  what direction, and what never crosses.
* **Submission is human-only.** A tool that submits a job application
  automatically is the failure this exists to prevent.
* **Platform authority is not claimable by this tool.** It is not a thing a
  tool can verify, and pretending otherwise is the wrong shape of claim.

The other two values a profile could plausibly add (``api_permission``,
``pii_flow``) are policy details, not a verdict. They are recorded as
information; the decision is the operator's.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__
from .capabilities import environment_label
from . import policy as policy_mod
from .status import FAIL, INFO, NOT_ENFORCED, NOT_RUN, PASS, REVIEW, STOP, Result

PROFILES: Dict[str, Dict[str, Any]] = {
    "job-submission": {
        "applies_to": "external platforms that take job applications",
        "api_permission": "an owner-scoped policy approval for the exact "
                          "(destination, data-class) pair, with an expiry",
        "pii_flow": "the categories of personal data the operator's own tool "
                    "ships, and the categories that never leave the operator's "
                    "machine; both lists are part of the operator's own policy",
        "human_only": True,
        "platform_authority": "NOT CLAIMABLE BY THIS TOOL",
        "what_would_verify": "an owner-scoped policy approval recorded via "
                             "`openready policy grant --actor owner`, AND a "
                             "human operator present for the actual submission",
    },
}

LIMITATION = (
    "A tool cannot consent on a platform's behalf. A profile that claimed to "
    "have done so would be the failure this module exists to prevent."
)


def profile(name: str) -> Optional[Dict[str, Any]]:
    return PROFILES.get(name)


def results(name: str, destination: Optional[str] = None,
            env: Optional[Dict[str, str]] = None) -> List[Result]:
    out: List[Result] = []
    record = profile(name)
    if record is None:
        out.append(Result(
            "external.profile-unknown", FAIL, STOP,
            f"no external-action profile named {name!r}; known profiles: "
            f"{sorted(PROFILES)}", __version__, environment_label(),
            limitations=[LIMITATION],
        ))
        return out

    out.append(Result(
        "external.profile", PASS, INFO,
        f"profile {name!r}: {record['applies_to']}",
        __version__, environment_label(), limitations=[LIMITATION],
    ))
    if record.get("human_only"):
        out.append(Result(
            "external.human-only", PASS, INFO,
            f"submission is human-only: a tool that submits on the operator's "
            f"behalf is the failure this profile exists to prevent",
            __version__, environment_label(), required=True, limitations=[LIMITATION],
        ))

    out.append(Result(
        "external.platform-authority", NOT_RUN, REVIEW,
        f"platform authorization: {record['platform_authority']}; this is an "
        f"external matter between the operator and the platform, not a tool "
        f"verdict", __version__, environment_label(), required=True,
        enforcement=NOT_ENFORCED, limitations=[LIMITATION],
    ))

    if destination:
        out.append(Result(
            "external.api-permission", INFO, INFO,
            f"API permission for {destination}: {record['api_permission']}; "
            f"the policy module is the place to record the approval, not this "
            f"profile", __version__, environment_label(), limitations=[LIMITATION],
        ))
        out.extend(policy_mod.check(destination, "applicant-pii", env=env))
    return out


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    import json as _json
    import sys

    from .status import EXIT_OK, EXIT_USAGE, exit_code_for

    parser = argparse.ArgumentParser(prog="openready-external",
                                     description="External-action profiles for high-risk "
                                                 "integrations. Read-only.")
    parser.add_argument("--profile", required=True)
    parser.add_argument("--destination", default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    results_list = results(args.profile, destination=args.destination)
    if args.json:
        print(_json.dumps({"profile": profile(args.profile),
                            "results": [r.to_dict() for r in results_list]},
                           indent=2, default=str))
        return exit_code_for(results_list)
    record = profile(args.profile)
    if record is None:
        for result in results_list:
            print(f"  {result.message}")
        return exit_code_for(results_list)
    print(f"  {args.profile}: {record['applies_to']}")
    print(f"      human-only: {record['human_only']}")
    print(f"      platform authority: {record['platform_authority']}")
    print(f"      pii flow: {record['pii_flow']}")
    for result in results_list:
        print(f"  - {result.message}")
    return exit_code_for(results_list)


if __name__ == "__main__":
    import sys
    raise SystemExit(main())
