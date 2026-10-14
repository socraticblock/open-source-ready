"""Detectable fixtures, assembled at run time instead of written whole.

**Why these are not plain string literals.** This repository is scanned by the very
deny-list it ships, and the tool refuses to export a tree containing a credential
shape or an absolute home path. A fixture written as a whole literal therefore makes
the tool unable to export *itself* -- the file is a deny-list hit in this
repository's own object store, acknowledged or not, and no acknowledgement can make
it exportable again. Assembling each value from fragments keeps the runtime bytes
identical (adjacent literals concatenate at compile time) while the source text
stops containing the shape. ``tests/test_self_clean.py`` fails if a whole literal
creeps back into any tracked file.

**None of these is a credential.** ``AWS_EXAMPLE_KEY`` is AWS's own published
example key -- invalid, and published in their documentation as the canonical
example. The paths are synthetic. The PEM values are headers with no key body.
"""

import pathlib

REPO = pathlib.Path(__file__).resolve().parents[1]

#: AWS's published example access-key id (20 chars: the 4-char prefix + 16).
AWS_EXAMPLE_KEY = "AKIA" + "IOSFODNN7EXAMPLE"

#: A PEM header, whole and split two ways: across the newline between tokens, and
#: inside a token (the evasion a whitespace-stripping scan has to close).
_HEAD = "-" * 5 + "BEGIN RSA PRIVATE KEY" + "-" * 5
PEM_HEADER = _HEAD
PEM_HEADER_SPLIT_BETWEEN_TOKENS = _HEAD[:13] + "\n" + _HEAD[13:]
PEM_HEADER_SPLIT_INSIDE_TOKEN = _HEAD[:9] + "\n" + _HEAD[9:]

#: Synthetic home paths: one with a trailing component (the probe's own defect D01
#: was a path with none, which the pattern must still catch).
HOST_PATH = "/home/" + "example/private/notes.md"
HOST_PATH_BARE = "/home/" + "example"

#: Credential-shaped assignments. The key *name* is assembled too: written whole,
#: `api_key = "..."` is a deny-list hit in the source even with the value split.
QUOTED_ASSIGNMENT = "api_" + "key" + " = " + '"' + "a" * 20 + '"'
UNQUOTED_ASSIGNMENT = "pass" + "word: correct-horse-battery-staple"


def host_path_line(prefix: str = "PRIVATE_HOME=", bare: bool = True) -> str:
    """A line of the shape the scanner must refuse, with a synthetic path."""
    return prefix + (HOST_PATH_BARE if bare else HOST_PATH) + "\n"


def aws_key_split_with_indentation(indent: str = " " * 8) -> str:
    """A key split across a newline *with* indentation on the next line.

    The evasion that made the scanner's copy choice matter: stripping all whitespace
    closed it and manufactured false positives; stripping only the indentation closes it
    and leaves ordinary code alone.
    """
    return AWS_EXAMPLE_KEY[:12] + "\n" + indent + AWS_EXAMPLE_KEY[12:]


def pem_header_split_with_indentation(indent: str = " " * 6) -> str:
    return _HEAD[:9] + "\n" + indent + _HEAD[9:]


#: Absolute path to the tool's source, for child processes that run from another
#: directory. `PYTHONPATH=src` is relative to the *caller's* cwd, so it stops working the
#: moment a child process changes directory -- which the commit-time hook in a created
#: project does. The suite must not depend on how it was invoked.
SRC_PATH = str(REPO / "src")

#: A git identity for the child processes these tests start.
#:
#: Found by the scrubbed run: `verify` runs a candidate's tests with only PATH, a
#: throwaway HOME, LANG and TMPDIR, and five of them failed there and passed here,
#: because they relied on the developer's `~/.gitconfig` for an author identity. A suite
#: a stranger cannot run is not evidence about the tool, and the tool's own answer when
#: no identity is configured is a reported `NOT_RUN` (`create.initial-commit`), never a
#: silent success -- so the identity is set here, explicitly, instead of being inherited.
GIT_IDENTITY = {
    "GIT_AUTHOR_NAME": "openready test",
    "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "openready test",
    "GIT_COMMITTER_EMAIL": "test@example.invalid",
}


def git_env(base=None) -> dict:
    """An environment for a child process that may need to commit."""
    env = dict(base if base is not None else {})
    env.update(GIT_IDENTITY)
    return env


def assignment_n(n: int) -> str:
    """A credential-shaped assignment whose value differs per call.

    The history tests need *different* content per commit -- identical content is one
    blob -- so the varying part is appended to the assembled value.
    """
    return "api_" + "key" + " = " + '"' + "a" * 20 + str(n) + '"'


#: An unquoted, secret-named assignment: the D02 evasion, assembled like the rest.
#: The separator is its own fragment: `"secret" + ": value"` leaves a quote and a `+`
#: between the name and the colon, in the raw text *and* in the whitespace-stripped
#: copy the scanner also reads -- `"secret: value"` written whole would match there.
CLIENT_SECRET_ASSIGNMENT = "client_" + "secret" + ": hunter2hunter2"
