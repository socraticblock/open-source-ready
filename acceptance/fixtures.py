"""Detectable fixtures for the acceptance harness, assembled at run time.

Same rule as ``tests/fixtures.py``, and the comment there explains it: a whole
literal would be a deny-list hit in this repository's own object store and would make
the tool unable to export itself. The two modules are deliberately separate because
`tests/` and `acceptance/` are separate programs with their own `sys.path` setup, not
because the values may drift -- if you change one, change the other. Nothing here is
a credential; the key is AWS's own published example.
"""

#: AWS's published example access-key id (4-char prefix + 16 chars).
FAKE_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def credential_line(key: str = FAKE_KEY) -> str:
    """A credential-shaped assignment line, whole at run time, split in the source.

    The acceptance rows need a file the tool must refuse, so the value has to be
    detectable when written -- and undetectable in this file, which the tool also
    scans.
    """
    return "API_" + "KEY" + " = " + '"' + key + '"' + "\n"
