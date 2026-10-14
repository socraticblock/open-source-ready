"""Open-Ready -- private-first project care and release-candidate preparation.

Specification: "Open-Ready definitive agent handoff v1.0". This package implements
the P0 foundation: versioned contracts, honest capability detection, private
project initialisation, and a ``doctor`` that reports what it did not check.

Governing rule, stated once here and enforced in code: a run that contains a
required unrun, unenforced or untested check is **never** reported as green.
"""

__version__ = "0.1.0-p0"
POLICY_VERSION = "1.0"

# The wording every surface must use. There is no safe-to-publish state.
PUBLICATION_STATUS = "NOT APPROVED -- requires separate owner review of the exact candidate"
