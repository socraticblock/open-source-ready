# ADR 013: immutable artifact boundaries and opt-in execution

Status: accepted for implementation; owner review required before merge.

## Problem

Scanning a source path and later copying it can export different bytes from those
inspected. Reading manifest paths without confinement can cross an artifact's
boundary. Silently skipping backup files can report success for incomplete data.
Updating an existing candidate in place can mix releases or destroy evidence.

## Decision

Capture bounded, regular, single-link files through descriptor-relative opens
that refuse symlinks in every component. Scan and assemble only those captured
bytes. Preflight, policy decisions, assembly, and metadata finalization have
separate interfaces. Promote a completed staging directory with a single rename.

Candidate output must be absent or empty. Re-exporting into an existing candidate
is now refused, including when it contains unrelated files. The old tests allowing
re-export and warning about stray files encoded the superseded behavior; their
replacements require preservation of the existing artifact and a refusal.

Verification validates metadata and paths, captures its input, and operates on
that captured tree. Integrity failures stop subsequent processing. History-bearing
research artifacts are refused before scans or builds. Tests previously expecting
continued history inspection now require this early refusal. A regenerated-forgery
test must update byte totals as well as hashes: malformed metadata is not a valid
example of a self-consistent forgery.

Candidate code execution is off by default. `verify --run-build` explicitly opts
into the existing scrubbed runner. `--no-build` remains accepted for compatibility.
`test` is already an explicit execution command. Neither command is a sandbox.

Backups fail on unreadable, oversized, nonregular or linked required files, and on
namespace collisions. Documented directory exclusions are recorded in the backup
manifest. Restore accepts bounded regular-file/directory archives and never calls
`extractall`: it checks streams, types, canonical names, duplicates, hashes and
sizes, then writes only validated bytes into staging. Decompression is bounded
including headers and padding. Archive replacement after validation cannot change
restored bytes. Restored content uses private permissions, not archive ownership.

## Bounds and compatibility

The initial limits are 64 MiB per content file, 512 MiB total content, 10,000 content
files, and 8 MiB per metadata document. Decompressed tar data also has an aggregate
bound, including metadata. Oversized data is refused, never silently skipped.
Snapshots are bounded in-memory captures; they are not a filesystem-wide atomic
snapshot. A concurrent multi-file edit can yield a mixed revision, but every byte
exported is a byte scanned. Source-revision metadata is informational.

The descriptor primitives target Linux/POSIX. CI covers CPython 3.12 and 3.13 on
Linux; other platforms are not an asserted support target. Atomic visibility is
not a general power-loss durability guarantee. This does not protect against a
hostile process running as the same OS identity and able to tamper with private
staging directories, or against a compromised kernel.

The content digest deliberately retains its existing byte identity. It does not
bind permissions or authenticate metadata; use the separately recorded expected
digest and owner review. Pattern scans cannot establish absence of arbitrary
private prose, prove rights, or authorize publication.

## Verification

The boundary regression suite exercises mutations between scan and copy, symlink
and traversal inputs, duplicate and malformed metadata, failed writes, destination
replacement, archive replacement, unreadable backup inputs and resource limits.
A six-control mutation gate verifies that removing selected protections causes
assertion failures. It is not a comprehensive mutation score or an independent
audit. Branch coverage floors and strict typing apply to all four boundary modules.

The acceptance harness now runs from source without depending on global CLI
installation or Git identity. It no longer reads real credential files or probes
account privileges. Its isolation and publisher-separation rows remain explicitly
unverified or unenforced. Comment text is excluded from its workflow token scan;
executable workflow references are still checked.
