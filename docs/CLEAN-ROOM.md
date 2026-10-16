# Isolated verification

`openready verify` validates and scans a captured candidate without running its
code. `--run-build` explicitly opts into execution. The test runner scrubs the
environment and uses a temporary working directory; it does **not** restrict
filesystem access, process privileges or network traffic.

For unfamiliar candidate code, use a disposable Linux virtual machine with no
shared folders, clipboard, host credentials, cloud identity, or network adapter.
Install the pinned verification tools before disconnecting the network. Copy
only the candidate and the separately recorded expected digest into the VM.

1. Check the candidate without executing it:
   `openready verify --candidate candidate --expected-digest <reviewed-digest>`.
2. Confirm that the VM cannot read a host-only canary or reach the network.
   Record the VM configuration and the actual denial results.
3. Only then opt into candidate execution with `--run-build`. Run as an
   unprivileged account and impose VM memory, disk, CPU and time limits.
4. Export only the results through an owner-reviewed channel, then discard the VM.

This is an operator procedure, not an implemented sandbox. CI's acceptance row
A23 remains NOT_TESTED until a separate environment demonstrates those denials.
A scrubbed environment, an installed isolation binary, or a passing unit suite
is not evidence of containment. Do not run unfamiliar code on a credentialed
workstation solely because its manifest is internally consistent.
