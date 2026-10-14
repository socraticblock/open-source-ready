# Making "only the owner publishes" true, rather than merely stated

## The problem this solves

Open-Ready's promise is that an agent prepares a release and the owner authorises it. The
tool's half of that is real: there is no `publish` command, no code path that changes a
repository's visibility, and an approval that the builder cannot write.

But the tool runs as *you* on *your* machine. If the credential the agent uses can also
publish — change a repository's visibility, push a release, publish a package — then nothing
physical stops it. The tool reports this rather than hiding it:

```
UNRUN trust.publisher-separation: no publisher principal separate from the builder exists (ADR-002) [NOT_ENFORCED]
```

`NOT_ENFORCED` is the honest label. It means: *this is a rule the agent follows, not a wall
it cannot pass.*

Analogy: the workshop has no door to the street, which is good — but the key to the street
door is hanging on a hook inside the workshop. This document is how to keep the key on your
own person.

## What to do (once, minutes)

Give the agent a credential that can do its work and **cannot publish**; keep the publishing
power in your own hands.

For a GitHub-hosted project that means two credentials:

**The agent's** — a fine-grained token, scoped to that one repository:

| Permission | Setting |
|---|---|
| Metadata | Read |
| Contents | Read and write |
| Pull requests | Read and write |
| **Administration** | **No access** |
| **Workflows** | No access unless the work needs it |

Administration is the one that matters: changing visibility, deleting the repository and
rewriting its settings all need it. Without it, `gh repo edit --visibility public` fails for
the agent.

**Yours** — your own account, logging in as yourself (a browser session is fine), or a
separate admin credential you never give to an agent. Use it for the visibility decision, the
merge to `main`, and repository settings.

Then verify, with the *agent's* credential, that the wall is where you put it:

```bash
# this must FAIL (a permissions error, not a successful change)
gh repo edit <owner>/<repo> --visibility public

# ...and the repository must still be private
gh api repos/<owner>/<repo> --jq .visibility      # -> "private"

# the agent must still be able to do its actual work
git push origin HEAD:refs/heads/work/scratch-check
```

If the first command succeeds, the split is not in place.

## What this does and does not change

**It changes:** whether an agent *can* publish without you. After the split, the answer is
no, and that is a property of the host rather than of the agent's good behaviour. This is the
single highest-value thing an operator can do for the tool's central claim, and it matters
most in exactly the case the tool exists for: an agent that has been bent by something it
read.

**It does not change:** what the tool reports. `trust.publisher-separation` stays
`NOT_ENFORCED` after you do this, because the tool cannot see your credential scopes — asking
the hosting provider would be a network call, and this tool makes none by design. Its
capability table says so in as many words: *"no separate publisher principal exists in this
implementation"*. Making the tool's answer change requires a publisher principal to exist as
a component (OR-022), which is a design job, not a configuration one.

So read the two separately:

- **`NOT_ENFORCED` in the tool** = *the tool* cannot verify this. It stays, and it is honest.
- **the credential split** = *you* have made it true anyway, and proven it to yourself with
  the commands above.

A release packet is still always `REVIEW_REQUIRED` and still carries `rights: NOT_RUN`, for
the same reason: those are not facts a scan can establish.

## The same question for other destinations

The principle is provider-independent: find the permission that performs the publish, and
keep it off the agent's credential. A package registry: publishing rights for you, read-only
or a scoped publish token for the agent. A hosting provider: deploy rights for you, a
preview-only key for the agent. Whatever the mechanism, the test is the same three commands:
the publishing act must fail for the agent, the current state must be unchanged afterwards,
and the agent must still be able to do its actual job.

This tool ships adapters for GitHub first (`providers.py`, read-only) and documents the rest
rather than pretending to cover them.
