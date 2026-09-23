# Quickstart

Four steps, smallest first. **The first one costs nothing** — no
install, no database, no credential — and it is the one that tells you
whether the rest is worth your time.

Every command below is either run by CI on every commit or was run
against a real cluster while this was written. Where something is
unverified, it says so.

---

## Step 0 — is this even your problem?

VOYD is for you if **more than one thing reads your data**: a service, a
notebook, an analytics job, an agent, a migration script. And if some of
your documents are ones you would rather not serve — expired, revoked,
belonging to another tenant, above somebody's clearance.

It is **not** for you if you have one service, one language, one read
path, and one person maintaining it. The filter in your query is the
same guarantee and one fewer process. That is a real answer and the
[README](README.md#when-you-do-not-need-this) gives it properly.

---

## Step 1 — find the holes in your own code (costs nothing)

One file, standard library only, no install and no import of this
package. Point it at your repository:

```bash
curl -sO https://raw.githubusercontent.com/ranfysvalle02/VOYD/main/scanner/voyd_scan
python3 voyd_scan path/to/your/app
```

Or from a clone: `python3 scanner/voyd_scan app/ services/`

```
notes: `expire_at` (declared by a write or index); `forgotten` (declared by a write or index)

25 of 25 read(s) against them do not:
  refuse.py:79   notes  (filter does not name `expire_at`, `forgotten`)
  embed.py:163   notes  (filter does not name `expire_at`, `forgotten`)
```

**It is not configured with your field names.** It works them out: a TTL
index names its own deadline, and beyond that, the field most reads
filter on is your convention — so a read that omits it is a deviation
from a spec you wrote without noticing. It gets *stronger* on bigger
codebases, because the majority establishing the convention is bigger.

Useful flags: `--json` for a machine, `--all` to list everything,
`--strict` to fail on unjudged reads, `--read-verb fetch_all` if your
data layer wraps the driver.

**If this prints nothing, stop here.** You do not have the problem.

---

## Step 2 — count what is exposed right now (costs a read-only URI)

Still no proxy, no install in anybody's path, nothing deployed. Write
the policy you *would* enforce, then ask what it would have refused.

```bash
pip install git+https://github.com/ranfysvalle02/VOYD
```

There is no package-index install and that is deliberate for now, so
`pip install voyd` will 404 no matter how reasonable it looks.

```python
# voydfile.py
from voyd import deadline, guard, revocable, tenant

@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
```

```bash
voyd-plan --audit --proposed voydfile.py \
          --target "$READONLY_URI" --database app --all
```

```
reachable today, and refused by this policy

  records  1000 of 4100 read are reachable now and would be refused
         812  are past an expire_at the TTL monitor has not reached
         188  carry an erasure mark and are still being served
```

That number is not a projection. It is the same function the boundary
would run, on your documents.

`--all` reads every document; drop it and you get `--sample 500`, which
says it is a sample where the number is.

---

## Step 3 — see it refuse, on your laptop (about a minute)

```bash
git clone https://github.com/ranfysvalle02/VOYD && cd VOYD
docker compose up -d --wait mongo
uv sync --all-extras
uv run python examples/refuse.py
```

This writes a policy, starts a real boundary, and then talks to it with
an ordinary `pymongo.MongoClient` that imports nothing from this
package. It shows a `delete_one` becoming a revocation: the driver gets
`deleted_count=1`, the row stops being reachable on the next read, and
it is **deliberately still on disk at the end** — that is the proof, not
a failure to clean up.

Other examples worth ten minutes, all run by CI on every commit:

| | |
|---|---|
| `examples/tenancy.py` | one tenant's read cannot see another's |
| `examples/clearance.py` | a caller below a document's classification |
| `examples/embed.py` | a query vector from the wrong model, refused |
| `examples/shred.py` | destroy a key; every copy becomes unreadable |
| `examples/drift.py` | measures how long a vector index disagrees with the collection — no VOYD in it at all |

---

## Step 4 — put it on the wire

```bash
voyd-wire --config voydfile.py --target localhost:27017
```

Then change one connection string in your application. Nothing is
imported, no handle replaces a collection, no read path is rewritten.

### The three things that will catch you

**1. Your driver will go around it unless you tell it not to.**

```
mongodb://localhost:27500/?directConnection=true
```

Without `directConnection=true`, the driver asks the cluster for its own
host list and connects straight to the real nodes — past the boundary,
silently, with everything working. The alternative is
`voyd-wire --advertise-self`. One of the two is required and there is no
third option.

**2. Without `--tls-cert` it binds loopback only.**

Deliberate, not a default. A plaintext boundary reachable from a network
would carry in the clear every document it had just refused to serve.

**3. Your credentials stay yours.** The boundary forwards the handshake
and asks the *deployment* who authenticated. It does not authenticate on
your behalf and will not believe a claim the client asserts — a rule
whose only input is the caller's own assertion is not an authorisation
system. So connect with exactly the credentials you would have used
against the cluster.

### Before it serves anything

```bash
voyd-wire --config voydfile.py --target "$URI" --ensure app --verify
```

`--ensure` builds what the policy declares — collections, a TTL index
behind each deadline, an index leading with each tenant. `--verify` has
a separately written checker refuse to agree it is there. Either alone
is a boot step; the pair is evidence. Both finish before the listener
binds, so a boundary that would enforce a policy the cluster cannot
satisfy says so on one screen instead of one query at a time.

---

## Then: keep it from drifting

Add the check to your pull requests. No cluster and no secret — the
structural findings are facts about the policy file:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: ranfysvalle02/VOYD@main
```

It reads the policy at the PR's base, compares it to the branch, posts
the plan as a comment it updates in place, and **fails the job if the
boundary opened**. A change that widens access is the one a reviewer
cannot see: a deleted line in a diff does not say *"412 documents just
became reachable by tier-1 support."*

---

## Writing your own rules

Read [`ethos.md`](ethos.md) first. It is short, and it is the difference
between a policy file that stays magic and one that becomes a second
application in a worse language.

The one-line version: **a rule answers whether there is a reason this
document may not reach a prompt.** Not what to do about it, not what
happens next. If your rule needs a database, an API call, or an
`if`/`elif` chain on business state, it belongs in your application.

A rule is three members — `reason`, `refuses(doc)`, `clause()` — and a
rule you write is a first-class one with no privileged path for the
builtins:

```python
@guard("notes")
class Notes:
    expire_at = deadline()
    region    = Jurisdiction(allowed="eu")     # your dataclass, not ours
```

A policy file that is wrong fails when it is **loaded**, not when
somebody's query returns the wrong rows.

---

## Troubleshooting

| what you see | what it is |
|---|---|
| reads return everything, boundary looks idle | the driver went around it — see `directConnection=true` above |
| `voyd-wire` refuses to start, naming a collection | `--verify` found the cluster cannot satisfy the policy. That is the feature |
| every read of one collection is refused | a `clearance()` with no `roles={...}` mapping — the wire cannot supply that claim, and it says so at boot |
| a change stream errors | refused on purpose over a guarded collection; open it on a direct connection. [Why](docs/why-not-native.md#change-streams) |
| a client's `queryVector` is refused | the collection declares `auto_embed`; send `$vectorSearch.query` with the text instead |
| `voyd-plan` exits 2 | the plan could not be computed — a policy file did not load. Never confuse this with "found nothing" |

---

## Where to go next

| | |
|---|---|
| [`ethos.md`](ethos.md) | what belongs in a policy file, and what never does |
| [`docs/why-not-native.md`](docs/why-not-native.md) | why not just use views, `$where`, change streams, TTL |
| [`blog.md`](blog.md) | the story, if you want to know whether the author is thinking clearly |
| [`README.md`](README.md) | the full reference |

---

**One thing to know before you rely on this.** Nobody has run it but its
author. It is young, every number in this repository comes from its own
tests on one machine, and a wire proxy is an unforgiving place to be
new. Steps 1 and 2 are designed for exactly that: they cost you nothing
and risk nothing, and they tell you whether the problem is real on your
data before you trust anything with your traffic.
