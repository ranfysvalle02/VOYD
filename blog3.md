# The agent is two callers, and the database only ever met one

*Delegated identity at the wire, and why the default has to be the
intersection.*

---

Every retrieval bug in the first two essays had the same shape: a filter
somebody forgot, failing in the direction of *more*. Agents bring a new
way to forget it, and it is the most natural thing in the world.

An agent reads for somebody. It runs as a service account, because it
serves every user, and a service account that serves every user can
see every user's data. The user it is acting for right now — the one
whose question this is — is a fact that lives in the agent's memory,
in a variable, in a prompt. The database never hears about it.

So every agent deployment makes one of two choices, and both are the
bug:

    over-share     the agent reads as its service account; every
                   user's question is answered from every user's data
    re-implement   each tool filters by the current user in agent code;
                   the forgotten tenant filter, once per tool

The second one looks responsible. It is the first essay again: the tool
that forgot the filter does not raise. It answers better.

## Two callers, one read

The fix starts by admitting there are two identities in every agent
read, and permission needs both of them:

- **the principal** — the user the agent acts for
- **the actor** — the agent doing the reading, with the scopes it was
  granted

A document may reach the agent's context only if **the principal may see
it, and the actor may read it on the principal's behalf.** Either alone
leaks. The principal's view alone lets a narrow billing bot read
everything its user can. The actor's view alone is the over-share.

So in VOYD every rule that reads a caller asks both sides, and a
document passes only if both answers are yes:

```python
@guard("notes", delegation="required", scope="notes:read")
class Notes:
    tenant_id = tenant()                          # the principal's tenant
    audience  = restricted_to("roles")            # both sides must overlap
    level     = clearance(order=("public", "internal", "secret"),
                          roles={"analyst": "internal"})   # the lower rung
    salary    = mask(visible_to=("hr",))          # both must be hr
```

The intersection is not a preference. It is the only default that cannot
widen: union lets the agent's service roles lift the user's view, and
either side alone drops half the question. A rule that asks one side on
purpose says so — `via="principal"` — and `voyd-plan` reports it as a
change that fails open, because it is one.

## The token is checked, not believed

The identity arrives as a token, and the boundary is in the worst
possible position to take anybody's word for it, because the client is
the only thing talking to it. So:

- **Asymmetric signatures only.** `none` and every `HS*` are refused at
  load. A shared secret in the proxy would be a key any operator of any
  client could mint with.
- **Keys are fetched off the request path.** The verifier is a pure
  function of the token, the keys and the clock — covered by the same
  purity check as every rule — so a slow identity provider cannot stall
  a read, and an unknown key id is a refusal, never a fetch.
- **Key confusion is refused.** A key whose type or curve does not match
  the header's algorithm does not verify anything.

It reaches the wire in something every driver already sends:

```python
notes.aggregate(pipeline, comment={"voyd": token})
```

— verified, then stripped before the command is forwarded, so it never
lands in a server log or the profiler (there is a test that reads
`system.profile` to check). Or once per connection, through the
`MONGODB-OIDC` mechanism current drivers already support with a token
callback. Either way, a cursor keeps the identity that opened it: a
`getMore` under anybody else is refused.

And only the service users a policy names may present tokens at all.
A delegated identity narrows a connection. Nothing lets it widen one.

## Receipts that say for whom

The stamps from the last essay proved *what* was served. On a delegated
read they now say **for whom**:

    caller      the connection that read
    principal   the user it read for
    actor       the agent that read
    token       which grant it was

— each a hash, because a stamp travels with the chunk into prompts and
logs, and each checkable: `voyd-verify --principal alice@example.com`
recomputes it. The audit question agent deployments cannot answer today
— *every chunk this agent put in front of a model for this user, and
the policy that let it through* — becomes a verification, not a
reconstruction from application logs.

## A memory cannot outlive its sources by assertion

That receipt is now also the authority for agent memory. A collection that
stores summaries names the source collections it may derive from and keeps a
lineage field for revocation to follow:

```python
@guard("memories", lineage_field="lineage",
    derived_from=("notes", "tickets"))
class Memories:
    expire_at = deadline()
    tenant_id = tenant()
    forgotten = revocable()
```

The agent writes the receipts it was served, not a list of source ids it
invented:

```python
memories.insert_one({
    "text": summary,
    "_voyd_from": [chunk["_voyd"] for chunk in context],
})
```

The boundary verifies each receipt using the source collection's active
attestation key, verifies that it was served to this writer, and re-reads the
source before judging it again. It then replaces client-controlled lineage,
tenant, deadline and writer metadata with its own values. A revoked or
expired source cannot be turned into a fresh memory; a source from another
tenant cannot cross the boundary; and a later revocation reaches every
derived memory through the lineage the boundary wrote. A memory also cannot
outlive its sources: the boundary caps its deadline at the earliest source
deadline, while retaining a deliberately shorter deadline on an insert or
replacement. A modifier update may not write the deadline directly.

There is one deliberately conservative consequence. Every replacement or
modifier update to a derived memory needs a fresh citation in
`$set._voyd_from`. The boundary cannot infer whether a field is a harmless
label or the agent's rewritten summary, so it does not guess. Pipeline
updates, `findOneAndUpdate`, `findOneAndReplace`, and `$rename` are refused
on these collections until they have a citation-safe representation.

This proves provenance, not semantic derivation. An agent can cite only a
subset of the facts it read; the boundary can prove those cited facts were
admitted and are still admissible, but it cannot inspect a model's reasoning.

## Tools are recipes

Recipes were already the reviewed home for a pipeline. With identity
they gain a grant:

```python
@recipe("billing_export", collection="invoices",
        actors=("finance-bot",), scopes=("invoices:read",))
def billing_export(month: str): ...
```

That line is least privilege for an agent, written in the policy file
and diffed by `voyd-plan` like every other rule.

`voyd-mcp` is where it pays off. It turns every recipe into an MCP
tool — the recipe's typed parameters become the tool's JSON Schema, its
docstring the description — and an agent connecting with a bearer token
lists exactly the tools that token is granted. It calls them through
`voyd-wire`, so every guarantee applies unchanged, and it hands the
agent the documents *with their stamps*.

It is deliberately thin. `voyd-mcp` enforces nothing itself: the list it
shows is a convenience, and the wire's refusal is the guarantee. Two
boundaries that have to agree are one boundary with a bug waiting in
the gap.

## What it does not do

- It **verifies** tokens; it does not issue them. There is no login
  flow here.
- It has **no replay cache.** A captured token works until it expires,
  on any connection its issuer admits. Short expiries are the answer
  for now; a cache would be state the proxy does not keep.
- It **calls no model.** Still. The boundary decides what context an
  agent receives, for whom, and proves it. What the agent does with it
  is the agent's business.

Ranking is not permission. Neither, it turns out, is being the service
account that happened to run the query.
