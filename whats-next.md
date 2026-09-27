# What's next: an agent reads as two callers at once

*Spec for 0.4.0 — delegated identity at the wire, and `voyd-mcp` to
deliver it.*

---

## The problem

The caller VOYD judges today is whoever authenticated to MongoDB. That
is the right answer for an application and the wrong one for an agent.

An agent reads *for* somebody. It runs as a service account that can
usually see everything, because it serves every user, and the user it is
acting for this second is a fact the database never hears about. So
every agent deployment picks one of two failures:

    over-share     the agent reads as its service account, and every
                   user's question is answered from every user's data
    re-implement   the agent's code filters per user, which is the
                   forgotten tenant filter again, one call site per tool

The second one fails the way this project was built to prevent: silently,
in the direction of *more*. An agent missing a user filter does not
error. It answers better.

Two identities are in play, and permission needs both:

- **the principal** — the user the agent acts for (`sub`)
- **the actor** — the agent doing the reading (`act`), with the scopes it
  was granted

A document may reach the agent's context only if **the principal may see
it and the actor may read it on the principal's behalf.** Either alone
is a leak: the principal's view without the actor's scope lets a
narrow agent read everything its user can; the actor's view without the
principal's is the over-share.

## Goals

1. A read through `voyd-wire` can carry a delegated identity —
   principal, actor, scopes — **verified by the boundary itself**, never
   taken on the client's word.
2. Every existing rule can be asked about the principal, the actor, or
   both, and the default for a delegated read is the **intersection**.
3. Receipts name both: *served to actor A acting for principal P, under
   policy H*.
4. Recipes can be granted to actors, so an agent may run the pipelines it
   was given and nothing else.
5. `voyd-mcp` exposes recipes as MCP tools, so any agent framework gets
   governed retrieval with no MongoDB code and the identity flows through
   the protocol it already speaks.

## Non-goals

- **Issuing tokens.** VOYD verifies; an identity provider issues. There
  is no login flow, no token store, no refresh.
- **Calling a model.** Unchanged. `voyd-mcp` serves context; the agent
  owns inference.
- **Authorising writes by delegation.** Reads first. A delegated write
  is a different question (whose write is it?) and is listed under
  open questions.
- **Policy languages.** No Rego, no Cedar. The voydfile stays the policy,
  and every new rule stays a pure function.

---

## Design

### 1. Where the identity comes from

Drivers cannot add HTTP headers; the wire has to carry the token in
something every driver already sends. Two sources, one verifier:

**Connection-level: MONGODB-OIDC.** Current drivers (PyMongo, the Node
driver, the Go and Java drivers) support the `MONGODB-OIDC` auth
mechanism with a *callback that returns an access token*. An agent
runtime already holds a delegated token; it hands it to the driver's
callback, and the driver puts it in `saslStart`. The proxy reads the JWT
out of the SASL payload, verifies it, and binds the connection to that
identity. Nothing in the application changes except the auth mechanism
in the connection string.

Upstream, one of two modes, declared per deployment:

    passthrough   the SASL exchange continues to the deployment, which
                  also validates the token (Atlas workload identity).
                  The server-reported identity and the verified one
                  must agree, or the connection is refused.
    terminate     the proxy completes authentication itself and talks
                  upstream with its own credentials. The token is the
                  only identity; the deployment never sees the user.

**Request-level: a signed token per command.** An agent runtime that
multiplexes many users over one pooled connection cannot re-authenticate
per request. It puts a token in the command's `comment` field, which
every driver passes through verbatim:

```python
coll.aggregate(pipeline, comment={"voyd": token})
```

The proxy verifies it, judges this one command under it, and strips it
before forwarding so the token never reaches server logs or the
profiler. A request-level identity **narrows** a connection-level one
and can never widen it: the effective principal must be one the
connection's own identity is allowed to act for.

A command on a collection that declares delegation and carries no
verifiable identity is refused. Absent is not anonymous.

### 2. Verification

A pure function: `verify(token, keys, now, expected) -> Identity | Refusal`.

- JWT, signed with an asymmetric algorithm only (`RS256`, `ES256`,
  `EdDSA`). `none` and every `HS*` are refused at load and at runtime —
  a shared secret in the proxy is a key any client operator could mint
  with.
- Keys come from a configured JWKS: a file, or a URL fetched **at
  startup and on a timer, never on the request path**, so verification
  stays pure and a slow identity provider cannot stall a read. Unknown
  `kid` is a refusal, not a fetch.
- Checked: `iss` against the configured issuers, `aud` against the
  proxy's audience, `exp`/`nbf` with a declared skew, and `act` present
  when the policy requires a delegated read.
- The token's `jti` and hash go into the receipt; the token itself is
  never logged or stored.

Configuration lives in the voydfile, because the issuer is policy:

```python
from voyd import issuer

issuer("https://login.example.com",
       audience="voyd://prod",
       jwks="https://login.example.com/.well-known/jwks.json",
       principal="sub", actor="act.sub", scopes="scope",
       roles="https://example.com/roles")
```

The claim mapping is explicit because identity providers disagree about
where roles live. A mapping that names a claim the token lacks yields an
empty value, and an empty value admits nothing that requires it.

### 3. The identity model

A verified identity is two claim sets and a scope list:

    principal   user, roles, groups, tenant, ...   (from the mapping)
    actor       client id, agent name, roles       (from `act`)
    scopes      ["notes:read", "tickets:read"]     (what was delegated)

This is an extension of what rules already read. `SUPPLIABLE_CLAIMS`
grows from `user`, `db`, `groups`, `roles` to the same names under
`principal.` and `actor.`, plus `scopes`. A non-delegated connection has
a principal (the server-reported user) and no actor, so every existing
policy reads exactly as it does now.

### 4. Rules: the intersection by default

Every rule that reads a caller gains a `via=` that says whose claims it
asks, with one default for all of them:

```python
@guard("notes", delegation="required", scope="notes:read")
class Notes:
    tenant_id = tenant(via="principal.tenant")
    audience  = restricted_to("roles")               # both must overlap
    level     = clearance(order=("public", "internal", "secret"),
                          roles={"analyst": "internal"})   # min of the two
    salary    = mask(visible_to=("hr",))             # both must be hr
```

- **`via` omitted means both.** `restricted_to("roles")` admits a
  document only if the principal's roles *and* the actor's roles each
  overlap its audience. `clearance` takes the lower of the two rungs.
  `mask(visible_to=...)` unmasks only if both are in the audience.
- **`via="principal"` or `via="actor"`** asks one side, explicitly, and
  `voyd-plan` reports it — a rule that ignores the actor is a decision
  somebody should have made on purpose.
- **`scope=`** on the guard: the collection is readable only by an actor
  granted that scope. Missing scope refuses the *read*, not each
  document, with an error naming the scope.
- **`delegation=`** on the guard: `"allowed"` (default: a delegated
  identity is judged as above, a plain one as today), `"required"`
  (every read must carry one), or `"forbidden"` (agents may not read
  this collection at all).

The intersection is the only default that cannot leak. Union would let
the agent's service-account roles lift the user's view; principal-only
would let a narrowly-scoped agent read everything its user can.

**Push-down.** Rules that express as query clauses do so with the
intersected values, so reductions, prefilter and backfill keep working
under delegation. A tenant rule under delegation pins the principal's
tenant into the query itself; the client does not have to.

### 5. Receipts

`_voyd` gains two fields when the read was delegated:

    principal   domain-separated hash of the principal
    actor       domain-separated hash of the actor (client id)
    token       hash of the token's jti

Hashes rather than names, for the reason `caller` is a hash today: a
stamp travels with the chunk into prompts and logs. `voyd-verify
--principal alice@example.com` recomputes the hash and checks it, so an
auditor who knows who to ask about can prove it without the stamp
naming anyone.

The audit sentence this enables — *every chunk agent A put in front of a
model on behalf of user P was served under policy H, and here are the
signatures* — is the one agent deployments cannot produce today.

### 6. Recipes, granted to actors

```python
@recipe("support_context", collection="tickets",
        actors=("support-bot",), scopes=("tickets:read",))
def support_context(q: str, k: int = 8): ...
```

A recipe with `actors=` or `scopes=` runs only for a delegated identity
whose actor or scopes match. Combined with `recipes_only=True`, a
collection's entire agent surface is a reviewed, typed list of
pipelines, each granted to named agents — least privilege stated in the
policy file and diffed by `voyd-plan`.

### 7. `voyd-mcp`

A separate entry point, `voyd-mcp`, speaking the Model Context Protocol
over streamable HTTP (and stdio for local use):

- **Tools are recipes.** Each recipe the connecting actor is granted
  becomes a tool. Its parameters, already typed for injection safety,
  become the tool's JSON Schema; its docstring becomes the description.
  An agent lists tools and sees exactly the retrieval it is allowed.
- **Identity is MCP authorisation.** The MCP client's bearer token is
  the delegated identity, verified by the same `verify`. `voyd-mcp`
  then calls through `voyd-wire` like any other client, so every
  guarantee — refusal, masks, sanitising, stages, receipts — applies
  unchanged. It adds no enforcement of its own and needs none.
- **Results are documents with their stamps.** The tool result carries
  the served documents and their `_voyd` receipts, so the agent can
  cite them and an auditor can verify them later.
- **No model, no prompt.** It returns context. What the agent does with
  it is the agent's business.

`voyd-mcp` is a thin adapter on purpose: if it enforced anything itself,
there would be two boundaries to keep in agreement.

---

## Threat model

| Threat | Answer |
| --- | --- |
| Client forges a principal | The token is verified against configured keys; an unsigned or HS-signed token is refused. |
| Agent presents a user token without delegation | `delegation="required"` and `act` checks refuse it: a user token is not an agent acting for a user. |
| Agent widens via its own service roles | Intersection: the actor's roles can only narrow the principal's view. |
| Request token widens the connection's identity | Refused: a request-level principal must be one the connection may act for. |
| Replay of a captured token | Bounded by `exp`; `jti` is recorded in receipts. A replay cache is an open question (it is state). |
| Token leaks into server logs | Stripped from `comment` before forwarding; never logged by the proxy. |
| Identity provider is slow or down | JWKS refreshed off the request path; last good keys used until a declared maximum age, then reads refuse. |
| Key rotation at the IdP | JWKS holds several keys by `kid`; unknown `kid` refuses rather than fetches. |
| Direct connection to the deployment | Outside every guarantee here, as today. `terminate` mode lets the deployment hold no user identities at all. |

## Testing plan

- **Pure:** token verification (every algorithm, `none`, HS confusion,
  expired, not-yet-valid, wrong issuer/audience, unknown `kid`, missing
  `act`); claim mapping; intersection semantics for every caller rule,
  including clearance's minimum and mask's audience; request-level
  narrowing and refused widening; scope refusal; recipe grants.
- **Wire:** a `pymongo` client using `MONGODB-OIDC` with a callback that
  returns a test-issued token, through a real `voyd-wire`, in both
  `passthrough` and `terminate`; a pooled client switching principals
  per request via `comment`; the token absent from the profiler.
- **Receipts:** stamps carry principal and actor hashes; `voyd-verify
  --principal` checks them.
- **Plan:** new structural findings — `delegation_loosened`,
  `scope_removed`, `via_narrowed_to_one_side`, `recipe_grant_widened` —
  each marked fail-open or not.
- **MCP:** `voyd-mcp` lists exactly the granted recipes, rejects a call
  without a valid bearer, and returns stamped documents that verify.

## Open questions

1. **Delegated writes.** Does a write under delegation carry the
   principal into lineage, so a revocation can follow "everything agent
   A wrote for user P"? That is the memory-poisoning story and probably
   0.5.0.
2. **Replay protection.** A `jti` cache is state the proxy does not
   keep today. Short `exp` may be enough; a shared cache would not be
   pure.
3. **Multi-hop delegation.** Agent → sub-agent → tool. RFC 8693 nests
   `act` claims; the intersection extends naturally (every hop narrows),
   but the claim mapping and receipt format need to say how deep.
4. **Passthrough on self-managed MongoDB.** OIDC on self-managed
   deployments depends on server edition; `terminate` may be the only
   mode there.

## Milestones

1. **0.4.0-a** — `issuer()`, pure `verify`, request-level tokens via
   `comment`, principal/actor claims, intersection for every caller
   rule, `scope=` and `delegation=`, plan findings.
2. **0.4.0-b** — connection-level `MONGODB-OIDC` in both modes,
   receipts with principal and actor, recipe grants.
3. **0.4.0** — `voyd-mcp`, an end-to-end example (an agent with a
   delegated token calling a granted recipe over MCP and verifying the
   stamps on what it got back), and the blog post that goes with it.
