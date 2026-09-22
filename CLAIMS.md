# Claims

Every guarantee this project makes, and the file that would go red if it
stopped being true.

This page exists because of the thesis underneath the whole project: **a
statement of intent is not a guarantee.** A README is a statement of intent.
So each claim below names its evidence, and
`tests/test_every_claim_names_its_evidence.py` checks the mapping both ways --
a claim with no test, or a test file no claim points at, fails the suite.

That check is the smallest possible version of the argument. It does not know
whether a test is any good; it knows whether a claim is *attached to
something*. The difference between "we believe this" and "this is held up by
a named file that runs in CI" is the entire distance this project is about.

**What it cannot do**, said here rather than discovered: a test can be
attached and still be weak. One on this page was —
`test_one_erased_tenant_does_not_fail_the_page` had a docstring about a page
of fifty and asserted a page of one, and it passed under sabotage. See
`LIMITS.md` §1. Attachment is a floor, not a ceiling.

---

## The boundary

| claim | held up by |
|---|---|
| A forgotten fact cannot reach a prompt — expired, revoked, unreadable-deadline, off-tenant — decided **with no database anywhere near it** | `tests/test_the_boundary_refuses.py` |
| A `delete` becomes a revocation: unreachable on the next read, row still on disk, deadline pulled in. The deadline moves *earlier only*; a quarantine stays pinned; a revocation cannot be lifted | `tests/test_the_write_path_forgets_without_deleting.py` |
| Revoking a source reaches the summary, the answer and the embedding built on it — **through the wire**, children marked before the source, for a client that imported nothing | `tests/test_a_refusal_travels_and_is_gated.py` |
| An insert that says what it was made out of has its ancestry closed transitively on the way in, and is refused outright if a named parent is missing, out of scope or already refused | `tests/test_a_refusal_travels_and_is_gated.py` |
| A `$vectorSearch` hit is refused on the path that never passes through a query | `tests/test_search_refuses_on_the_path_that_bypasses_the_query.py` |
| `numCandidates` is sized from the measured refusal rate, not a constant | `tests/test_the_boundary_sizes_its_own_fetch.py` |
| A read the boundary cannot judge per document — `distinct`, `count`, a pipeline that groups or reshapes, **or a `find` whose projection hides the marks** — has the refusal pushed into its query instead, and is refused outright in the cases where that push-down would be narrower than the guarantee | `tests/test_a_derived_read_cannot_launder_a_forgotten_fact.py` |

## The wire

| claim | held up by |
|---|---|
| A plain driver with no VOYD import gets every guarantee — real `mongod`, real proxy, real driver. Sessions, transactions and retryable writes cross intact; read preference is honoured against a topology of one | `tests/test_the_wire_is_the_front_door.py` |
| The wire codec round-trips, including the kind-1 document sequence that carries a write | `tests/test_the_codec_round_trips.py` |
| A client cannot walk past the boundary: `hello` is rewritten, so the guarantee is not a connection-string option somebody remembers | `tests/test_a_client_cannot_walk_past_the_boundary.py` |
| It is operable: TLS termination, a capped message size, keepalive, a draining `SIGTERM` | `tests/test_the_boundary_is_operable.py` |
| It survives hostile conditions — backpressure, resets mid-reply, garbage on the port, an upstream restart | `tests/test_the_boundary_survives_hostile_conditions.py` |
| It scales across cores without the counting getting looser | `tests/test_the_boundary_scales_without_lying.py` |
| It says what it did, while it is still running | `tests/test_the_boundary_says_what_it_is_doing.py` |
| The vector dies with the fact: an erasure through the wire nulls every declared derived encoding, because an embedding is a lossy copy of the text and not a pointer to it | `tests/test_the_vector_dies_with_the_fact.py` |
| A cumulative rule — a token `budget()`, a `distinct()` — is enforced across the whole read and not per batch, so a client cannot reset it by asking for a smaller `batchSize` | `tests/test_a_page_budget_survives_the_batch_size.py` |
| The proxy builds what it enforces — `--ensure` creates the collection, the TTL index, the tenant index and the server-embedded vector index the policy declares, and `--verify`, written separately, then has nothing to report | `tests/test_the_proxy_provisions_what_it_enforces.py` |
| The secondary ranks and the primary permits, so replication lag never becomes a second delete-is-a-wish window | `tests/test_the_boundary_ranks_on_a_replica_and_asks_the_primary.py` |
| Caller-scoped rules run on the wire, and the claims are the *server's* account of who authenticated — `connectionStatus` on the client's own connection, never anything the client asserted | `tests/test_the_boundary_learns_who_is_asking.py` |

## Erasure

| claim | held up by |
|---|---|
| A key per scope, destroyed on the scope's deadline: plaintext is not on disk, and shredding one tenant leaves the others readable | `tests/test_encryption_is_the_answer_refusal_cannot_give.py` |
| Through the wire, a driver with no encryption configured writes ciphertext — and an erasure is unreachable **immediately** and unreadable everywhere after, because the revocation precedes the shred | `tests/test_the_boundary_seals_and_shreds.py` |

## Declaration

| claim | held up by |
|---|---|
| The policy file is the whole configuration surface, and a wrong one fails at *load* | `tests/test_the_policy_file_is_the_configuration.py` |
| The server owns the encoding: a client-supplied `queryVector` is refused where `auto_embed` is declared, decided with no database | `tests/test_the_server_owns_the_encoding.py` |
| The policy is checked against the cluster, read-only, before serving — and a probe that failed never reports a clean bill | `tests/test_the_policy_is_checked_against_the_cluster.py` |
| The deployment is asked, never assumed. No capability is inferred from a version number or a connection string | `tests/test_the_deployment_is_asked_not_assumed.py` |

## The tools that make the claims

| claim | held up by |
|---|---|
| The scanner is not confidently wrong about a stranger's code | `tests/test_the_scanner_is_not_confidently_wrong.py` |
| Every performance number in `LIMITS.md` comes from a script that checks the boundary was still refusing while it was being fast | `tests/test_the_benchmark_measures_the_boundary.py` |
| The suite does not leak databases, because a stale search index starves the next index build | `tests/test_the_suite_does_not_leak_databases.py` |
| Every claim on this page names a test, and every test file is named by a claim | `tests/test_every_claim_names_its_evidence.py` |
| Every `docker compose up` a document tells you to run names a service that exists — and every service exists in a document | `tests/test_every_documented_command_is_real.py` |
