VOYD is a MongoDB wire proxy that answers the question retrieval never asks: may this fact reach a prompt? You write one policy file and change one connection string — no application code — and expired, revoked, or out-of-tenant documents stop being reachable from any driver, language, notebook, or agent, because the boundary binds the connection and there's nothing to reach past.

Why it's cool is one property with three payoffs. Putting the check on the wire forced it to be a pure function — a document, a policy, a clock, no I/O. That constraint looked like a tax and turned out to be the whole advantage:

- It audits before it installs. voyd-plan --audit runs as a batch job against a read-only URI and tells you how many documents are reachable right now that shouldn't be. Every competing sidecar needs to be deployed first to tell you anything.
- It diffs policy changes in CI. A deleted line in a diff doesn't say "412 documents just became reachable by tier-1 support." This does, and fails the PR.
- Your reranker cannot leak. Page-shaping code runs inside the boundary, with the authoritative check after it — so a transform can reorder, merge, cache, even inject, and a forgotten fact still can't get out. Proven by a test that tries to smuggle documents through a real proxy and fails.

-----

Your reranker cannot leak

The line: "You can run a stranger's reranking code inside my authorization boundary, and I'll still guarantee nothing forbidden comes out. Not because I reviewed the code — because the boundary runs after it."

This is the best thing in the project and the only one nobody else in the category can say. Everyone's reranker/dedupe/cache runs after retrieval, which means it's downstream of the filter, which means it can undo it — and almost always by accident: merging a cached list, falling back to the unfiltered candidate pool because an empty page looked like a bug.

Flip the order and the problem disappears:

pure rules  →  your transform  →  every rule, terminally  →  the wire

Why it's convincing: there's a test that writes a transform whose only purpose is to inject expired and revoked documents, runs it through a real proxy with a real driver, and shows they don't arrive. Not sandboxed. Not reviewed. It runs, returns the documents, and they're gone.

The strategic kicker: security's standing objection to a programmable proxy is "unvetted code modifying data in flight." Here that's the feature.


 The cosine numbers

The line: "Swap your embedding model without reindexing and your search doesn't get worse — it inverts. Same text scores −0.053. Unrelated text scores +0.301."

Best single fact in the project for a bar, a tweet, or a conference hallway. Everyone who's touched a vector DB feels it in their stomach. And the safety net people assume they have — the dimension check — catches none of it, because a whole generation of models shares a width.

voyd-plan — terraform plan, for authorization

The line: "A diff says a line was deleted. It doesn't say 412 documents just became reachable by tier-1 support. This does, and it fails the PR."

per caller
  caller          newly reachable   examined
  tier1-support               412        824
  analyst                       0        824
  clinician                     0        824

Why it lands with engineers: nobody can currently answer "prove this policy change didn't widen access" with anything but someone's recollection. Exit code 1. One uses: line. No cluster, no secret.

The deeper cool: this only exists because the check is pure. If enforcement lived inside the query there'd be nowhere to stand to ask the question except production.




The 60-second demo

This is what you actually show someone:

around the boundary   5 documents on disk
through the boundary  2 — the expired and the revoked are refused,
                          and the other tenant was never in scope

Two terminals, same cluster, one connection string different. No application code changed. Then delete the tenant() line from the policy file and run voyd-plan — it fails, and names what just became reachable.

---