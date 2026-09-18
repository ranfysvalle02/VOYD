# Atlas Local accepts `autoEmbed` index definitions it cannot serve

**Filed by:** Fabian Valle
**Date:** 18 September 2026
**Component:** `mongodb/mongodb-atlas-local` (Atlas Local / `localDev` mongot edition)
**Severity:** low for correctness, high for developer experience
**Type:** feature-parity gap, plus a misleading error message
**Confirmed against production Atlas:** the feature works there (mongod
9.0.1, `voyage-4`); this is specifically about the local edition

---

## Summary

Atlas Local validates a `vectorSearch` index definition using
`"type": "autoEmbed"` — it checks the field type, then demands `model`, then
demands `modality` — and only after all of that reports that **no embedding
models exist on the deployment at all**:

```
CanonicalModel: voyage-3-large not registered yet, supported models are: []
```

Every model name fails identically, because the supported list is empty.

Two separate things are worth looking at, and only the second is arguably a
defect:

1. **Parity.** Automatic embedding cannot be exercised on Atlas Local, so
   application code that uses it cannot be developed locally or tested in CI
   against anything but a real cluster. If that is intentional, it would help
   to say so loudly, because right now it is discovered by trial.

2. **The error message.** *"not registered yet"* with an empty supported list
   reads as a transient or configuration problem — as though there is a
   registration step the caller has missed. There isn't one on this
   deployment. This cost me an hour of looking for a credential to supply and
   a command to call, both of which do not exist here.

I am not assuming (1) is a bug. It may be a deliberate boundary of the local
edition. The ask is a decision and a clear signal, not necessarily a feature.

**Since filing, I ran the same code against a real Atlas cluster and it works
end to end** -- index created, documents embedded server-side, text queries
returning the right rows, tenant filters intact. So the feature is sound and
this report is narrowly about the local-development story.

That comparison also sharpens point (2). Production says:

    Unsupported model 'voyage-3-large' in index: ae. Supported models are:
    [voyage-code-4, voyage-4, voyage-code-3, voyage-4-large, voyage-4-lite]

which is a genuinely good error -- it names the alternatives and I fixed my
code from it in one attempt. Atlas Local says:

    CanonicalModel: voyage-3-large not registered yet, supported models are: []

Same failure class, and the empty list plus "not registered yet" reads as a
transient or misconfigured state rather than an unsupported edition. Making
the local message say what the production one says -- minus the list, plus
the reason it is empty -- would close the entire gap between them.

---

## Environment

| | |
|---|---|
| Image | `mongodb/mongodb-atlas-local:8.2` |
| Digest | `sha256:3870c226d312019cdea22d9daee92ea63f1585f161631bfbfc844a9994babcd1` |
| mongod | 8.2.11, `modules: []` |
| mongot | 0.69.1 |
| mongot edition | `localDev` (`/etc/mongodb-atlas-local/mongot-edition`) |
| Driver | PyMongo 4.x async |
| Host | macOS 15 (Darwin 25.6.0), Docker Desktop |

---

## Reproduction

Self-contained; needs only the image running on `27018`.

```python
import asyncio, uuid
from pymongo import AsyncMongoClient

URI = "mongodb://localhost:27018/?directConnection=true"

async def main():
    c = AsyncMongoClient(URI)
    db = c[f"ae_repro_{uuid.uuid4().hex[:8]}"]
    try:
        await db.docs.insert_one({"text": "fault code P0301"})
        for model in ("voyage-3-large", "voyage-3", "voyage-3.5"):
            try:
                await db.docs.create_search_index({
                    "name": "ae", "type": "vectorSearch",
                    "definition": {"fields": [{
                        "type": "autoEmbed", "path": "text",
                        "model": model, "modality": "text"}]}})
                print(f"{model}: CREATED")
            except Exception as e:
                print(f"{model}: {str(e).split(', full error')[0]}")
    finally:
        await c.drop_database(db.name); await c.close()

asyncio.run(main())
```

### Actual

```
voyage-3-large: CanonicalModel: voyage-3-large not registered yet, supported models are: []
voyage-3:       CanonicalModel: voyage-3 not registered yet, supported models are: []
voyage-3.5:     CanonicalModel: voyage-3.5 not registered yet, supported models are: []
```

### Expected

Either the index is created and documents are embedded, **or** the failure
says plainly that this deployment cannot do automatic embedding, ideally with
a pointer to what can.

---

## The discovery path, which is the actual complaint

The server teaches the schema one field at a time, then refuses the whole
thing. Each of these is a separate round trip:

```
1.  {"type": "autoEmbedding", ...}
    -> "type" must be one of [autoEmbed, embeddedDocuments, filter, text, vector]
       (good error -- this is how I learned the correct spelling)

2.  {"type": "autoEmbed", "path": "text"}
    -> "model" is required

3.  {"type": "autoEmbed", "path": "text", "model": "voyage-3-large"}
    -> "modality" is required

4.  {"type": "autoEmbed", "path": "text", "model": "...", "modality": "text"}
    -> not registered yet, supported models are: []
```

Steps 1–3 are a normal, well-behaved validator and they strongly imply the
feature is present. Step 4 reveals it never was. A reader reasonably concludes
at step 3 that they are one field away from working, which is what makes the
final message expensive rather than merely unhelpful.

**A short-circuit at step 1** — "automatic embedding is not available on the
`localDev` edition" — would end the investigation immediately.

## What I tried before concluding it is unavailable

Recorded so nobody repeats it:

- Supplying a Voyage key from the client. **Does not apply**: with
  `autoEmbed`, mongot performs the embedding call, so the credential has to be
  server-side. A client-held `VOYAGE_API_KEY` is irrelevant to this path.
- `docker inspect` / container env for an embedding credential — none present.
- `listSearchModels`, `registerSearchModel`, `listEmbeddingModels` — no such
  command.
- Six model names including `default` and `auto` — all identical, empty list.

---

## Why it matters (the use case)

The pattern Atlas Local exists to support is "develop against the same engine
you deploy to, with no Atlas account." That holds well for `$vectorSearch`,
`$search`, `$rankFusion`, TTL indexes and change streams — all of which this
project depends on and tests locally, in CI, with no mock tier.

`autoEmbed` is the one feature where it breaks, and it breaks in the
direction that costs the most: a project can adopt it, ship it, and only
discover at deploy time that its local suite never covered a line of it.

What I did instead, and would recommend to anyone in the same position: treat
the capability as *declared* rather than assumed. The application names the
model it wants; index creation either succeeds or is refused, and a refusal
falls back to a client-computed vector index — logged, counted, and visible
on a health endpoint. The same code then takes the server-side path wherever
models exist. That made it safe to adopt before the local edition caught up,
and the fallback is what CI exercises every run.

It is still a worse outcome than parity. The happy path had to be written
blind, from error messages, and sat unverified until a cluster was available.
It turned out to be correct -- but "turned out to be" is doing real work in
that sentence.

---

## Suggested resolution, in order of cost

1. **Fail fast and say why.** Reject `type: autoEmbed` at validation on
   `localDev` with a message naming the edition and the limitation. Cheapest
   change, removes the entire investigation above.
2. **Document the boundary.** A line in the Atlas Local docs listing what the
   local edition does *not* include. Currently the feature list reads as
   complete.
3. **Support it locally**, with a configurable provider credential
   (`MONGOT_EMBEDDING_API_KEY` or similar) so mongot can call Voyage itself.
   Most expensive, and the only option that restores full parity — worth it
   only if automatic embedding is meant to be a default-path feature rather
   than a cloud convenience.

Happy to test a build of any of these.

---

## Appendix: what works fine

Not a complaint about Atlas Local generally, which has been excellent. On the
same image, all of the following work and are covered by this project's CI:

- `$vectorSearch` and `$search`, and `$rankFusion` over both
- Search index lifecycle, including `queryable` status and definition updates
- Change streams with pre-images (used here as the blob GC trigger)
- TTL indexes; measured sweep interval 60.0s over 20 samples
- `find_one_and_update` as a job-claim primitive

The gap is specifically automatic embedding.
