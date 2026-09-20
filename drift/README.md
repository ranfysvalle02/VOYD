# The drift exhibit, and the portability argument

Two files here, answering the two objections a reader is entitled to raise.

`exhibit.py` runs the **four owners** claim against real services. Read on for
that one.

`refusal_on_postgres.py` answers the other: *is this just MongoDB advocacy?*
It ports the thesis in full to pgvector, with no MongoDB anywhere in the file
— the same silent bug, refusal in the read path, then the structural version
(revoke the table, grant only a view, so the naive read raises `permission
denied` instead of leaking), then inherited refusal via a recursive CTE. It
also states what is genuinely **harder** on Postgres: no TTL, so the moment
you need rows actually gone the deadline has two owners again. That part of
VOYD's claim really is stronger on MongoDB, and saying so is the difference
between an argument and a pitch.

```bash
docker compose -f drift/docker-compose.drift.yml up -d --wait drift-postgres
uv run --extra drift python drift/refusal_on_postgres.py   # 0 = every claim held
```

---

VOYD rests on two claims. The second — that a read path must *refuse* what it
has forgotten — is proven by `examples/refuse.py` in five seconds. This
directory is for the first, which is an architecture opinion and therefore the
one a reader is entitled to disbelieve:

> Four owners, four clocks, four ways to drift — and the drift *is* the bug.
> The vector outlives the document. The bytes outlive the row.

This directory makes that claim executable. It stands up the stack the claim
is about — Postgres for the row, Qdrant for the vector, MinIO for the bytes,
and a cron job to keep them agreeing — ingests one document with a deadline,
lets the deadline pass, runs the cron, and then asks the retrieval system a
question.

```bash
docker compose up -d --wait mongo                                  # VOYD's own
docker compose -f drift/docker-compose.drift.yml up -d --wait      # the other three
uv sync --all-extras
uv run --extra drift python drift/exhibit.py
```

Teardown:

```bash
docker compose -f drift/docker-compose.drift.yml down -v
```

## What it prints

Act I ends here:

```
  5. Now ask the retrieval system a question. This is the call an
     This is the call retrieval makes -- it queries the vector index, not Postgres.

     -> returned 1 hit(s). Top hit:
        score   1.0000
        text    'the 2019 acquisition fell through because of the pension liability'
        pg_id   1 <- this row no longer exists
    [ok  ] THE DELETED DOCUMENT ANSWERED THE QUERY
    [ok  ] and S3 still serves the bytes -- the lifecycle rule cannot fire for ~a day
```

Act II runs the same scenario in VOYD, where the expired memory stops
answering *while its row is still on disk*, because the read path owns the
same deadline the reaper does.

## The two rules it plays by

**Every system gets its real mechanism.** Postgres gets a `DELETE` driven by
a cron, because Postgres has no TTL and a cron is genuinely how this is done.
S3 gets a real lifecycle rule applied through the real API — and the exhibit
reports what that rule actually promises, which is `Days: 1`, against a
5-second deadline. Qdrant gets its real delete API. Nothing is stubbed,
nothing is sabotaged, and no service is configured to fail.

**Every claim is checked, not narrated.** Each step asserts the state it
describes, and the exhibit exits non-zero if any check fails. In particular it
does *not* assert "Postgres has no TTL" as a fact — it lets the deadline pass
and measures that the expired row is still there. If some future version of
any of these services closes the gap, this file fails, and that is the correct
outcome: an argument worth making should be falsifiable.

## What it is not

Not a benchmark (see `bench/` for numbers), and not a claim that these are bad
systems. Qdrant is a good vector database; the exhibit's own final step shows
that one extra delete call fixes the leak.

That extra call is the entire point. It is application code, it is not
transactional with the first delete, and when it is forgotten or fails the only
symptom is an answer that should not exist — a confident, well-scored hit from
a document the system of record says is gone. Nothing is broken enough to page
anyone.

Nothing in VOYD imports any of this. The `drift` extra exists only for this
directory and is deliberately excluded from `voyd[all]`.
