# Pilot report (self-run)

- generated: 2026-09-20 08:29:24 -0400
- machine: Darwin arm64, Python 3.12.11
- scenario: synthetic support-notes scope, one tenant, run against a
  throwaway MongoDB. No cloud, no API key, no vector index.

## What this run proves

| claim | result |
|---|---|
| the canary is served by the raw path and refused by the handle | yes |
| after erasure, the raw read a teammate writes still serves the leak | yes |
| after erasure, the handle's find refuses it | refused: yes |
| an unfiltered candidate producer included the leak | yes |
| reachable() refused it on the way out | refused: yes |
| the summary written out of the leak was refused too (lineage) | refused: yes |
| the rows are all still on disk (revoke deleted nothing) | 9 rows |
| a token budget cut the page | 2 admitted, 80 spent at limit 100 |

## The PILOT.md report, filled

```
Team / service:                                 self-run (bench/pilot.py)
Collection and read path piloted:               notes, find + reachable()
find-only or vector (Atlas autoEmbed)?          find + direct egress candidate batch

Integration time (first line to green CI):      the quickstart block
Application lines changed:                       6 (pinned <10 by test_the_quickstart_refuses.py)
Where the time actually went:                    n/a for a self-run

Measured in our environment:
  admission overhead p50 / p99:                0.93 / 1.19 us per candidate
  over-fetch (examined/admitted) at our rate:  2.00
  starvation observed:                         no

Incidents the handle would have caused / prevented during the trial:
  prevented: a revoked credential reaching a prompt through the naive read
             and through an unfiltered candidate producer; and through the
             summary an agent wrote out of it.

Kept after two weeks?                          UNKNOWN -- a self-run cannot answer this
In our own words, why:                         (the one line only a real team fills)
```

## What this run cannot prove

Demand. This is us, and we were already convinced. Every line above is
the mechanism working; none of it is a stranger choosing to keep the
handle after two weeks, which is the only evidence that moves adoption.
That line is left UNKNOWN on purpose -- see [`PILOT.md`](../PILOT.md).
