# Admission overhead (measured)

- generated: 2026-09-20 08:20:39 -0400
- machine: Darwin arm64, Python 3.12.11, pymongo 4.18.1
- laptop numbers: relative and order-of-magnitude, not a capacity plan.

## 1. Per-hit classification cost (CPU, no database)

Refusal rate 50%, 2000 repeats. Microseconds per candidate.

| rule set | page | p50 us | p95 us | p99 us |
|---|---|---|---|---|
| deadline+revoked | 1 | 1.17 | 1.25 | 1.33 |
| deadline+revoked | 10 | 0.93 | 1.10 | 1.66 |
| deadline+revoked | 100 | 0.91 | 1.05 | 1.37 |
| deadline+revoked+quarantined | 1 | 1.46 | 1.58 | 1.92 |
| deadline+revoked+quarantined | 10 | 1.10 | 1.40 | 1.90 |
| deadline+revoked+quarantined | 100 | 1.07 | 1.23 | 1.54 |

## 2. Over-fetch factor (saturate, no database)

limit=10, corpus=500, trials=400, rounds cap=4. `worst` ranks every refused row ahead of a live one; `shuffled` interleaves them.

| refusal rate | examined/admitted p50 | p99 | rounds p50 | starved rate |
|---|---|---|---|---|
| 0.00/shuffled | 2.00 | 2.00 | 1 | 0% |
| 0.00/worst | 2.00 | 2.00 | 1 | 0% |
| 0.10/shuffled | 2.00 | 2.00 | 1 | 0% |
| 0.10/worst | 8.00 | 8.00 | 2 | 0% |
| 0.50/shuffled | 2.00 | 6.10 | 1 | 0% |
| 0.50/worst | 32.00 | 32.00 | 3 | 0% |
| 0.80/shuffled | 7.60 | 30.10 | 2 | 0% |
| 0.80/worst | 50.00 | 50.00 | 4 | 0% |
| 0.90/shuffled | 15.10 | 40.10 | 2 | 0% |
| 0.90/worst | 50.00 | 50.00 | 4 | 0% |

## 3. End-to-end on Atlas autoEmbed

Not run (pass `--atlas` with `VOYD_ATLAS_URI` set).
