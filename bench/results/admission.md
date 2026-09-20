# Admission overhead (measured)

- generated: 2026-09-19 23:21:22 -0400
- machine: Darwin arm64, Python 3.12.11, pymongo 4.18.1
- laptop numbers: relative and order-of-magnitude, not a capacity plan.

## 1. Per-hit classification cost (CPU, no database)

Refusal rate 50%, 2000 repeats. Microseconds per candidate.

| rule set | page | p50 us | p95 us | p99 us |
|---|---|---|---|---|
| deadline+revoked | 1 | 0.46 | 0.50 | 0.54 |
| deadline+revoked | 10 | 0.49 | 0.53 | 0.66 |
| deadline+revoked | 100 | 0.48 | 0.57 | 0.70 |
| deadline+revoked+quarantined | 1 | 0.54 | 0.71 | 0.79 |
| deadline+revoked+quarantined | 10 | 0.54 | 0.57 | 0.75 |
| deadline+revoked+quarantined | 100 | 0.52 | 0.62 | 0.77 |

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

model voyage-4, corpus 120, limit 10, requested refusal ~40%.

- examined/admitted: **2.00** (admitted 10, starved False)
- wall-clock p50/p99 **including cloud round-trips**: 176 / 211 ms -- this is network to a cloud cluster, not the admission cost; see scenario 1 for that.
