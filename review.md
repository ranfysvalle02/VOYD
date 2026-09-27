# Project Review

## Score: 9/10

VOYD has an unusually coherent security thesis: retrieval policy belongs at
the database boundary, and each feature is argued in terms of what can fail
open. The policy vocabulary is small, the prose explains the security reason
behind the mechanics, and the test suite uses real wire behavior where that
matters. The new 0.5.0 work keeps that discipline by treating provenance as a
boundary-owned fact rather than a client convention.

## What Is Strong

- The project consistently prefers refusal over a partial guarantee.
- Receipts, lineage, revocation and delegated identity compose into a useful
  audit story rather than separate features.
- Documentation is unusually clear about threat models, non-goals, and the
  failure mode each mechanism closes.
- Tests name behaviors and security properties, which makes regressions easy
  to reason about.

## Main Risks

- Citation verification currently accepts only the source guard's active
  attestation key. Receipt-key rotation needs a trusted public-key set before
  older valid citations can remain usable safely.
- The new derived-write path has focused unit coverage but still needs a live
  MongoDB test that exercises read, stamped citation, write, and revocation
  end to end.
- Derived collections intentionally reject several MongoDB mutation forms.
  This is secure, but the supported write ergonomics need a documented path
  before broader adoption.

## Verification Status

The full suite passes in the configured Python 3.12 environment with
`1051 passed, 61 skipped, 3 deselected`. The touched files pass Ruff plus
`git diff --check`. MCP 2.2 is included in the development extra so the MCP
integration tests run rather than silently skipping, and the Action test
harness now supplies the planner command that the action's install step
creates in CI.

## Recommended Next Steps

1. Add an end-to-end MongoDB test for delegated citations, source revocation,
   inherited deadline, and cross-tenant refusal.
2. Design attestation-key rotation with a configured verification key ring.
3. Add a supported cited mutation representation for `findAndModify` and
   pipeline updates, or keep their refusal prominently documented.