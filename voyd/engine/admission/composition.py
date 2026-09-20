"""What each capability mixin is allowed to assume the handle already has.

``Admission`` in handle.py is six classes composed into one object, and that
handle's docstring has always stated the rule they compose under: *each mixin
owns one job and may only reach the core's protocol to do it.* That rule was
prose. Nothing checked it, and a type checker reading ``marks.py`` on its own
saw a class reaching for fifteen attributes it does not define -- which is why
``py.typed`` shipped a promise no run had ever tested.

The protocols below are that rule, written down where a tool can read it.
Each one is the *exact* surface a mixin touches, so widening a mixin's reach
means editing this file, which means somebody types out that the dependency
is intended -- the same mechanism
``tests/test_the_public_surface_is_deliberate.py`` uses on ``__all__``, and
the same one ``including_refused()`` uses on break-glass. The safe thing is
the default; the other thing has to be said out loud.

Two of them are not the core. Writing the contracts down is what surfaced it:

- ``ReadPath`` reaches ``Sealing.seals`` / ``Sealing._unsealed``
- ``MarkWrites`` reaches ``Lineage._descendants`` / ``Lineage._with_descendants``

Those are real sibling dependencies, and the handle's ordering comment was
wrong to imply the graph is a star. It is a DAG, it is small, and it is now
named: ``SealingState`` and ``LineageState`` exist so a reader learns that
from the types rather than from a stack trace.

Nothing here runs. Every mixin binds these under ``TYPE_CHECKING`` only and
inherits ``object`` at runtime, so the real MRO in ``Admission`` is byte-for
-byte what it was -- these classes cost an import that never happens.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Protocol

from .receipts import Receipts
from .rules import Rule, Tab
from .spec import AdmissionSpec


class CoreState(Protocol):
    """``AdmissionCore``, as the capability mixins are permitted to see it.

    ``handle.py`` asserts that the real ``AdmissionCore`` satisfies this, so
    the two cannot drift: narrow the core and this file stops type-checking.
    """

    # ---- the state -----------------------------------------------------
    db: Any
    engine: Any
    spec: AdmissionSpec
    rules: tuple[Rule, ...]
    collection: str
    tenant: Any
    receipts_log: Receipts
    ledger: Any
    context: Any
    perimeter: Any
    perimeter_log: Any
    sealing: Any
    authority: Any
    _include: bool
    _break_glass: bool
    _bound: bool
    _as_of: datetime | None
    _caller: dict | None

    # ---- authority -----------------------------------------------------
    def _authorise(self, operation: str) -> None: ...
    def _actor(self) -> str | None: ...
    def _require_caller(self) -> None: ...

    # ---- the two enforcement points, and the clones around them --------
    def _query(self, filters: dict | None) -> dict: ...
    def _admit(self, doc: dict | None, *, when: datetime | None = ...,
               tally: dict[str, int] | None = ..., tab: Tab | None = ...
               ) -> dict | None: ...
    def _begin_read(self) -> None: ...
    def _open_tab(self) -> Tab | None: ...
    def _classify(self, docs: list[dict], *, when: datetime | None = ...,
                  max_kept: int | None = ...
                  ) -> tuple[list[dict], dict[str, int], Tab | None, int]: ...
    def _harvest(self, docs: list[dict]) -> tuple[list[dict], int]: ...
    def reachable(self, docs: Iterable[dict], *,
                  when: datetime | None = ...) -> list[dict]: ...

    # ---- the named escape hatch ----------------------------------------
    def _unfiltered(self) -> Any: ...


class SealingState(Protocol):
    """The sealing surface ``ReadPath`` depends on.

    A read has to know whether any field is ciphertext before it can hand a
    document to a caller, so this edge is not incidental -- it is the reason
    ``search`` can return plaintext at all.
    """

    @property
    def seals(self) -> bool: ...
    async def _unsealed(self, documents: list[dict]) -> tuple[list, dict]: ...


class LineageState(Protocol):
    """The lineage surface ``MarkWrites`` depends on.

    ``revoke(..., cascade=True)`` is the whole reason: a mark that does not
    travel to what was made of the fact is not a refusal, so the write path
    must be able to ask what is downstream.
    """

    async def _descendants(self, query: dict) -> tuple[list, int]: ...
    def _with_descendants(self, query: dict, filters: dict | None,
                          ids: list) -> dict: ...
