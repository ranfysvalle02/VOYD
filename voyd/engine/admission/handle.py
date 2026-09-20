"""The one object a caller holds.

The handle is deliberately a single class with a single fluent surface, and
that is the constraint the whole package is arranged around. The argument in
``__init__`` is that there is **no unfiltered read on this handle** -- no
``find``, no ``search`` -- so refusal does not depend on the next author
remembering it. Splitting the capabilities into separate objects would hand
that author a second object to reach for, which is the failure mode restated
rather than fixed.

So the capabilities are composed in, not delegated to. Each mixin owns one
job and may only reach the core's protocol to do it: the state, ``_query``
for the cheap half, and ``_admit`` for the authoritative one. The result is
that "what may reach a prompt" is answerable by reading one class,
``AdmissionCore``, while "what can be done about it" is answerable one file
at a time.

Read them in this order -- each depends on the one above it:

    core.py         the state, and the two enforcement points
    reads.py        every way out, all of them ending at ``_admit``
    marks.py        imposing a reason, and lifting one where it inverts
    lineage.py      making the refusal travel to what was made of it
    sealing.py      the erasure refusal cannot perform
    attestation.py  what the model was allowed to see
"""

from __future__ import annotations

from .attestation import Attestation
from .core import AdmissionCore
from .lineage import Lineage
from .marks import MarkWrites
from .reads import ReadPath
from .sealing import Sealing


class Admission(AdmissionCore, ReadPath, MarkWrites, Lineage, Sealing,
                Attestation):
    """A read handle that cannot return a forgotten fact.

    Install it on a model (``.forgettable()``) or build it directly. It is a
    trait, so ``ensure()`` gives the mark field an index -- revocation has to
    be cheap to filter on, or it will be skipped at scale.

    The body is in the six modules above. This class exists to say that they
    are one thing, because to a caller they are.
    """
