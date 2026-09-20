"""Ciphertext, both ways -- and the erasure refusal cannot perform.

Refusal answers "may this reach a prompt" for every read *this application*
serves. It cannot answer for a replica, a snapshot, or a backup nobody has
restored yet. Destroying the key can, which is why sealing lives on the same
handle rather than in a parallel object the caller has to carry: the scope of
the key is the tenant they already have.

Decryption is explicit here rather than automatic, and ``unseal`` says why at
length: automatic decryption fails the whole batch when one key is gone, and
a crypto-erased document is a *normal* state, not an incident.
"""

from __future__ import annotations

import logging
from typing import Self, Iterable

from ..authority import SHRED
from ..errors import ScopeRequired, UnknownReason
from .reasons import KEY_UNAVAILABLE, UNRECOVERABLE
from .receipts import Page
from .rules import _is_ciphertext

log = logging.getLogger("engine.admission")


class Sealing:
    """Encrypt on write, decrypt on read, and destroy the key on request.

    The erasure refusal cannot perform: refusal binds this application's
    read paths, a shredded key binds every copy that exists anywhere.
    """

    # ---- ciphertext, both ways -----------------------------------------
    #
    # Sealing is something a collection *has*, like a tenant or a rule, so
    # it lives on this handle rather than in a parallel object the caller
    # has to carry alongside it. Three things follow from that, and each
    # one removes something a caller would otherwise have to remember:
    #
    #   seal()      mints the scope's key if it is new, then writes through
    #               the encrypting client. There is no step where you have
    #               a key but no document, or a document but no key.
    #   find()/search()
    #               decrypt on the way out and refuse what they cannot,
    #               so no read site passes a keyring and a field list.
    #   shred()     the scope's key, by the same name the documents use.
    #
    # And the writer that skips all of this -- a migration script, a shell,
    # a second service holding the plain client -- is refused by the
    # *server*, because ``Keyring.enforce()`` puts a binData validator on
    # the collection. See its docstring: that is the difference between
    # encryption as a convention and encryption as a guarantee.

    def sealed_by(self, sealing) -> Self:
        """Attach a resolved ``Sealing``. Returns ``self``.

        A cumulative rule and sealing are rejected together for now. Sealing
        can refuse a selected hit only after asynchronous decryption; charging
        a budget before that would report room spent on content never returned,
        while charging after it requires the refill loop to decrypt before
        cumulative admission. Both are implementable, but silently choosing
        the first is a false precision claim. Fail at construction until the
        read path owns that ordering explicitly.
        """
        cumulative = [r.reason for r in self.rules
                      if getattr(r, "needs_tab", False)]
        if cumulative:
            raise ValueError(
                f"{self.collection}: sealing cannot yet compose with "
                f"cumulative rule(s) {cumulative}; decryption must happen "
                "before budget charging so Page.spent stays truthful")
        self.sealing = sealing
        return self

    @property
    def seals(self) -> bool:
        return self.sealing is not None

    def _require_sealing(self, verb: str):
        if self.sealing is None:
            raise UnknownReason(
                self.collection, verb,
                ("declare .sealed(...) on the model to encrypt fields",))
        return self.sealing

    async def seal(self, documents, *, scope: str | None = None) -> list:
        """Write documents with their sealed fields encrypted.

        The scope defaults to the document's own tenant value, which is the
        point of tying the two together: a per-tenant key needs no second
        field, no second lookup and no second thing to keep in step. One
        declaration -- ``model(tenant="t").sealed("text")`` -- and erasure
        is per tenant because the key already was.

        The key is minted here if the scope is new. Requiring a separate
        ``key_for()`` first would make "wrote a document, forgot the key" a
        reachable state, and the driver's answer to that state is an
        exception on the *write* -- which is safe, and is still a step the
        caller can only get wrong.
        """
        sealing = self._require_sealing("seal")
        docs = [documents] if isinstance(documents, dict) else list(documents)
        if not docs:
            return []
        self._require_caller()

        prepared, scopes = [], set()
        for doc in docs:
            row = dict(doc)
            at = scope or row.get(sealing.scope_field)
            if at is None:
                raise ScopeRequired(self.collection, sealing.scope_field)
            row[sealing.scope_field] = at
            scopes.add(at)
            prepared.append(row)

        ring = sealing.keyring
        ce = await ring.encryption()
        try:
            for at in sorted(scopes):
                await ring.key_for(at, encryption=ce)
        finally:
            await ce.close()

        collection = await ring.writer(self.collection)
        result = await collection.insert_many(prepared)
        log.info("sealed %d document(s) into %s under %d scope key(s)",
                 len(prepared), self.collection, len(scopes))
        return list(result.inserted_ids)

    async def shred(self, scope: str) -> int:
        """Destroy one scope's key. Its ciphertext is noise, everywhere.

        Named on the handle as well as on the keyring because this is where
        the caller already is, and because the scope is the tenant they
        already have. An erasure request should not require knowing that a
        key vault exists.
        """
        self._authorise(SHRED)
        return await self._require_sealing("shred").keyring.shred(scope)

    async def _unsealed(self, documents: list[dict]) -> tuple[list, dict]:
        """Decrypt, refusing per document. ``(kept, tally)``."""
        if self.sealing is None or not documents:
            return list(documents), {}
        page = await self.unseal(documents, fields=self.sealing.fields,
                                 keyring=self.sealing.keyring, count=False)
        return list(page), dict(page.refused)

    async def unseal(self, documents, *, fields: Iterable[str],
                     keyring, encryption=None, count: bool = True) -> Page:
        """Decrypt sealed fields, and refuse the documents whose key is gone.

        The read half of ``keyring.py``, and it is explicit for a reason
        that is stated at length there and worth one line here: automatic
        decryption raises ``EncryptionError`` for the whole batch when a
        single key is missing, so one crypto-erased document would turn a
        page of fifty into a 500. "Fewer rows, or an error" is the shape
        this codebase refuses everywhere else, and a crypto-erased document
        is a *normal, expected* state -- it is the feature working.

        So a missing key is a refusal, counted under ``unrecoverable``,
        beside the deadline and the revocation. Three reasons a fact may
        not reach a prompt, one question, one place that answers it.
        """
        ce = encryption or await keyring.encryption()
        fields = tuple(fields)
        # Materialised once. ``documents`` is an Iterable, and the count
        # below used to re-walk it -- which is 0 for a generator, so
        # ``examined`` silently under-reported on exactly the callers that
        # stream. A cost figure that reads 0 under load is worse than no
        # cost figure.
        documents = list(documents)
        scope_field = getattr(self.sealing, "scope_field", None)
        kept, tally, verdicts = [], {}, {}
        for doc in documents:
            out = dict(doc)
            for name in fields:
                value = out.get(name)
                if not _is_ciphertext(value):
                    continue
                try:
                    out[name] = await ce.decrypt(value)
                except Exception:  # noqa: BLE001 - a key that is gone is an
                    # answer, not an incident. Which of the two answers it
                    # is takes a lookup; see ``_why_undecryptable``.
                    reason = await self._why_undecryptable(
                        keyring, doc.get(scope_field) if scope_field else None,
                        verdicts)
                    tally[reason] = tally.get(reason, 0) + 1
                    out = None
                    break
            if out is not None:
                kept.append(out)
        if count:
            # A caller that folds this into a page commits the tally once,
            # with the rest of that page's refusals -- counting here as
            # well would double it, in the one direction that makes a lower
            # bound a lie.
            self.receipts_log.record_many(tally)
        if tally.get(UNRECOVERABLE):
            log.info("%s: %d document(s) are unrecoverable -- their key was "
                     "destroyed, so no read path anywhere can produce the "
                     "plaintext", self.collection, tally[UNRECOVERABLE])
        if tally.get(KEY_UNAVAILABLE):
            # ERROR, not info. The key still exists and could not be
            # fetched, so this is an outage wearing the costume of a
            # feature -- and the documents are being withheld from callers
            # who are entitled to them.
            log.error("%s: %d document(s) could not be decrypted although "
                      "their key still exists. This is a KMS or key-vault "
                      "failure, not an erasure: the data is being withheld, "
                      "not destroyed", self.collection,
                      tally[KEY_UNAVAILABLE])
        return Page(kept, refused=tally, examined=len(documents))

    async def _why_undecryptable(self, keyring, scope, cache: dict) -> str:
        """Was the key destroyed, or merely unreachable? ``(the difference)``

        These produce an identical failure at the driver and mean opposite
        things: one is the feature working -- somebody asked to be
        forgotten and the key is gone -- and the other is an outage, during
        which a dashboard reporting "erasures: 41" is reporting a lie.

        **Discriminated by asking our own key vault, not by reading the
        driver's error text.** A message like *"not all keys requested were
        satisfied"* is a string in somebody else's library and will change
        without telling us; whether the key document still exists is a fact
        we own. Present and undecryptable means the KMS could not unwrap
        it. Absent means it was shredded.

        Cached per call, because a page of fifty documents from one erased
        scope should cost one lookup, not fifty. And when the lookup itself
        fails, the answer is ``key_unavailable`` -- if the key vault cannot
        be read, "the key is gone" is a conclusion the evidence does not
        support.
        """
        if scope is None or keyring is None:
            return UNRECOVERABLE
        if scope in cache:
            return cache[scope]
        try:
            alive = await keyring.db[keyring.collection].find_one(
                {"keyAltNames": scope}, {"_id": 1}) is not None
        except Exception:  # noqa: BLE001 - see docstring
            alive = True
        cache[scope] = KEY_UNAVAILABLE if alive else UNRECOVERABLE
        return cache[scope]
