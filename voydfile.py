"""Deliberately unscoped, on a branch that exists to make the check speak."""

from voyd import deadline, guard, revocable


@guard("notes")
class Notes:
    expire_at = deadline()


@guard("cases")
class Cases:
    expire_at = deadline()
    forgotten = revocable()
