"""Deliberately unscoped, on a branch that exists to make the check speak."""

from voyd import deadline, guard


@guard("notes")
class Notes:
    expire_at = deadline()
