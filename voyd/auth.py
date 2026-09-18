"""Owner credentials: one kind, and it is an API key.

There used to be two. Owners could sign in to an HTML console with an email
and a password, which meant argon2 password hashing, session tokens, a
``sessions`` collection with its own TTL index, and a cookie. All of that
existed to serve a browser.

The browser is gone, and with it the second credential. What remains is the
one a program uses:

``voyd_`` + 32 random URL-safe bytes, stored only as a SHA-256 hash. A fast
deterministic hash is right here and wrong for a password -- the key is
high-entropy, so there is nothing to brute force and the lookup has to be an
indexed equality match. ``hash_api_key`` lives next to the dependency that
uses it, in ``web/deps.py``.

Passcodes on a void are a different thing and still argon2: those are chosen
by humans, short, and guessable. See ``voyd/guards.py``.
"""

from __future__ import annotations

import secrets


def new_api_key() -> str:
    return "voyd_" + secrets.token_urlsafe(32)
