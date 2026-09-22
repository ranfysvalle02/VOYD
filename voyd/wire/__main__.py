"""``python -m voyd.wire`` -- the same entry point as ``voyd-wire``.

It exists so the module form does not warn. ``voyd/wire/__init__.py``
imports ``main`` from ``.proxy``, so ``python -m voyd.wire.proxy`` loads
the package first and then re-executes the submodule, and Python says so
on stderr every time:

    RuntimeWarning: 'voyd.wire.proxy' found in sys.modules after import of
    package 'voyd.wire', but prior to execution of 'voyd.wire.proxy'

Harmless, and noise on the first line of every container's log -- which is
the line somebody reads when they are already worried.
"""

from .proxy import main

if __name__ == "__main__":
    raise SystemExit(main())
