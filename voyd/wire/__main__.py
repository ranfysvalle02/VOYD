"""``python -m voyd.wire`` -- the same entry point as ``voyd-wire``.

One spelling of "start the boundary", so the module form and the console
script cannot drift: both land on ``cli.main``. Running a *submodule* --
``python -m voyd.wire.cli`` -- would load the package first and then
re-execute the module, which Python reports on stderr:

    RuntimeWarning: 'voyd.wire.cli' found in sys.modules after import of
    package 'voyd.wire', but prior to execution of 'voyd.wire.cli'

Harmless, and noise on the first line of every container's log -- which is
the line somebody reads when they are already worried. This file is how
that is avoided.
"""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
