"""``python -m voyd_scan`` / ``python scanner/voyd_scan``.

The module next door is the whole program; this file exists only so the
package is runnable the two ways a stranger will actually try it, and the
path juggling below is why it is not one line. ``python -m voyd_scan``
imports this as part of a package; ``python scanner/voyd_scan`` runs it as a
loose script with no parent, where a relative import raises. A first-contact
tool that crashes on the more obvious of the two invocations has spent its
only chance.
"""

from __future__ import annotations

import pathlib
import sys

if __package__:
    from . import main
else:                                       # run as a path, not a module
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
    from voyd_scan import main

if __name__ == "__main__":
    raise SystemExit(main())
