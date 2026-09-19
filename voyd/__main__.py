"""``python -m voyd`` / ``voyd`` -- boot the runtime, or verify a deployment.

    voyd                 run the HTTP service (needs the `app` extra)
    voyd verify --uri    attack the refusal guarantee; exit 0 if it held

The HTTP service -- FastAPI, templates, auth -- lives behind the ``app`` extra.
``pip install voyd`` gives you ``Engine`` and nothing else, so booting the
runtime without that extra should be a clear instruction, not a raw
``ModuleNotFoundError`` three imports deep.
"""

from __future__ import annotations

import sys


def main() -> None:
    # ``voyd verify`` needs neither the app extra nor a running server -- it
    # talks to MongoDB and attacks the guarantee. Dispatched before the
    # import below, so a plain ``pip install voyd`` can run it.
    if len(sys.argv) > 1 and sys.argv[1] == "verify":
        from .verify import main as verify_main
        raise SystemExit(verify_main(sys.argv[2:]))

    try:
        from .settings import VoydSettings, build_app
    except ModuleNotFoundError as exc:  # the 'app' extra is not installed
        raise SystemExit(
            f"the voyd server needs the 'app' extra (missing: {exc.name}).\n"
            "    pip install 'voyd[app]'   # or uv sync --extra app"
        ) from exc

    settings = VoydSettings()
    try:
        app = build_app(settings)
    except ModuleNotFoundError as exc:
        # An extra is configured but not installed. The message already names
        # the install, so print it rather than a traceback.
        raise SystemExit(str(exc)) from exc
    app.run(host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
