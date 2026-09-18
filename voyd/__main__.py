"""``python -m voyd`` / ``voyd`` -- boot the runtime from environment settings.

The HTTP service -- FastAPI, templates, auth -- lives behind the ``app`` extra.
``pip install voyd`` gives you ``Engine`` and nothing else, so booting the
runtime without that extra should be a clear instruction, not a raw
``ModuleNotFoundError`` three imports deep.
"""

from __future__ import annotations


def main() -> None:
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
        # VOYD_R2_* configured without the 'r2' extra. The message already
        # names the install, so print it rather than a traceback.
        raise SystemExit(str(exc)) from exc
    app.run(host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
