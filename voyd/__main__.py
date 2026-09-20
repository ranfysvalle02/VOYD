"""``python -m voyd`` / ``voyd`` -- boot the runtime.

The HTTP service -- FastAPI, auth, the vault -- lives behind the ``app``
extra.
``pip install voyd`` gives you ``Engine`` and nothing else, so booting the
runtime without that extra should be a clear instruction, not a raw
``ModuleNotFoundError`` three imports deep.
"""

from __future__ import annotations


def missing_extra(exc: ModuleNotFoundError) -> SystemExit:
    """The message a bare install gets, as a function so it can be tested.

    Inline, it was only reachable by monkeypatching ``__import__`` -- which
    is order-dependent and passes alone while failing in a full run. A test
    that only holds in isolation is a flake generator, and the fix is to
    make the thing testable rather than to test it cleverly.
    """
    return SystemExit(
        f"the voyd server needs the 'app' extra (missing: {exc.name}).\n"
        "    pip install 'voyd[app]'   # or uv sync --extra app")


def main() -> None:
    try:
        from .settings import VoydSettings, build_app
    except ModuleNotFoundError as exc:  # the 'app' extra is not installed
        raise missing_extra(exc) from exc

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
