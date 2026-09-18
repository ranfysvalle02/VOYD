import pytest

# ``voyd.host`` imports starlette (the ``app`` extra) for the Host middleware.
# Pure slug logic, but engine-only installs skip it rather than fail collection.
pytest.importorskip("starlette")

from voyd.host import resolve_slug


def test_apex_hosts_have_no_slug():
    assert resolve_slug("voyd.com", "voyd.com") is None
    assert resolve_slug("localhost:8000", "voyd.com") is None
    assert resolve_slug("127.0.0.1:8000", "voyd.com") is None
    assert resolve_slug("localhost", "localhost") is None


def test_subdomain_of_domain():
    assert resolve_slug("auto.voyd.com", "voyd.com") == "auto"
    assert resolve_slug("pizza.voyd.com:8000", "voyd.com") == "pizza"
    assert resolve_slug("studio.voyd.com", "voyd.com") == "studio"


def test_local_dev_subdomain():
    assert resolve_slug("auto.localhost:8000", "voyd.com") == "auto"
    assert resolve_slug("auto.localhost", "localhost") == "auto"
    assert resolve_slug("auto.voyd.localhost", "voyd.localhost") == "auto"


def test_header_override_wins():
    assert resolve_slug("voyd.com", "voyd.com", header_slug="auto") == "auto"
    assert resolve_slug("anything", "voyd.com", header_slug="  Pizza ") == "pizza"


def test_unknown_bare_host_is_apex():
    assert resolve_slug("example.org", "voyd.com") is None
