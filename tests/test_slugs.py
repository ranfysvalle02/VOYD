"""The console derives a slug from a typed business name, so the derivation
has to be stable and the rules have to match what the JSON API enforces."""

from voyd.slugs import SLUG_RE, is_valid, slug_error, slugify


def test_slugify_turns_a_business_name_into_an_address():
    assert slugify("Mobile Wrench Master") == "mobile-wrench-master"
    assert slugify("Auto Repair  Orlando!!") == "auto-repair-orlando"
    assert slugify("  Joe's  Diner & Grill  ") == "joe-s-diner-grill"


def test_slugify_strips_accents_and_punctuation():
    assert slugify("Café Niño") == "cafe-nino"
    assert slugify("A/B Testing Co.") == "a-b-testing-co"


def test_slugify_never_emits_an_illegal_slug():
    for name in ["Mobile Wrench Master", "Café Niño", "---hello---",
                 "99 Problems", "A very long business name that keeps on going forever"]:
        slug = slugify(name)
        assert SLUG_RE.match(slug), slug
        assert len(slug) <= 40


def test_slugify_collapses_to_empty_for_junk():
    assert slugify("!!!") == ""
    assert slugify("") == ""


def test_slug_error_explains_problems_in_human_terms():
    assert "business name" in slug_error("").lower()
    assert "short" in slug_error("ab").lower()
    assert "reserved" in slug_error("admin").lower()
    assert slug_error("mobile-wrench-master") is None


def test_reserved_names_are_rejected():
    for reserved in ("www", "api", "admin", "login", "assets"):
        assert not is_valid(reserved)
