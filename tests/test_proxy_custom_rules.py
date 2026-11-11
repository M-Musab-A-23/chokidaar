import pytest

from proxy.logstore import LogStore
from proxy.rules import CUSTOM_DESCRIPTION, custom_rules, scan


@pytest.fixture
def store(tmp_path):
    return LogStore(str(tmp_path / "rules.db"))


def test_custom_rules_are_the_approved_proposals(store):
    approved = store.add_proposal(pattern=r"zz-marker-\d+", attack_type="cmdi")
    store.add_proposal(pattern="pending-one", attack_type="xss")
    rejected = store.add_proposal(pattern="rejected-one", attack_type="xss")
    store.approve(approved)
    store.reject(rejected)
    (rule,) = custom_rules(store)
    assert (rule.id, rule.attack_type, rule.regex, rule.description) == (
        f"custom-{approved}", "command_injection", r"zz-marker-\d+", CUSTOM_DESCRIPTION)
    (hit,) = scan({"query": "x=ZZ-MARKER-7"}, [rule])
    assert hit.rule_id == f"custom-{approved}"


def test_every_short_type_maps_to_a_rule_type(store):
    for i, short in enumerate(("sqli", "xss", "traversal", "cmdi")):
        store.approve(store.add_proposal(pattern=f"marker-{i}", attack_type=short))
    assert [r.attack_type for r in custom_rules(store)] == [
        "sql_injection", "xss", "path_traversal", "command_injection"]


def test_bad_approved_proposals_are_skipped(store, caplog):
    for pattern, attack_type in [("(broken", "xss"), ("good-one", "rce"), ("good-two", "sqli")]:
        store.approve(store.add_proposal(pattern=pattern, attack_type=attack_type))
    assert [r.regex for r in custom_rules(store)] == ["good-two"]
    assert "skipping rule custom-1" in caplog.text and "skipping rule custom-2" in caplog.text


def test_no_approved_proposals_gives_no_custom_rules(store):
    assert custom_rules(store) == []


def test_unreadable_store_gives_no_custom_rules(caplog):
    class Broken:
        def proposals(self, status=None):
            raise OSError("disk gone")

    assert custom_rules(Broken()) == []
    assert "using built-in rules only" in caplog.text
