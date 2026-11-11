import json
from pathlib import Path

import pytest

from proxy.rules import scan

PAYLOADS = json.loads((Path(__file__).parent / "payloads.json").read_text(encoding="utf-8"))
DEFAULTS = {"method": "GET", "path": "/", "query": "", "headers": {}, "body": ""}


def _cases():
    for attack_type, groups in PAYLOADS.items():
        if attack_type.startswith("_"):
            continue
        for kind in ("malicious", "benign"):
            for i, payload in enumerate(groups[kind]):
                yield pytest.param(attack_type, kind, payload, id=f"{attack_type}-{kind}-{i}")


@pytest.mark.parametrize("attack_type, kind, payload", list(_cases()))
def test_rules_against_payloads(attack_type, kind, payload):
    hits = scan({**DEFAULTS, **payload})
    if kind == "malicious":
        assert attack_type in {h.attack_type for h in hits}, f"missed: {payload}"
        assert all(h.rule_id and h.reason for h in hits)
    else:
        assert hits == [], f"false positive: {[(h.rule_id, h.matched) for h in hits]}"
