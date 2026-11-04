import pytest

from caziel import iam


def ps(*statements):
    return iam.PolicySet([{"Version": "2012-10-17", "Statement": list(statements)}])


def test_wildcards_and_case():
    p = ps({"Effect": "Allow", "Action": "IoT:Pub*", "Resource": "arn:aws:iot:*:*:topic/fleet/*"})
    assert p.allows("iot:Publish", "arn:aws:iot:us-west-2:1:topic/fleet/kx1-01/cmd/velocity")
    assert not p.allows("iot:Subscribe", "arn:aws:iot:us-west-2:1:topic/fleet/x")
    # ARNs are case-sensitive
    assert not p.allows("iot:Publish", "arn:aws:iot:us-west-2:1:topic/FLEET/x")


def test_question_mark_matches_one_character():
    p = ps({"Effect": "Allow", "Action": "iot:Publish", "Resource": "t/kx1-0?"})
    assert p.allows("iot:Publish", "t/kx1-07")
    assert not p.allows("iot:Publish", "t/kx1-10")


def test_explicit_deny_wins():
    p = ps(
        {"Effect": "Allow", "Action": "iot:*", "Resource": "*"},
        {"Effect": "Deny", "Action": "iot:Publish", "Resource": "t/fleet/*/cmd/velocity"},
    )
    assert not p.allows("iot:Publish", "t/fleet/a/cmd/velocity")
    assert p.allows("iot:Publish", "t/fleet/a/cmd/navigate")


def test_not_resource_and_not_action():
    p = ps(
        {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
        {"Effect": "Deny", "Action": "iot:Publish", "NotResource": ["t/ok"]},
    )
    assert p.allows("iot:Publish", "t/ok")
    assert not p.allows("iot:Publish", "t/other")
    assert not p.allows("iam:PassRole", "*")


def test_conditions_are_treated_conservatively():
    allow_if = ps({"Effect": "Allow", "Action": "iot:Publish", "Resource": "*", "Condition": {"Bool": {"x": "true"}}})
    d = allow_if.evaluate("iot:Publish", "t")
    assert d.allowed and d.conditional
    # A conditional deny might not fire, so it does not remove reach.
    deny_if = ps(
        {"Effect": "Allow", "Action": "iot:Publish", "Resource": "*"},
        {"Effect": "Deny", "Action": "iot:Publish", "Resource": "*", "Condition": {"Bool": {"x": "true"}}},
    )
    d = deny_if.evaluate("iot:Publish", "t")
    assert d.allowed and d.conditional


def test_single_statement_dict_and_empty_statement():
    p = iam.PolicySet([{"Statement": {"Effect": "Allow", "Action": "a:b", "Resource": "r"}}])
    assert p.allows("a:b", "r")
    s = iam.Statement.from_dict({"Effect": "Allow"})
    assert not s.applies("a:b", "r")


def test_invalid_effect():
    with pytest.raises(ValueError):
        ps({"Effect": "Maybe", "Action": "*", "Resource": "*"})
