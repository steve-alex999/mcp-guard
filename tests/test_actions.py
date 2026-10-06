import pytest
from pydantic import ValidationError

from gateway.actions import Actions, CloseAlertArgs, DisableAccountArgs, QuarantineHostArgs
from gateway.audit import connect


@pytest.fixture
def actions(db):
    return Actions(db, alert_ids={"ALR-1"}, accounts={"aditi.gupta"}, hosts={"web-prod-01"})


def recorded(actions):
    with connect(actions.path) as conn:
        return [tuple(r) for r in conn.execute("SELECT tool, target, reason FROM actions")]


def test_each_action_is_recorded(actions):
    actions.close_alert(CloseAlertArgs(alert_id="ALR-1", verdict="benign", reason="Explained by CHG-1"))
    actions.disable_account(DisableAccountArgs(account="aditi.gupta", reason="Phished"))
    output = actions.quarantine_host(QuarantineHostArgs(hostname="web-prod-01", reason="Beaconing"))
    assert (output["tool"], output["target"], output["simulated"]) == ("quarantine_host", "web-prod-01", True)
    assert recorded(actions) == [
        ("close_alert", "ALR-1", "[benign] Explained by CHG-1"),
        ("disable_account", "aditi.gupta", "Phished"),
        ("quarantine_host", "web-prod-01", "Beaconing"),
    ]


def test_unknown_targets_are_errors(actions):
    assert "error" in actions.close_alert(CloseAlertArgs(alert_id="ALR-2", verdict="threat", reason="r"))
    assert "error" in actions.disable_account(DisableAccountArgs(account="nobody", reason="r"))
    assert "error" in actions.quarantine_host(QuarantineHostArgs(hostname="nowhere", reason="r"))
    assert recorded(actions) == []


@pytest.mark.parametrize("build", [
    lambda: DisableAccountArgs(account="aditi.gupta", reason=""),
    lambda: DisableAccountArgs(account="aditi.gupta", reason="x" * 501),
    lambda: CloseAlertArgs(alert_id="ALR-1", verdict="maybe", reason="r"),
    lambda: QuarantineHostArgs(hostname="web-prod-01", reason="r", force=True),
], ids=["empty-reason", "long-reason", "bad-verdict", "extra-field"])
def test_argument_models_are_strict(build):
    with pytest.raises(ValidationError):
        build()
