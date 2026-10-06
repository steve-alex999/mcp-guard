import pytest
from fastapi.testclient import TestClient

from gateway.admin_api import create_app
from gateway.approvals import ApprovalQueue
from gateway.audit import AuditLog, CallRecord, new_id, timestamp
from gateway.config import load_policy
from gateway.tools import TOOLS

ARGS = {"account": "aditi.gupta", "reason": "Logged in from a known-bad IP"}


@pytest.fixture
def api(db, policy_path):
    return TestClient(create_app(db, policy_path))


def record_call(db, **overrides):
    fields = dict(id=new_id(), ts=timestamp(), client_id="claude-desktop", tool="get_asset",
                  args={"hostname": "web-prod-01"}, decision="ALLOW", reason="ok", latency_ms=2.0)
    call = CallRecord(**(fields | overrides))
    AuditLog(db).record(call)
    return call


def test_lists_calls_newest_first_with_filters(api, db):
    first = record_call(db)
    blocked = record_call(db, decision="BLOCK_NOT_ALLOWED", client_id="untrusted-agent")
    assert [c["id"] for c in api.get("/calls").json()] == [blocked.id, first.id]
    assert [c["id"] for c in api.get("/calls?decision=BLOCK_NOT_ALLOWED").json()] == [blocked.id]
    assert [c["id"] for c in api.get("/calls?client_id=claude-desktop").json()] == [first.id]
    assert api.get("/calls?decision=MAYBE").status_code == 422


def test_call_detail_includes_its_approval(api, db):
    queue = ApprovalQueue(db)
    approval = queue.create("c-1", "claude-desktop", "disable_account", ARGS)
    queue.resolve(approval.id, "approved", by="stephen")
    call = record_call(db, id="c-1", tool="disable_account", args=ARGS, approval_id=approval.id)
    body = api.get(f"/calls/{call.id}").json()
    assert body["args"] == ARGS
    assert (body["approval"]["status"], body["approval"]["resolved_by"]) == ("approved", "stephen")
    assert api.get("/calls/missing").status_code == 404


def test_approve_and_deny(api, db):
    queue = ApprovalQueue(db)
    first = queue.create("c-1", "claude-desktop", "disable_account", ARGS)
    second = queue.create("c-2", "claude-desktop", "quarantine_host", {"hostname": "web-prod-01", "reason": "r"})
    assert [p["id"] for p in api.get("/pending").json()] == [first.id, second.id]

    approved = api.post(f"/pending/{first.id}/approve", json={"by": "stephen", "note": "Ticket SEC-1"}).json()
    assert (approved["status"], approved["resolved_by"], approved["note"]) == ("approved", "stephen", "Ticket SEC-1")
    denied = api.post(f"/pending/{second.id}/deny").json()
    assert (denied["status"], denied["resolved_by"]) == ("denied", "dashboard")

    assert api.get("/pending").json() == []
    assert queue.get(first.id).status == "approved"


def test_resolving_twice_or_unknown(api, db):
    approval = ApprovalQueue(db).create("c-1", "claude-desktop", "disable_account", ARGS)
    assert api.post(f"/pending/{approval.id}/approve").status_code == 200
    assert api.post(f"/pending/{approval.id}/deny").status_code == 409
    assert api.post("/pending/missing/approve").status_code == 404


def test_lists_tools(api):
    tools = api.get("/tools").json()
    assert [t["name"] for t in tools] == list(TOOLS)
    assert {t["name"]: (t["risk"], t["writes"]) for t in tools}["disable_account"] == ("high", True)


def test_get_and_put_policy(api, policy_path):
    policy = api.get("/policy").json()
    assert policy == load_policy(policy_path).model_dump(mode="json")
    policy["scanner"]["mode"] = "envelope"
    policy["approval_required"] = ["disable_account"]
    assert api.put("/policy", json=policy).status_code == 200
    saved = load_policy(policy_path)
    assert (saved.scanner.mode, saved.approval_required) == ("envelope", ["disable_account"])


@pytest.mark.parametrize("change", [
    {"approval_required": ["rm_rf"]}, {"surprise": True}, {"rate_limit_per_minute": 0},
], ids=["unknown-tool", "unknown-field", "zero-rate"])
def test_rejects_an_invalid_policy(api, policy_path, change):
    before = policy_path.read_text()
    assert api.put("/policy", json=api.get("/policy").json() | change).status_code == 422
    assert policy_path.read_text() == before


def test_dashboard_origin_is_allowed(api):
    response = api.options("/pending", headers={
        "Origin": "http://localhost:3000", "Access-Control-Request-Method": "POST",
    })
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"
