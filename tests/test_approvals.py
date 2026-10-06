import anyio
import pytest

from gateway.approvals import ApprovalClosed, ApprovalQueue, UnknownApproval

pytestmark = pytest.mark.anyio

ARGS = {"account": "aditi.gupta", "reason": "Logged in from a known-bad IP"}


@pytest.fixture
def queue(db):
    return ApprovalQueue(db, poll_interval_s=0.01)


def create(queue):
    return queue.create("call-1", "claude-desktop", "disable_account", ARGS)


async def test_new_approvals_are_pending(queue):
    approval = create(queue)
    assert (approval.status, approval.tool, approval.args) == ("pending", "disable_account", ARGS)
    assert queue.pending() == [approval]
    assert queue.get(approval.id) == approval


async def test_resolve(queue):
    approval = create(queue)
    resolved = queue.resolve(approval.id, "denied", by="stephen", note="Not without a ticket")
    assert (resolved.status, resolved.resolved_by, resolved.note) == ("denied", "stephen", "Not without a ticket")
    assert resolved.resolved_ts
    assert queue.pending() == []


async def test_resolves_only_once(queue):
    approval = create(queue)
    queue.resolve(approval.id, "approved", by="stephen")
    with pytest.raises(ApprovalClosed):
        queue.resolve(approval.id, "denied", by="someone-else")
    assert queue.get(approval.id).status == "approved"


async def test_unknown_approval(queue):
    with pytest.raises(UnknownApproval):
        queue.resolve("missing", "approved", by="stephen")


async def test_wait_sees_a_resolution_made_elsewhere(queue):
    approval = create(queue)
    admin = ApprovalQueue(queue.path)  # separate connections, as the admin API process has

    async def approve_soon():
        await anyio.sleep(0.05)
        admin.resolve(approval.id, "approved", by="dashboard")

    async with anyio.create_task_group() as tg:
        tg.start_soon(approve_soon)
        result = await queue.wait(approval.id, timeout_s=5)
    assert (result.status, result.resolved_by) == ("approved", "dashboard")


async def test_wait_times_out(queue):
    approval = create(queue)
    ticks = []

    async def on_tick(waited):
        ticks.append(waited)

    result = await queue.wait(approval.id, timeout_s=0.05, on_tick=on_tick)
    assert (result.status, result.resolved_by) == ("timeout", "gateway")
    assert ticks
    with pytest.raises(ApprovalClosed):
        queue.resolve(approval.id, "approved", by="too-late")
