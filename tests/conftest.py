import shutil

import pytest
from pydantic import ValidationError
from qdrant_client import QdrantClient

from gateway.actions import Actions
from gateway.approvals import ApprovalQueue
from gateway.audit import AuditLog
from gateway.config import DEFAULT_POLICY, PolicyFile
from gateway.policy import PolicyResult
from gateway.server import Gateway
from gateway.tools import TOOLS
from triage.data import load_alerts
from triage.embeddings import HashEmbedder
from triage.tools import Toolbox


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="session")
def toolbox():
    return Toolbox.load(QdrantClient(":memory:"), HashEmbedder())


@pytest.fixture(scope="session")
def alert_ids():
    return {a.alert.id for a in load_alerts()}


@pytest.fixture
def policy_path(tmp_path):
    path = tmp_path / "policy.yaml"
    shutil.copy(DEFAULT_POLICY, path)
    return path


@pytest.fixture
def db(tmp_path):
    return tmp_path / "guard.db"


def permissive_check(call, config, context):
    """Stands in for policy.check in tests of the gateway rather than the policy: any known tool
    with valid arguments is allowed, and approval follows config.approval_required."""
    spec = TOOLS.get(call.tool)
    if spec is None:
        return PolicyResult("BLOCK_NOT_ALLOWED", f"Unknown tool {call.tool}")
    try:
        args = spec.args.model_validate(call.args)
    except ValidationError as e:
        return PolicyResult("BLOCK_SCHEMA", str(e))
    return PolicyResult("ALLOW", "Allowed by the test policy", args=args,
                        needs_approval=call.tool in config.approval_required)


@pytest.fixture
def gateway(toolbox, alert_ids, policy_path, db):
    return Gateway(
        toolbox, Actions(db, alert_ids, toolbox.identities, toolbox.assets), PolicyFile(policy_path),
        AuditLog(db), ApprovalQueue(db, poll_interval_s=0.02), check=permissive_check,
    )
