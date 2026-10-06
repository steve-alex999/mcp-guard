import os

import pytest
import yaml
from pydantic import ValidationError

from gateway.config import DEFAULT_POLICY, PolicyConfig, PolicyFile, ScannerPolicy, load_policy


def rewrite(path, text):
    """Write the file and push its mtime forward, so the change is seen even on a coarse clock."""
    mtime = path.stat().st_mtime_ns
    path.write_text(text)
    os.utime(path, ns=(mtime + 10**9, mtime + 10**9))


def test_policy_yaml_matches_the_spec():
    config = load_policy(DEFAULT_POLICY)
    assert config.clients["untrusted-agent"].tools == ["search_change_records", "get_asset"]
    assert "disable_account" not in config.clients["eval-agent"].tools
    assert config.approval_required == ["disable_account", "quarantine_host"]
    assert config.approval_timeout_s == 120
    assert config.protected_account_tags == ["admin", "service"]
    assert config.rate_limit_per_minute == 30
    assert config.scanner.mode == "redact"


def test_rejects_unknown_tools_and_fields():
    with pytest.raises(ValidationError, match="Unknown tools: rm_rf"):
        PolicyConfig.model_validate({"clients": {"a": {"tools": ["rm_rf"]}}})
    with pytest.raises(ValidationError, match="aproval_required"):
        PolicyConfig.model_validate({"clients": {}, "aproval_required": []})


def test_reloads_when_the_file_changes(policy_path):
    policy = PolicyFile(policy_path)
    assert policy.current().rate_limit_per_minute == 30
    data = yaml.safe_load(policy_path.read_text())
    rewrite(policy_path, yaml.safe_dump(data | {"rate_limit_per_minute": 5}))
    assert policy.current().rate_limit_per_minute == 5


def test_keeps_the_last_good_policy_when_the_file_breaks(policy_path):
    policy = PolicyFile(policy_path)
    rewrite(policy_path, "clients: [not, a, mapping]")
    assert policy.current().rate_limit_per_minute == 30


def test_save_round_trips(policy_path):
    policy = PolicyFile(policy_path)
    config = policy.current().model_copy(update={"scanner": ScannerPolicy(mode="envelope")})
    policy.save(config)
    assert load_policy(policy_path) == config
    assert PolicyFile(policy_path).current().scanner.mode == "envelope"
