import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from gateway.audit import AuditLog, CallRecord, connect, new_id, timestamp


def call(**overrides):
    fields = dict(id=new_id(), ts=timestamp(), client_id="eval-agent", tool="get_asset",
                  args={"hostname": "web-prod-01"}, decision="ALLOW", reason="ok",
                  output={"hostname": "web-prod-01"}, latency_ms=1.5)
    return CallRecord(**(fields | overrides))


def minutes_ago(n):
    return timestamp(datetime.now(UTC) - timedelta(minutes=n))


def test_round_trip(db):
    audit = AuditLog(db)
    record = call(args={"hostname": 42, "extra": ["x"]}, decision="BLOCK_SCHEMA", output=None,
                  findings=[{"field": "description", "rule": "ignore_previous"}])
    audit.record(record)
    assert audit.get(record.id) == record
    assert audit.get("missing") is None


def test_recent_is_newest_first_and_filters(db):
    audit = AuditLog(db)
    old = call(ts=minutes_ago(5))
    blocked = call(decision="BLOCK_NOT_ALLOWED", client_id="untrusted-agent")
    new = call()
    for record in (old, blocked, new):
        audit.record(record)
    assert [c.id for c in audit.recent()] == [new.id, blocked.id, old.id]
    assert [c.id for c in audit.recent(decision="BLOCK_NOT_ALLOWED")] == [blocked.id]
    assert [c.id for c in audit.recent(client_id="eval-agent")] == [new.id, old.id]
    assert [c.id for c in audit.recent(limit=1)] == [new.id]


def test_calls_are_append_only(db):
    audit = AuditLog(db)
    record = call()
    audit.record(record)
    with connect(db) as conn:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("UPDATE calls SET decision = 'BLOCK_RULE'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("DELETE FROM calls")
    assert audit.get(record.id) == record


def test_count_since(db):
    audit = AuditLog(db)
    for record in (call(ts=minutes_ago(2)), call(), call(decision="BLOCK_RATE"), call(client_id="other")):
        audit.record(record)
    assert audit.count_since("eval-agent", 60) == 2
