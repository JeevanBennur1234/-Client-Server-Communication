from server.security_monitor import SecurityMonitor


def test_repeated_failures_trigger_temporary_ip_block(tmp_path):
    monitor = SecurityMonitor(tmp_path / "events.jsonl", threshold=3, window_seconds=60, block_seconds=30)
    for _ in range(3):
        event = monitor.record("LOGIN_FAILED", "192.0.2.10", "demo", "invalid credentials")
    assert event["severity"] == "CRITICAL"
    assert event["action"] == "TEMP_BLOCK_30s"
    blocked, remaining = monitor.is_blocked("192.0.2.10")
    assert blocked is True
    assert remaining > 0


def test_benign_event_does_not_block_ip(tmp_path):
    monitor = SecurityMonitor(tmp_path / "events.jsonl", threshold=2)
    monitor.record("LOGIN_SUCCESS", "192.0.2.11", "alice")
    assert monitor.is_blocked("192.0.2.11") == (False, 0)


def test_event_log_excludes_secrets_and_marks_simulation(tmp_path):
    monitor = SecurityMonitor(tmp_path / "events.jsonl")
    monitor.record("LOGIN_FAILED", "127.0.0.1", "demo", "password omitted", simulated=True)
    content = (tmp_path / "events.jsonl").read_text(encoding="utf-8")
    assert "simulated" in content
    assert "password omitted" in content
