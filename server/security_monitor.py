"""Runtime intrusion detection, temporary IP blocking, and security event storage.

This module records metadata only: never credentials, message bodies, ciphertext,
file contents, session tokens, or private keys.
"""
from __future__ import annotations

import json
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class SecurityMonitor:
    """Small in-process detector with bounded rolling windows and JSONL events."""

    SUSPICIOUS_EVENTS = {"LOGIN_FAILED", "TLS_FAILED", "HTTP_ON_TLS", "PROTOCOL_INVALID"}

    def __init__(
        self,
        event_path: Path | str,
        *,
        threshold: int = 8,
        window_seconds: int = 60,
        block_seconds: int = 300,
    ) -> None:
        self.event_path = Path(event_path)
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.block_seconds = block_seconds
        self._lock = threading.RLock()
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._blocked_until: dict[str, float] = {}

    def is_blocked(self, ip: str) -> tuple[bool, int]:
        now = time.monotonic()
        with self._lock:
            until = self._blocked_until.get(ip, 0.0)
            if until <= now:
                self._blocked_until.pop(ip, None)
                return False, 0
            return True, max(1, int(until - now))

    def record(
        self,
        event_type: str,
        ip: str,
        username: str = "-",
        details: str = "",
        *,
        simulated: bool = False,
    ) -> dict[str, Any]:
        now = time.time()
        event: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(now, timezone.utc).isoformat(),
            "event": str(event_type)[:48],
            "source_ip": str(ip)[:64],
            "username": str(username)[:64],
            "details": str(details).replace("\\r", " ").replace("\\n", " ")[:240],
            "severity": "INFO",
            "action": "RECORDED",
            "simulated": bool(simulated),
        }

        with self._lock:
            if event_type in self.SUSPICIOUS_EVENTS and ip not in {"-", "", "unknown"}:
                attempts = self._attempts[ip]
                cutoff = time.monotonic() - self.window_seconds
                while attempts and attempts[0] < cutoff:
                    attempts.popleft()
                attempts.append(time.monotonic())
                if len(attempts) >= self.threshold:
                    self._blocked_until[ip] = time.monotonic() + self.block_seconds
                    event["severity"] = "CRITICAL"
                    event["action"] = f"TEMP_BLOCK_{self.block_seconds}s"
                elif event_type in {"TLS_FAILED", "HTTP_ON_TLS"}:
                    event["severity"] = "HIGH"
                    event["action"] = "CONNECTION_REJECTED"
                else:
                    event["severity"] = "MEDIUM"
                    event["action"] = "AUTH_ATTEMPT_REJECTED"

            self.event_path.parent.mkdir(parents=True, exist_ok=True)
            with self.event_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, ensure_ascii=True) + "\\n")
        return event
