"""Async Kafka consumer: validate → OPA → SQLite; clean events → LLM window analysis."""

from __future__ import annotations

import asyncio
import json
import signal
import sys
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

_SRC = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from aiokafka import AIOKafkaConsumer

from config import Settings, get_settings
from llm_client import OllamaAnomalyClient
from models import (
    AnomalyReportRecord,
    CloudAuditEvent,
    PolicyViolationRecord,
)
from opa_client import OpaClient
from storage import AuditStorage


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AuditMiddleware:
    """Event-driven audit pipeline with OPA-first routing and async LLM analysis."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.storage = AuditStorage(self.settings.sqlite_db_path)
        self.opa = OpaClient(
            base_url=self.settings.opa_url,
            deny_paths=self.settings.opa_deny_paths,
        )
        self.llm = OllamaAnomalyClient(
            base_url=self.settings.ollama_base_url,
            model=self.settings.ollama_model,
            timeout_seconds=self.settings.ollama_timeout_seconds,
        )
        self.window: deque[CloudAuditEvent] = deque(
            maxlen=self.settings.llm_window_size
        )
        self._llm_tasks: set[asyncio.Task[None]] = set()
        self._stop = asyncio.Event()
        self._consumer: AIOKafkaConsumer | None = None

    def request_stop(self) -> None:
        self._stop.set()

    def _track_task(self, task: asyncio.Task[None]) -> None:
        self._llm_tasks.add(task)
        task.add_done_callback(self._llm_tasks.discard)

    async def _run_llm_analysis(self, snapshot: list[CloudAuditEvent]) -> None:
        result = await self.llm.assess_window(snapshot)
        record = AnomalyReportRecord(
            created_at=_now_iso(),
            window_size=len(snapshot),
            is_anomalous=result.is_anomalous,
            risk_score=result.risk_score,
            anomaly_type=result.anomaly_type,
            incident_summary=result.incident_summary,
            fallback_used=result.fallback_used,
            window_event_names=",".join(event.eventName for event in snapshot),
            window_user_names=",".join(
                event.userIdentity.userName for event in snapshot
            ),
        )
        report_id = self.storage.record_anomaly_report(record)
        flag = "ANOMALY" if result.is_anomalous else "benign"
        fallback = " fallback" if result.fallback_used else ""
        print(
            f"LLM assessment id={report_id} {flag}{fallback} "
            f"type={result.anomaly_type} risk={result.risk_score:.2f} "
            f"summary={result.incident_summary}"
        )

    async def handle_event(self, raw: bytes) -> None:
        try:
            data = json.loads(raw.decode("utf-8"))
            event = CloudAuditEvent.model_validate(data)
        except (json.JSONDecodeError, ValidationError, UnicodeDecodeError) as exc:
            print(f"Invalid event skipped: {exc}")
            return

        violations = await self.opa.evaluate(event)
        if violations:
            for item in violations:
                record = PolicyViolationRecord(
                    event_time=event.eventTime,
                    event_name=event.eventName,
                    user_name=event.userIdentity.userName,
                    policy_path=item["policy_path"],
                    message=item["message"],
                    latency_ms=float(item["latency_ms"]),
                    raw_event_json=event.model_dump_json(),
                )
                row_id = self.storage.record_violation(record)
                print(
                    f"Violation Detected id={row_id} "
                    f"path={item['policy_path']} latency_ms={item['latency_ms']}: "
                    f"{item['message']}"
                )
            return

        print(
            f"Event Passed eventName={event.eventName} "
            f"userName={event.userIdentity.userName}"
        )
        self.window.append(event)
        snapshot = list(self.window)
        task = asyncio.create_task(self._run_llm_analysis(snapshot))
        self._track_task(task)

    async def run(self) -> None:
        consumer = AIOKafkaConsumer(
            self.settings.kafka_audit_topic,
            bootstrap_servers=self.settings.kafka_bootstrap_servers,
            group_id=self.settings.kafka_consumer_group,
            auto_offset_reset=self.settings.kafka_auto_offset_reset,
            enable_auto_commit=True,
        )
        self._consumer = consumer
        await consumer.start()
        print(
            f"Middleware consuming {self.settings.kafka_audit_topic} "
            f"from {self.settings.kafka_bootstrap_servers}"
        )
        print(f"OPA base: {self.settings.opa_url} paths={self.settings.opa_deny_paths}")
        print(
            f"Ollama: {self.settings.ollama_base_url} model={self.settings.ollama_model}"
        )
        print(f"SQLite: {self.settings.sqlite_db_path}")

        try:
            while not self._stop.is_set():
                batch = await consumer.getmany(timeout_ms=500, max_records=20)
                if not batch:
                    continue
                for _tp, messages in batch.items():
                    for msg in messages:
                        if self._stop.is_set():
                            break
                        await self.handle_event(msg.value)
        finally:
            if self._llm_tasks:
                await asyncio.gather(*self._llm_tasks, return_exceptions=True)
            await consumer.stop()
            await self.opa.aclose()
            await self.llm.aclose()
            self.storage.close()
            print("Middleware stopped")


async def main() -> None:
    middleware = AuditMiddleware()
    loop = asyncio.get_running_loop()

    def _on_signal() -> None:
        print("Shutdown signal received")
        middleware.request_stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _on_signal)

    await middleware.run()


if __name__ == "__main__":
    asyncio.run(main())
