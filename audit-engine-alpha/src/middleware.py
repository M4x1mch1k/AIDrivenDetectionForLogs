"""Async Kafka consumer that validates events and evaluates them against OPA."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import httpx
from aiokafka import AIOKafkaConsumer
from pydantic import ValidationError

_SRC = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from models import CloudAuditEvent

TOPIC = "audit-events"
GROUP_ID = os.getenv("KAFKA_GROUP_ID", "audit-middleware-alpha")
BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
OPA_URL = os.getenv(
    "OPA_URL",
    "http://localhost:8181/v1/data/aws/s3/compliance/deny",
)


async def evaluate_anomalies(event: CloudAuditEvent) -> str:
    """Stub for future LLM / Ollama anomaly detection (alpha: no real calls)."""
    _ = event
    return "LLM Check Bypassed for Alpha"


async def check_opa(client: httpx.AsyncClient, event: CloudAuditEvent) -> list[str]:
    """POST the event as OPA `input`; return deny message strings (empty = allow)."""
    response = await client.post(OPA_URL, json={"input": event.model_dump()})
    response.raise_for_status()
    result = response.json().get("result")
    if not result:
        return []
    if isinstance(result, list):
        return [str(item) for item in result]
    if isinstance(result, str):
        return [result]
    # OPA set may serialize as a JSON array; other shapes treated as a single reason.
    return [str(result)]


async def handle_event(client: httpx.AsyncClient, raw: bytes) -> None:
    try:
        data = json.loads(raw.decode("utf-8"))
        event = CloudAuditEvent.model_validate(data)
    except (json.JSONDecodeError, ValidationError) as exc:
        print(f"Invalid event skipped: {exc}")
        return

    violations = await check_opa(client, event)
    if violations:
        reason = "; ".join(violations)
        print(f"Violation Detected: {reason}")
        return

    print("Event Passed")
    anomaly_note = await evaluate_anomalies(event)
    print(f"  → {anomaly_note}")


async def main() -> None:
    consumer = AIOKafkaConsumer(
        TOPIC,
        bootstrap_servers=BOOTSTRAP_SERVERS,
        group_id=GROUP_ID,
        auto_offset_reset="earliest",
        enable_auto_commit=True,
    )
    await consumer.start()
    print(f"Middleware consuming {TOPIC} from {BOOTSTRAP_SERVERS}")
    print(f"OPA endpoint: {OPA_URL}")
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            async for msg in consumer:
                await handle_event(client, msg.value)
    finally:
        await consumer.stop()


if __name__ == "__main__":
    asyncio.run(main())
