"""Synthetic CloudTrail event producer for the audit-events Kafka topic."""

from __future__ import annotations

import asyncio
import os
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

from aiokafka import AIOKafkaProducer

_SRC = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from models import CloudAuditEvent, UserIdentity

TOPIC = "audit-events"
BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
INTERVAL_SECONDS = float(os.getenv("PRODUCER_INTERVAL_SECONDS", "2"))

USERS = [
    UserIdentity(type="IAMUser", principalId="AIDAEXAMPLE1", userName="alice"),
    UserIdentity(type="IAMUser", principalId="AIDAEXAMPLE2", userName="bob"),
    UserIdentity(type="AssumedRole", principalId="AROAEXAMPLE3", userName="deploy-bot"),
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_event() -> CloudAuditEvent:
    """Return a mix of compliant and non-compliant CreateBucket / other events."""
    user = random.choice(USERS)
    kind = random.choice(
        [
            "compliant_create",
            "violation_public_read",
            "other_list",
            "compliant_private_acl",
        ]
    )

    if kind == "violation_public_read":
        return CloudAuditEvent(
            eventTime=_now_iso(),
            eventName="CreateBucket",
            requestParameters={"bucketName": "public-logs", "acl": "public-read"},
            userIdentity=user,
        )
    if kind == "compliant_create":
        return CloudAuditEvent(
            eventTime=_now_iso(),
            eventName="CreateBucket",
            requestParameters={"bucketName": "private-data", "acl": "private"},
            userIdentity=user,
        )
    if kind == "compliant_private_acl":
        return CloudAuditEvent(
            eventTime=_now_iso(),
            eventName="CreateBucket",
            requestParameters={"bucketName": "analytics", "acl": "bucket-owner-full-control"},
            userIdentity=user,
        )
    return CloudAuditEvent(
        eventTime=_now_iso(),
        eventName="ListBuckets",
        requestParameters={},
        userIdentity=user,
    )


async def main() -> None:
    producer = AIOKafkaProducer(bootstrap_servers=BOOTSTRAP_SERVERS)
    await producer.start()
    print(f"Producer started → {BOOTSTRAP_SERVERS} topic={TOPIC}")
    try:
        while True:
            event = build_event()
            payload = event.model_dump_json().encode("utf-8")
            await producer.send_and_wait(TOPIC, payload)
            print(f"Published {event.eventName} user={event.userIdentity.userName} "
                  f"acl={event.requestParameters.get('acl', '-')}")
            await asyncio.sleep(INTERVAL_SECONDS)
    finally:
        await producer.stop()


if __name__ == "__main__":
    asyncio.run(main())
