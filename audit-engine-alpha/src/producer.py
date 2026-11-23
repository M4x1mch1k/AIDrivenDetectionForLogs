"""Cyclic synthetic CloudTrail event producer for the audit-events Kafka topic."""

from __future__ import annotations

import asyncio
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from aiokafka import AIOKafkaProducer

_SRC = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from config import get_settings
from models import CloudAuditEvent, UserIdentity

ALICE = UserIdentity(type="IAMUser", principalId="AIDAEXAMPLE1", userName="alice")
BOB = UserIdentity(type="IAMUser", principalId="AIDAEXAMPLE2", userName="bob")
ADMIN = UserIdentity(type="IAMUser", principalId="AIDAEXAMPLE3", userName="admin")
DEPLOY = UserIdentity(type="AssumedRole", principalId="AROAEXAMPLE4", userName="deploy-bot")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _compliant_list_buckets() -> tuple[CloudAuditEvent, str]:
    return (
        CloudAuditEvent(
            eventTime=_now_iso(),
            eventName="ListBuckets",
            requestParameters={},
            userIdentity=ALICE,
            sourceIPAddress="10.0.0.10",
            awsRegion="us-east-1",
        ),
        "compliant",
    )


def _violation_public_read_bucket() -> tuple[CloudAuditEvent, str]:
    return (
        CloudAuditEvent(
            eventTime=_now_iso(),
            eventName="CreateBucket",
            requestParameters={"bucketName": "public-logs", "acl": "public-read"},
            userIdentity=ALICE,
            sourceIPAddress="10.0.0.10",
            awsRegion="us-east-1",
        ),
        "policy_violation_s3_public_read",
    )


def _violation_create_access_key_admin() -> tuple[CloudAuditEvent, str]:
    return (
        CloudAuditEvent(
            eventTime=_now_iso(),
            eventName="CreateAccessKey",
            requestParameters={"status": "Active", "userName": "admin"},
            userIdentity=ADMIN,
            sourceIPAddress="10.0.0.20",
            awsRegion="us-east-1",
        ),
        "policy_violation_iam_create_access_key",
    )


def _violation_create_db_unencrypted() -> tuple[CloudAuditEvent, str]:
    return (
        CloudAuditEvent(
            eventTime=_now_iso(),
            eventName="CreateDbInstance",
            requestParameters={
                "dbInstanceIdentifier": "prod-db",
                "storageEncrypted": False,
                "kmsKeyId": "",
            },
            userIdentity=DEPLOY,
            sourceIPAddress="10.0.0.30",
            awsRegion="eu-west-1",
        ),
        "policy_violation_kms_db_unencrypted",
    )


def _suspicious_bob_assume_role() -> tuple[CloudAuditEvent, str]:
    return (
        CloudAuditEvent(
            eventTime=_now_iso(),
            eventName="AssumeRole",
            requestParameters={"roleArn": "arn:aws:iam::123456789012:role/AuditReader"},
            userIdentity=BOB,
            sourceIPAddress="203.0.113.50",
            awsRegion="us-east-1",
        ),
        "suspicious_bob_sequence",
    )


def _suspicious_bob_list_users() -> tuple[CloudAuditEvent, str]:
    return (
        CloudAuditEvent(
            eventTime=_now_iso(),
            eventName="ListUsers",
            requestParameters={},
            userIdentity=BOB,
            sourceIPAddress="203.0.113.50",
            awsRegion="us-east-1",
        ),
        "suspicious_bob_sequence",
    )


def _suspicious_bob_get_secret() -> tuple[CloudAuditEvent, str]:
    return (
        CloudAuditEvent(
            eventTime=_now_iso(),
            eventName="GetSecretValue",
            requestParameters={"secretId": "prod/db/password"},
            userIdentity=BOB,
            sourceIPAddress="203.0.113.50",
            awsRegion="us-east-1",
        ),
        "suspicious_bob_sequence",
    )


def _suspicious_bob_create_access_key_with_kms() -> tuple[CloudAuditEvent, str]:
    """CreateAccessKey for bob (non-privileged) with kms so OPA IAM deny stays empty."""
    return (
        CloudAuditEvent(
            eventTime=_now_iso(),
            eventName="CreateAccessKey",
            requestParameters={
                "status": "Inactive",
                "userName": "bob",
                "kmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
            },
            userIdentity=BOB,
            sourceIPAddress="203.0.113.50",
            awsRegion="us-east-1",
        ),
        "suspicious_bob_sequence",
    )


SCENARIO_BUILDERS: list[Callable[[], tuple[CloudAuditEvent, str]]] = [
    _compliant_list_buckets,
    _violation_public_read_bucket,
    _violation_create_access_key_admin,
    _violation_create_db_unencrypted,
    _suspicious_bob_assume_role,
    _suspicious_bob_list_users,
    _suspicious_bob_get_secret,
    _suspicious_bob_create_access_key_with_kms,
]


async def main() -> None:
    settings = get_settings()
    producer = AIOKafkaProducer(bootstrap_servers=settings.kafka_bootstrap_servers)
    await producer.start()
    stop_event = asyncio.Event()

    def _request_stop(*_args: object) -> None:
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _request_stop)

    print(
        f"Producer started → {settings.kafka_bootstrap_servers} "
        f"topic={settings.kafka_audit_topic}"
    )
    index = 0
    try:
        while not stop_event.is_set():
            builder = SCENARIO_BUILDERS[index % len(SCENARIO_BUILDERS)]
            event, scenario = builder()
            payload = event.model_dump_json().encode("utf-8")
            await producer.send_and_wait(settings.kafka_audit_topic, payload)
            print(
                f"Published eventName={event.eventName} "
                f"userName={event.userIdentity.userName} scenario={scenario}"
            )
            index += 1
            try:
                await asyncio.wait_for(
                    stop_event.wait(),
                    timeout=settings.producer_interval_seconds,
                )
            except asyncio.TimeoutError:
                continue
    finally:
        await producer.stop()
        print("Producer stopped")


if __name__ == "__main__":
    asyncio.run(main())
