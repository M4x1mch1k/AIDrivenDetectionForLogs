"""Unit and e2e-routing tests for the MVP audit pipeline (mocked httpx + temp SQLite)."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from config import Settings
from llm_client import OllamaAnomalyClient, parse_llm_json
from models import (
    AnomalyAssessmentResult,
    AnomalyReportRecord,
    CloudAuditEvent,
    PolicyViolationRecord,
    UserIdentity,
)
from middleware import AuditMiddleware
from opa_client import OpaClient
from storage import AuditStorage


def _event(
    name: str = "ListBuckets",
    user: str = "alice",
    params: dict | None = None,
) -> CloudAuditEvent:
    return CloudAuditEvent(
        eventTime="2026-11-23T12:00:00Z",
        eventName=name,
        requestParameters=params or {},
        userIdentity=UserIdentity(
            type="IAMUser",
            principalId="AIDA1",
            userName=user,
        ),
        sourceIPAddress="10.0.0.1",
        awsRegion="us-east-1",
    )


class TestModels:
    def test_cloud_audit_event_defaults(self) -> None:
        event = CloudAuditEvent(
            eventTime="2026-11-23T12:00:00Z",
            eventName="ListBuckets",
            userIdentity=UserIdentity(
                type="IAMUser", principalId="1", userName="alice"
            ),
        )
        assert event.sourceIPAddress == "127.0.0.1"
        assert event.awsRegion == "us-east-1"
        assert event.eventVersion == "1.08"

    def test_anomaly_assessment_clamps_risk_score(self) -> None:
        high = AnomalyAssessmentResult(
            is_anomalous=True,
            risk_score=1.5,
            anomaly_type="x",
            incident_summary="s",
        )
        low = AnomalyAssessmentResult(
            is_anomalous=False,
            risk_score=-0.2,
            anomaly_type="y",
            incident_summary="s",
        )
        assert high.risk_score == 1.0
        assert low.risk_score == 0.0


class TestStorage:
    def test_record_violation_and_anomaly_and_summary(self, tmp_path: Path) -> None:
        db = tmp_path / "audit.db"
        store = AuditStorage(str(db))
        try:
            vid = store.record_violation(
                PolicyViolationRecord(
                    event_time="2026-11-23T12:00:00Z",
                    event_name="CreateBucket",
                    user_name="alice",
                    policy_path="/v1/data/aws/s3/compliance/deny",
                    message="denied",
                    latency_ms=1.5,
                    raw_event_json="{}",
                )
            )
            aid = store.record_anomaly_report(
                AnomalyReportRecord(
                    created_at="2026-11-23T12:01:00Z",
                    window_size=2,
                    is_anomalous=True,
                    risk_score=0.9,
                    anomaly_type="privilege_escalation",
                    incident_summary="suspicious",
                    fallback_used=False,
                    window_event_names="AssumeRole,ListUsers",
                    window_user_names="bob,bob",
                )
            )
            assert vid >= 1
            assert aid >= 1
            summary = store.get_recent_summary()
            assert summary["violation_count"] == 1
            assert summary["anomaly_report_count"] == 1
            assert summary["anomalous_count"] == 1
            assert summary["recent_violations"][0]["user_name"] == "alice"
            assert summary["recent_anomalies"][0]["anomaly_type"] == "privilege_escalation"
        finally:
            store.close()


class TestLlmParseAndFallback:
    def test_parse_plain_json(self) -> None:
        result = parse_llm_json(
            '{"is_anomalous": true, "risk_score": 0.8, '
            '"anomaly_type": "recon", "incident_summary": "odd sequence"}'
        )
        assert result.is_anomalous is True
        assert result.risk_score == 0.8
        assert result.fallback_used is False
        assert result.anomaly_type == "recon"

    def test_parse_fenced_json(self) -> None:
        raw = (
            "Here you go:\n```json\n"
            '{"is_anomalous": false, "risk_score": 0.1, '
            '"anomaly_type": "none", "incident_summary": "ok"}\n```'
        )
        result = parse_llm_json(raw)
        assert result.is_anomalous is False
        assert result.anomaly_type == "none"

    @pytest.mark.asyncio
    async def test_assess_window_fallback_on_http_error(self) -> None:
        transport = httpx.MockTransport(
            lambda request: httpx.Response(500, text="boom")
        )
        async with httpx.AsyncClient(transport=transport) as client:
            llm = OllamaAnomalyClient(
                base_url="http://ollama.test",
                model="llama3.2",
                client=client,
            )
            result = await llm.assess_window([_event()])
        assert result.fallback_used is True
        assert result.is_anomalous is False
        assert result.risk_score == 0.0
        assert result.anomaly_type == "llm_unavailable_or_unparsed"

    @pytest.mark.asyncio
    async def test_assess_window_fallback_on_unparsed(self) -> None:
        transport = httpx.MockTransport(
            lambda request: httpx.Response(
                200, json={"response": "not-json-at-all"}
            )
        )
        async with httpx.AsyncClient(transport=transport) as client:
            llm = OllamaAnomalyClient(
                base_url="http://ollama.test",
                model="llama3.2",
                client=client,
            )
            result = await llm.assess_window([_event()])
        assert result.fallback_used is True
        assert result.anomaly_type == "llm_unavailable_or_unparsed"


class TestOpaClient:
    @pytest.mark.asyncio
    async def test_multi_path_aggregate(self) -> None:
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(str(request.url.path))
            if request.url.path.endswith("/aws/s3/compliance/deny"):
                return httpx.Response(200, json={"result": ["s3 deny"]})
            if request.url.path.endswith("/aws/iam_kms/compliance/deny"):
                return httpx.Response(200, json={"result": []})
            return httpx.Response(404, json={"error": "missing"})

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            opa = OpaClient(
                base_url="http://opa.test",
                deny_paths=[
                    "/v1/data/aws/s3/compliance/deny",
                    "/v1/data/aws/iam_kms/compliance/deny",
                ],
                client=client,
            )
            violations = await opa.evaluate(
                _event(
                    "CreateBucket",
                    params={"acl": "public-read", "bucketName": "x"},
                )
            )
        assert len(violations) == 1
        assert violations[0]["message"] == "s3 deny"
        assert "latency_ms" in violations[0]
        assert len(calls) == 2


class TestE2ERouting:
    @pytest.mark.asyncio
    async def test_violation_does_not_call_llm(self, tmp_path: Path) -> None:
        settings = Settings(
            SQLITE_DB_PATH=str(tmp_path / "mvp.db"),
            LLM_WINDOW_SIZE=5,
            OPA_URL="http://opa.test",
            OPA_DENY_PATHS=["/v1/data/aws/s3/compliance/deny"],
            OLLAMA_BASE_URL="http://ollama.test",
            OLLAMA_MODEL="llama3.2",
        )
        mw = AuditMiddleware(settings=settings)
        mw.opa = MagicMock()
        mw.opa.evaluate = AsyncMock(
            return_value=[
                {
                    "policy_path": "/v1/data/aws/s3/compliance/deny",
                    "message": "denied public-read",
                    "latency_ms": 2.0,
                }
            ]
        )
        mw.llm = MagicMock()
        mw.llm.assess_window = AsyncMock()

        event = _event(
            "CreateBucket",
            params={"bucketName": "public-logs", "acl": "public-read"},
        )
        await mw.handle_event(event.model_dump_json().encode("utf-8"))

        summary = mw.storage.get_recent_summary()
        assert summary["violation_count"] == 1
        assert summary["anomaly_report_count"] == 0
        mw.llm.assess_window.assert_not_called()
        mw.storage.close()

    @pytest.mark.asyncio
    async def test_compliant_triggers_async_llm_and_db(self, tmp_path: Path) -> None:
        settings = Settings(
            SQLITE_DB_PATH=str(tmp_path / "mvp.db"),
            LLM_WINDOW_SIZE=5,
            OPA_URL="http://opa.test",
            OPA_DENY_PATHS=["/v1/data/aws/s3/compliance/deny"],
            OLLAMA_BASE_URL="http://ollama.test",
            OLLAMA_MODEL="llama3.2",
        )
        mw = AuditMiddleware(settings=settings)
        mw.opa = MagicMock()
        mw.opa.evaluate = AsyncMock(return_value=[])
        mw.llm = MagicMock()
        mw.llm.assess_window = AsyncMock(
            return_value=AnomalyAssessmentResult(
                is_anomalous=True,
                risk_score=0.75,
                anomaly_type="suspicious_sequence",
                incident_summary="bob recon then key create",
                fallback_used=False,
            )
        )

        event = _event("ListBuckets", user="bob")
        await mw.handle_event(event.model_dump_json().encode("utf-8"))
        assert len(mw._llm_tasks) == 1
        await asyncio.gather(*mw._llm_tasks)

        summary = mw.storage.get_recent_summary()
        assert summary["violation_count"] == 0
        assert summary["anomaly_report_count"] == 1
        assert summary["anomalous_count"] == 1
        assert summary["recent_anomalies"][0]["anomaly_type"] == "suspicious_sequence"
        mw.llm.assess_window.assert_awaited()
        mw.storage.close()


def test_settings_deny_paths_csv() -> None:
    settings = Settings(
        OPA_DENY_PATHS="/v1/data/a,/v1/data/b",
    )
    assert settings.opa_deny_paths == ["/v1/data/a", "/v1/data/b"]
    assert settings.kafka_auto_offset_reset == "earliest"
    assert settings.llm_window_size == 5
