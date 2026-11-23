"""Pydantic v2 models for CloudTrail-like audit events and detection records."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class UserIdentity(BaseModel):
    type: str
    principalId: str
    userName: str


class CloudAuditEvent(BaseModel):
    eventVersion: str = "1.08"
    eventTime: str
    eventName: str
    requestParameters: dict[str, Any] = Field(default_factory=dict)
    userIdentity: UserIdentity
    sourceIPAddress: Optional[str] = "127.0.0.1"
    awsRegion: Optional[str] = "us-east-1"


class PolicyViolationRecord(BaseModel):
    """Persisted OPA policy violation for a single audit event."""

    event_time: str
    event_name: str
    user_name: str
    policy_path: str
    message: str
    latency_ms: float
    raw_event_json: str


class AnomalyAssessmentResult(BaseModel):
    """Structured LLM (or fallback) anomaly assessment for an event window."""

    is_anomalous: bool
    risk_score: float
    anomaly_type: str
    incident_summary: str
    fallback_used: bool = False

    @field_validator("risk_score")
    @classmethod
    def _clamp_risk_score(cls, value: float) -> float:
        if value < 0.0:
            return 0.0
        if value > 1.0:
            return 1.0
        return value


class AnomalyReportRecord(BaseModel):
    """Persisted anomaly assessment tied to a sliding event window."""

    created_at: str
    window_size: int
    is_anomalous: bool
    risk_score: float
    anomaly_type: str
    incident_summary: str
    fallback_used: bool
    window_event_names: str
    window_user_names: str
