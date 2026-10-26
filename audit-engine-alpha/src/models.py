"""Pydantic v2 models for a simplified AWS CloudTrail audit event."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


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
