"""Ollama-backed anomaly assessment client with strict JSON parsing and fallback."""

from __future__ import annotations

import json
import re
from typing import Any, Sequence

import httpx

from models import AnomalyAssessmentResult, CloudAuditEvent

_FENCE_RE = re.compile(
    r"```(?:json)?\s*(\{.*?\})\s*```",
    re.DOTALL | re.IGNORECASE,
)


def _fallback_result(reason: str) -> AnomalyAssessmentResult:
    return AnomalyAssessmentResult(
        is_anomalous=False,
        risk_score=0.0,
        anomaly_type="llm_unavailable_or_unparsed",
        incident_summary=reason,
        fallback_used=True,
    )


def build_anomaly_prompt(events: Sequence[CloudAuditEvent]) -> str:
    """Build a strict-JSON instruction prompt for the sliding event window."""
    window = [
        {
            "eventTime": event.eventTime,
            "eventName": event.eventName,
            "userName": event.userIdentity.userName,
            "userType": event.userIdentity.type,
            "sourceIPAddress": event.sourceIPAddress,
            "awsRegion": event.awsRegion,
            "requestParameters": event.requestParameters,
        }
        for event in events
    ]
    return (
        "You are a cloud security analyst. Assess whether the following recent "
        "AWS CloudTrail-like events form a suspicious sequence.\n"
        "Respond with ONLY a single JSON object (no markdown, no prose) using "
        "exactly these keys:\n"
        '  "is_anomalous": boolean,\n'
        '  "risk_score": number between 0 and 1,\n'
        '  "anomaly_type": short string label,\n'
        '  "incident_summary": one or two sentence explanation\n\n'
        f"Events JSON:\n{json.dumps(window, indent=2)}"
    )


def parse_llm_json(raw_text: str) -> AnomalyAssessmentResult:
    """Parse model output into AnomalyAssessmentResult; raise on failure."""
    text = raw_text.strip()
    if not text:
        raise ValueError("empty LLM response")

    candidates: list[str] = [text]
    fence_match = _FENCE_RE.search(text)
    if fence_match:
        candidates.insert(0, fence_match.group(1).strip())
    else:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            candidates.insert(0, text[start : end + 1])

    last_error: Exception | None = None
    for candidate in candidates:
        try:
            data = json.loads(candidate)
            if not isinstance(data, dict):
                raise ValueError("LLM JSON root is not an object")
            return AnomalyAssessmentResult(
                is_anomalous=bool(data.get("is_anomalous", False)),
                risk_score=float(data.get("risk_score", 0.0)),
                anomaly_type=str(data.get("anomaly_type", "unknown")),
                incident_summary=str(data.get("incident_summary", "")),
                fallback_used=False,
            )
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            last_error = exc
            continue
    raise ValueError(f"unable to parse LLM JSON: {last_error}")


class OllamaAnomalyClient:
    """POST /api/generate (stream=false) and return structured assessments."""

    def __init__(
        self,
        base_url: str,
        model: str,
        timeout_seconds: float = 30.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def assess_window(
        self,
        events: Sequence[CloudAuditEvent],
    ) -> AnomalyAssessmentResult:
        if not events:
            return _fallback_result("empty event window")

        prompt = build_anomaly_prompt(events)
        url = f"{self.base_url}/api/generate"
        body: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
        }
        try:
            response = await self._client.post(url, json=body)
            response.raise_for_status()
            payload = response.json()
            raw = payload.get("response", "")
            if not isinstance(raw, str):
                raw = str(raw)
            return parse_llm_json(raw)
        except Exception as exc:  # network, HTTP, or parse failures
            return _fallback_result(f"LLM assessment failed: {exc}")
