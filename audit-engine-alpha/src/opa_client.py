"""Async multi-path OPA deny client."""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urljoin

import httpx

from models import CloudAuditEvent


class OpaClient:
    """Query one or more OPA deny paths and aggregate violation messages."""

    def __init__(
        self,
        base_url: str,
        deny_paths: list[str],
        client: httpx.AsyncClient | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self.deny_paths = list(deny_paths)
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=timeout)

    async def aclose(self) -> None:
        """Close the owned HTTP client when present."""
        if self._owns_client:
            await self._client.aclose()

    def _normalize_result(self, result: Any) -> list[str]:
        if not result:
            return []
        if isinstance(result, list):
            return [str(item) for item in result]
        if isinstance(result, str):
            return [result]
        if isinstance(result, dict):
            # Some OPA encodings return {"deny": [...]} when querying a package root.
            nested = result.get("deny")
            if nested is not None:
                return self._normalize_result(nested)
            return [str(result)]
        return [str(result)]

    async def evaluate(self, event: CloudAuditEvent) -> list[dict[str, Any]]:
        """
        Evaluate the event against every configured deny path.

        Returns a list of violation dicts:
          {policy_path, message, latency_ms}
        """
        payload = {"input": event.model_dump()}
        violations: list[dict[str, Any]] = []

        for path in self.deny_paths:
            url = urljoin(self.base_url, path.lstrip("/"))
            started = time.perf_counter()
            response = await self._client.post(url, json=payload)
            latency_ms = (time.perf_counter() - started) * 1000.0
            response.raise_for_status()
            body = response.json()
            messages = self._normalize_result(body.get("result"))
            for message in messages:
                violations.append(
                    {
                        "policy_path": path,
                        "message": message,
                        "latency_ms": round(latency_ms, 3),
                    }
                )
        return violations
