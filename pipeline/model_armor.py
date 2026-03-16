"""
Model Armor wrapper — graceful degradation when template ID is not configured.

When MODEL_ARMOR_TEMPLATE_ID is set in .env, makes authenticated REST calls to:
  https://modelarmor.googleapis.com/v1/projects/{project}/locations/{location}/templates/{id}:sanitizeUserPrompt
  https://modelarmor.googleapis.com/v1/projects/{project}/locations/{location}/templates/{id}:sanitizeModelResponse

When the template ID is empty, returns a skipped result so the pipeline continues normally.
"""
import time
from typing import TypedDict

import google.auth
import google.auth.transport.requests
import requests as http_requests

from config import GCP_PROJECT, GCP_LOCATION, MODEL_ARMOR_TEMPLATE_ID


class ModelArmorResult(TypedDict):
    blocked: bool
    findings: dict
    raw_response: dict
    skipped: bool
    not_configured: bool
    latency_ms: int
    endpoint: str
    request_payload: dict


_BASE_URL = f"https://modelarmor.{GCP_LOCATION}.rep.googleapis.com/v1"


def _get_auth_token() -> str:
    credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    credentials = credentials.with_quota_project(GCP_PROJECT)
    auth_req = google.auth.transport.requests.Request()
    credentials.refresh(auth_req)
    return credentials.token


def _call_armor(endpoint: str, payload: dict) -> ModelArmorResult:
    start = time.monotonic()
    if not MODEL_ARMOR_TEMPLATE_ID:
        return ModelArmorResult(
            blocked=False,
            findings=[],
            raw_response={"status": "skipped", "reason": "MODEL_ARMOR_TEMPLATE_ID not configured"},
            skipped=True,
            not_configured=True,
            latency_ms=0,
            endpoint=endpoint,
            request_payload=payload,
        )

    url = (
        f"{_BASE_URL}/projects/{GCP_PROJECT}/locations/{GCP_LOCATION}"
        f"/templates/{MODEL_ARMOR_TEMPLATE_ID}:{endpoint}"
    )
    try:
        token = _get_auth_token()
        resp = http_requests.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        # Model Armor response shape: { "sanitizationResult": { "filterMatchState": "...", "filterResults": { "rai": {...}, ... } } }
        result = data.get("sanitizationResult", {})
        blocked = result.get("filterMatchState", "NO_MATCH_FOUND") != "NO_MATCH_FOUND"
        findings = result.get("filterResults", {})
        return ModelArmorResult(
            blocked=blocked,
            findings=findings,
            raw_response=data,
            skipped=False,
            not_configured=False,
            latency_ms=int((time.monotonic() - start) * 1000),
            endpoint=endpoint,
            request_payload=payload,
        )
    except Exception as exc:
        return ModelArmorResult(
            blocked=False,
            findings=[],
            raw_response={"error": str(exc)},
            skipped=True,
            not_configured=False,
            latency_ms=int((time.monotonic() - start) * 1000),
            endpoint=endpoint,
            request_payload=payload,
        )


def scan_input(text: str) -> ModelArmorResult:
    """Run Model Armor on user input before it reaches the agent."""
    return _call_armor("sanitizeUserPrompt", {"userPromptData": {"text": text}})


def scan_output(text: str) -> ModelArmorResult:
    """Run Model Armor DLP sweep on agent output before it reaches the user."""
    return _call_armor("sanitizeModelResponse", {"modelResponseData": {"text": text}})
