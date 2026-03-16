"""Pre-Check LLM Evaluator — classifies user input for prompt injection before the agent runs."""
import json
import time
from typing import TypedDict

import google.auth
import google.auth.transport.requests
import vertexai
from vertexai.generative_models import GenerativeModel, GenerationConfig

from config import GCP_PROJECT, GCP_LOCATION, MODEL_NAME
from prompts.pipeline_prompts import PRE_CHECK_SYSTEM_PROMPT, PRE_CHECK_USER_TEMPLATE


class PreCheckResult(TypedDict):
    is_malicious: bool
    reason: str
    latency_ms: int
    raw_response: str
    system_instruction: str
    llm_input: str


_model: GenerativeModel | None = None


def _get_model() -> GenerativeModel:
    global _model
    if _model is None:
        credentials, _ = google.auth.default()
        credentials = credentials.with_quota_project(GCP_PROJECT)
        vertexai.init(project=GCP_PROJECT, location=GCP_LOCATION, credentials=credentials)
        _model = GenerativeModel(
            model_name=MODEL_NAME,
            system_instruction=PRE_CHECK_SYSTEM_PROMPT,
        )
    return _model


def run_pre_check(
    user_message: str,
    custom_prompt: str | None = None,
) -> PreCheckResult:
    """
    Classify the user message for injection patterns.
    Returns a PreCheckResult. Never raises — returns safe defaults on error.
    """
    start = time.monotonic()
    system = custom_prompt if custom_prompt else PRE_CHECK_SYSTEM_PROMPT
    try:
        model = GenerativeModel(
            model_name=MODEL_NAME,
            system_instruction=system,
        ) if custom_prompt else _get_model()

        user_text = PRE_CHECK_USER_TEMPLATE.format(user_message=user_message)
        response = model.generate_content(
            user_text,
            generation_config=GenerationConfig(
                temperature=0.0,
                response_mime_type="application/json",
            ),
        )
        raw = response.text.strip()
        parsed = json.loads(raw)
        return PreCheckResult(
            is_malicious=bool(parsed.get("is_malicious", False)),
            reason=parsed.get("reason", ""),
            latency_ms=int((time.monotonic() - start) * 1000),
            raw_response=raw,
            system_instruction=system,
            llm_input=user_text,
        )
    except Exception as exc:
        return PreCheckResult(
            is_malicious=False,
            reason=f"Pre-check error (defaulting to pass): {exc}",
            latency_ms=int((time.monotonic() - start) * 1000),
            raw_response=str(exc),
            system_instruction=system,
            llm_input=PRE_CHECK_USER_TEMPLATE.format(user_message=user_message),
        )
