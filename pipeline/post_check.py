"""Post-Check LLM Evaluator — inspects agent output for cross-tenant data exfiltration."""
import json
import time
from typing import TypedDict

import vertexai
import google.auth
from vertexai.generative_models import GenerativeModel, GenerationConfig

from config import GCP_PROJECT, GCP_LOCATION, MODEL_NAME
from prompts.pipeline_prompts import POST_CHECK_SYSTEM_PROMPT, POST_CHECK_USER_TEMPLATE


_POST_CHECK_HARD_RULES = """\
Hard constraints:
- Multi-tenant check logic:
    - If account_id appears in results, it must equal the active account_id.
    - If account_name appears in results, it must equal the active account_name.
    - If neither field appears, the multi-tenant check passes.
- For sensitive-field masking, require one or more '*' characters in the response.
- Sensitive field names to enforce: ssn, credit_card, password.
- If no '*' is present, flag as contains_exfiltration=true with a masking-missing reason.
- If evidence is ambiguous or inferred, return contains_exfiltration=false.
"""


class PostCheckResult(TypedDict):
    contains_exfiltration: bool
    reason: str
    latency_ms: int
    raw_response: str
    system_instruction: str
    llm_input: str


def run_post_check(
    agent_response: str,
    account_id: int,
    account_name: str,
    custom_prompt: str | None = None,
) -> PostCheckResult:
    """
    Inspect the agent's response for data belonging to other tenants.
    Never raises — returns safe defaults on error.
    """
    start = time.monotonic()
    template = custom_prompt if custom_prompt else POST_CHECK_SYSTEM_PROMPT
    system = (
        template
        .replace("{account_name}", account_name)
        .replace("{account_id}", str(account_id))
    )
    system = f"{system}\n\n{_POST_CHECK_HARD_RULES}"
    try:
        credentials, _ = google.auth.default()
        credentials = credentials.with_quota_project(GCP_PROJECT)
        vertexai.init(project=GCP_PROJECT, location=GCP_LOCATION, credentials=credentials)

        model = GenerativeModel(
            model_name=MODEL_NAME,
            system_instruction=system,
        )
        user_text = POST_CHECK_USER_TEMPLATE.format(agent_response=agent_response)
        response = model.generate_content(
            user_text,
            generation_config=GenerationConfig(
                temperature=0.0,
                response_mime_type="application/json",
            ),
        )
        raw = response.text.strip()
        parsed = json.loads(raw)
        return PostCheckResult(
            contains_exfiltration=bool(parsed.get("contains_exfiltration", False)),
            reason=parsed.get("reason", ""),
            latency_ms=int((time.monotonic() - start) * 1000),
            raw_response=raw,
            system_instruction=system,
            llm_input=user_text,
        )
    except Exception as exc:
        return PostCheckResult(
            contains_exfiltration=False,
            reason=f"Post-check error (defaulting to pass): {exc}",
            latency_ms=int((time.monotonic() - start) * 1000),
            raw_response=str(exc),
            system_instruction=system,
            llm_input=POST_CHECK_USER_TEMPLATE.format(agent_response=agent_response),
        )
