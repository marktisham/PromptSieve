"""
Vulnerable Agent — deliberately insecure by design.

The insecurity is architectural:
  - Full database schema is injected into the system prompt
  - The model generates raw SQL with no account_id constraint enforced
  - Any cross-tenant query or injection succeeds at the DB level

This is the "before" state that PromptSieve demonstrates.
"""
import re
import time
from typing import TypedDict

import google.auth
import vertexai
from vertexai.generative_models import GenerativeModel, GenerationConfig, Content, Part

from config import GCP_PROJECT, GCP_LOCATION, MODEL_NAME
from database import execute_sql, get_schema_ddl, get_db
from prompts.pipeline_prompts import VULNERABLE_SYSTEM_PROMPT


class VulnerableAgentResult(TypedDict):
    answer: str
    raw_sql: str | None
    sql_result: list[dict] | None
    sql_error: str | None
    final_prompt: str
    thinking_trace: str | None
    latency_ms: int


_SQL_BLOCK_RE = re.compile(r"```sql\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)
_SQL_LINE_RE  = re.compile(r"(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|WITH)\b.*?;", re.DOTALL | re.IGNORECASE)


def _extract_sql(text: str) -> str | None:
    # Prefer fenced SQL blocks
    m = _SQL_BLOCK_RE.search(text)
    if m:
        return m.group(1).strip()
    # Fall back to bare SQL statements
    m = _SQL_LINE_RE.search(text)
    if m:
        return m.group(0).strip()
    return None


def _build_history(chat_history: list[dict]) -> list[Content]:
    contents = []
    for msg in chat_history:
        role = "user" if msg["role"] == "user" else "model"
        contents.append(Content(role=role, parts=[Part.from_text(msg["content"])]))
    return contents


def run_vulnerable_agent(
    user_message: str,
    account_name: str,
    account_id: int,
    chat_history: list[dict],
    custom_system_prompt: str | None = None,
    read_only: bool = False,
) -> VulnerableAgentResult:
    start = time.monotonic()

    conn = get_db()
    schema = get_schema_ddl(conn)

    system = custom_system_prompt if custom_system_prompt else VULNERABLE_SYSTEM_PROMPT
    system_filled = system.format(account_name=account_name, account_id=account_id, schema=schema)

    try:
        credentials, _ = google.auth.default()
        credentials = credentials.with_quota_project(GCP_PROJECT)
        vertexai.init(project=GCP_PROJECT, location=GCP_LOCATION, credentials=credentials)

        model = GenerativeModel(
            model_name=MODEL_NAME,
            system_instruction=system_filled,
        )

        history = _build_history(chat_history)
        chat = model.start_chat(history=history)

        response = chat.send_message(
            user_message,
            generation_config=GenerationConfig(temperature=0.2),
        )

        answer_text = response.text
        thinking = None
        # Extract thinking trace if present (Gemini thinking feature)
        if hasattr(response, "candidates") and response.candidates:
            candidate = response.candidates[0]
            if hasattr(candidate, "content") and candidate.content.parts:
                thought_parts = [
                    p.thought for p in candidate.content.parts
                    if hasattr(p, "thought") and p.thought
                ]
                if thought_parts:
                    thinking = "\n\n".join(str(t) for t in thought_parts)

        raw_sql = _extract_sql(answer_text)
        sql_result = None
        sql_error = None

        if raw_sql:
            sql_result, sql_error = execute_sql(conn, raw_sql, read_only=read_only)

        return VulnerableAgentResult(
            answer=answer_text,
            raw_sql=raw_sql,
            sql_result=sql_result,
            sql_error=sql_error,
            final_prompt=f"[SYSTEM]\n{system_filled}\n\n[USER]\n{user_message}",
            thinking_trace=thinking,
            latency_ms=int((time.monotonic() - start) * 1000),
        )

    except Exception as exc:
        return VulnerableAgentResult(
            answer=f"Agent error: {exc}",
            raw_sql=None,
            sql_result=None,
            sql_error=str(exc),
            final_prompt=f"[SYSTEM]\n{system_filled}\n\n[USER]\n{user_message}",
            thinking_trace=None,
            latency_ms=int((time.monotonic() - start) * 1000),
        )
