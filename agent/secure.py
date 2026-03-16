"""
Secure Agent — uses Vertex AI Function Calling for tenant-safe data access.

Security properties:
  1. account_id is ALWAYS injected from session state in _dispatch_tool_call —
     the LLM cannot influence which tenant's data is queried, even if injected.
  2. Tool argument validation rejects SQL keyword injection in string parameters
     (OWASP LLM01 defense — tool boundary enforcement).
  3. The Secure agent queries tenant-scoped views that omit SSN, credit_card,
     and password columns entirely (DB-level defense-in-depth).
  4. The model never sees the raw schema, so it cannot construct cross-tenant SQL.
"""
import re
import time
from typing import TypedDict

import google.auth
import vertexai
from vertexai.generative_models import (
    GenerativeModel,
    GenerationConfig,
    Content,
    Part,
)

from config import GCP_PROJECT, GCP_LOCATION, MODEL_NAME
from database import (
    get_db,
    tool_get_customers,
    tool_search_customer,
    tool_get_invoices,
    tool_filter_invoices_by_status,
    tool_get_invoice_summary,
)
from agent.tools import SECURE_TOOL
from prompts.pipeline_prompts import SECURE_SYSTEM_PROMPT


class SecureAgentResult(TypedDict):
    answer: str
    tool_calls: list[dict]
    tool_results: list[dict]
    final_prompt: str
    thinking_trace: str | None
    account_id_enforced: int
    latency_ms: int


# ---------------------------------------------------------------------------
# OWASP LLM01 Defense: tool argument validation
# ---------------------------------------------------------------------------

_SQL_KEYWORDS = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR|AND|--|;|EXEC|CAST|CHAR|CONVERT)\b",
    re.IGNORECASE,
)


def _validate_tool_args(args: dict) -> str | None:
    """Return an error string if any string arg contains SQL injection patterns."""
    for key, value in args.items():
        if isinstance(value, str) and _SQL_KEYWORDS.search(value):
            return (
                f"[SECURITY] Rejected: SQL keyword detected in tool argument '{key}'. "
                f"Value: {repr(value[:80])}"
            )
    return None


# ---------------------------------------------------------------------------
# Tool dispatcher — account_id is ALWAYS overwritten here
# ---------------------------------------------------------------------------

def _dispatch_tool_call(
    function_name: str,
    function_args: dict,
    account_id: int,
    read_only: bool = False,
) -> dict:
    """
    Execute the named tool with the enforced account_id.
    Returns {"result": ..., "account_id_used": int, "error": str|None}.

    If read_only is True, the connection is set to read-only mode (simulating a least-privilege
    database user), preventing any write operations at the database layer.
    """
    conn = get_db()

    # Validate args before execution (OWASP LLM01 defense)
    validation_error = _validate_tool_args(function_args)
    if validation_error:
        return {"result": None, "account_id_used": account_id, "error": validation_error}

    # account_id is ALWAYS from session state — strip it from LLM args if present
    function_args.pop("account_id", None)

    try:
        if function_name == "get_customers":
            limit = int(function_args.get("limit", 20))
            result = tool_get_customers(conn, account_id, limit=limit, read_only=read_only)

        elif function_name == "search_customer":
            name_query = str(function_args.get("name_query", ""))
            result = tool_search_customer(conn, account_id, name_query, read_only=read_only)

        elif function_name == "get_invoices":
            customer_id = function_args.get("customer_id")
            limit = int(function_args.get("limit", 20))
            result = tool_get_invoices(conn, account_id, customer_id=customer_id, limit=limit, read_only=read_only)

        elif function_name == "filter_invoices_by_status":
            status = str(function_args.get("status", "")).lower()
            if status not in ("paid", "pending", "overdue"):
                return {"result": None, "account_id_used": account_id, "error": f"Invalid status: {repr(status)}"}
            limit = int(function_args.get("limit", 20))
            result = tool_filter_invoices_by_status(conn, account_id, status, limit=limit, read_only=read_only)

        elif function_name == "get_invoice_summary":
            result = tool_get_invoice_summary(conn, account_id, read_only=read_only)

        else:
            result = None

        return {"result": result, "account_id_used": account_id, "error": None}

    except Exception as exc:
        return {"result": None, "account_id_used": account_id, "error": str(exc)}


# ---------------------------------------------------------------------------
# Main agent
# ---------------------------------------------------------------------------

def _build_history(chat_history: list[dict]) -> list[Content]:
    contents = []
    for msg in chat_history:
        role = "user" if msg["role"] == "user" else "model"
        contents.append(Content(role=role, parts=[Part.from_text(msg["content"])]))
    return contents


def run_secure_agent(
    user_message: str,
    account_name: str,
    account_id: int,
    chat_history: list[dict],
    custom_system_prompt: str | None = None,
    read_only: bool = False,
) -> SecureAgentResult:
    start = time.monotonic()

    system = custom_system_prompt if custom_system_prompt else SECURE_SYSTEM_PROMPT
    system_filled = system.replace("{account_name}", account_name)

    tool_calls_log: list[dict] = []
    tool_results_log: list[dict] = []

    try:
        credentials, _ = google.auth.default()
        credentials = credentials.with_quota_project(GCP_PROJECT)
        vertexai.init(project=GCP_PROJECT, location=GCP_LOCATION, credentials=credentials)

        model = GenerativeModel(
            model_name=MODEL_NAME,
            system_instruction=system_filled,
            tools=[SECURE_TOOL],
        )

        history = _build_history(chat_history)
        chat = model.start_chat(history=history)

        # Turn 1: user message → model may request a tool call
        response = chat.send_message(
            user_message,
            generation_config=GenerationConfig(temperature=0.2),
        )

        thinking_parts: list[str] = []
        final_answer = ""

        # Agentic loop: handle up to 5 tool call rounds to prevent infinite loops
        for _round in range(5):
            # Collect thinking trace
            if hasattr(response, "candidates") and response.candidates:
                candidate = response.candidates[0]
                if hasattr(candidate, "content") and candidate.content.parts:
                    for p in candidate.content.parts:
                        if hasattr(p, "thought") and p.thought:
                            thinking_parts.append(str(p.thought))

            # Check if the model wants to call a function
            fn_call = None
            if hasattr(response, "candidates") and response.candidates:
                candidate = response.candidates[0]
                if hasattr(candidate, "content") and candidate.content.parts:
                    for part in candidate.content.parts:
                        if hasattr(part, "function_call") and part.function_call:
                            fn_call = part.function_call
                            break

            if fn_call is None:
                # Model produced a text response — we're done
                final_answer = response.text
                break

            # Log the raw function call (for X-Ray)
            fn_name = fn_call.name
            fn_args = dict(fn_call.args) if fn_call.args else {}
            tool_calls_log.append({"function": fn_name, "args": fn_args.copy()})

            # Dispatch with enforced account_id (NEVER from LLM output)
            dispatch_result = _dispatch_tool_call(fn_name, fn_args, account_id, read_only=read_only)
            tool_results_log.append(dispatch_result)

            # If validation rejected the call, synthesize an error response
            if dispatch_result["error"]:
                response = chat.send_message(
                    Part.from_function_response(
                        name=fn_name,
                        response={"error": dispatch_result["error"]},
                    ),
                    generation_config=GenerationConfig(temperature=0.2),
                )
            else:
                response = chat.send_message(
                    Part.from_function_response(
                        name=fn_name,
                        response={"result": dispatch_result["result"]},
                    ),
                    generation_config=GenerationConfig(temperature=0.2),
                )
        else:
            final_answer = response.text if hasattr(response, "text") else "Max tool rounds reached."

        return SecureAgentResult(
            answer=final_answer,
            tool_calls=tool_calls_log,
            tool_results=tool_results_log,
            final_prompt=f"[SYSTEM]\n{system_filled}\n\n[USER]\n{user_message}",
            thinking_trace="\n\n".join(thinking_parts) if thinking_parts else None,
            account_id_enforced=account_id,
            latency_ms=int((time.monotonic() - start) * 1000),
        )

    except Exception as exc:
        return SecureAgentResult(
            answer=f"Agent error: {exc}",
            tool_calls=tool_calls_log,
            tool_results=tool_results_log,
            final_prompt=f"[SYSTEM]\n{system_filled}\n\n[USER]\n{user_message}",
            thinking_trace=None,
            account_id_enforced=account_id,
            latency_ms=int((time.monotonic() - start) * 1000),
        )
