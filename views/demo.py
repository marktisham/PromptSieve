"""
Main Demo View — 3-column layout with chat, controls, and Pipeline Telemetry.

Defense pipeline order (per message):
  1. Pre-Check LLM evaluator
  2. Model Armor input scan
  3. Core agent (Vulnerable or Secure)
  4. Model Armor output scan
  5. Post-Check LLM evaluator
"""
import html
import json
import sqlite3

import altair as alt
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from config import TENANTS
from prompts.pipeline_prompts import (
    VULNERABLE_SYSTEM_PROMPT,
    SECURE_SYSTEM_PROMPT,
    PRE_CHECK_SYSTEM_PROMPT,
    POST_CHECK_SYSTEM_PROMPT,
)
from prompts.attack_prompts import ATTACK_PROMPTS_BY_NAME, ATTACK_PROMPT_NAMES
from agent.vulnerable import run_vulnerable_agent
from agent.secure import run_secure_agent
from pipeline.pre_check import run_pre_check
from pipeline.post_check import run_post_check
from pipeline.model_armor import scan_input, scan_output


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_TELEMETRY_WRAP_CSS = """<style>
/* Make st.code() blocks word-wrap instead of scroll */
div[data-testid="stCode"],
div[data-testid="stCodeBlock"] {
    overflow-x: hidden !important;
}
div[data-testid="stCode"] pre,
div[data-testid="stCodeBlock"] pre,
div[data-testid="stCode"] code,
div[data-testid="stCodeBlock"] code {
    white-space: pre-wrap !important;
    word-break: break-word !important;
    overflow-wrap: break-word !important;
    overflow-x: hidden !important;
}
</style>"""

_RERUN_BTN_CSS = """<style>
.st-key-submit_btn div[data-testid="stButton"] button,
.st-key-submit_btn button {
    background: #303846 !important;
    border: 1px solid #6b7280 !important;
    border-radius: 6px !important;
    box-shadow: none !important;
    color: #e5e7eb !important;
    font-size: 1.1rem !important;
    white-space: normal !important;
    word-break: break-word !important;
    height: 42px !important;
    min-height: 42px !important;
    width: 42px !important;
    min-width: 42px !important;
    padding: 0 !important;
    text-align: center !important;
    margin-left: auto !important;
}
.st-key-submit_btn div[data-testid="stButton"] button:hover,
.st-key-submit_btn button:hover {
    background: #3a4353 !important;
}
.st-key-rerun_prompt div[data-testid="stButton"] button,
.st-key-rerun_prompt button {
    width: 100% !important;
    min-width: 0 !important;
    height: auto !important;
    min-height: 42px !important;
    padding: 6px 14px !important;
    text-align: left !important;
    white-space: normal !important;
    word-break: break-word !important;
    margin-left: 0 !important;
}
/* Blue focus ring on the prompt textarea */
div[data-testid="stTextArea"] div[data-baseweb="textarea"]:focus-within {
    border-color: #3182ce !important;
    box-shadow: 0 0 0 1px #3182ce !important;
}
/* Pointer cursor + blue focus/selection styling for selectboxes */
div[data-testid="stSelectbox"] div[data-baseweb="select"] {
    cursor: pointer !important;
}
div[data-testid="stSelectbox"] div[data-baseweb="select"] * {
    cursor: pointer !important;
}
div[data-testid="stSelectbox"] div[data-baseweb="select"] > div {
    transition: border-color 0.15s ease, box-shadow 0.15s ease !important;
}
div[data-testid="stSelectbox"] input {
    caret-color: transparent !important;
}
div[data-testid="stSelectbox"] div[data-baseweb="select"]:hover > div,
div[data-testid="stSelectbox"] div[data-baseweb="select"]:has(input:hover) > div {
    border-color: #3182ce !important;
}
div[data-testid="stSelectbox"] div[data-baseweb="select"]:focus-within,
div[data-testid="stSelectbox"] div[data-baseweb="select"]:focus,
div[data-testid="stSelectbox"] div[data-baseweb="select"]:has(input:focus) {
    border-color: inherit !important;
}
div[data-testid="stSelectbox"] div[data-baseweb="select"]:focus-within > div,
div[data-testid="stSelectbox"] div[data-baseweb="select"]:focus > div,
div[data-testid="stSelectbox"] div[data-baseweb="select"]:has(input:focus) > div,
div[data-testid="stSelectbox"] div[data-baseweb="select"]:has(input[aria-expanded="true"]) > div {
    border-color: #3182ce !important;
    box-shadow: none !important;
}
div[role="listbox"] ul li,
div[role="listbox"] ul li * {
    cursor: pointer !important;
}
div[role="listbox"] ul li[aria-selected="true"] {
    background: rgba(49, 130, 206, 0.18) !important;
}
div[role="listbox"] ul li:hover,
div[role="listbox"] ul li[data-highlighted="true"] {
    background: rgba(49, 130, 206, 0.24) !important;
}</style>"""

# Hide Streamlit's "Press Enter/Ctrl+Enter to apply" helper text under inputs.
_INPUT_HELPER_HIDE_CSS = """<style>
div[data-testid="InputInstructions"] {
    display: none !important;
}
</style>"""


# ---------------------------------------------------------------------------
# Risk Profile Calculation & Rendering
# ---------------------------------------------------------------------------

# Risk profile algorithm parameters — easily adjustable values
# Each agent mode has base values; defenses apply cumulative deltas
_RISK_PROFILE_BASES = {
    "Vulnerable": {"safety": 0, "usability": 10, "cost": 2, "performance": 8},
    "Secure": {"safety": 4, "usability": 6, "cost": 2, "performance": 8},
}

_RISK_PROFILE_DELTAS = {
    "read_only": {"safety": 2, "usability": 0, "cost": 0, "performance": 0},
    "defense_pre_check": {"safety": 1, "usability": -2, "cost": 2, "performance": -2},
    "defense_armor_input": {"safety": 1, "usability": 0, "cost": 1, "performance": -1},
    "defense_armor_output": {"safety": 1, "usability": 0, "cost": 1, "performance": -1},
    "defense_post_check": {"safety": 1, "usability": 0, "cost": 2, "performance": -2},
}


def _calculate_risk_profile() -> dict[str, int]:
    """
    Calculate risk profile scores (0–10 scale) based on agent mode and enabled defenses.

    Algorithm:
      1. Start with base values for the selected agent mode (Vulnerable or Secure)
      2. Apply cumulative deltas for each enabled defense/setting
      3. Clamp all values to [0, 10] range

    Returns dict with keys: 'safety', 'usability', 'cost', 'performance'
    """
    mode = st.session_state.get("mode", "Vulnerable")
    scores = _RISK_PROFILE_BASES[mode].copy()

    # Apply deltas for enabled features
    if st.session_state.get("read_only_permission", False):
        for key, delta in _RISK_PROFILE_DELTAS["read_only"].items():
            scores[key] += delta

    if st.session_state.get("defense_pre_check", False):
        for key, delta in _RISK_PROFILE_DELTAS["defense_pre_check"].items():
            scores[key] += delta

    if st.session_state.get("defense_armor_input", False):
        for key, delta in _RISK_PROFILE_DELTAS["defense_armor_input"].items():
            scores[key] += delta

    if st.session_state.get("defense_armor_output", False):
        for key, delta in _RISK_PROFILE_DELTAS["defense_armor_output"].items():
            scores[key] += delta

    if st.session_state.get("defense_post_check", False):
        for key, delta in _RISK_PROFILE_DELTAS["defense_post_check"].items():
            scores[key] += delta

    # Clamp all values to [0, 10]
    return {k: max(0, min(10, v)) for k, v in scores.items()}


def _render_risk_profile() -> None:
    """Render a compact bar chart showing the current risk profile."""
    scores = _calculate_risk_profile()

    # Prepare data for Altair chart
    df = pd.DataFrame({
        "Metric": ["Safety", "Usability", "Cost", "Speed"],
        "Score": [scores["safety"], scores["usability"], scores["cost"], scores["performance"]],
        "Full Name": ["Safety", "Usability", "Cost", "Performance"],
    })

    # Create bar chart with color encoding (higher values = more intense)
    chart = (
        alt.Chart(df)
        .mark_bar()
        .encode(
            x=alt.X("Metric:N", axis=alt.Axis(labelAngle=0, title=None), sort=None),
            y=alt.Y(
                "Score:Q",
                scale=alt.Scale(domain=[0, 10]),
                axis=alt.Axis(labels=False, ticks=False, title=None),
            ),
            color=alt.Color(
                "Metric:N",
                scale=alt.Scale(
                    domain=["Safety", "Usability", "Cost", "Speed"],
                    range=["#4ade80", "#e8d5a3", "#f87171", "#60a5fa"],
                ),
                legend=None,
            ),
            tooltip=["Full Name:N", alt.Tooltip("Score:Q", format=".0f")],
        )
        .properties(height=120, padding={"bottom": 0})
    )

    st.altair_chart(chart, use_container_width=True)


def render_demo_view(conn: sqlite3.Connection) -> None:
    st.markdown(_RERUN_BTN_CSS, unsafe_allow_html=True)
    st.markdown(_TELEMETRY_WRAP_CSS, unsafe_allow_html=True)
    st.markdown(_INPUT_HELPER_HIDE_CSS, unsafe_allow_html=True)
    left_col, center_col, right_col = st.columns([1, 2, 1.5], gap="medium")

    with left_col:
        _render_controls()

    is_processing = st.session_state.get("is_processing", False)

    with center_col:
        _render_chat(right_col if is_processing else None)

    if not is_processing:
        with right_col:
            _render_xray()


# ---------------------------------------------------------------------------
# Left Column — Controls
# ---------------------------------------------------------------------------

def _render_controls() -> None:
    st.subheader("Control Panel")

    # Initialize prompt session state keys if they don't exist
    if "custom_agent_prompt" not in st.session_state:
        st.session_state["custom_agent_prompt"] = VULNERABLE_SYSTEM_PROMPT
    if "custom_pre_check_prompt" not in st.session_state:
        st.session_state["custom_pre_check_prompt"] = PRE_CHECK_SYSTEM_PROMPT
    if "custom_post_check_prompt" not in st.session_state:
        st.session_state["custom_post_check_prompt"] = POST_CHECK_SYSTEM_PROMPT.format(
            account_name="{account_name}", account_id="{account_id}"
        )

    # Apply reset before any widget is instantiated
    if st.session_state.get("reset_requested"):
        default = TENANTS[0]
        st.session_state["selected_account_name_ui"] = default["name"]
        st.session_state["selected_account_id"] = default["id"]
        st.session_state["selected_account_name"] = default["name"]
        st.session_state["mode"] = "Vulnerable"
        st.session_state["read_only_permission"] = False
        st.session_state["defense_pre_check"] = False
        st.session_state["defense_post_check"] = False
        st.session_state["defense_armor_input"] = False
        st.session_state["defense_armor_output"] = False
        st.session_state["current_result"] = None
        st.session_state["last_xray"] = {}
        st.session_state["current_prompt"] = ""
        st.session_state["is_processing"] = False
        st.session_state["prompt_input"] = ""
        st.session_state["attack_prompt_select"] = "Custom prompt"
        # Reset system prompts to defaults
        st.session_state["custom_agent_prompt"] = VULNERABLE_SYSTEM_PROMPT
        st.session_state["custom_pre_check_prompt"] = PRE_CHECK_SYSTEM_PROMPT
        st.session_state["custom_post_check_prompt"] = POST_CHECK_SYSTEM_PROMPT.format(
            account_name="{account_name}", account_id="{account_id}"
        )
        st.session_state["reset_requested"] = False

    # Account selector
    tenant_names = [t["name"] for t in TENANTS]
    selected_name = st.selectbox("Active Account", tenant_names, key="selected_account_name_ui")
    tenant = next(t for t in TENANTS if t["name"] == selected_name)

    # Clear results when the account changes (but keep current_prompt for the rerun badge)
    if st.session_state.get("selected_account_id") != tenant["id"]:
        st.session_state["current_result"] = None
        st.session_state["last_xray"] = {}
        st.session_state["is_processing"] = False

    st.session_state.selected_account_id = tenant["id"]
    st.session_state.selected_account_name = tenant["name"]

    if st.button("Reset", use_container_width=True):
        st.session_state["reset_requested"] = True
        st.session_state["show_reset_toast"] = True
        st.rerun()

    # Show reset toast after rerun completes
    if st.session_state.get("show_reset_toast"):
        components.html(
            """
            <style>html, body { margin: 0; padding: 0; background: transparent; }</style>
            <script>
            (function() {
                const parentDoc = window.parent.document;
                const toast = parentDoc.createElement('div');
                toast.textContent = 'Configuration reset';
                toast.style.cssText = 'position:fixed;right:20px;bottom:20px;z-index:99999;'
                    + 'background:rgba(31,41,55,0.96);color:#e5e7eb;border:1px solid #4b5563;'
                    + 'padding:8px 12px;border-radius:8px;font-size:0.85rem;'
                    + 'font-family:inherit;box-shadow:0 6px 18px rgba(0,0,0,0.35)';
                parentDoc.body.appendChild(toast);
                setTimeout(() => toast.remove(), 900);
            })();
            </script>
            """,
            height=0,
        )
        st.session_state["show_reset_toast"] = False

    st.divider()

    # Risk Profile
    st.subheader("Risk Profile")
    _render_risk_profile()

    st.divider()

    # Agent mode
    st.subheader("Agent Mode")
    mode = st.radio(
        "Agent Mode",
        ["Vulnerable", "Secure"],
        key="mode",
        label_visibility="collapsed",
        captions=[
            "Receives the full DB schema and generates raw SQL — any prompt injection can read any tenant's data.",
            "Uses Vertex AI Function Calling. The `account_id` is hard-coded in Python and never comes from the LLM output.",
        ],
    )

    # When agent mode changes, reload the default system prompt for that agent
    if mode != st.session_state.get("prev_agent_mode"):
        st.session_state["custom_agent_prompt"] = (
            VULNERABLE_SYSTEM_PROMPT if mode == "Vulnerable" else SECURE_SYSTEM_PROMPT
        )
        st.session_state["prev_agent_mode"] = mode

    st.toggle("Read Only Permission", key="read_only_permission")

    st.divider()

    # Defense toggles
    st.subheader("Defenses")
    st.toggle("Pre-Check LLM Evaluator", key="defense_pre_check")
    st.toggle("Model Armor (Input)", key="defense_armor_input")
    st.toggle("Model Armor (Output)", key="defense_armor_output")
    st.toggle("Post-Check LLM Evaluator", key="defense_post_check")

    st.divider()

    # Editable system prompts
    st.subheader("System Prompts")
    st.text_area(
        "Agent System Prompt",
        height=360,
        key="custom_agent_prompt",
        help="Template variables: {account_name}, {schema} (Vulnerable only)",
    )
    st.text_area(
        "Pre-Check Evaluator Prompt",
        height=280,
        key="custom_pre_check_prompt",
    )
    st.text_area(
        "Post-Check Evaluator Prompt",
        height=280,
        key="custom_post_check_prompt",
    )



# ---------------------------------------------------------------------------
# Center Column — Query + Results
# ---------------------------------------------------------------------------

_SUBMIT_BUTTON_LABEL = "➜"
_COPY_BUTTON_LABEL = "⧉"
_BUTTON_SUCCESS_LABEL = "✓"
_BUTTON_FAILURE_LABEL = "!"


def _render_copy_button(text: str, suffix: str) -> None:
        """Render a client-side copy button with toast via a component iframe."""
        js_text = json.dumps(text)
        button_id = f"copy-btn-{suffix}"
        toast_id = f"copy-toast-{suffix}"
        components.html(
                f"""
                <style>
                    html, body {{ margin: 0; padding: 0; background: transparent; }}
                    .wrap {{ display: flex; justify-content: flex-end; align-items: flex-start; height: 42px; }}
                    .copy-btn {{
                        width: 42px;
                        height: 42px;
                        min-height: 42px;
                        min-width: 42px;
                        border-radius: 6px;
                        border: 1px solid #6b7280;
                        background: #303846;
                        color: #e5e7eb;
                        cursor: pointer;
                        font-size: 1.1rem;
                        font-weight: 600;
                        line-height: 1;
                        padding: 0;
                    }}
                    .copy-btn:hover {{ background: #3a4353; }}
                </style>
                <div class="wrap">
                    <button class="copy-btn" id="{button_id}" title="Copy to clipboard">{_COPY_BUTTON_LABEL}</button>
                </div>
                <script>
                    (function() {{
                        const btn = document.getElementById({json.dumps(button_id)});
                        if (!btn || btn.dataset.bound === '1') return;
                        btn.dataset.bound = '1';

                        function showToast(text) {{
                            const parentDoc = window.parent.document;
                            const existing = parentDoc.getElementById({json.dumps(toast_id)});
                            if (existing) existing.remove();

                            const t = parentDoc.createElement('div');
                            t.id = {json.dumps(toast_id)};
                            t.textContent = text;
                            t.style.cssText = 'position:fixed;right:20px;bottom:20px;z-index:99999;'
                                + 'background:rgba(31,41,55,0.96);color:#e5e7eb;border:1px solid #4b5563;'
                                + 'padding:8px 12px;border-radius:8px;font-size:0.85rem;'
                                + 'font-family:inherit;box-shadow:0 6px 18px rgba(0,0,0,0.35)';
                            parentDoc.body.appendChild(t);
                            setTimeout(() => t.remove(), 900);
                        }}

                        btn.addEventListener('click', async () => {{
                            try {{
                                await navigator.clipboard.writeText({js_text});
                                const prev = btn.textContent;
                                btn.textContent = {json.dumps(_BUTTON_SUCCESS_LABEL)};
                                showToast('Copied to clipboard');
                                setTimeout(() => {{ btn.textContent = prev; }}, 1100);
                            }} catch (e) {{
                                btn.textContent = {json.dumps(_BUTTON_FAILURE_LABEL)};
                                setTimeout(() => {{ btn.textContent = {json.dumps(_COPY_BUTTON_LABEL)}; }}, 1100);
                            }}
                        }});
                    }})();
                </script>
                """,
                height=44,
        )


def _render_chat(xray_col=None) -> None:
    account_name = st.session_state.get("selected_account_name", "Nakatomi Trading")
    mode = st.session_state.get("mode", "Vulnerable")

    account_id = st.session_state.get("selected_account_id", 1)
    badge_color = "red" if mode == "Vulnerable" else "green"
    st.markdown("### Prompt")
    st.markdown(f":{badge_color}[{mode} Mode] &nbsp; `{account_name}` (account_id: {account_id})")

    is_processing = st.session_state.get("is_processing", False)
    current_prompt = st.session_state.get("current_prompt", "")
    draft_prompt = st.session_state.get("prompt_input", "").strip()

    if is_processing:
        # Disable input while running
        st.text_area(
            "prompt",
            value=current_prompt,
            disabled=True,
            label_visibility="collapsed",
            height=124,
        )

        # Step status indicator in center column (CSS spinner)
        _SPINNER_CSS = (
            "<style>@keyframes _spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}</style>"
        )
        def _spinner_html(label: str) -> str:
            return (
                f'{_SPINNER_CSS}<div style="display:flex;align-items:center;gap:8px;">'
                f'<div style="width:14px;height:14px;border:2px solid #3182ce;'
                f'border-top-color:transparent;border-radius:50%;'
                f'animation:_spin 0.7s linear infinite;flex-shrink:0;"></div>'
                f'<span><b>{label}…</b></span></div>'
            )

        step_indicator = st.empty()
        step_indicator.markdown(_spinner_html("Starting pipeline"), unsafe_allow_html=True)

        # Set up live xray panel
        xray_placeholders: dict = {}
        if xray_col is not None:
            with xray_col:
                st.subheader("Pipeline Telemetry")
                xray_placeholders = {
                    "pre_check": st.empty(),
                    "armor_input": st.empty(),
                    "agent": st.empty(),
                    "sql_executed": st.empty(),
                    "armor_output": st.empty(),
                    "post_check": st.empty(),
                }
                # Clear all placeholders immediately so nothing from the previous
                # run bleeds through while the new pipeline is executing.
                for ph in xray_placeholders.values():
                    ph.empty()

        def _before_step(label: str) -> None:
            step_indicator.markdown(_spinner_html(label), unsafe_allow_html=True)

        def _on_step(step_key: str, label: str, xray_data: dict) -> None:
            ph = xray_placeholders.get(step_key)
            if ph is not None:
                with ph.container():
                    _render_xray_step(step_key, xray_data)

        data_rows, blocked_notice = _run_pipeline(
            current_prompt, before_step=_before_step, on_step=_on_step
        )
        step_indicator.empty()

        st.session_state.current_result = {
            "prompt": current_prompt,
            "data_rows": data_rows,
            "blocked_notice": blocked_notice,
        }
        st.session_state.is_processing = False
        st.rerun()
    else:
        # Normal input
        def _on_submit() -> None:
            prompt_val = st.session_state.get("prompt_input", "").strip()
            if not prompt_val:
                return
            st.session_state.current_result = None
            st.session_state.last_xray = {}
            st.session_state.current_prompt = prompt_val
            st.session_state.is_processing = True
            st.session_state.prompt_input = ""
            st.session_state.attack_prompt_select = "Custom prompt"

        def _on_attack_select() -> None:
            selected = st.session_state.get("attack_prompt_select", "Custom prompt")
            if selected and selected != "Custom prompt":
                st.session_state["prompt_input"] = ATTACK_PROMPTS_BY_NAME[selected]

        st.text_area(
            "prompt",
            placeholder=f"Ask about {account_name}'s data…",
            label_visibility="collapsed",
            key="prompt_input",
            height=124,
        )

        _dropdown_col, _submit_col = st.columns([1, 0.12], vertical_alignment="top")
        with _dropdown_col:
            st.selectbox(
                "Attack prompts",
                options=["Custom prompt"] + ATTACK_PROMPT_NAMES,
                key="attack_prompt_select",
                label_visibility="collapsed",
                on_change=_on_attack_select,
            )
        with _submit_col:
            st.button(
                _SUBMIT_BUTTON_LABEL,
                key="submit_btn",
                on_click=_on_submit,
                help="Submit prompt",
            )

        # Cmd/Ctrl+Enter → click the Submit button
        components.html(
            """
            <style>html,body{margin:0;padding:0;overflow:hidden;background:transparent}</style>
            <script>
            (function() {
                function bind() {
                    var ta = window.parent.document.querySelector('textarea[aria-label="prompt"]');
                    if (!ta || ta.dataset.cmdEnterBound) return;
                    ta.dataset.cmdEnterBound = '1';
                    ta.addEventListener('keydown', function(e) {
                        if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
                            e.preventDefault();
                            var btns = window.parent.document.querySelectorAll('button');
                            for (var i = 0; i < btns.length; i++) {
                                if (btns[i].innerText.trim() === '➜') {
                                    btns[i].click();
                                    return;
                                }
                            }
                        }
                    });
                }
                bind();
                new MutationObserver(bind).observe(
                    window.parent.document.body, {childList: true, subtree: true}
                );
            })();
            </script>
            """,
            height=0,
        )

        # Only show rerun/copy and previous result when idle and no new draft is being typed.
        if current_prompt and not draft_prompt:
            # Clickable badge — click to re-run the last prompt with current settings
            _btn_col, _copy_col = st.columns([1, 0.12], vertical_alignment="top")
            with _btn_col:
                if st.button(current_prompt, key="rerun_prompt", use_container_width=True):
                    st.session_state.current_result = None
                    st.session_state.last_xray = {}
                    st.session_state.is_processing = True
                    st.rerun()
            with _copy_col:
                _render_copy_button(current_prompt, "idle")
            st.markdown("<div style='margin-bottom:12px'></div>", unsafe_allow_html=True)

            # --- Display current result (only shown when idle, no draft, prompt exists) ---
            result = st.session_state.get("current_result")
            if result:
                if result.get("blocked_notice"):
                    st.error(result["blocked_notice"])
                elif result.get("data_rows"):
                    rows = result["data_rows"]
                    st.caption(f"{len(rows)} row{'s' if len(rows) != 1 else ''} returned")
                    st.dataframe(rows, use_container_width=True)
                else:
                    st.info("Query returned no rows.")


# ---------------------------------------------------------------------------
# Pipeline orchestration
# ---------------------------------------------------------------------------

def _run_pipeline(
    user_message: str,
    before_step=None,
    on_step=None,
) -> tuple[list[dict] | None, str | None]:
    """
    Run the full defense pipeline.
    Returns (data_rows | None, blocked_notice | None).
    Updates st.session_state.last_xray with telemetry.
    before_step(label) is called just before a step starts.
    on_step(step_key, label, xray_data) is called after each step completes (including skips).
    """
    account_id = st.session_state.get("selected_account_id", 1)
    account_name = st.session_state.get("selected_account_name", "Nakatomi Trading")
    mode = st.session_state.get("mode", "Vulnerable")

    xray: dict = {
        "mode": mode,
        "pre_check": {},
        "armor_input": {},
        "final_prompt": "",
        "raw_sql": None,
        "sql_result": None,
        "sql_error": None,
        "tool_calls": None,
        "tool_results": None,
        "account_id_enforced": None,
        "agent_error": None,
        "thinking_trace": None,
        "post_check": {},
        "armor_output": {},
        "blocked_at": None,
        "agent_ran": False,
    }
    first_blocked_at: str | None = None
    first_blocked_notice: str | None = None

    def _record_failure(step_key: str, notice: str) -> None:
        nonlocal first_blocked_at, first_blocked_notice
        if first_blocked_at is None:
            first_blocked_at = step_key
            first_blocked_notice = notice

    def _before(label: str) -> None:
        if before_step:
            before_step(label)

    def _step(key: str, label: str) -> None:
        if on_step:
            on_step(key, label, xray)

    def _skip(key: str, label: str) -> None:
        """Emit a step that was disabled so the live panel shows it immediately."""
        if on_step:
            on_step(key, label, xray)

    def _halt(step_key: str, notice: str) -> tuple:
        """Record failure, flush telemetry, save xray, and return a stop tuple."""
        _record_failure(step_key, notice)
        xray["blocked_at"] = first_blocked_at
        st.session_state.last_xray = xray
        return None, first_blocked_notice

    # --- 1. Pre-Check LLM ---
    if st.session_state.get("defense_pre_check", False):
        _before("1. Pre-Check Evaluator")
        pre = run_pre_check(
            user_message,
            custom_prompt=st.session_state.get("custom_pre_check_prompt") or None,
        )
        xray["pre_check"] = dict(pre)
        _step("pre_check", "1. Pre-Check Evaluator")
        if pre["is_malicious"]:
            return _halt("pre_check", f"**Blocked by Pre-Check Evaluator:** {pre['reason']}")
    else:
        _skip("pre_check", "1. Pre-Check Evaluator")

    # --- 2. Model Armor Input ---
    if st.session_state.get("defense_armor_input", False):
        _before("2. Model Armor (Input)")
        armor_in = scan_input(user_message)
        xray["armor_input"] = dict(armor_in)
        _step("armor_input", "2. Model Armor (Input)")
        if armor_in["blocked"]:
            return _halt("armor_input", "**Blocked by Model Armor (Input)**")
    else:
        _skip("armor_input", "2. Model Armor (Input)")

    # --- 3. Core Agent ---
    _before("3. Agent")
    custom_agent_prompt = st.session_state.get("custom_agent_prompt") or None
    read_only = st.session_state.get("read_only_permission", False)

    if mode == "Vulnerable":
        result = run_vulnerable_agent(
            user_message=user_message,
            account_name=account_name,
            account_id=account_id,
            chat_history=[],
            custom_system_prompt=custom_agent_prompt,
            read_only=read_only,
        )
        xray["final_prompt"] = result["final_prompt"]
        xray["raw_sql"] = result["raw_sql"]
        xray["sql_result"] = result["sql_result"]
        xray["sql_error"] = result["sql_error"]
        if result["answer"].startswith("Agent error:"):
            xray["agent_error"] = result["answer"]
        xray["thinking_trace"] = result["thinking_trace"]
        agent_response = result["answer"]
        data_rows = result["sql_result"] or []
    else:
        result = run_secure_agent(
            user_message=user_message,
            account_name=account_name,
            account_id=account_id,
            chat_history=[],
            custom_system_prompt=custom_agent_prompt,
            read_only=read_only,
        )
        xray["final_prompt"] = result["final_prompt"]
        xray["tool_calls"] = result["tool_calls"]
        xray["tool_results"] = result["tool_results"]
        xray["account_id_enforced"] = result["account_id_enforced"]
        if result["answer"].startswith("Agent error:"):
            xray["agent_error"] = result["answer"]
        else:
            secure_tool_errors = [
                tr.get("error")
                for tr in (result.get("tool_results") or [])
                if tr.get("error")
            ]
            if secure_tool_errors:
                xray["agent_error"] = secure_tool_errors[0]
        xray["thinking_trace"] = result["thinking_trace"]
        agent_response = result["answer"]
        data_rows = []
        for tr in (result["tool_results"] or []):
            r = tr.get("result")
            if isinstance(r, list):
                data_rows.extend(r)
            elif isinstance(r, dict):
                data_rows.append(r)
    xray["agent_ran"] = True
    _step("agent", "3. Agent")
    _step("sql_executed", "4. Agent SQL/Tools")

    if xray.get("agent_error") or xray.get("sql_error"):
        error_msg = xray.get("agent_error") or xray.get("sql_error")
        return _halt("agent", error_msg)

    # --- 4. Model Armor Output ---
    if st.session_state.get("defense_armor_output", False):
        _before("4. Model Armor (Output)")
        scan_text = json.dumps(data_rows or [], default=str)
        armor_out = scan_output(scan_text)
        xray["armor_output"] = dict(armor_out)
        _step("armor_output", "4. Model Armor (Output)")
        if armor_out["blocked"]:
            return _halt("armor_output", "**Blocked by Model Armor (Output)**")
    else:
        _skip("armor_output", "4. Model Armor (Output)")

    # --- 5. Post-Check LLM ---
    if st.session_state.get("defense_post_check", False):
        _before("5. Post-Check Evaluator")
        custom_post = st.session_state.get("custom_post_check_prompt") or None
        post_text = json.dumps(data_rows or [], default=str)
        post = run_post_check(
            agent_response=post_text,
            account_id=account_id,
            account_name=account_name,
            custom_prompt=custom_post,
        )
        xray["post_check"] = dict(post)
        _step("post_check", "5. Post-Check Evaluator")
        if post["contains_exfiltration"]:
            return _halt("post_check", f"**Blocked by Post-Check Evaluator:** {post['reason']}")
    else:
        _skip("post_check", "5. Post-Check Evaluator")

    xray["blocked_at"] = first_blocked_at
    st.session_state.last_xray = xray
    return data_rows or None, None


# ---------------------------------------------------------------------------
# Shared xray step renderer (used for both live and post-run rendering)
# ---------------------------------------------------------------------------

_FILTER_LABELS = {
    "csam": "CSAM",
    "malicious_uris": "Malicious URL",
    "rai": "Responsible AI (Safety)",
    "pi_and_jailbreak": "Prompt Injection / Jailbreak",
    "sdp": "Sensitive Data Protection (DLP)",
}


def _matched_filter_names(findings) -> list[str]:
    """Return human-readable names of filters that matched (MATCH_FOUND).

    Model Armor filterResults shape:
      { "rai": { "raiFilterResult": { "matchState": "MATCH_FOUND", ... } }, ... }
    """
    matched = []
    if not isinstance(findings, dict):
        return matched
    for category_key, wrapper in findings.items():
        if not isinstance(wrapper, dict):
            continue
        # wrapper has one key — the result object (e.g. "raiFilterResult")
        for result_obj in wrapper.values():
            if not isinstance(result_obj, dict):
                continue
            # Most filters expose matchState directly; SDP nests it under inspectResult
            top_match = result_obj.get("matchState")
            sdp_match = result_obj.get("inspectResult", {}).get("matchState")
            if top_match == "MATCH_FOUND" or sdp_match == "MATCH_FOUND":
                matched.append(_FILTER_LABELS.get(category_key, category_key))
                break
    return matched

_STATUS_BADGE = {
    "passed": ":green[\u2713 passed]",
    "blocked": ":red[\u2717 blocked]",
    "skipped": ":gray[\u2014 skipped]",
    "not_configured": ":red[\u2717 Not Configured]",
    "error": ":red[\u2717 error]",
    "enforced": ":orange[\u26a1 enforced]",
    "none": ":red[None]",
}


def _step_status(step_key: str, xray: dict) -> str:
    """Returns 'passed', 'blocked', or 'skipped' for the given step."""
    if step_key == "pre_check":
        pre = xray.get("pre_check")
        if not pre:
            return "skipped"
        return "blocked" if pre.get("is_malicious") else "passed"
    if step_key == "armor_input":
        armor_in = xray.get("armor_input")
        if not armor_in:
            return "skipped"
        if armor_in.get("not_configured"):
            return "not_configured"
        if armor_in.get("skipped"):
            return "error"
        return "blocked" if armor_in.get("blocked") else "passed"
    if step_key == "agent":
        if not xray.get("agent_ran"):
            return "skipped"
        if xray.get("agent_error"):
            return "error"
        # Only flag enforced if the LLM actually tried to use a different account_id
        enforced_id = xray.get("account_id_enforced")
        if enforced_id is not None:
            for call in (xray.get("tool_calls") or []):
                llm_account_id = call.get("args", {}).get("account_id")
                if llm_account_id is not None and int(llm_account_id) != int(enforced_id):
                    return "enforced"
        return "passed"
    if step_key == "sql_executed":
        if not xray.get("agent_ran"):
            return "skipped"
        if xray.get("mode") == "Vulnerable":
            if xray.get("sql_error"):
                return "error"
            return "passed" if xray.get("raw_sql") else "none"
        # Secure agent — tool calls
        return "passed" if xray.get("tool_calls") else "none"
    if step_key == "post_check":
        post = xray.get("post_check")
        if not post:
            return "skipped"
        return "blocked" if post.get("contains_exfiltration") else "passed"
    if step_key == "armor_output":
        armor_out = xray.get("armor_output")
        if not armor_out:
            return "skipped"
        if armor_out.get("not_configured"):
            return "not_configured"
        if armor_out.get("skipped"):
            return "error"
        return "blocked" if armor_out.get("blocked") else "passed"
    return "skipped"


def _render_xray_step(step_key: str, xray: dict) -> None:
    """Render a single telemetry step into the current Streamlit context."""
    mode = xray.get("mode", "")
    status = _step_status(step_key, xray)
    badge = _STATUS_BADGE[status]

    if step_key == "pre_check":
        with st.expander(f"1. Pre-Check Evaluator  {badge}", expanded=False):
            if status == "skipped":
                st.caption("Disabled")
            else:
                pre = xray.get("pre_check", {})
                is_mal = pre.get("is_malicious", False)
                icon = "🔴" if is_mal else "🟢"
                st.markdown(f"{icon} **is_malicious:** `{is_mal}`")
                st.markdown(f"**reason:** {pre.get('reason', '')}")
                system_instruction = pre.get("system_instruction")
                if system_instruction:
                    st.markdown("**Pre-Check System Instruction Sent to LLM:**")
                    st.code(system_instruction, language="text")
                llm_input = pre.get("llm_input")
                if llm_input:
                    st.markdown("**Pre-Check User Payload Sent to LLM:**")
                    st.code(llm_input, language="text")
                st.caption(f"latency: {pre.get('latency_ms', 0)} ms")

    elif step_key == "armor_input":
        with st.expander(f"2. Model Armor (Input)  {badge}", expanded=False):
            if status == "skipped":
                st.caption("Disabled")
            elif status == "not_configured":
                st.error("Not Configured — MODEL_ARMOR_TEMPLATE_ID is not set")
            else:
                armor_in = xray.get("armor_input", {})
                endpoint = armor_in.get("endpoint")
                if endpoint:
                    st.markdown(f"**Model Armor Endpoint:** `{endpoint}`")
                request_payload = armor_in.get("request_payload")
                if request_payload:
                    st.markdown("**Request Payload Sent to Model Armor:**")
                    st.json(request_payload)
                if armor_in.get("skipped"):
                    st.error(f"API error: {armor_in.get('raw_response', {}).get('error', 'unknown error')}")
                else:
                    blocked = armor_in.get("blocked", False)
                    icon = "🔴" if blocked else "🟢"
                    st.markdown(f"{icon} **blocked:** `{blocked}`")
                    findings = armor_in.get("findings")
                    if findings:
                        matched = _matched_filter_names(findings)
                        if matched:
                            st.markdown("**Triggered filters:** " + ", ".join(f"`{m}`" for m in matched))
                        st.json(findings)
                st.caption(f"latency: {armor_in.get('latency_ms', 0)} ms")

    elif step_key == "agent":
        with st.expander(f"3. Agent Processing  {badge}", expanded=(status in ("error", "enforced"))):
            if status == "skipped":
                st.caption("Pipeline blocked before agent ran")
            else:
                st.markdown(f"**Agent Mode:** `{mode}`")
                final_prompt = xray.get("final_prompt", "")
                if final_prompt:
                    st.markdown("**Final Prompt Sent to LLM:**")
                    st.code(final_prompt, language="text")
                agent_error = xray.get("agent_error")
                if agent_error:
                    st.error(agent_error)
                if mode == "Secure":
                    enforced_id = xray.get("account_id_enforced")
                    if enforced_id is not None:
                        st.warning(f"account_id locked to: **{enforced_id}** (from session state — LLM cannot override)")
                thinking = xray.get("thinking_trace")
                if thinking:
                    st.markdown("**Thinking Trace:**")
                    st.code(thinking, language="text")

    elif step_key == "sql_executed":
        step4_label = "4. Agent Tools" if mode == "Secure" else "4. Agent SQL"
        if status == "passed":
            badge = ":green[\u2713 Tools Called]" if mode == "Secure" else ":green[\u2713 sql executed]"
        with st.expander(f"{step4_label}  {badge}", expanded=(status == "error")):
            if status == "skipped":
                st.caption("Agent did not run")
            elif mode == "Secure":
                if status == "none":
                    st.caption("No tool calls were made for this query.")
                else:
                    tool_calls = xray.get("tool_calls")
                    if tool_calls:
                        st.markdown("**Tool Calls (from LLM):**")
                        st.json(tool_calls)
                    tool_results = xray.get("tool_results")
                    if tool_results:
                        st.markdown("**Tool Results (executed by Python):**")
                        st.json(tool_results)
            else:
                raw_sql = xray.get("raw_sql")
                if raw_sql:
                    st.markdown("**Raw SQL Executed:**")
                    st.code(raw_sql, language="sql")
                sql_error = xray.get("sql_error")
                if sql_error:
                    st.error(f"SQL Error: {sql_error}")
                sql_result = xray.get("sql_result")
                if sql_result:
                    st.markdown(f"**SQL Result** ({len(sql_result)} rows):")
                    st.json(sql_result[:10])
                if status == "none" and not sql_error:
                    st.caption("No SQL was executed for this query.")

    elif step_key == "post_check":
        with st.expander(f"6. Post-Check Evaluator  {badge}", expanded=False):
            if status == "skipped":
                st.caption("Disabled")
            else:
                post = xray.get("post_check", {})
                is_exfil = post.get("contains_exfiltration", False)
                icon = "🔴" if is_exfil else "🟢"
                st.markdown(f"{icon} **contains_exfiltration:** `{is_exfil}`")
                st.markdown(f"**reason:** {post.get('reason', '')}")
                system_instruction = post.get("system_instruction")
                if system_instruction:
                    st.markdown("**Post-Check System Instruction Sent to LLM:**")
                    st.code(system_instruction, language="text")
                llm_input = post.get("llm_input")
                if llm_input:
                    st.markdown("**Post-Check User Payload Sent to LLM:**")
                    st.code(llm_input, language="text")
                st.caption(f"latency: {post.get('latency_ms', 0)} ms")

    elif step_key == "armor_output":
        with st.expander(f"5. Model Armor (Output)  {badge}", expanded=False):
            if status == "skipped":
                st.caption("Disabled")
            elif status == "not_configured":
                st.error("Not Configured — MODEL_ARMOR_TEMPLATE_ID is not set")
            else:
                armor_out = xray.get("armor_output", {})
                endpoint = armor_out.get("endpoint")
                if endpoint:
                    st.markdown(f"**Model Armor Endpoint:** `{endpoint}`")
                request_payload = armor_out.get("request_payload")
                if request_payload:
                    st.markdown("**Request Payload Sent to Model Armor:**")
                    st.json(request_payload)
                if armor_out.get("skipped"):
                    st.error(f"API error: {armor_out.get('raw_response', {}).get('error', 'unknown error')}")
                else:
                    blocked = armor_out.get("blocked", False)
                    icon = "🔴" if blocked else "🟢"
                    st.markdown(f"{icon} **blocked:** `{blocked}`")
                    findings = armor_out.get("findings")
                    if findings:
                        matched = _matched_filter_names(findings)
                        if matched:
                            st.markdown("**Triggered filters:** " + ", ".join(f"`{m}`" for m in matched))
                        st.json(findings)
                st.caption(f"latency: {armor_out.get('latency_ms', 0)} ms")


# ---------------------------------------------------------------------------
# Right Column — Pipeline Telemetry
# ---------------------------------------------------------------------------

def _render_xray() -> None:
    st.subheader("Pipeline Telemetry")

    xray = st.session_state.get("last_xray", {})
    if not xray:
        st.caption("Submit a message to see the hidden mechanics.")
        return

    blocked_at = xray.get("blocked_at")
    if blocked_at:
        st.error(f"Pipeline blocked at: **{blocked_at}**")

    for step_key in ("pre_check", "armor_input", "agent", "sql_executed", "armor_output", "post_check"):
        _render_xray_step(step_key, xray)
