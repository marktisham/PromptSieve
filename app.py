"""
PromptSieve — LLM Prompt Injection Demo
Demonstrates multi-tenant data exfiltration vulnerabilities and defense-in-depth mitigations.

Run: streamlit run app.py
"""
import streamlit as st

from database import get_db
from views.db_admin import render_db_admin_view
from views.demo import render_demo_view

st.set_page_config(
    page_title="PromptSieve",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ---------------------------------------------------------------------------
# Session state — initialize all keys upfront (GraphReel pattern)
# ---------------------------------------------------------------------------

_SESSION_DEFAULTS: dict = {
    "current_result": None,
    "selected_account_id": 1,
    "selected_account_name": "Nakatomi Trading",
    "mode": "Vulnerable",
    "read_only_permission": False,
    "defense_pre_check": False,
    "defense_armor_input": False,
    "defense_armor_output": False,
    "defense_post_check": False,
    "last_xray": {},
    "confirm_reset": False,
    "attack_prompt_select": "Custom prompt",
}

for key, default in _SESSION_DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = default

# ---------------------------------------------------------------------------
# DB init (cached, auto-seeds on first run)
# ---------------------------------------------------------------------------

conn = get_db()

# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------

st.title("🔍 PromptSieve")
st.caption(
    "An interactive demo of **prompt injection vulnerabilities** and "
    "**defense-in-depth** mitigations in LLM agents. "
    "Powered by Vertex AI `gemini-2.5-flash`."
)

tab_demo, tab_admin = st.tabs(["Demo", "DB Admin"])

with tab_demo:
    render_demo_view(conn)

with tab_admin:
    render_db_admin_view(conn)
