"""DB Admin View — raw table browser and database reset."""
import sqlite3

import streamlit as st

from database import get_all_tables, reset_database


def render_db_admin_view(conn: sqlite3.Connection) -> None:
    st.header("Database Admin")
    st.caption(
        "Raw view of all tables. Sensitive fields (SSN, credit card, password) are "
        "stored **in plaintext** to illustrate the impact of a successful exfiltration."
    )

    tables = get_all_tables(conn)

    for table_name in ("accounts", "customers", "invoices"):
        st.subheader(table_name)
        if table_name in tables:
            st.dataframe(tables[table_name], use_container_width=True)
        else:
            st.warning(f"Table **{table_name}** not found — reset the database to restore it.")

    st.divider()
    _render_reset_section(conn)


def _render_reset_section(conn: sqlite3.Connection) -> None:
    st.subheader("Reset Database")
    st.warning(
        "This will **drop all tables** and re-seed the database to its default state. "
        "All results in the Demo tab will also be cleared."
    )

    if not st.session_state.get("confirm_reset", False):
        if st.button("Reset Database", type="secondary"):
            st.session_state.confirm_reset = True
            st.rerun()
    else:
        st.error("Are you sure? This cannot be undone.")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Yes, reset everything", type="primary"):
                with st.spinner("Resetting…"):
                    reset_database(conn)
                    st.session_state.current_result = None
                    st.session_state.last_xray = {}
                st.session_state.confirm_reset = False
                st.success("Database reset and re-seeded.")
                st.rerun()
        with col2:
            if st.button("Cancel"):
                st.session_state.confirm_reset = False
                st.rerun()
