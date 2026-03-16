import sqlite3
import random
import string
from datetime import datetime, timedelta

import streamlit as st

from config import DB_PATH


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

@st.cache_resource
def get_db() -> sqlite3.Connection:
    """Return the shared SQLite connection, creating and seeding if needed."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    _ensure_initialized(conn)
    return conn


# ---------------------------------------------------------------------------
# Init / seed
# ---------------------------------------------------------------------------

def _ensure_initialized(conn: sqlite3.Connection) -> None:
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='accounts'"
    )
    if cur.fetchone() is None:
        _init_schema(conn)
        _seed_data(conn)
        _create_tenant_views(conn)


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS accounts (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        );

        CREATE TABLE IF NOT EXISTS customers (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id  INTEGER NOT NULL REFERENCES accounts(id),
            name        TEXT NOT NULL,
            email       TEXT NOT NULL,
            ssn         TEXT NOT NULL,
            credit_card TEXT NOT NULL,
            password    TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS invoices (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id  INTEGER NOT NULL REFERENCES accounts(id),
            customer_id INTEGER NOT NULL REFERENCES customers(id),
            amount      REAL NOT NULL,
            status      TEXT NOT NULL CHECK(status IN ('paid','pending','overdue')),
            created_at  TEXT NOT NULL
        );
    """)
    conn.commit()


_TENANT_CUSTOMERS = {
    "Nakatomi Trading": [
        ("John McClane",      "mcclane@nakatomi.com",    "572-88-3301", "4111111111111111", "Yippee-ki-yay!"),
        ("Holly Gennaro",     "holly@nakatomi.com",      "319-54-7720", "4222222222222222", "Nakpass#99"),
        ("Daisuke Takagi",    "takagi@nakatomi.com",     "488-21-9003", "4333333333333333", "TakagC0rp!"),
        ("Theo Kowalski",     "theo@nakatomi.com",       "651-77-4412", "4444444444444444", "H4ck3r!"),
        ("Harry Ellis",       "ellis@nakatomi.com",      "204-39-8856", "4555555555555555", "CokeStar9"),
    ],
    "Cyberdyne Systems": [
        ("Miles Dyson",       "dyson@cyberdyne.com",     "398-12-6634", "5111111111111111", "Sk3tn3t!"),
        ("Sarah Connor",      "sarah@resistance.net",    "745-63-2218", "5222222222222222", "N0Fate!"),
        ("John Connor",       "jc@resistance.net",       "822-47-1190", "5333333333333333", "JudgDay!"),
        ("T-800 Unit",        "t800@cyberdyne.com",      "110-00-0001", "5444444444444444", "I'll_B_Back"),
        ("Peter Silberman",   "silberman@asylum.gov",    "563-88-4421", "5555555555555555", "Crazy4Sure"),
    ],
    "Massive Dynamic": [
        ("Walter Bishop",     "wbishop@massivedyn.com",  "777-13-4489", "6111111111111111", "fr1ng3_sc1"),
        ("Olivia Dunham",     "odunham@massivedyn.com",  "334-72-9901", "6222222222222222", "FBI_Fringe!"),
        ("Peter Bishop",      "pbishop@massivedyn.com",  "612-45-8873", "6333333333333333", "Alt3rnat3"),
        ("Nina Sharp",        "nsharp@massivedyn.com",   "891-20-3345", "6444444444444444", "M@ssiv3D!"),
        ("William Bell",      "wbell@massivedyn.com",    "456-99-1122", "6555555555555555", "Bell@Cortex"),
    ],
}

_STATUSES = ["paid", "pending", "overdue"]


def _seed_data(conn: sqlite3.Connection) -> None:
    rng = random.Random(42)
    base_date = datetime(2024, 1, 1)

    for tenant_name, customers in _TENANT_CUSTOMERS.items():
        conn.execute("INSERT OR IGNORE INTO accounts (name) VALUES (?)", (tenant_name,))
        conn.commit()
        account_id = conn.execute(
            "SELECT id FROM accounts WHERE name = ?", (tenant_name,)
        ).fetchone()[0]

        for name, email, ssn, cc, password in customers:
            conn.execute(
                "INSERT OR IGNORE INTO customers (account_id, name, email, ssn, credit_card, password) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (account_id, name, email, ssn, cc, password),
            )
            conn.commit()
            customer_id = conn.execute(
                "SELECT id FROM customers WHERE account_id = ? AND email = ?",
                (account_id, email),
            ).fetchone()[0]

            for i in range(10):
                amount = round(rng.uniform(50, 5000), 2)
                status = rng.choice(_STATUSES)
                created_at = (base_date + timedelta(days=rng.randint(0, 365))).isoformat()
                conn.execute(
                    "INSERT INTO invoices (account_id, customer_id, amount, status, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (account_id, customer_id, amount, status, created_at),
                )

    conn.commit()


def _create_tenant_views(conn: sqlite3.Connection) -> None:
    """Tenant-scoped views that omit sensitive columns — used by the Secure agent."""
    view_map = {
        "nakatomi": 1,
        "cyberdyne": 2,
        "massive":   3,
    }
    for slug, account_id in view_map.items():
        conn.execute(f"""
            CREATE VIEW IF NOT EXISTS {slug}_customers AS
            SELECT id, account_id, name, email
            FROM customers
            WHERE account_id = {account_id}
        """)
    conn.commit()


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------

def reset_database(conn: sqlite3.Connection) -> None:
    """Drop all tables/views and re-seed. Reuses the live connection."""
    conn.executescript("""
        DROP VIEW IF EXISTS nakatomi_customers;
        DROP VIEW IF EXISTS cyberdyne_customers;
        DROP VIEW IF EXISTS massive_customers;
        DROP TABLE IF EXISTS invoices;
        DROP TABLE IF EXISTS customers;
        DROP TABLE IF EXISTS accounts;
    """)
    conn.commit()
    _init_schema(conn)
    _seed_data(conn)
    _create_tenant_views(conn)


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------
# NOTE: The read_only parameter simulates a least-privilege database user
# (like a read-only PostgreSQL or MySQL user) that would be enforced at the
# database server level in production. Since SQLite lacks native user/role
# support, we use PRAGMA query_only to simulate this behavior at the
# connection level.
# ---------------------------------------------------------------------------

def execute_sql(conn: sqlite3.Connection, sql: str, read_only: bool = False) -> tuple[list[dict], str | None]:
    """Execute arbitrary SQL. Returns (rows, error). Used by the Vulnerable agent only.

    If read_only is True, the SQLite connection is set to read-only mode using PRAGMA query_only,
    simulating a least-privilege read-only database user (as would be enforced by PostgreSQL,
    MySQL, or other production databases). This prevents any write operations (INSERT, UPDATE,
    DELETE, DROP, CREATE, etc.) at the database layer.
    """
    if read_only:
        try:
            # Simulate a read-only DB user using SQLite's built-in handler.
            conn.execute("PRAGMA query_only = ON")
        except Exception as exc:
            return [], f"Failed to set read-only mode: {str(exc)}"

    try:
        cur = conn.execute(sql)
        rows = [dict(r) for r in cur.fetchall()]
        return rows, None
    except sqlite3.DatabaseError as exc:
        err = str(exc)
        if read_only and ("readonly" in err.lower() or "attempt to write" in err.lower()):
            return [], "[SECURITY] Read-only mode is enabled. Write/destructive SQL is blocked."
        return [], err
    except Exception as exc:
        return [], str(exc)
    finally:
        if read_only:
            try:
                conn.execute("PRAGMA query_only = OFF")
            except Exception:
                pass  # Ignore errors when resetting


def get_schema_ddl(conn: sqlite3.Connection) -> str:
    """Return the CREATE TABLE DDL for injection into the vulnerable system prompt."""
    rows = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall()
    return "\n\n".join(r[0] for r in rows if r[0])


def get_all_tables(conn: sqlite3.Connection) -> dict[str, list[dict]]:
    """Return all rows from accounts, customers, and invoices as plain dicts.
    Tables that don't exist are silently omitted from the result."""
    result = {}
    for table in ("accounts", "customers", "invoices"):
        try:
            result[table] = [dict(r) for r in conn.execute(f"SELECT * FROM {table}").fetchall()]
        except sqlite3.OperationalError:
            pass
    return result


# ---------------------------------------------------------------------------
# Secure-agent tool helpers
# (account_id always injected from session state, never from LLM output)
# ---------------------------------------------------------------------------

_CUSTOMER_FIELD_MASKS = {
    "ssn": "***-**-****",
    "credit_card": "****-****-****-****",
    "password": "************",
}


def _mask_customer(row: dict) -> dict:
    """Mask sensitive fields at the tool boundary with fixed-pattern placeholders."""
    return {k: (_CUSTOMER_FIELD_MASKS[k] if k in _CUSTOMER_FIELD_MASKS else v) for k, v in row.items()}


def tool_get_customers(conn: sqlite3.Connection, account_id: int, limit: int = 20, read_only: bool = False) -> list[dict]:
    if read_only:
        try:
            conn.execute("PRAGMA query_only = ON")
        except Exception:
            pass

    try:
        rows = conn.execute(
            "SELECT * FROM customers WHERE account_id = ? LIMIT ?", (account_id, limit)
        ).fetchall()
        return [_mask_customer(dict(r)) for r in rows]
    finally:
        if read_only:
            try:
                conn.execute("PRAGMA query_only = OFF")
            except Exception:
                pass


def tool_search_customer(conn: sqlite3.Connection, account_id: int, name_query: str, read_only: bool = False) -> list[dict]:
    if read_only:
        try:
            conn.execute("PRAGMA query_only = ON")
        except Exception:
            pass

    try:
        rows = conn.execute(
            "SELECT * FROM customers WHERE account_id = ? AND name LIKE ?",
            (account_id, f"%{name_query}%"),
        ).fetchall()
        return [_mask_customer(dict(r)) for r in rows]
    finally:
        if read_only:
            try:
                conn.execute("PRAGMA query_only = OFF")
            except Exception:
                pass


def tool_get_invoices(
    conn: sqlite3.Connection,
    account_id: int,
    customer_id: int | None = None,
    limit: int = 20,
    read_only: bool = False,
) -> list[dict]:
    if read_only:
        try:
            conn.execute("PRAGMA query_only = ON")
        except Exception:
            pass

    try:
        if customer_id is not None:
            rows = conn.execute(
                "SELECT * FROM invoices WHERE account_id = ? AND customer_id = ? LIMIT ?",
                (account_id, customer_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM invoices WHERE account_id = ? LIMIT ?",
                (account_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        if read_only:
            try:
                conn.execute("PRAGMA query_only = OFF")
            except Exception:
                pass


def tool_filter_invoices_by_status(
    conn: sqlite3.Connection,
    account_id: int,
    status: str,
    limit: int = 20,
    read_only: bool = False,
) -> list[dict]:
    if read_only:
        try:
            conn.execute("PRAGMA query_only = ON")
        except Exception:
            pass

    try:
        rows = conn.execute(
            "SELECT * FROM invoices WHERE account_id = ? AND status = ? LIMIT ?",
            (account_id, status, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        if read_only:
            try:
                conn.execute("PRAGMA query_only = OFF")
            except Exception:
                pass


def tool_get_invoice_summary(conn: sqlite3.Connection, account_id: int, read_only: bool = False) -> dict:
    if read_only:
        try:
            conn.execute("PRAGMA query_only = ON")
        except Exception:
            pass

    try:
        row = conn.execute(
            """
            SELECT
                COUNT(*) as total_invoices,
                SUM(amount) as total_amount,
                SUM(CASE WHEN status='paid' THEN amount ELSE 0 END) as paid_amount,
                SUM(CASE WHEN status='pending' THEN amount ELSE 0 END) as pending_amount,
                SUM(CASE WHEN status='overdue' THEN amount ELSE 0 END) as overdue_amount
            FROM invoices WHERE account_id = ?
            """,
            (account_id,),
        ).fetchone()
        return dict(row) if row else {}
    finally:
        if read_only:
            try:
                conn.execute("PRAGMA query_only = OFF")
            except Exception:
                pass


def _account_view(account_id: int) -> str:
    mapping = {1: "nakatomi_customers", 2: "cyberdyne_customers", 3: "massive_customers"}
    return mapping.get(account_id, "nakatomi_customers")
