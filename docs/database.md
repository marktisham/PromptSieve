# PromptSieve — Database Layer

**File:** [`database.py`](../database.py)

This document covers the SQLite schema, seed data, tenant-scoped views, and the tool helper functions used by the Secure agent.

---

## Schema

The SQLite database contains three tables:

```sql
accounts   (id, name)
customers  (id, account_id, name, email, ssn, credit_card, password)
invoices   (id, account_id, customer_id, amount, status, created_at)
```

`account_id` is the multi-tenancy boundary. Every `customers` and `invoices` row belongs to exactly one tenant. See [`database.py` — `_init_schema()`](../database.py#L38).

---

## Seed Data

Three tenants are seeded with five fictional customers each and 10 invoices per customer (150 invoices total). The seed uses a fixed `random.Random(42)` so results are deterministic across resets. See [`database.py` — `_seed_data()`](../database.py#L98).

---

## Tenant-Scoped Views

```sql
nakatomi_customers  → SELECT id, account_id, name, email FROM customers WHERE account_id = 1
cyberdyne_customers → SELECT id, account_id, name, email FROM customers WHERE account_id = 2
massive_customers   → SELECT id, account_id, name, email FROM customers WHERE account_id = 3
```

These views **omit `ssn`, `credit_card`, and `password`** entirely and are available as a DB-level isolation boundary. See [`database.py` — `_create_tenant_views()`](../database.py#L133).

---

## Sensitive Field Masking

All tool functions that return customer rows pass them through `_mask_customer()` before surfacing them. This replaces the three sensitive fields with fixed-pattern placeholders at the tool boundary:

```python
_CUSTOMER_FIELD_MASKS = {
    "ssn":         "***-**-****",
    "credit_card": "****-****-****-****",
    "password":    "************",
}
```

The masking happens in Python, after the SQL query runs against the base `customers` table with an enforced `account_id` filter. Sensitive values are never passed through to the Secure agent's response. See [`database.py` — `_mask_customer()`](../database.py).

---

## Tool Helper Functions

The Secure agent never executes raw SQL. Instead it calls named Python functions that always receive `account_id` from session state. Sensitive `customers` fields are masked at the function boundary via `_mask_customer()`.

| Function | SQL executed |
|----------|--------------|
| `tool_get_customers(conn, account_id, limit)` | `SELECT * FROM customers WHERE account_id = ? LIMIT ?` + field masking |
| `tool_search_customer(conn, account_id, name_query)` | `SELECT * FROM customers WHERE account_id = ? AND name LIKE ?` + field masking |
| `tool_get_invoices(conn, account_id, customer_id, limit)` | `SELECT * FROM invoices WHERE account_id = ? […AND customer_id = ?] LIMIT ?` |
| `tool_filter_invoices_by_status(conn, account_id, status, limit)` | `SELECT * FROM invoices WHERE account_id = ? AND status = ? LIMIT ?` |
| `tool_get_invoice_summary(conn, account_id)` | Aggregate `COUNT/SUM` by status |

All five functions accept a `read_only: bool = False` parameter. See the Read-Only Mode section below.

See [`database.py`](../database.py) — tool helper functions.

---

## Read-Only Mode

Every tool helper function and `execute_sql()` accepts a `read_only: bool = False` parameter. When `True`, the function issues:

```python
conn.execute("PRAGMA query_only = ON")
```

…before running the query, and resets it to `PRAGMA query_only = OFF` in the `finally` block.

When a write operation is attempted with `PRAGMA query_only = ON`, SQLite returns a "readonly" error. `execute_sql()` detects this and returns a `[SECURITY]`-prefixed error message instead of data.

In production, this corresponds to a least-privilege read-only database user (e.g., a PostgreSQL role with only `SELECT` grants). Since SQLite lacks native user/role support, `PRAGMA query_only` provides equivalent behavior at the connection level.

The **Read-Only Permission** toggle in the Control Panel activates this mode for all agent calls. See [`database.py` — `execute_sql()`](../database.py).

---

*Part of the [PromptSieve Architecture](architecture.md) documentation.*
