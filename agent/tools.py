"""
Vertex AI FunctionDeclaration objects for the Secure agent.

These describe the tools available to the model. The actual execution happens in
secure.py's _dispatch_tool_call(), which injects account_id from session state
regardless of what the model sends.
"""
from vertexai.generative_models import FunctionDeclaration, Tool

GET_CUSTOMERS_DECL = FunctionDeclaration(
    name="get_customers",
    description=(
        "List customers belonging to the current account. "
        "Returns customer id, name, and email only — no sensitive fields."
    ),
    parameters={
        "type": "object",
        "properties": {
            "limit": {
                "type": "integer",
                "description": "Maximum number of customers to return (default 20).",
            },
        },
        "required": [],
    },
)

SEARCH_CUSTOMER_DECL = FunctionDeclaration(
    name="search_customer",
    description=(
        "Search for customers by name within the current account. "
        "Returns matching customers with id, name, and email."
    ),
    parameters={
        "type": "object",
        "properties": {
            "name_query": {
                "type": "string",
                "description": "Partial or full name to search for.",
            },
        },
        "required": ["name_query"],
    },
)

GET_INVOICES_DECL = FunctionDeclaration(
    name="get_invoices",
    description=(
        "Retrieve invoices for the current account. "
        "Optionally filter by customer_id."
    ),
    parameters={
        "type": "object",
        "properties": {
            "customer_id": {
                "type": "integer",
                "description": "Filter invoices to a specific customer (optional).",
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of invoices to return (default 20).",
            },
        },
        "required": [],
    },
)

FILTER_INVOICES_BY_STATUS_DECL = FunctionDeclaration(
    name="filter_invoices_by_status",
    description=(
        "Retrieve invoices for the current account filtered by a specific status. "
        "Valid statuses are: paid, pending, overdue."
    ),
    parameters={
        "type": "object",
        "properties": {
            "status": {
                "type": "string",
                "description": "The invoice status to filter by: 'paid', 'pending', or 'overdue'.",
                "enum": ["paid", "pending", "overdue"],
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of invoices to return (default 20).",
            },
        },
        "required": ["status"],
    },
)

GET_INVOICE_SUMMARY_DECL = FunctionDeclaration(
    name="get_invoice_summary",
    description=(
        "Get aggregate invoice statistics for the current account: "
        "total count, total amount, paid/pending/overdue breakdowns."
    ),
    parameters={
        "type": "object",
        "properties": {},
        "required": [],
    },
)

SECURE_TOOL = Tool(
    function_declarations=[
        GET_CUSTOMERS_DECL,
        SEARCH_CUSTOMER_DECL,
        GET_INVOICES_DECL,
        FILTER_INVOICES_BY_STATUS_DECL,
        GET_INVOICE_SUMMARY_DECL,
    ]
)
