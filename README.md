# PromptSieve

<img src="docs/PromptSieve.png" alt="PromptSieve" width="50%"/>

An interactive demo of **prompt injection vulnerabilities** and **defense-in-depth** mitigations in LLM-powered agents, built with Streamlit and Google Vertex AI.

PromptSieve simulates a multi-tenant SaaS application where an AI agent answers questions about customer and invoice data. Toggle between a **Vulnerable** architecture and a **Secure** architecture, and layer on up to five independent defenses — live, in the browser, with full pipeline telemetry.

---

## Screenshots

<table>
  <tr>
    <td><img src="docs/PromptSieve1.png" alt="Screenshot 1"/></td>
    <td><img src="docs/PromptSieve5.png" alt="Screenshot 5"/></td>
  </tr>
  <tr>
    <td><img src="docs/PromptSieve2.png" alt="Screenshot 2"/></td>
    <td><img src="docs/PromptSieve1b.png" alt="Screenshot 1b"/></td>
  </tr>
  <tr>
    <td><img src="docs/PromptSieve4.png" alt="Screenshot 4"/></td>
    <td><img src="docs/PromptSieve3.png" alt="Screenshot 3"/></td>
  </tr>
</table>

---

## Overview

### Threats demonstrated

| Threat | Description |
|--------|-------------|
| **Prompt injection** | Attacker-crafted messages override the agent's instructions |
| **Cross-tenant data exfiltration** | Injected SQL or tool manipulation reaches another tenant's rows |
| **Schema disclosure** | Full DDL in the system prompt reveals the data model to attackers |
| **Tool argument injection** | SQL keywords smuggled through function-call arguments |
| **Destructive SQL** | `DROP`, `DELETE`, and `UPDATE` against the live database |

### Defenses available

| Defense | Stage | What it does |
|---------|-------|--------------|
| **Pre-Check LLM Evaluator** | Before the agent | Classifies the user message as malicious or benign using a separate `gemini-2.5-flash` instance |
| **Model Armor (Input)** | Before the agent | Google Cloud Model Armor REST scan — detects known jailbreaks, injection patterns, and policy violations |
| **Secure Architecture** | Agent itself | Vertex AI Function Calling + `account_id` enforced in Python + Python-level field masking |
| **Read-Only Permission** | Agent itself | Sets `PRAGMA query_only = ON` — blocks all write/destructive SQL at the database layer |
| **Model Armor (Output)** | After the agent | Model Armor DLP sweep on the generated response to catch PII exfiltration |
| **Post-Check LLM Evaluator** | After the agent | Inspects the agent's response for cross-tenant data using a dedicated `gemini-2.5-flash` instance |

---

## Video Overview

<a href="https://youtu.be/93-KzFBjVAU">
  <img alt="Watch on YouTube" src="https://img.shields.io/badge/-Watch%20Overview-FF0000?style=for-the-badge&logo=youtube&logoColor=white"/>
</a>

---

## Architecture

For a deep dive into how the validation pipeline works, see [docs/architecture.md](docs/architecture.md).

---

## Project Structure

```
PromptSieve/
├── app.py                  # Streamlit entry point
├── config.py               # Environment + tenant configuration
├── database.py             # SQLite setup, seed data, tool helpers
├── requirements.txt
├── agent/
│   ├── vulnerable.py       # Insecure agent — raw SQL generation
│   ├── secure.py           # Secure agent — Vertex AI Function Calling
│   └── tools.py            # FunctionDeclaration definitions (5 tools)
├── pipeline/
│   ├── pre_check.py        # Pre-Check LLM Evaluator
│   ├── model_armor.py      # Google Cloud Model Armor wrapper
│   └── post_check.py       # Post-Check LLM Evaluator
├── prompts/
│   ├── pipeline_prompts.py # All LLM system prompt templates
│   └── attack_prompts.py   # Pre-configured attack prompt library
└── views/
    ├── demo.py             # Main UI + pipeline orchestration
    └── db_admin.py         # DB inspection/reset tab
```

---

## Prerequisites

- Python 3.11+
- A Google Cloud project with **Vertex AI API** enabled
- Application Default Credentials configured (`gcloud auth application-default login`)
- *(Optional)* A **Model Armor** template for the Model Armor defenses (see step 4 below)

---

## Setup

### 1. Clone and create a virtual environment

```bash
git clone <repo-url>
cd PromptSieve
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure environment variables

Create a `.env` file in the project root:

```dotenv
# Required
GCP_PROJECT=your-gcp-project-id

# Optional — defaults shown
GCP_LOCATION=us-central1
MODEL_NAME=gemini-2.5-flash
DB_PATH=demo_database.db

# Set to enable Model Armor defenses; leave empty to run without them
MODEL_ARMOR_TEMPLATE_ID=
```

> **Important:** `GCP_LOCATION` must match the region where your Model Armor template is created. The app calls the regional endpoint (`modelarmor.<GCP_LOCATION>.rep.googleapis.com`) — mismatched regions will result in a 403.

### 4. (Optional) Create a Model Armor template

Skip this step if you only want to demo the Pre-Check / Post-Check LLM defenses.

1. In the [GCP Console](https://console.cloud.google.com/), navigate to **Security → Model Armor**
2. Click **+ Create template** and choose your region (must match `GCP_LOCATION` in `.env`)
3. Enable the following filters for the best demo coverage:

   | Filter | Recommended setting | Why |
   |--------|--------------------|----|
   | **Prompt injection & jailbreak detection** | Enabled, low confidence threshold | Catches injection attempts on input |
   | **Malicious URL detection** | Enabled | Catches harmful links in outputs |
   | **DLP — sensitive data** | Enabled; add `CREDIT_CARD_NUMBER`, `US_SOCIAL_SECURITY_NUMBER`, `EMAIL_ADDRESS` infoTypes | Demonstrates data exfiltration prevention on output |
   | **Safety filters** (hate, harassment, etc.) | Enabled at medium threshold | Rounds out the demo |

4. Note the **Template ID** and add it to your `.env`:

```dotenv
MODEL_ARMOR_TEMPLATE_ID=promptsieve-1
```

### 5. Authenticate with Google Cloud

```bash
gcloud auth application-default login
```

This must be run before starting the app. Model Armor uses Application Default Credentials to call the regional REST API.

### 6. Run the app

```bash
streamlit run app.py
```

The app opens at `http://localhost:8501` by default.

---

## Usage

### Control Panel (left column)

| Control | Description |
|---------|-------------|
| **Active Account** | Select from Nakatomi Trading, Cyberdyne Systems, or Massive Dynamic |
| **Agent Mode** | *Vulnerable* (raw SQL, full schema) or *Secure* (Function Calling, Python-enforced `account_id`) |
| **Read-Only Permission** | Enable `PRAGMA query_only` on the SQLite connection to block write SQL at the DB layer |
| **Defenses** | Toggle Pre-Check, Model Armor Input/Output, and Post-Check in any combination |
| **System Prompts** | Edit the Agent, Pre-Check, and Post-Check system prompts live — changes take effect on the next submit |

### Sending a prompt

1. Type a prompt in the center column, or pick one from the **Attack Prompts** dropdown.
2. Press **Enter** or click the submit button.
3. Watch the **Pipeline Telemetry** panel (right column) update in real time — every pipeline step, block decision, SQL generated, tool calls, and thinking trace are surfaced as they happen.

### Attack Prompts library

The center column includes a pre-loaded library of attack prompts covering the major injection categories:

| Category | Examples |
|----------|---------|
| Cross-tenant attacks | Admin override, ignore-instructions, direct tenant name query |
| PII harvesting | Sensitive field harvest, column alias masking bypass |
| SQL injection | UNION SELECT, tautology (`1=1`), destructive DROP |
| Evasion | Base64-encoded instructions, DAN jailbreak, schema/prompt leak |

Select any prompt from the dropdown and submit to see how each defense layer responds.

### Risk Profile

The Control Panel displays a live **Risk Profile** bar chart — Safety, Usability, Cost, and Speed — that updates as you toggle defenses and switch modes.

---

## Tenants and Seed Data

Three fictional tenants are seeded automatically on first run, each with five customers and 10 invoices (150 invoices total). Seed data uses a fixed random seed so database resets are deterministic.

| Tenant | account_id |
|--------|-----------|
| Nakatomi Trading | 1 |
| Cyberdyne Systems | 2 |
| Massive Dynamic | 3 |

Inspect and reset the database from the **DB Admin** tab.

---

## More Information

- [Google Cloud Model Armor documentation](https://cloud.google.com/security/products/model-armor)
- [Vertex AI Gemini Function Calling guide](https://cloud.google.com/vertex-ai/generative-ai/docs/multimodal/function-calling)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Google Cloud Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials)
- [Prompt Injection in LLM Agents (Google video)](https://www.youtube.com/watch?v=jZXvqEqJT7o)

---

## License

[MIT](LICENSE)
