# Kubernetes Log Investigation Agent (`k8s-investigator`)

A specialized Site Reliability Engineering (SRE) investigation agent built on the **Gemini Enterprise Agent Platform** using the **Google Agent Development Kit (ADK)** and `agents-cli`.

The agent ingests raw container or pod logs (or files), extracts failure signatures (e.g. `OOMKilled` exit code 137, probe failures, DNS/networking errors, CrashLoopBackOff, RBAC denials), traces a chronological event timeline, redacts sensitive credentials, and produces a comprehensive incident analysis with supporting evidence and actionable `kubectl` remediation commands.

## Architecture

- **Platform**: Gemini Enterprise Agent Platform (`google-adk` + `google-genai`)
- **Model**: `gemini-3.8-flash`
- **Agent Entrypoint**: [`app/agent.py`](file:///home/raiyan10/k8s-investigation-agent/app/agent.py) (`k8s_investigator`)
- **Investigation Tools**: [`app/tools.py`](file:///home/raiyan10/k8s-investigation-agent/app/tools.py)
  - `parse_and_sanitize_logs`: Normalizes logs, extracts line numbers (1-indexed), isolates anomalies and stack traces, and redacts sensitive credentials (bearer tokens, passwords, keys).
  - `match_k8s_signatures`: Diagnoses failures against Kubernetes SRE catalog (OOMKilled, Liveness/Readiness probes, CoreDNS NXDOMAIN, RBAC 403, missing ConfigMaps/Secrets).
  - `generate_investigation_report`: Compiles dual output: human-readable Markdown with RCA, timeline, evidence table, and kubectl commands + structured JSON payload.

## Project Structure

```
k8s-investigator/
├── app/                       # Core agent code
│   ├── agent.py               # Main agent logic and SRE instructions
│   ├── tools.py               # Diagnostic, sanitization, and reporting tools
│   ├── fast_api_app.py        # FastAPI Backend server
│   └── app_utils/             # App utilities and helpers
├── tests/                     # Unit, integration, and eval suites
│   ├── unit/test_tools.py     # Diagnostic and sanitization unit tests
│   ├── integration/           # E2E streaming and server integration tests
│   └── eval/                  # Quality flywheel eval dataset and judge
├── .agents-cli-spec.md        # Approved project specification
├── GEMINI.md                  # Coding agent guidance
└── pyproject.toml             # Project dependencies (uv)
```

> 💡 **Tip:** Use [Antigravity CLI](https://antigravity.google/) for AI-assisted development - project context is pre-configured in `GEMINI.md`.

## Requirements

Before you begin, ensure you have:
- **uv**: Python package manager (used for all dependency management in this project) - [Install](https://docs.astral.sh/uv/getting-started/installation/) ([add packages](https://docs.astral.sh/uv/concepts/dependencies/) with `uv add <package>`)
- **agents-cli**: Agents CLI - Install with `uv tool install google-agents-cli`
- **Google Cloud SDK**: For GCP services - [Install](https://cloud.google.com/sdk/docs/install)


## Quick Start

Install `agents-cli` and its skills if not already installed:

```bash
uvx google-agents-cli setup
```

Install required packages:

```bash
agents-cli install
```

Test the agent with a local web server:

```bash
agents-cli playground
```

You can also use features from the [ADK](https://adk.dev/) CLI with `uv run adk`.

## Commands

| Command              | Description                                                                                 |
| -------------------- | ------------------------------------------------------------------------------------------- |
| `agents-cli install` | Install dependencies using uv                                                         |
| `agents-cli playground` | Launch local development environment                                                  |
| `agents-cli lint`    | Run code quality checks                                                               |
| `agents-cli eval`    | Evaluate agent behavior (generate, grade, analyze, and more — see `agents-cli eval --help`) |
| `uv run pytest tests/unit tests/integration` | Run unit and integration tests                                                        || [A2A Inspector](https://github.com/a2aproject/a2a-inspector) | Launch A2A Protocol Inspector                                                        |

## 🛠️ Project Management

| Command | What It Does |
|---------|--------------|
| `agents-cli scaffold enhance` | Add CI/CD pipelines and Terraform infrastructure |
| `agents-cli infra cicd` | One-command setup of entire CI/CD pipeline + infrastructure |
| `agents-cli scaffold upgrade` | Auto-upgrade to latest version while preserving customizations |

---

## Development

Edit your agent logic in `app/agent.py` and test with `agents-cli playground` - it auto-reloads on save.

## Deployment

```bash
gcloud config set project <your-project-id>
agents-cli deploy
```

To add CI/CD and Terraform, run `agents-cli scaffold enhance`.
To set up your production infrastructure, run `agents-cli infra cicd`.

## Observability

Built-in telemetry exports to Cloud Trace, BigQuery, and Cloud Logging.

## A2A Inspector

This agent supports the [A2A Protocol](https://a2a-protocol.org/). Use the [A2A Inspector](https://github.com/a2aproject/a2a-inspector) to test interoperability.
See the [A2A Inspector docs](https://github.com/a2aproject/a2a-inspector) for details.
